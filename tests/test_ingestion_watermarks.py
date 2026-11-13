from datetime import datetime, timedelta, timezone
import json
import unittest

from driftwatch.ingestion import sort_for_replay
from driftwatch.models import BehaviorEvent, CapabilityDeclaration, parse_time
from driftwatch.validation import FixtureValidator, ConfigValidator

from support import ServiceCase, capability, event, test_config


class ModelValidationTests(unittest.TestCase):
    def test_behavior_normalizes_time_and_dimensions(self):
        raw = event(0, dimensions={"z": 2, "a": 1})
        item = BehaviorEvent.from_dict(raw)
        self.assertEqual(item.event_time, "2026-01-01T00:00:00Z")
        self.assertEqual(item.dimension_key, '{"a":"1","z":"2"}')
        self.assertEqual(item.value, 10.0)

    def test_behavior_rejects_missing_fields(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            BehaviorEvent.from_dict({"event_id": "x"})

    def test_behavior_rejects_nonfinite_value(self):
        raw = event(0)
        raw["value"] = "nan"
        with self.assertRaisesRegex(ValueError, "finite"):
            BehaviorEvent.from_dict(raw)

    def test_behavior_rejects_boolean_value(self):
        raw = event(0)
        raw["value"] = True
        with self.assertRaisesRegex(ValueError, "numeric"):
            BehaviorEvent.from_dict(raw)

    def test_capabilities_are_sorted_and_unique(self):
        item = CapabilityDeclaration.from_dict(capability(0, ["b", "a", "b", ""]))
        self.assertEqual(item.capabilities, ("a", "b"))

    def test_capability_rejects_non_list(self):
        raw = capability(0, ["a"])
        raw["capabilities"] = "a"
        with self.assertRaisesRegex(ValueError, "list"):
            CapabilityDeclaration.from_dict(raw)

    def test_naive_datetime_becomes_utc(self):
        self.assertEqual(parse_time("2026-01-01T00:00:00").tzinfo, timezone.utc)

    def test_invalid_config_window_is_rejected(self):
        with self.assertRaises(ValueError):
            test_config(windows=[{"name": "x", "size_seconds": 301, "step_seconds": 60}])

    def test_config_validator_warns_empty_protected_set(self):
        raw = test_config().__dict__
        normalized = test_config().to_dict()
        normalized["protected_capabilities"] = []
        result = ConfigValidator().validate(normalized)
        self.assertTrue(result["valid"])
        self.assertIn("empty_protected_set", {item["code"] for item in result["issues"]})


class IngestionTests(ServiceCase):
    def test_insert_event_updates_store_and_partition(self):
        result = self.service.ingestor.ingest_records([event(0)])
        self.assertEqual(result.inserted, 1)
        self.assertEqual(len(self.service.store.active_behavior_events()), 1)
        state = self.service.watermarks.snapshot()[0]
        self.assertEqual(state["event_count"], 1)

    def test_duplicate_is_idempotent(self):
        first = self.service.ingestor.ingest_records([event(0)])
        second = self.service.ingestor.ingest_records([event(0)])
        self.assertEqual(first.inserted, 1)
        self.assertEqual(second.duplicates, 1)
        self.assertEqual(len(self.service.store.active_behavior_events()), 1)

    def test_conflicting_same_revision_is_invalid(self):
        self.service.ingestor.ingest_records([event(0)])
        changed = event(0, value=11)
        result = self.service.ingestor.ingest_records([changed])
        self.assertEqual(result.invalid, 1)
        self.assertIn("conflicting", result.errors[0]["error"])

    def test_higher_revision_replaces_active(self):
        self.service.ingestor.ingest_records([event(0, value=10)])
        revised = event(0, value=12, revision=2, delay=10)
        result = self.service.ingestor.ingest_records([revised])
        self.assertEqual(result.revised, 1)
        active = self.service.store.active_behavior_events()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].value, 12)
        self.assertEqual(active[0].revision, 2)

    def test_stale_revision_is_ignored(self):
        self.service.ingestor.ingest_records([event(0, revision=2)])
        result = self.service.ingestor.ingest_records([event(0, revision=1)])
        self.assertEqual(result.stale, 1)
        self.assertEqual(self.service.store.active_behavior_events()[0].revision, 2)

    def test_capability_duplicate_is_idempotent(self):
        records = [capability(0, ["observe"]), capability(0, ["observe"])]
        result = self.service.ingestor.ingest_records(records)
        self.assertEqual(result.inserted, 1)
        self.assertEqual(result.duplicates, 1)
        self.assertEqual(len(self.service.store.active_capabilities()), 1)

    def test_strict_mode_raises_invalid_record(self):
        with self.assertRaises(ValueError):
            self.service.ingestor.ingest_records([{"type": "unknown"}], strict=True)

    def test_non_strict_mode_quarantines_invalid_record(self):
        result = self.service.ingestor.ingest_records([{"type": "unknown"}], strict=False)
        self.assertEqual(result.invalid, 1)
        self.assertEqual(result.received, 1)

    def test_jsonl_invalid_line_is_quarantined(self):
        path = self.root / "input.jsonl"
        path.write_text(json.dumps(event(0)) + "\n{broken\n", encoding="utf-8")
        result = self.service.ingestor.ingest_jsonl(path)
        self.assertEqual(result.inserted, 1)
        self.assertEqual(result.invalid, 1)

    def test_fixture_validator_reports_duplicate_key(self):
        result = FixtureValidator().validate_records([event(0), event(0)])
        self.assertTrue(result["valid"])
        self.assertEqual(result["warnings"], 1)

    def test_fixture_validator_rejects_too_many_records(self):
        validator = FixtureValidator(maximum_records=1)
        path = self.write_fixture([event(0), event(1)])
        with self.assertRaisesRegex(ValueError, "maximum"):
            validator.load(path)


class WatermarkTests(ServiceCase):
    def test_watermark_tracks_max_event_minus_lateness(self):
        self.service.ingestor.ingest_records([event(0), event(2)])
        state = self.service.watermarks.snapshot()[0]
        self.assertEqual(state["watermark"], "2026-01-01T00:08:00Z")

    def test_watermark_never_moves_backward(self):
        self.service.ingestor.ingest_records([event(3)])
        before = self.service.watermarks.snapshot()[0]["watermark"]
        late = event(0, delay=2000)
        self.service.ingestor.ingest_records([late])
        after = self.service.watermarks.snapshot()[0]["watermark"]
        self.assertEqual(before, after)

    def test_late_event_counter_increments(self):
        self.service.ingestor.ingest_records([event(3)])
        result = self.service.ingestor.ingest_records([event(0, delay=2000)])
        self.assertEqual(result.late, 1)
        self.assertEqual(self.service.watermarks.snapshot()[0]["late_count"], 1)

    def test_duplicate_counter_increments(self):
        self.service.ingestor.ingest_records([event(0), event(0)])
        self.assertEqual(self.service.watermarks.snapshot()[0]["duplicate_count"], 1)

    def test_global_watermark_uses_minimum_partition(self):
        self.service.ingestor.ingest_records([event(4, metric="calls"), event(2, metric="latency")])
        self.assertEqual(self.service.watermarks.global_watermark(), "2026-01-01T00:08:00Z")

    def test_idle_partition_can_be_ignored(self):
        self.service.ingestor.ingest_records([event(0, metric="old")])
        self.service.ingestor.ingest_records([event(10, metric="new")])
        now = "2026-01-01T00:51:00Z"
        self.assertEqual(self.service.watermarks.global_watermark(now), "2026-01-01T00:48:00Z")

    def test_replay_sort_orders_by_event_time_then_id(self):
        records = [event(2), event(0), event(1)]
        ordered = sort_for_replay(records)
        self.assertEqual([item["event_id"] for item in ordered], ["a1-calls-0", "a1-calls-1", "a1-calls-2"])


if __name__ == "__main__":
    unittest.main()

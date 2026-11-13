from datetime import datetime, timedelta, timezone
import unittest

from driftwatch.baselines import (BaselineBackfill, BaselineEngine, robust_location_scale, season_slot, trimmed)
from driftwatch.lateness import LateDataPlanner
from driftwatch.models import BehaviorEvent, iso
from driftwatch.windows import floor_time, median_absolute_deviation, window_starts

from support import ServiceCase, aggregate, event


class WindowMathTests(unittest.TestCase):
    def test_floor_time_rounds_down(self):
        value = floor_time("2026-01-01T00:07:59Z", 300)
        self.assertEqual(iso(value), "2026-01-01T00:05:00Z")

    def test_tumbling_window_has_one_start(self):
        from driftwatch.models import WindowSpec
        spec = WindowSpec("5m", 300, 300, 60, 1)
        starts = window_starts("2026-01-01T00:07:00Z", spec)
        self.assertEqual([iso(item) for item in starts], ["2026-01-01T00:05:00Z"])

    def test_sliding_window_has_multiple_starts(self):
        from driftwatch.models import WindowSpec
        spec = WindowSpec("15m", 900, 300, 60, 1)
        starts = window_starts("2026-01-01T00:12:00Z", spec)
        self.assertEqual(len(starts), 3)
        self.assertEqual(iso(starts[0]), "2026-01-01T00:10:00Z")
        self.assertEqual(iso(starts[-1]), "2026-01-01T00:00:00Z")

    def test_mad_is_robust_to_outlier(self):
        self.assertEqual(median_absolute_deviation([1, 1, 1, 100]), 0.0)

    def test_trimmed_removes_symmetric_tails(self):
        self.assertEqual(trimmed(list(range(10)), 0.2), [2, 3, 4, 5, 6, 7])

    def test_robust_scale_respects_floor(self):
        center, spread = robust_location_scale([5, 5, 5, 5], 0.2, 0)
        self.assertEqual(center, 5)
        self.assertEqual(spread, 0.2)

    def test_season_slot_repeats_daily(self):
        first = season_slot("2026-01-01T03:10:00Z", 86400, 3600)
        second = season_slot("2026-01-02T03:20:00Z", 86400, 3600)
        self.assertEqual(first, second)


class WindowEngineTests(ServiceCase):
    def test_materialize_event_creates_two_granularities(self):
        raw = event(0)
        self.service.ingestor.ingest_records([raw])
        windows = self.service.windows.materialize_event(BehaviorEvent.from_dict(raw))
        self.assertEqual({item.spec_name for item in windows}, {"5m", "15m"})

    def test_window_statistics_are_correct(self):
        records = [event(0, 1), event(0, 3, metric="calls", dimensions={"channel": "background"})]
        records = [event(0, 1), {**event(0, 3), "event_id": "second"}]
        self.service.ingestor.ingest_records(records)
        target = BehaviorEvent.from_dict(records[0])
        window = next(item for item in self.service.windows.materialize_event(target) if item.spec_name == "5m")
        self.assertEqual(window.count, 2)
        self.assertEqual(window.total, 4)
        self.assertEqual(window.mean, 2)
        self.assertEqual(window.median, 2)

    def test_repeated_materialization_without_change_is_idempotent(self):
        raw = event(0)
        self.service.ingestor.ingest_records([raw])
        target = BehaviorEvent.from_dict(raw)
        first = self.service.windows.materialize_event(target)
        second = self.service.windows.materialize_event(target)
        self.assertEqual([(item.window_id, item.version) for item in first],
                         [(item.window_id, item.version) for item in second])

    def test_revision_creates_new_window_version(self):
        first = event(0, 10)
        self.service.ingestor.ingest_records([first])
        target = BehaviorEvent.from_dict(first)
        initial = next(item for item in self.service.windows.materialize_event(target) if item.spec_name == "5m")
        revised = event(0, 20, revision=2)
        self.service.ingestor.ingest_records([revised])
        corrected = next(item for item in self.service.windows.materialize_event(BehaviorEvent.from_dict(revised), "revision")
                         if item.spec_name == "5m")
        self.assertEqual(corrected.version, initial.version + 1)
        self.assertEqual(corrected.mean, 20)
        self.assertEqual(corrected.correction_reason, "revision")

    def test_window_finalizes_after_watermark_passes_end(self):
        records = [event(0), event(2)]
        self.service.ingestor.ingest_records(records)
        target = BehaviorEvent.from_dict(records[0])
        window = next(item for item in self.service.windows.materialize_event(target) if item.spec_name == "5m")
        self.assertTrue(window.finalized)

    def test_window_remains_open_before_watermark(self):
        raw = event(0)
        self.service.ingestor.ingest_records([raw])
        window = next(item for item in self.service.windows.materialize_event(BehaviorEvent.from_dict(raw))
                      if item.spec_name == "5m")
        self.assertFalse(window.finalized)

    def test_rebuild_scope_materializes_all_unique_windows(self):
        records = [event(index, value=10 + index) for index in range(6)]
        self.service.ingestor.ingest_records(records)
        windows = self.service.windows.rebuild_scope(reason="test")
        self.assertGreaterEqual(len(windows), 8)
        self.assertEqual(len({(item.window_id, item.version) for item in windows}), len(windows))

    def test_empty_scope_returns_no_windows(self):
        self.assertEqual(self.service.windows.rebuild_scope(), [])

    def test_finalized_windows_filter(self):
        self.service.ingestor.ingest_records([event(0), event(3)])
        self.service.windows.rebuild_scope()
        self.assertTrue(all(item.finalized for item in self.service.windows.finalized_windows()))


class BaselineEngineTests(ServiceCase):
    def save_history(self, values):
        items = []
        for index, value in enumerate(values):
            item = aggregate(index, value)
            self.service.store.save_window(item, item.end_time)
            items.append(item)
        return items

    def test_baseline_requires_minimum_samples(self):
        items = self.save_history([10, 10])
        target = aggregate(3, 11)
        self.assertIsNone(self.service.baselines.build(target, target.end_time))

    def test_baseline_uses_robust_center(self):
        self.save_history([10, 10, 11, 100])
        target = aggregate(5, 12)
        baseline = self.service.baselines.build(target, target.end_time)
        self.assertIsNotNone(baseline)
        self.assertLess(baseline.center, 20)

    def test_standardized_score_uses_spread_floor(self):
        self.save_history([10, 10, 10, 10])
        target = aggregate(5, 11)
        baseline = self.service.baselines.build(target, target.end_time)
        self.assertGreater(self.service.baselines.standardized_score(target, baseline), 0)

    def test_classification_thresholds(self):
        self.assertEqual(self.service.baselines.classify(0), "normal")
        self.assertEqual(self.service.baselines.classify(3), "warning")
        self.assertEqual(self.service.baselines.classify(5), "critical")

    def test_explanation_contains_method_and_score(self):
        self.save_history([10, 10, 10, 10])
        target = aggregate(5, 20)
        baseline = self.service.baselines.build(target, target.end_time)
        explanation = self.service.baselines.explain(target, baseline)
        self.assertIn("standardized_score", explanation)
        self.assertIn("method", explanation)

    def test_backfill_skips_unfinalized_windows(self):
        items = self.save_history([10, 10, 10, 10])
        items.append(aggregate(5, 11, finalized=False))
        results = BaselineBackfill(self.service.baselines).run(items, "2026-01-03T00:00:00Z")
        self.assertGreaterEqual(len(results), 1)
        self.assertTrue(all(item.as_of != items[-1].start_time for item in results))


class LatenessPlannerTests(ServiceCase):
    def test_plan_targets_all_overlapping_windows(self):
        item = BehaviorEvent.from_dict(event(2))
        targets = self.service.lateness.plan_event(item)
        self.assertEqual(len(targets), 4)
        self.assertEqual({target.spec_name for target in targets}, {"5m", "15m"})

    def test_coalesce_combines_event_ids(self):
        first = BehaviorEvent.from_dict(event(2))
        second_raw = event(2)
        second_raw["event_id"] = "other"
        second = BehaviorEvent.from_dict(second_raw)
        targets = self.service.lateness.coalesce([first, second], "late")
        self.assertTrue(all(len(target.event_ids) == 2 for target in targets))

    def test_impact_flags_finalized_reconciliation(self):
        raw = event(0)
        self.service.ingestor.ingest_records([raw, event(3)])
        self.service.windows.materialize_event(BehaviorEvent.from_dict(raw))
        targets = self.service.lateness.plan_event(BehaviorEvent.from_dict(raw))
        impact = self.service.lateness.impact(targets)
        self.assertTrue(impact["requires_alert_reconciliation"])

    def test_audit_plan_adds_audit_entry(self):
        targets = self.service.lateness.plan_event(BehaviorEvent.from_dict(event(0)))
        result = self.service.lateness.audit_plan(targets, "2026-01-02T00:00:00Z", "tester")
        self.assertEqual(result["targets"], len(targets))
        self.assertIn("correction_plan", {row["action"] for row in self.service.store.audit_rows()})


if __name__ == "__main__":
    unittest.main()

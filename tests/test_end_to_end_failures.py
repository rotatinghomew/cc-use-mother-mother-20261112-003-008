from pathlib import Path
import json
import sqlite3
import unittest

from driftwatch.acceptance import run as acceptance_run
from driftwatch.checkpoints import CheckpointManager
from driftwatch.models import BehaviorEvent
from driftwatch.service import DriftMonitoringService, default_config
from driftwatch.simulation import SimulationPlan, StreamSimulator
from driftwatch.validation import FixtureValidator

from support import ServiceCase, capability, event, test_config


class EndToEndFlowTests(ServiceCase):
    def fixture(self, intervals=30):
        path = self.root / "stream.json"
        StreamSimulator(SimulationPlan(agents=("agent-demo",), intervals=intervals, drift_start=18,
                                       capability_expansion_at=22, duplicate_rate=0.05, late_rate=0.15)).write(path)
        return path

    def test_ingest_simulated_stream_populates_all_core_surfaces(self):
        service = DriftMonitoringService(self.root / "e2e.sqlite", default_config())
        result = service.ingest_fixture(self.fixture(), strict=True)
        self.assertGreater(result["counts"]["behavior_events"], 0)
        self.assertGreater(result["counts"]["window_aggregates"], 0)
        self.assertGreater(result["counts"]["baselines"], 0)
        self.assertGreater(result["counts"]["evidence"], 0)
        self.assertGreater(result["counts"]["alerts"], 0)

    def test_same_fixture_second_ingest_is_idempotent(self):
        service = DriftMonitoringService(self.root / "e2e.sqlite", default_config())
        path = self.fixture()
        first = service.ingest_fixture(path, strict=True)
        counts = service.store.counts()
        second = service.ingest_fixture(path, strict=True)
        self.assertEqual(second["ingestion"]["inserted"], 0)
        self.assertGreater(second["ingestion"]["duplicates"] + second["ingestion"]["stale"], 0)
        self.assertEqual(service.store.counts()["behavior_events"], counts["behavior_events"])

    def test_late_revision_rebuilds_window_without_duplicate_active_event(self):
        service = DriftMonitoringService(self.root / "e2e.sqlite", default_config())
        service.ingest_records([event(0), event(4)], strict=True)
        revised = event(0, value=30, revision=2, delay=2000)
        result = service.ingest_records([revised], strict=True)
        active = service.store.active_behavior_events()
        self.assertEqual(len([item for item in active if item.event_id == revised["event_id"]]), 1)
        versions = [item for item in service.store.windows(active_only=False) if item.metric == "calls"]
        self.assertTrue(any(item.correction_reason for item in versions))
        self.assertEqual(result["ingestion"]["revised"], 1)

    def test_recompute_preserves_active_event_count(self):
        service = DriftMonitoringService(self.root / "e2e.sqlite", default_config())
        service.ingest_fixture(self.fixture(), strict=True)
        before = len(service.store.active_behavior_events())
        result = service.recompute("2026-11-12T12:00:00Z", "test rebuild", {})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(service.store.active_behavior_events()), before)

    def test_report_after_recompute_remains_explainable(self):
        service = DriftMonitoringService(self.root / "e2e.sqlite", default_config())
        service.ingest_fixture(self.fixture(), strict=True)
        service.recompute("2026-11-12T12:00:00Z", "test rebuild", {})
        report = service.report(self.root / "report.json", "agent-demo")
        self.assertTrue(report["timeline"])
        self.assertTrue(report["evidence"])
        self.assertTrue(report["alerts"])

    def test_review_queue_covers_capability_and_behavior_categories(self):
        service = DriftMonitoringService(self.root / "e2e.sqlite", default_config())
        service.ingest_fixture(self.fixture(), strict=True)
        items = service.review.build(maximum=20)
        categories = {item.category for item in items}
        self.assertIn("capability_expansion", categories)
        self.assertTrue(categories & {"behavior_drift", "change_point", "cumulative_drift"})


class FailureRecoveryTests(ServiceCase):
    def test_malformed_fixture_does_not_create_database_records(self):
        path = self.root / "bad.json"
        path.write_text('{"records": [', encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            self.service.ingest_fixture(path, strict=True)
        self.assertEqual(self.service.store.counts()["behavior_events"], 0)

    def test_conflicting_revision_does_not_replace_active_value(self):
        self.service.ingestor.ingest_records([event(0, value=10)])
        result = self.service.ingestor.ingest_records([event(0, value=99)])
        self.assertEqual(result.invalid, 1)
        self.assertEqual(self.service.store.active_behavior_events()[0].value, 10)

    def test_failed_recompute_records_failure(self):
        original = self.service.windows.rebuild_scope
        def broken(**kwargs):
            raise RuntimeError("synthetic rebuild failure")
        self.service.windows.rebuild_scope = broken
        try:
            result = self.service.recompute("2026-01-02T00:00:00Z", "failure test", {})
        finally:
            self.service.windows.rebuild_scope = original
        self.assertEqual(result["status"], "failed")
        with self.service.store.connect() as connection:
            row = connection.execute("SELECT status,error_text FROM recomputations").fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertIn("synthetic", row["error_text"])

    def test_corrupt_checkpoint_is_refused_for_restore(self):
        self.service.ingestor.ingest_records([event(0)])
        manager = CheckpointManager(self.service.store)
        checkpoint = self.root / "checkpoint"
        manager.create(checkpoint, "2026-01-02T00:00:00Z")
        database = checkpoint / "driftwatch.sqlite"
        with database.open("ab") as handle:
            handle.write(b"corrupt")
        with self.assertRaisesRegex(ValueError, "verification"):
            manager.restore(checkpoint, self.root / "restored.sqlite")

    def test_restore_to_new_database_can_continue_ingestion(self):
        self.service.ingestor.ingest_records([event(0)])
        manager = CheckpointManager(self.service.store)
        checkpoint = self.root / "checkpoint"
        manager.create(checkpoint, "2026-01-02T00:00:00Z")
        restored_path = self.root / "restored.sqlite"
        manager.restore(checkpoint, restored_path)
        restored = DriftMonitoringService(restored_path, test_config())
        result = restored.ingestor.ingest_records([event(1)])
        self.assertEqual(result.inserted, 1)
        self.assertEqual(len(restored.store.active_behavior_events()), 2)

    def test_invalid_alert_transition_keeps_alert_state(self):
        item = self.service.alerts.consume(__import__('support').evidence(0))
        self.service.alerts.resolve(item.alert_id, "2026-01-02T01:00:00Z", "op", "fixed")
        with self.assertRaises(ValueError):
            self.service.alerts.acknowledge(item.alert_id, "2026-01-02T02:00:00Z", "op")
        self.assertEqual(self.service.store.alerts()[0].state, "resolved")

    def test_fixture_validator_reports_multiple_failures(self):
        result = FixtureValidator().validate_records([1, {"type": "unknown"}, {"event_id": "x"}])
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"], 3)


class AcceptanceContractTests(ServiceCase):
    def test_acceptance_writes_all_required_artifacts(self):
        fixture = self.root / "acceptance.json"
        StreamSimulator(SimulationPlan(agents=("agent-demo",), intervals=30, drift_start=18,
                                       capability_expansion_at=22)).write(fixture)
        output = self.root / "output"
        result = acceptance_run(fixture, output)
        self.assertTrue(result["passed"])
        self.assertTrue((output / "acceptance-result.json").is_file())
        self.assertTrue((output / "offline-report.json").is_file())
        self.assertTrue((output / "audit-proof.json").is_file())
        self.assertTrue((output / "checkpoint" / "manifest.json").is_file())

    def test_acceptance_result_has_all_boolean_checks_true(self):
        fixture = self.root / "acceptance.json"
        StreamSimulator(SimulationPlan(agents=("agent-demo",), intervals=30, drift_start=18,
                                       capability_expansion_at=22)).write(fixture)
        result = acceptance_run(fixture, self.root / "output")
        self.assertTrue(all(result["checks"].values()))


if __name__ == "__main__":
    unittest.main()

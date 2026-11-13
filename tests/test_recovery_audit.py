from pathlib import Path
import json
import sqlite3
import unittest

from driftwatch.audit import AuditVerifier
from driftwatch.checkpoints import CheckpointManager
from driftwatch.integrity import IntegrityAnalyzer
from driftwatch.migrations import CURRENT_SCHEMA_VERSION, SchemaMigrator
from driftwatch.retention import RetentionManager, RetentionPolicy
from driftwatch.storage import Store

from support import ServiceCase, capability, event, evidence


class MigrationTests(ServiceCase):
    def test_service_migrates_to_current_version(self):
        self.assertEqual(self.service.migrations.version(), CURRENT_SCHEMA_VERSION)

    def test_migrate_is_idempotent(self):
        result = self.service.migrations.migrate()
        self.assertEqual(result.status, "current")
        self.assertEqual(result.applied, ())

    def test_downgrade_rejected(self):
        with self.assertRaisesRegex(ValueError, "downgrade"):
            self.service.migrations.migrate(1)

    def test_target_above_current_rejected(self):
        with self.assertRaises(ValueError):
            self.service.migrations.migrate(CURRENT_SCHEMA_VERSION + 1)

    def test_compatibility_reports_tables_and_integrity(self):
        result = self.service.migrations.compatibility()
        self.assertTrue(result["compatible"])
        self.assertEqual(result["integrity"], "ok")
        self.assertEqual(result["missing_tables"], [])

    def test_stamp_user_version(self):
        value = self.service.migrations.stamp_user_version()
        with self.service.store.connect() as connection:
            stored = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(value, stored)


class AuditTests(ServiceCase):
    def setUp(self):
        super().setUp()
        self.service.ingestor.ingest_records([event(0), capability(0, ["observe"])])
        self.verifier = AuditVerifier(self.service.store)

    def test_proofs_form_hash_chain(self):
        proofs = self.verifier.proofs()
        self.assertGreater(len(proofs), 1)
        for left, right in zip(proofs, proofs[1:]):
            self.assertEqual(right.previous_hash, left.entry_hash)

    def test_root_hash_is_last_entry(self):
        self.assertEqual(self.verifier.root_hash(), self.verifier.proofs()[-1].entry_hash)

    def test_empty_store_has_zero_root(self):
        empty = Store(self.root / "empty.sqlite")
        self.assertEqual(AuditVerifier(empty).root_hash(), "0" * 64)

    def test_export_and_verify(self):
        path = self.root / "audit.json"
        payload = self.verifier.export(path)
        result = self.verifier.verify_export(path)
        self.assertTrue(result["valid"])
        self.assertEqual(payload["root_hash"], result["root_hash"])

    def test_tampered_export_fails(self):
        path = self.root / "audit.json"
        payload = self.verifier.export(path)
        payload["root_hash"] = "bad"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.assertFalse(self.verifier.verify_export(path)["valid"])

    def test_entity_trace_filters(self):
        trace = self.verifier.entity_trace("behavior_event", "a1-calls-0")
        self.assertEqual(len(trace), 1)
        self.assertEqual(trace[0]["action"], "insert")

    def test_action_counts(self):
        counts = self.verifier.action_counts()
        self.assertGreaterEqual(counts["insert"], 2)


class CheckpointTests(ServiceCase):
    def setUp(self):
        super().setUp()
        self.service.ingestor.ingest_records([event(0), event(1)])
        self.manager = CheckpointManager(self.service.store)

    def test_memory_store_rejected(self):
        with self.assertRaises(ValueError):
            CheckpointManager(Store(":memory:"))

    def test_create_writes_database_and_manifest(self):
        target = self.root / "checkpoint"
        manifest = self.manager.create(target, "2026-01-02T00:00:00Z")
        self.assertTrue((target / "driftwatch.sqlite").is_file())
        self.assertTrue((target / "manifest.json").is_file())
        self.assertEqual(manifest["counts"], self.service.store.counts())

    def test_verify_valid_checkpoint(self):
        target = self.root / "checkpoint"
        self.manager.create(target, "2026-01-02T00:00:00Z")
        self.assertTrue(self.manager.verify(target)["valid"])

    def test_verify_incomplete_checkpoint_rejected(self):
        target = self.root / "checkpoint"
        target.mkdir()
        with self.assertRaises(ValueError):
            self.manager.verify(target)

    def test_restore_reproduces_counts(self):
        target = self.root / "checkpoint"
        self.manager.create(target, "2026-01-02T00:00:00Z")
        restored = self.manager.restore(target, self.root / "restored.sqlite")
        self.assertEqual(restored["counts"], self.service.store.counts())

    def test_compare_detects_growth(self):
        first = self.root / "first"
        second = self.root / "second"
        self.manager.create(first, "2026-01-02T00:00:00Z")
        self.service.ingestor.ingest_records([event(2)])
        self.manager.create(second, "2026-01-02T01:00:00Z")
        comparison = self.manager.compare(first, second)
        self.assertGreater(comparison["count_deltas"]["behavior_events"], 0)
        self.assertFalse(comparison["same_database"])


class IntegrityTests(ServiceCase):
    def test_event_gap_detected(self):
        self.service.ingestor.ingest_records([event(0), event(5)])
        gaps = self.service.integrity.event_gaps(300, multiplier=2)
        self.assertEqual(len(gaps), 1)
        self.assertGreater(gaps[0].missing_estimate, 1)

    def test_arrival_delay_statistics(self):
        self.service.ingestor.ingest_records([event(0, delay=1), event(1, delay=10), event(2, delay=100)])
        stats = self.service.integrity.arrival_delays()
        self.assertEqual(stats["count"], 3)
        self.assertEqual(stats["maximum"], 100)

    def test_revision_history_detected(self):
        self.service.ingestor.ingest_records([event(0), event(0, revision=2, value=11)])
        history = self.service.integrity.revision_history()
        self.assertEqual(history[0]["versions"], 2)
        self.assertEqual(history[0]["active_versions"], 1)

    def test_stale_window_detected_after_manual_corruption(self):
        self.service.ingest_records([event(0), event(2)], strict=True)
        window = self.service.store.windows()[0]
        with self.service.store.transaction() as connection:
            connection.execute("UPDATE window_aggregates SET mean=999 WHERE window_id=? AND version=?",
                               (window.window_id, window.version))
        self.assertTrue(self.service.integrity.stale_windows())

    def test_capability_schema_regression_detected(self):
        self.service.ingestor.ingest_records([capability(0, ["a"], schema_version=2),
                                              capability(1, ["a"], schema_version=1)])
        self.assertEqual(len(self.service.integrity.capability_regressions()), 1)

    def test_health_failed_for_stale_window(self):
        self.service.ingest_records([event(0), event(2)], strict=True)
        window = self.service.store.windows()[0]
        with self.service.store.transaction() as connection:
            connection.execute("UPDATE window_aggregates SET total=999 WHERE window_id=? AND version=?",
                               (window.window_id, window.version))
        self.assertEqual(self.service.integrity.health()["status"], "failed")

    def test_health_healthy_empty_store(self):
        self.assertEqual(self.service.integrity.health()["status"], "healthy")


class RetentionTests(ServiceCase):
    def test_policy_requires_positive_days(self):
        with self.assertRaises(ValueError):
            RetentionManager(self.service.store, RetentionPolicy(raw_event_days=0))

    def test_audit_retention_covers_alerts(self):
        with self.assertRaises(ValueError):
            RetentionManager(self.service.store, RetentionPolicy(resolved_alert_days=100, audit_days=90))

    def test_dry_run_does_not_delete(self):
        self.service.ingestor.ingest_records([event(0), event(0, revision=2, value=11)])
        before = self.service.store.counts()["behavior_events"]
        manager = RetentionManager(self.service.store, RetentionPolicy(raw_event_days=1))
        result = manager.execute("2026-02-01T00:00:00Z", dry_run=True)
        self.assertGreaterEqual(result.behavior_events, 1)
        self.assertEqual(self.service.store.counts()["behavior_events"], before)

    def test_purge_removes_inactive_revision(self):
        self.service.ingestor.ingest_records([event(0), event(0, revision=2, value=11)])
        manager = RetentionManager(self.service.store, RetentionPolicy(raw_event_days=1))
        result = manager.execute("2026-02-01T00:00:00Z", dry_run=False)
        self.assertEqual(result.behavior_events, 1)
        self.assertEqual(self.service.store.counts()["behavior_events"], 1)


class ReplayTests(ServiceCase):
    def test_recompute_records_completed_run(self):
        self.service.ingestor.ingest_records([event(0), event(2)])
        result = self.service.recompute("2026-01-02T00:00:00Z", "test", {})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.service.store.counts()["recomputations"], 1)

    def test_fixture_replay_is_idempotent_on_second_run(self):
        path = self.write_fixture([event(0), event(1)])
        first = self.service.replay_fixture(path, "2026-01-02T00:00:00Z")
        second = self.service.replay_fixture(path, "2026-01-02T01:00:00Z")
        self.assertGreater(first["inserted"], 0)
        self.assertEqual(second["inserted"], 0)
        self.assertGreater(second["duplicates"], 0)


if __name__ == "__main__":
    unittest.main()

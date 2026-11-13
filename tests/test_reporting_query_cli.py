from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import json
import subprocess
import sys
import unittest

from driftwatch.cli import main as cli_main
from driftwatch.explanations import ExplanationBuilder
from driftwatch.metrics import MetricsCollector
from driftwatch.query import CursorCodec
from driftwatch.review import ReviewQueue
from driftwatch.simulation import SimulationPlan, StreamSimulator, compact_fixture

from support import ServiceCase, capability, event, evidence


class ReportingTests(ServiceCase):
    def seed(self):
        self.service.ingest_records([event(i, 10 + i) for i in range(5)] +
                                    [capability(0, ["observe"]), capability(1, ["observe", "purchase"])],
                                    strict=True)

    def test_summary_contains_counts_and_facets(self):
        self.seed()
        summary = self.service.reporter.summary()
        self.assertIn("counts", summary)
        self.assertIn("alerts_by_state", summary)
        self.assertIn("evidence_by_kind", summary)

    def test_agent_report_contains_timeline(self):
        self.seed()
        report = self.service.reporter.agent_report("a1")
        self.assertEqual(report["agent_id"], "a1")
        self.assertTrue(report["timeline"])
        self.assertIn("capability_versions", report)

    def test_write_report_creates_json(self):
        self.seed()
        path = self.root / "report.json"
        result = self.service.reporter.write(path, "a1")
        self.assertEqual(json.loads(path.read_text())["agent_id"], "a1")
        self.assertEqual(result["agent_id"], "a1")

    def test_timeline_is_time_sorted(self):
        self.seed()
        timeline = self.service.reporter.timeline("a1")
        self.assertEqual([item["time"] for item in timeline], sorted(item["time"] for item in timeline))

    def test_fleet_analytics_scores_agents(self):
        item = evidence(0)
        self.service.store.save_evidence(item, item.observed_at)
        self.service.alerts.consume(item)
        scores = self.service.analytics.agent_scores()
        self.assertEqual(scores[0]["agent_id"], "a1")
        self.assertGreater(scores[0]["risk_score"], 0)

    def test_suppression_effectiveness_handles_empty(self):
        result = self.service.analytics.suppression_effectiveness()
        self.assertEqual(result["suppression_rate"], 0)

    def test_offline_snapshot_contains_episodes(self):
        item = evidence(0)
        self.service.store.save_evidence(item, item.observed_at)
        self.assertEqual(len(self.service.analytics.offline_snapshot()["episodes"]), 1)


class ExplanationTests(ServiceCase):
    def test_evidence_explanation_has_conclusion(self):
        item = evidence(0)
        self.service.store.save_evidence(item, item.observed_at)
        result = self.service.explanations.evidence(item.evidence_id)
        self.assertEqual(result["steps"][-1]["title"], "Detection conclusion")

    def test_missing_evidence_raises(self):
        with self.assertRaises(KeyError):
            self.service.explanations.evidence("missing")

    def test_alert_explanation_mentions_suppression_budget(self):
        self.service.alerts.consume(evidence(0))
        self.service.alerts.consume(evidence(1))
        self.service.alerts.consume(evidence(2))
        alert = self.service.alerts.consume(evidence(3))
        result = self.service.explanations.alert(alert.alert_id)
        self.assertIn("budget", result["why_visible"].lower())

    def test_window_provenance_lists_source_events(self):
        self.service.ingest_records([event(0), event(2)], strict=True)
        window = self.service.store.windows()[0]
        result = self.service.explanations.window_provenance(window.window_id)
        self.assertTrue(result["source_events"])
        self.assertGreaterEqual(len(result["versions"]), 1)

    def test_summarize_agent_handles_no_active_alerts(self):
        lines = self.service.explanations.summarize_agent("a1")
        self.assertIn("No alerts", lines[-1])


class QueryTests(ServiceCase):
    def setUp(self):
        super().setUp()
        for index in range(5):
            item = evidence(index, fingerprint=f"fp-{index}")
            self.service.store.save_evidence(item, item.observed_at)
            self.service.alerts.consume(item)

    def test_cursor_round_trip(self):
        value = {"offset": 2, "collection": "x"}
        self.assertEqual(CursorCodec.decode(CursorCodec.encode(value)), value)

    def test_invalid_cursor_rejected(self):
        with self.assertRaises(ValueError):
            CursorCodec.decode("not-json")

    def test_alert_pagination(self):
        first = self.service.query.alerts(limit=2)
        second = self.service.query.alerts(limit=2, cursor=first.next_cursor)
        self.assertEqual(len(first.items), 2)
        self.assertEqual(len(second.items), 2)
        self.assertNotEqual(first.items[0]["alert_id"], second.items[0]["alert_id"])

    def test_cursor_expires_when_data_changes(self):
        first = self.service.query.alerts(limit=2)
        item = evidence(10, fingerprint="new")
        self.service.alerts.consume(item)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.service.query.alerts(limit=2, cursor=first.next_cursor)

    def test_cursor_collection_mismatch(self):
        first = self.service.query.alerts(limit=2)
        with self.assertRaisesRegex(ValueError, "collection"):
            self.service.query.evidence(limit=2, cursor=first.next_cursor)

    def test_page_limit_bounds(self):
        with self.assertRaises(ValueError):
            self.service.query.alerts(limit=0)
        with self.assertRaises(ValueError):
            self.service.query.alerts(limit=501)

    def test_evidence_filter_kind(self):
        page = self.service.query.evidence(kind="change_point")
        self.assertEqual(page.total, 5)

    def test_facets_count_alert_states(self):
        facets = self.service.query.facets()
        self.assertEqual(facets["alert_state"]["open"], 5)

    def test_timeline_search_text(self):
        results = self.service.query.search_timeline("a1", text="change_point")
        self.assertTrue(results)


class ReviewTests(ServiceCase):
    def seed(self):
        for index, severity in enumerate(["warning", "critical", "info"]):
            item = evidence(index, severity=severity, fingerprint=f"fp-{index}", score=index + 1)
            self.service.store.save_evidence(item, item.observed_at)
            self.service.alerts.consume(item)

    def test_review_queue_prioritizes_critical(self):
        self.seed()
        items = self.service.review.build()
        self.assertEqual(items[0].severity, "critical")

    def test_review_queue_is_deterministic(self):
        self.seed()
        first = [item.review_id for item in self.service.review.build(maximum=2)]
        second = [item.review_id for item in self.service.review.build(maximum=2)]
        self.assertEqual(first, second)

    def test_review_queue_validates_maximum(self):
        with self.assertRaises(ValueError):
            self.service.review.build(maximum=0)

    def test_review_coverage(self):
        self.seed()
        coverage = self.service.review.coverage(self.service.review.build())
        self.assertEqual(coverage["items"], 3)
        self.assertIn("critical", coverage["severities"])


class MetricsTests(ServiceCase):
    def test_metrics_include_database_counts(self):
        self.service.ingestor.ingest_records([event(0)])
        names = {item.name for item in self.service.metrics.collect()}
        self.assertIn("driftwatch_behavior_events_total", names)
        self.assertIn("driftwatch_partition_events_total", names)

    def test_metrics_text_has_labels(self):
        self.service.ingestor.ingest_records([event(0)])
        text = self.service.metrics.text()
        self.assertIn('partition="behavior:a1:calls:', text)

    def test_metrics_snapshot_counts_metrics(self):
        snapshot = self.service.metrics.snapshot()
        self.assertEqual(snapshot["metric_count"], len(snapshot["metrics"]))


class SimulationTests(unittest.TestCase):
    def test_plan_rejects_short_horizon(self):
        with self.assertRaises(ValueError):
            SimulationPlan(intervals=5).validate()

    def test_simulation_is_deterministic(self):
        plan = SimulationPlan(seed=9, agents=("a",), intervals=12)
        self.assertEqual(StreamSimulator(plan).generate(), StreamSimulator(plan).generate())

    def test_simulation_contains_capability_expansion(self):
        plan = SimulationPlan(agents=("a",), intervals=12, capability_expansion_at=5)
        records = StreamSimulator(plan).generate()
        declarations = [item for item in records if item["type"] == "capability"]
        self.assertEqual(len(declarations), 2)
        self.assertIn("purchase", declarations[-1]["capabilities"] if declarations[-1]["declaration_id"].endswith("1") else declarations[0]["capabilities"])

    def test_compact_fixture_has_records(self):
        fixture = compact_fixture()
        self.assertGreater(len(fixture["records"]), 100)


class CliTests(ServiceCase):
    def capture(self, argv):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = cli_main(argv)
        return code, json.loads(buffer.getvalue())

    def test_cli_simulate(self):
        output = self.root / "sim.json"
        code, value = self.capture(["simulate", str(output), "--intervals", "12"])
        self.assertEqual(code, 0)
        self.assertTrue(output.is_file())
        self.assertGreater(value["records"], 0)

    def test_cli_ingest(self):
        fixture = self.write_fixture([event(0), event(2)])
        code, value = self.capture(["--db", str(self.root / "cli.sqlite"), "ingest", str(fixture), "--strict"])
        self.assertEqual(code, 0)
        self.assertEqual(value["ingestion"]["inserted"], 2)

    def test_cli_status_output_file(self):
        database = self.root / "cli.sqlite"
        fixture = self.write_fixture([event(0)])
        self.capture(["--db", str(database), "ingest", str(fixture)])
        output = self.root / "status.json"
        code, value = self.capture(["--db", str(database), "status", "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertTrue(output.is_file())
        self.assertIn("summary", value)

    def test_cli_report(self):
        database = self.root / "cli.sqlite"
        fixture = self.write_fixture([event(0)])
        self.capture(["--db", str(database), "ingest", str(fixture)])
        output = self.root / "report.json"
        code, value = self.capture(["--db", str(database), "report", str(output), "--agent", "a1"])
        self.assertEqual(code, 0)
        self.assertEqual(value["agent_id"], "a1")


if __name__ == "__main__":
    unittest.main()

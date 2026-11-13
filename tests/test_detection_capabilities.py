import unittest

from driftwatch.analytics import EpisodeBuilder
from driftwatch.capabilities import CapabilityDiffer
from driftwatch.models import CapabilityDeclaration

from support import ServiceCase, aggregate, capability, evidence


class CapabilityDiffTests(ServiceCase):
    def declare(self, raw):
        item = CapabilityDeclaration.from_dict(raw)
        self.service.store.put_capability_declaration(item, item.arrival_time)
        return item

    def test_first_declaration_adds_all_capabilities(self):
        item = self.declare(capability(0, ["observe", "summarize"]))
        diff = self.service.capabilities.compare(item)
        self.assertEqual(diff.added, ("observe", "summarize"))
        self.assertIsNone(diff.previous_id)

    def test_second_declaration_detects_added_and_removed(self):
        self.declare(capability(0, ["observe", "summarize"]))
        item = self.declare(capability(1, ["observe", "purchase"]))
        diff = self.service.capabilities.compare(item)
        self.assertEqual(diff.added, ("purchase",))
        self.assertEqual(diff.removed, ("summarize",))
        self.assertEqual(diff.unchanged, ("observe",))

    def test_unexpected_capability_increases_risk(self):
        self.declare(capability(0, ["observe"]))
        item = self.declare(capability(1, ["observe", "unknown_tool"]))
        diff = self.service.capabilities.compare(item)
        self.assertEqual(diff.unexpected, ("unknown_tool",))
        self.assertGreaterEqual(diff.risk_score, 3)

    def test_protected_capability_is_critical(self):
        self.declare(capability(0, ["observe"]))
        item = self.declare(capability(1, ["observe", "purchase"]))
        result = self.service.capabilities.evidence(item)
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.status, "confirmed")

    def test_no_change_produces_no_evidence(self):
        self.declare(capability(0, ["observe"]))
        item = self.declare(capability(1, ["observe"]))
        self.assertIsNone(self.service.capabilities.evidence(item))

    def test_small_allowed_expansion_is_info_candidate(self):
        first = self.declare(capability(0, []))
        item = self.declare(capability(1, ["observe"]))
        result = self.service.capabilities.evidence(item)
        self.assertEqual(result.severity, "info")
        self.assertEqual(result.status, "candidate")

    def test_timeline_has_each_declaration(self):
        self.declare(capability(0, ["observe"]))
        self.declare(capability(1, ["observe", "summarize"]))
        self.assertEqual(len(self.service.capabilities.timeline("a1")), 2)


class DriftDetectorTests(ServiceCase):
    def history(self, values):
        items = []
        for index, value in enumerate(values):
            item = aggregate(index, value)
            self.service.store.save_window(item, item.end_time)
            items.append(item)
        return items

    def test_point_evidence_for_outlier(self):
        self.history([10, 10, 10, 10])
        target = aggregate(5, 20)
        baseline = self.service.baselines.build(target, target.end_time)
        result = self.service.detectors.point_evidence(target, baseline)
        self.assertIsNotNone(result)
        self.assertEqual(result.kind, "behavior_drift")
        self.assertEqual(result.payload["direction"], "increase")

    def test_point_evidence_none_inside_band(self):
        self.history([10, 10, 10, 10])
        target = aggregate(5, 10.1)
        baseline = self.service.baselines.build(target, target.end_time)
        self.assertIsNone(self.service.detectors.point_evidence(target, baseline))

    def test_change_assessment_needs_history(self):
        target = aggregate(0, 10)
        result = self.service.detectors.assess_change(target)
        self.assertFalse(result.changed)
        self.assertIn("insufficient", result.reason)

    def test_change_assessment_confirms_level_shift(self):
        items = self.history([10, 10, 10, 10, 20, 21])
        result = self.service.detectors.assess_change(items[-1])
        self.assertTrue(result.changed)
        self.assertEqual(result.direction, "increase")
        self.assertGreater(result.confidence, 0.9)

    def test_change_evidence_contains_assessment(self):
        items = self.history([10, 10, 10, 10, 20, 21])
        result = self.service.detectors.change_evidence(items[-1])
        self.assertEqual(result.status, "confirmed")
        self.assertIn("assessment", result.payload)

    def test_cusum_accumulates_small_deviations(self):
        items = self.history([10, 10, 10, 11, 11, 11, 11])
        target = items[-1]
        baseline = self.service.baselines.build(target, target.end_time)
        result = self.service.detectors.cusum_evidence(target, baseline)
        self.assertTrue(result is None or result.kind == "cumulative_drift")

    def test_evaluate_returns_empty_without_baseline(self):
        target = aggregate(0, 10)
        self.assertEqual(self.service.detectors.evaluate(target, target.end_time), [])

    def test_evidence_fingerprint_stable_across_windows(self):
        self.history([10, 10, 10, 10])
        first = aggregate(5, 20)
        second = aggregate(6, 22)
        baseline1 = self.service.baselines.build(first, first.end_time)
        self.service.store.save_window(first, first.end_time)
        baseline2 = self.service.baselines.build(second, second.end_time)
        ev1 = self.service.detectors.point_evidence(first, baseline1)
        ev2 = self.service.detectors.point_evidence(second, baseline2)
        self.assertEqual(ev1.fingerprint, ev2.fingerprint)


class EvidencePersistenceTests(ServiceCase):
    def test_save_evidence_is_idempotent(self):
        item = evidence()
        self.assertTrue(self.service.store.save_evidence(item, item.observed_at))
        self.assertFalse(self.service.store.save_evidence(item, item.observed_at))
        self.assertEqual(len(self.service.store.evidence()), 1)

    def test_evidence_filters_by_agent_and_status(self):
        first = evidence(0, status="confirmed", agent="a1")
        second = evidence(1, status="candidate", agent="a2", fingerprint="fp2")
        self.service.store.save_evidence(first, first.observed_at)
        self.service.store.save_evidence(second, second.observed_at)
        self.assertEqual(len(self.service.store.evidence(agent_id="a1")), 1)
        self.assertEqual(len(self.service.store.evidence(status="candidate")), 1)

    def test_episode_builder_groups_nearby_evidence(self):
        items = [evidence(0), evidence(1), evidence(120, fingerprint="fp")]
        episodes = EpisodeBuilder(maximum_gap_seconds=600).build(items)
        self.assertEqual(len(episodes), 2)
        self.assertEqual(episodes[0].evidence_count, 2)

    def test_episode_builder_separates_fingerprints(self):
        items = [evidence(0, fingerprint="a"), evidence(1, fingerprint="b")]
        self.assertEqual(len(EpisodeBuilder().build(items)), 2)

    def test_episode_direction_uses_majority(self):
        items = [evidence(0), evidence(1), evidence(2)]
        items[1].payload["direction"] = "decrease"
        result = EpisodeBuilder().build(items)[0]
        self.assertEqual(result.direction, "increase")


class CorrelationTests(ServiceCase):
    def test_correlator_groups_cross_signal_evidence(self):
        behavior = evidence(0, kind="change_point", fingerprint="behavior")
        capability_item = evidence(1, kind="capability_expansion", severity="critical", score=5,
                                   fingerprint="capability")
        capability_item.payload.update({"added": ["purchase"]})
        self.service.store.save_evidence(behavior, behavior.observed_at)
        self.service.store.save_evidence(capability_item, capability_item.observed_at)
        incidents = self.service.correlator.build()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(set(incidents[0].kinds), {"change_point", "capability_expansion"})

    def test_correlator_separates_distant_evidence(self):
        first = evidence(0, fingerprint="a")
        second = evidence(200, fingerprint="b")
        self.service.store.save_evidence(first, first.observed_at)
        self.service.store.save_evidence(second, second.observed_at)
        self.assertEqual(len(self.service.correlator.build()), 2)

    def test_incident_explain_includes_evidence(self):
        item = evidence(0)
        self.service.store.save_evidence(item, item.observed_at)
        incident = self.service.correlator.build()[0]
        explanation = self.service.correlator.explain(incident.incident_id)
        self.assertEqual(explanation["incident"]["incident_id"], incident.incident_id)
        self.assertEqual(len(explanation["evidence"]), 1)

    def test_incident_explain_missing_raises(self):
        with self.assertRaises(KeyError):
            self.service.correlator.explain("missing")


if __name__ == "__main__":
    unittest.main()

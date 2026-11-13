from datetime import timedelta
import unittest

from driftwatch.alerts import greater_severity
from driftwatch.policies import EvidenceRule, PolicyEngine, default_rules

from support import ServiceCase, evidence


class SeverityTests(unittest.TestCase):
    def test_greater_severity_keeps_critical(self):
        self.assertEqual(greater_severity("critical", "warning"), "critical")

    def test_greater_severity_upgrades_warning(self):
        self.assertEqual(greater_severity("info", "warning"), "warning")


class AlertLifecycleTests(ServiceCase):
    def test_first_evidence_opens_alert(self):
        item = evidence(0)
        alert = self.service.alerts.consume(item)
        self.assertEqual(alert.state, "open")
        self.assertEqual(alert.occurrence_count, 1)

    def test_duplicate_evidence_is_suppressed(self):
        first = self.service.alerts.consume(evidence(0))
        second = self.service.alerts.consume(evidence(1))
        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual(second.state, "suppressed")
        self.assertEqual(second.suppressed_count, 1)

    def test_suppression_budget_forces_open(self):
        self.service.alerts.consume(evidence(0))
        self.service.alerts.consume(evidence(1))
        self.service.alerts.consume(evidence(2))
        result = self.service.alerts.consume(evidence(3))
        self.assertEqual(result.state, "open")
        self.assertIn("budget exhausted", result.reason)

    def test_critical_evidence_bypasses_suppression(self):
        self.service.alerts.consume(evidence(0))
        result = self.service.alerts.consume(evidence(1, severity="critical", score=9))
        self.assertEqual(result.state, "open")
        self.assertIn("critical", result.reason)

    def test_max_suppression_duration_forces_open(self):
        self.service.alerts.consume(evidence(0))
        result = self.service.alerts.consume(evidence(30))
        self.assertEqual(result.state, "open")
        self.assertIn("maximum suppression", result.reason)

    def test_occurrence_context_tracks_evidence_ids(self):
        self.service.alerts.consume(evidence(0))
        result = self.service.alerts.consume(evidence(1))
        self.assertEqual(result.context["evidence_ids"], ["ev-change_point-0", "ev-change_point-1"])

    def test_acknowledge_changes_state(self):
        alert = self.service.alerts.consume(evidence(0))
        updated = self.service.alerts.acknowledge(alert.alert_id, "2026-01-02T01:00:00Z", "operator", "checking")
        self.assertEqual(updated.state, "acknowledged")
        self.assertIn("operator", updated.reason)

    def test_resolve_requires_reason(self):
        alert = self.service.alerts.consume(evidence(0))
        with self.assertRaisesRegex(ValueError, "reason"):
            self.service.alerts.resolve(alert.alert_id, "2026-01-02T01:00:00Z", "operator", "")

    def test_resolve_and_reopen_same_alert(self):
        alert = self.service.alerts.consume(evidence(0))
        self.service.alerts.resolve(alert.alert_id, "2026-01-02T00:10:00Z", "operator", "fixed")
        reopened = self.service.alerts.consume(evidence(20))
        self.assertEqual(reopened.alert_id, alert.alert_id)
        self.assertEqual(reopened.state, "open")
        self.assertIn("reopened", reopened.reason)

    def test_resolved_alert_outside_reopen_window_creates_new(self):
        alert = self.service.alerts.consume(evidence(0))
        self.service.alerts.resolve(alert.alert_id, "2026-01-02T00:10:00Z", "operator", "fixed")
        new_alert = self.service.alerts.consume(evidence(120))
        self.assertNotEqual(new_alert.alert_id, alert.alert_id)

    def test_acknowledge_missing_alert_raises(self):
        with self.assertRaises(KeyError):
            self.service.alerts.acknowledge("missing", "2026-01-02T00:00:00Z", "x")

    def test_auto_resolve_stale_alert(self):
        alert = self.service.alerts.consume(evidence(0))
        results = self.service.alerts.auto_resolve("2026-01-02T01:00:00Z")
        self.assertEqual(results[0].alert_id, alert.alert_id)
        self.assertEqual(results[0].state, "resolved")

    def test_auto_resolve_keeps_recent_alert(self):
        self.service.alerts.consume(evidence(0))
        self.assertEqual(self.service.alerts.auto_resolve("2026-01-02T00:10:00Z"), [])

    def test_candidate_evidence_can_be_retained(self):
        item = evidence(0, status="candidate", severity="info")
        alert = self.service.alerts.consume(item)
        self.assertIsNotNone(alert)

    def test_rejected_status_is_not_consumed(self):
        item = evidence(0, status="rejected")
        self.assertIsNone(self.service.alerts.consume(item))

    def test_suppression_ledger_cost(self):
        self.service.alerts.consume(evidence(0))
        self.service.alerts.consume(evidence(1))
        cost = self.service.store.suppression_cost("fp", "2026-01-01T00:00:00Z")
        self.assertEqual(cost, 1)


class PolicyRuleTests(unittest.TestCase):
    def test_rule_requires_name_and_kinds(self):
        with self.assertRaises(ValueError):
            EvidenceRule.from_dict({})

    def test_rule_matches_all_conditions(self):
        rule = EvidenceRule("x", ("change_point",), 0.5, ("warning",), "confirmed", "a")
        self.assertTrue(rule.matches(evidence(0, score=1)))

    def test_rule_rejects_low_score(self):
        rule = EvidenceRule("x", ("change_point",), 2.0)
        self.assertFalse(rule.matches(evidence(0, score=1)))

    def test_rule_rejects_agent_prefix(self):
        rule = EvidenceRule("x", ("change_point",), agent_prefix="prod-")
        self.assertFalse(rule.matches(evidence(0, agent="a1")))

    def test_duplicate_rule_names_rejected(self):
        rule = EvidenceRule("x", ("change_point",))
        with self.assertRaisesRegex(ValueError, "unique"):
            PolicyEngine([rule, rule])

    def test_policy_alerts_first_match(self):
        engine = PolicyEngine([EvidenceRule("x", ("change_point",), cooldown_seconds=60)])
        decision = engine.evaluate(evidence(0))[0]
        self.assertEqual(decision.action, "alert")

    def test_policy_cooldown_blocks_repeat(self):
        engine = PolicyEngine([EvidenceRule("x", ("change_point",), cooldown_seconds=600)])
        engine.evaluate(evidence(0))
        decision = engine.evaluate(evidence(1))[0]
        self.assertEqual(decision.action, "cooldown")

    def test_policy_allows_after_cooldown(self):
        engine = PolicyEngine([EvidenceRule("x", ("change_point",), cooldown_seconds=60)])
        engine.evaluate(evidence(0))
        decision = engine.evaluate(evidence(2))[0]
        self.assertEqual(decision.action, "alert")

    def test_nonmatching_policy_ignores(self):
        engine = PolicyEngine([EvidenceRule("x", ("capability_expansion",))])
        decision = engine.evaluate(evidence(0))[0]
        self.assertEqual(decision.action, "ignore")

    def test_filter_alertable_without_rules_passes_all(self):
        items = [evidence(0), evidence(1)]
        self.assertEqual(PolicyEngine([]).filter_alertable(items), items)

    def test_default_rules_include_three_routes(self):
        self.assertEqual(len(default_rules()), 3)


class ServiceRoutingTests(ServiceCase):
    def test_route_confirmed_change_opens_alert(self):
        item = evidence(0, kind="change_point", score=1)
        alert = self.service.route_evidence(item)
        self.assertIsNotNone(alert)

    def test_route_low_capability_candidate_does_not_alert(self):
        item = evidence(0, kind="capability_expansion", severity="info", score=1, status="candidate")
        self.assertIsNone(self.service.route_evidence(item))

    def test_lifecycle_dispatch_acknowledge(self):
        alert = self.service.alerts.consume(evidence(0))
        result = self.service.lifecycle("acknowledge", alert.alert_id, "2026-01-02T01:00:00Z", "op", "note")
        self.assertEqual(result["state"], "acknowledged")

    def test_lifecycle_dispatch_resolve(self):
        alert = self.service.alerts.consume(evidence(0))
        result = self.service.lifecycle("resolve", alert.alert_id, "2026-01-02T01:00:00Z", "op", "fixed")
        self.assertEqual(result["state"], "resolved")

    def test_lifecycle_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            self.service.lifecycle("close", "x", "2026-01-02T00:00:00Z", "op")


if __name__ == "__main__":
    unittest.main()

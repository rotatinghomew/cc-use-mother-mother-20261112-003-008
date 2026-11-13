from __future__ import annotations

from datetime import timedelta
from typing import Any

from .config import AlertPolicy
from .models import AlertRecord, DetectionEvidence, iso, parse_time, stable_id
from .storage import Store


SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
OPEN_STATES = ("open", "acknowledged", "suppressed")


def greater_severity(left: str, right: str) -> str:
    return left if SEVERITY_ORDER.get(left, -1) >= SEVERITY_ORDER.get(right, -1) else right


class AlertManager:
    def __init__(self, store: Store, policy: AlertPolicy):
        self.store = store
        self.policy = policy

    def consume(self, evidence: DetectionEvidence) -> AlertRecord | None:
        if evidence.status not in {"confirmed", "candidate"}:
            return None
        existing = self.store.alerts(fingerprint=evidence.fingerprint)
        active = next((item for item in existing if item.state in OPEN_STATES), None)
        recent = existing[0] if existing else None
        observed = parse_time(evidence.observed_at)
        if active:
            return self._update_active(active, evidence)
        if recent and recent.state == "resolved":
            elapsed = (observed - parse_time(recent.updated_at)).total_seconds()
            if elapsed <= self.policy.reopen_seconds:
                reopened = AlertRecord(
                    alert_id=recent.alert_id, fingerprint=recent.fingerprint, agent_id=recent.agent_id,
                    kind=recent.kind, state="open", severity=greater_severity(recent.severity, evidence.severity),
                    opened_at=recent.opened_at, updated_at=evidence.observed_at,
                    last_evidence_at=evidence.observed_at, occurrence_count=recent.occurrence_count + 1,
                    suppressed_count=recent.suppressed_count, reason="reopened by recurring evidence",
                    context=self._merge_context(recent.context, evidence),
                )
                self.store.save_alert(reopened)
                return reopened
        alert = AlertRecord(
            alert_id=stable_id(evidence.fingerprint, evidence.observed_at, "alert"),
            fingerprint=evidence.fingerprint,
            agent_id=evidence.agent_id,
            kind=evidence.kind,
            state="open",
            severity=evidence.severity,
            opened_at=evidence.observed_at,
            updated_at=evidence.observed_at,
            last_evidence_at=evidence.observed_at,
            occurrence_count=1,
            suppressed_count=0,
            reason=evidence.summary,
            context={"evidence_ids": [evidence.evidence_id], "latest": evidence.payload},
        )
        self.store.save_alert(alert)
        return alert

    def _update_active(self, alert: AlertRecord, evidence: DetectionEvidence) -> AlertRecord:
        observed = parse_time(evidence.observed_at)
        elapsed = max(0.0, (observed - parse_time(alert.last_evidence_at)).total_seconds())
        budget_start = observed - timedelta(seconds=self.policy.budget_window_seconds)
        spent = self.store.suppression_cost(alert.fingerprint, iso(budget_start))
        can_suppress = spent < self.policy.suppression_budget
        within_dedupe = elapsed <= self.policy.dedupe_seconds
        within_bound = (observed - parse_time(alert.opened_at)).total_seconds() <= self.policy.max_suppression_seconds
        severity = greater_severity(alert.severity, evidence.severity)
        if within_dedupe and can_suppress and within_bound and evidence.severity != "critical":
            state = "suppressed"
            reason = "duplicate evidence suppressed within bounded budget"
            suppressed_count = alert.suppressed_count + 1
            self.store.record_suppression(alert.fingerprint, evidence.observed_at, "suppress", 1, reason, alert.alert_id)
        else:
            state = "open"
            suppressed_count = alert.suppressed_count
            if not can_suppress:
                reason = "suppression budget exhausted; alert forced open"
                self.store.record_suppression(alert.fingerprint, evidence.observed_at, "budget_exhausted", 0,
                                              reason, alert.alert_id)
            elif not within_bound:
                reason = "maximum suppression duration reached; alert forced open"
            elif evidence.severity == "critical":
                reason = "critical evidence bypassed suppression"
            else:
                reason = "new evidence outside dedupe interval"
        updated = AlertRecord(
            alert_id=alert.alert_id, fingerprint=alert.fingerprint, agent_id=alert.agent_id, kind=alert.kind,
            state=state, severity=severity, opened_at=alert.opened_at, updated_at=evidence.observed_at,
            last_evidence_at=evidence.observed_at, occurrence_count=alert.occurrence_count + 1,
            suppressed_count=suppressed_count, reason=reason, context=self._merge_context(alert.context, evidence),
        )
        self.store.save_alert(updated)
        return updated

    @staticmethod
    def _merge_context(context: dict[str, Any], evidence: DetectionEvidence) -> dict[str, Any]:
        result = dict(context)
        identifiers = list(result.get("evidence_ids", []))
        if evidence.evidence_id not in identifiers:
            identifiers.append(evidence.evidence_id)
        result["evidence_ids"] = identifiers[-20:]
        result["latest"] = evidence.payload
        result["latest_score"] = evidence.score
        return result

    def acknowledge(self, alert_id: str, occurred_at: str, actor: str, note: str = "") -> AlertRecord:
        alert = self._one(alert_id)
        if alert.state == "resolved":
            raise ValueError("resolved alert cannot be acknowledged")
        updated = AlertRecord(**{**alert.to_dict(), "state": "acknowledged", "updated_at": iso(occurred_at),
                                 "reason": f"acknowledged by {actor}: {note}".rstrip()})
        self.store.save_alert(updated)
        return updated

    def resolve(self, alert_id: str, occurred_at: str, actor: str, reason: str) -> AlertRecord:
        if not reason.strip():
            raise ValueError("resolution reason is required")
        alert = self._one(alert_id)
        updated = AlertRecord(**{**alert.to_dict(), "state": "resolved", "updated_at": iso(occurred_at),
                                 "reason": f"resolved by {actor}: {reason}"})
        self.store.save_alert(updated)
        return updated

    def auto_resolve(self, now: str) -> list[AlertRecord]:
        cutoff = parse_time(now) - timedelta(seconds=self.policy.auto_resolve_seconds)
        results = []
        for alert in self.store.alerts(states=OPEN_STATES):
            if parse_time(alert.last_evidence_at) <= cutoff:
                results.append(self.resolve(alert.alert_id, now, "system", "no confirming evidence within recovery window"))
        return results

    def _one(self, alert_id: str) -> AlertRecord:
        matches = [item for item in self.store.alerts() if item.alert_id == alert_id]
        if not matches:
            raise KeyError(f"alert not found: {alert_id}")
        return matches[0]

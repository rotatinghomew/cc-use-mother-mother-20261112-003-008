from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable

from .models import DetectionEvidence, WindowAggregate
from .storage import Store


@dataclass(frozen=True)
class ExplanationStep:
    order: int
    title: str
    statement: str
    facts: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExplanationBuilder:
    def __init__(self, store: Store):
        self.store = store

    def evidence(self, evidence_id: str) -> dict[str, Any]:
        evidence = next((item for item in self.store.evidence() if item.evidence_id == evidence_id), None)
        if evidence is None:
            raise KeyError(f"evidence not found: {evidence_id}")
        steps = []
        payload = evidence.payload
        if "window" in payload:
            window = payload["window"]
            steps.append(ExplanationStep(1, "Observed window",
                                         f"{window['metric']} window ended with mean {window['mean']:.6g}",
                                         window))
        if "baseline" in payload:
            baseline = payload["baseline"]
            steps.append(ExplanationStep(len(steps) + 1, "Robust expectation",
                                         f"baseline center {baseline['center']:.6g} from {baseline['sample_count']} windows",
                                         baseline))
        if "assessment" in payload:
            assessment = payload["assessment"]
            steps.append(ExplanationStep(len(steps) + 1, "Change confirmation",
                                         assessment.get("reason", "change assessment completed"), assessment))
        if evidence.kind == "capability_expansion":
            steps.append(ExplanationStep(len(steps) + 1, "Capability set difference",
                                         f"added {len(payload.get('added', []))} and removed {len(payload.get('removed', []))}",
                                         payload))
        steps.append(ExplanationStep(len(steps) + 1, "Detection conclusion", evidence.summary,
                                     {"severity": evidence.severity, "score": evidence.score,
                                      "status": evidence.status, "fingerprint": evidence.fingerprint}))
        return {"evidence": evidence.to_dict(), "steps": [item.to_dict() for item in steps]}

    def alert(self, alert_id: str) -> dict[str, Any]:
        alert = next((item for item in self.store.alerts() if item.alert_id == alert_id), None)
        if alert is None:
            raise KeyError(f"alert not found: {alert_id}")
        identifiers = alert.context.get("evidence_ids", [])
        explanations = []
        for identifier in identifiers:
            try:
                explanations.append(self.evidence(identifier))
            except KeyError:
                explanations.append({"evidence": {"evidence_id": identifier}, "steps": [],
                                     "warning": "evidence was removed by retention"})
        return {
            "alert": alert.to_dict(),
            "why_visible": self._visibility_reason(alert.reason, alert.state),
            "evidence_chain": explanations,
            "audit_trace": self.store.audit_rows(alert.agent_id),
        }

    @staticmethod
    def _visibility_reason(reason: str, state: str) -> str:
        if "budget exhausted" in reason:
            return "The alert is visible because its bounded suppression budget was exhausted."
        if "maximum suppression" in reason:
            return "The alert is visible because suppression reached its maximum duration."
        if "critical" in reason:
            return "Critical evidence bypasses normal duplicate suppression."
        if state == "suppressed":
            return "The alert is retained but temporarily suppressed as a bounded duplicate."
        if state == "resolved":
            return "The alert remains in history after explicit or automatic resolution."
        return "The alert is visible because new evidence passed routing and deduplication policies."

    def window_provenance(self, window_id: str) -> dict[str, Any]:
        versions = [item for item in self.store.windows(active_only=False) if item.window_id == window_id]
        if not versions:
            raise KeyError(f"window not found: {window_id}")
        versions.sort(key=lambda item: item.version)
        active = versions[-1]
        events = self.store.active_behavior_events(
            agent_id=active.agent_id, metric=active.metric, dimension_key=active.dimension_key,
            start=active.start_time, end=active.end_time,
        )
        return {
            "active": active.to_dict(),
            "versions": [item.to_dict() for item in versions],
            "source_events": [item.to_dict() for item in events],
            "correction_count": max(0, len(versions) - 1),
            "finalized": active.finalized,
        }

    def summarize_agent(self, agent_id: str) -> list[str]:
        evidence = self.store.evidence(agent_id=agent_id)
        alerts = self.store.alerts(agent_id=agent_id)
        capabilities = self.store.active_capabilities(agent_id)
        lines = [f"Agent {agent_id} has {len(evidence)} evidence records and {len(alerts)} alerts."]
        if capabilities:
            latest = max(capabilities, key=lambda item: item.event_time)
            lines.append(f"Latest capability declaration lists {len(latest.capabilities)} capabilities.")
        open_alerts = [item for item in alerts if item.state != "resolved"]
        if open_alerts:
            lines.append(f"{len(open_alerts)} alerts remain active; highest severity is " +
                         max((item.severity for item in open_alerts), key=lambda value: {"info": 0, "warning": 1, "critical": 2}[value]) + ".")
        else:
            lines.append("No alerts remain active.")
        kinds = sorted({item.kind for item in evidence})
        if kinds:
            lines.append("Observed evidence types: " + ", ".join(kinds) + ".")
        return lines

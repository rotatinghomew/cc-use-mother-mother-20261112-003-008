from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Iterable

from .models import DetectionEvidence, parse_time, stable_id
from .storage import Store


@dataclass(frozen=True)
class CorrelatedIncident:
    incident_id: str
    agent_id: str
    start_time: str
    end_time: str
    evidence_ids: tuple[str, ...]
    kinds: tuple[str, ...]
    severity: str
    confidence: float
    narrative: tuple[str, ...]
    fingerprints: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IncidentCorrelator:
    def __init__(self, store: Store, horizon_seconds: int = 7200):
        if horizon_seconds <= 0:
            raise ValueError("correlation horizon must be positive")
        self.store = store
        self.horizon_seconds = horizon_seconds

    def build(self, agent_id: str | None = None) -> list[CorrelatedIncident]:
        evidence = self.store.evidence(agent_id=agent_id)
        groups: dict[str, list[DetectionEvidence]] = {}
        for item in evidence:
            groups.setdefault(item.agent_id, []).append(item)
        incidents = []
        for agent, items in groups.items():
            ordered = sorted(items, key=lambda item: (item.observed_at, item.evidence_id))
            cluster: list[DetectionEvidence] = []
            for item in ordered:
                if cluster and (parse_time(item.observed_at) - parse_time(cluster[-1].observed_at)).total_seconds() > self.horizon_seconds:
                    incidents.append(self._incident(agent, cluster))
                    cluster = []
                cluster.append(item)
            if cluster:
                incidents.append(self._incident(agent, cluster))
        return sorted(incidents, key=lambda item: (item.start_time, item.agent_id, item.incident_id))

    def _incident(self, agent: str, evidence: list[DetectionEvidence]) -> CorrelatedIncident:
        severity_order = {"info": 0, "warning": 1, "critical": 2}
        severity = max((item.severity for item in evidence), key=lambda value: severity_order.get(value, -1))
        kinds = tuple(sorted({item.kind for item in evidence}))
        fingerprints = tuple(sorted({item.fingerprint for item in evidence}))
        diversity = min(1.0, len(kinds) / 3)
        confirmed = sum(item.status == "confirmed" for item in evidence) / len(evidence)
        critical = sum(item.severity == "critical" for item in evidence) / len(evidence)
        confidence = round(min(1.0, diversity * 0.4 + confirmed * 0.4 + critical * 0.2), 6)
        narrative = tuple(self._narrative(evidence))
        return CorrelatedIncident(
            incident_id=stable_id(agent, evidence[0].observed_at, evidence[-1].observed_at, fingerprints),
            agent_id=agent, start_time=evidence[0].observed_at, end_time=evidence[-1].observed_at,
            evidence_ids=tuple(item.evidence_id for item in evidence), kinds=kinds, severity=severity,
            confidence=confidence, narrative=narrative, fingerprints=fingerprints,
        )

    @staticmethod
    def _narrative(evidence: list[DetectionEvidence]) -> list[str]:
        lines = []
        capabilities = [item for item in evidence if item.kind == "capability_expansion"]
        behavior = [item for item in evidence if item.kind in {"behavior_drift", "change_point", "cumulative_drift"}]
        if capabilities:
            latest = capabilities[-1]
            added = latest.payload.get("added", ())
            lines.append(f"capability set added {len(added)} entries")
        if behavior:
            directions = [str(item.payload.get("direction", "unknown")) for item in behavior]
            lines.append(f"behavior evidence contains {len(behavior)} deviations; latest direction {directions[-1]}")
        if capabilities and behavior:
            delta = abs((parse_time(behavior[-1].observed_at) - parse_time(capabilities[-1].observed_at)).total_seconds())
            lines.append(f"capability and behavior evidence are separated by {int(delta)} seconds")
        if not lines:
            lines.append(f"incident groups {len(evidence)} related evidence records")
        return lines

    def high_confidence(self, minimum: float = 0.6) -> list[CorrelatedIncident]:
        return [item for item in self.build() if item.confidence >= minimum]

    def explain(self, incident_id: str) -> dict[str, Any]:
        incident = next((item for item in self.build() if item.incident_id == incident_id), None)
        if incident is None:
            raise KeyError(f"incident not found: {incident_id}")
        evidence = [item.to_dict() for item in self.store.evidence() if item.evidence_id in incident.evidence_ids]
        return {"incident": incident.to_dict(), "evidence": evidence,
                "alerts": [item.to_dict() for item in self.store.alerts(agent_id=incident.agent_id)
                             if item.fingerprint in incident.fingerprints]}

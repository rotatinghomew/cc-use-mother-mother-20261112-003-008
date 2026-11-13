from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .config import MonitorConfig
from .models import CapabilityDeclaration, DetectionEvidence, stable_id
from .storage import Store


@dataclass(frozen=True)
class CapabilityDiff:
    agent_id: str
    declaration_id: str
    observed_at: str
    previous_id: str | None
    added: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged: tuple[str, ...]
    unexpected: tuple[str, ...]
    protected_added: tuple[str, ...]
    risk_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CapabilityDiffer:
    def __init__(self, store: Store, config: MonitorConfig):
        self.store = store
        self.config = config

    def previous(self, declaration: CapabilityDeclaration) -> CapabilityDeclaration | None:
        items = self.store.active_capabilities(declaration.agent_id)
        earlier = [item for item in items if (item.event_time, item.declaration_id) <
                   (declaration.event_time, declaration.declaration_id)]
        return earlier[-1] if earlier else None

    def compare(self, declaration: CapabilityDeclaration) -> CapabilityDiff:
        previous = self.previous(declaration)
        old = set(previous.capabilities if previous else ())
        new = set(declaration.capabilities)
        added = new - old
        removed = old - new
        allowed = set(self.config.capability_allowlist.get(declaration.agent_id, ()))
        unexpected = added - allowed if allowed else set()
        protected = added & set(self.config.protected_capabilities)
        score = len(added) + len(unexpected) * 2.0 + len(protected) * 4.0 + len(removed) * 0.25
        return CapabilityDiff(
            agent_id=declaration.agent_id,
            declaration_id=declaration.declaration_id,
            observed_at=declaration.event_time,
            previous_id=previous.declaration_id if previous else None,
            added=tuple(sorted(added)),
            removed=tuple(sorted(removed)),
            unchanged=tuple(sorted(old & new)),
            unexpected=tuple(sorted(unexpected)),
            protected_added=tuple(sorted(protected)),
            risk_score=score,
        )

    def evidence(self, declaration: CapabilityDeclaration) -> DetectionEvidence | None:
        diff = self.compare(declaration)
        if not diff.added and not diff.removed:
            return None
        if diff.protected_added:
            severity = "critical"
        elif diff.unexpected or len(diff.added) >= 3:
            severity = "warning"
        else:
            severity = "info"
        fingerprint = stable_id("capability-expansion", diff.agent_id, diff.added, diff.protected_added)
        summary = f"capabilities changed: +{len(diff.added)} -{len(diff.removed)}"
        return DetectionEvidence(
            evidence_id=stable_id(declaration.declaration_id, declaration.revision, diff.to_dict()),
            agent_id=diff.agent_id,
            kind="capability_expansion",
            observed_at=diff.observed_at,
            severity=severity,
            score=diff.risk_score,
            summary=summary,
            fingerprint=fingerprint,
            payload=diff.to_dict(),
            status="confirmed" if severity in {"warning", "critical"} else "candidate",
        )

    def timeline(self, agent_id: str) -> list[CapabilityDiff]:
        declarations = self.store.active_capabilities(agent_id)
        results = []
        for item in declarations:
            results.append(self.compare(item))
        return results

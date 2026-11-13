from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Iterable
import hashlib

from .analytics import EpisodeBuilder
from .models import AlertRecord, DetectionEvidence
from .storage import Store


@dataclass(frozen=True)
class ReviewItem:
    review_id: str
    agent_id: str
    priority: float
    category: str
    severity: str
    alert_id: str | None
    evidence_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    sampled: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReviewQueue:
    def __init__(self, store: Store, seed: str = "driftwatch-review-v1"):
        self.store = store
        self.seed = seed

    def build(self, maximum: int = 100, include_resolved: bool = False) -> list[ReviewItem]:
        if maximum < 1:
            raise ValueError("maximum review items must be positive")
        alerts = self.store.alerts()
        if not include_resolved:
            alerts = [item for item in alerts if item.state != "resolved"]
        evidence = self.store.evidence()
        evidence_by_fingerprint: dict[str, list[DetectionEvidence]] = defaultdict(list)
        for item in evidence:
            evidence_by_fingerprint[item.fingerprint].append(item)
        items = []
        seen_fingerprints = set()
        for alert in alerts:
            related = evidence_by_fingerprint.get(alert.fingerprint, [])
            items.append(self._from_alert(alert, related))
            seen_fingerprints.add(alert.fingerprint)
        for fingerprint, related in evidence_by_fingerprint.items():
            if fingerprint in seen_fingerprints:
                continue
            if not related:
                continue
            items.append(self._from_evidence(related))
        selected = self._stratified(items, maximum)
        selected_ids = {item.review_id for item in selected}
        return [ReviewItem(**{**item.to_dict(), "sampled": item.review_id in selected_ids})
                for item in sorted(items, key=lambda value: (-value.priority, value.review_id))
                if item.review_id in selected_ids]

    def _from_alert(self, alert: AlertRecord, evidence: list[DetectionEvidence]) -> ReviewItem:
        severity_weight = {"info": 1.0, "warning": 4.0, "critical": 10.0}.get(alert.severity, 2.0)
        state_weight = {"open": 3.0, "acknowledged": 1.5, "suppressed": 2.0, "resolved": 0.2}.get(alert.state, 1.0)
        score = severity_weight + state_weight + min(alert.occurrence_count, 10) * 0.5
        if "budget exhausted" in alert.reason:
            score += 4.0
        if alert.suppressed_count:
            score += min(alert.suppressed_count, 5) * 0.25
        reasons = [f"{alert.severity} {alert.state} alert", f"{alert.occurrence_count} occurrences"]
        if alert.suppressed_count:
            reasons.append(f"{alert.suppressed_count} duplicate occurrences suppressed")
        if "budget exhausted" in alert.reason:
            reasons.append("bounded suppression budget exhausted")
        return ReviewItem(
            review_id=self._id(alert.agent_id, alert.fingerprint), agent_id=alert.agent_id,
            priority=round(score, 6), category=alert.kind, severity=alert.severity, alert_id=alert.alert_id,
            evidence_ids=tuple(item.evidence_id for item in evidence), reasons=tuple(reasons), sampled=False,
        )

    def _from_evidence(self, evidence: list[DetectionEvidence]) -> ReviewItem:
        latest = max(evidence, key=lambda item: item.observed_at)
        score = sum(item.score for item in evidence) / len(evidence)
        severity = max((item.severity for item in evidence), key=lambda value: {"info": 0, "warning": 1, "critical": 2}[value])
        return ReviewItem(
            review_id=self._id(latest.agent_id, latest.fingerprint), agent_id=latest.agent_id,
            priority=round(score, 6), category=latest.kind, severity=severity, alert_id=None,
            evidence_ids=tuple(item.evidence_id for item in evidence),
            reasons=("evidence did not produce an active alert", f"{len(evidence)} related evidence records"), sampled=False,
        )

    def _stratified(self, items: list[ReviewItem], maximum: int) -> list[ReviewItem]:
        if len(items) <= maximum:
            return items
        strata: dict[tuple[str, str], list[ReviewItem]] = defaultdict(list)
        for item in items:
            strata[(item.severity, item.category)].append(item)
        selected = []
        for key in sorted(strata):
            candidates = sorted(strata[key], key=lambda item: (-item.priority, self._rank(item.review_id)))
            selected.append(candidates[0])
        remaining = [item for item in items if item.review_id not in {value.review_id for value in selected}]
        remaining.sort(key=lambda item: (-item.priority, self._rank(item.review_id)))
        selected.extend(remaining[:max(0, maximum - len(selected))])
        if len(selected) > maximum:
            selected.sort(key=lambda item: (-item.priority, self._rank(item.review_id)))
            selected = selected[:maximum]
        return selected

    def _rank(self, value: str) -> str:
        return hashlib.sha256(f"{self.seed}:{value}".encode()).hexdigest()

    def _id(self, agent_id: str, fingerprint: str) -> str:
        return hashlib.sha256(f"{agent_id}:{fingerprint}".encode()).hexdigest()[:24]

    def coverage(self, items: Iterable[ReviewItem]) -> dict[str, Any]:
        values = list(items)
        return {
            "items": len(values),
            "agents": len({item.agent_id for item in values}),
            "categories": sorted({item.category for item in values}),
            "severities": sorted({item.severity for item in values}),
            "with_alert": sum(item.alert_id is not None for item in values),
            "without_alert": sum(item.alert_id is None for item in values),
        }

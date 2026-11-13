from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable

from .baselines import BaselineEngine
from .config import ChangePolicy
from .models import BaselineSnapshot, DetectionEvidence, WindowAggregate, stable_id
from .storage import Store


@dataclass(frozen=True)
class ChangeAssessment:
    changed: bool
    direction: str
    effect: float
    confidence: float
    short_center: float
    long_center: float
    confirming_windows: int
    reason: str


class DriftDetector:
    def __init__(self, store: Store, baselines: BaselineEngine, policy: ChangePolicy):
        self.store = store
        self.baselines = baselines
        self.policy = policy

    def point_evidence(self, window: WindowAggregate, baseline: BaselineSnapshot) -> DetectionEvidence | None:
        score = self.baselines.standardized_score(window, baseline)
        severity = self.baselines.classify(score)
        if severity == "normal":
            return None
        direction = "increase" if score > 0 else "decrease"
        fingerprint = stable_id("behavior-drift", window.agent_id, window.metric, window.dimension_key,
                                window.spec_name, direction)
        payload = {
            "window": window.to_dict(),
            "baseline": baseline.to_dict(),
            "standardized_score": score,
            "direction": direction,
        }
        return DetectionEvidence(
            evidence_id=stable_id(window.window_id, window.version, baseline.baseline_id, "point"),
            agent_id=window.agent_id,
            kind="behavior_drift",
            observed_at=window.end_time,
            severity=severity,
            score=abs(score),
            summary=f"{window.metric} {direction} outside robust baseline",
            fingerprint=fingerprint,
            payload=payload,
            status="candidate",
        )

    def assess_change(self, window: WindowAggregate) -> ChangeAssessment:
        history = self.store.windows(
            agent_id=window.agent_id, metric=window.metric, spec_name=window.spec_name,
            dimension_key=window.dimension_key, before=window.end_time,
            limit=self.policy.long_windows + self.policy.short_windows + 2,
        )
        ordered = sorted({item.window_id: item for item in history}.values(), key=lambda item: item.end_time)
        if not ordered or ordered[-1].window_id != window.window_id:
            ordered.append(window)
        needed = self.policy.long_windows + self.policy.short_windows
        if len(ordered) < needed:
            return ChangeAssessment(False, "none", 0.0, 0.0, 0.0, 0.0, 0, "insufficient history")
        recent = ordered[-self.policy.short_windows:]
        prior = ordered[-needed:-self.policy.short_windows]
        short_center = float(median(item.mean for item in recent))
        long_center = float(median(item.mean for item in prior))
        denominator = max(abs(long_center), 1e-9)
        effect = (short_center - long_center) / denominator
        direction = "increase" if effect > 0 else "decrease"
        confirmations = sum(1 for item in recent if (item.mean - long_center) * effect > 0)
        confidence = confirmations / len(recent)
        changed = abs(effect) >= self.policy.minimum_effect and confirmations >= self.policy.confirmation_windows
        reason = "confirmed level shift" if changed else "effect or confirmation below threshold"
        return ChangeAssessment(changed, direction, effect, confidence, short_center, long_center, confirmations, reason)

    def change_evidence(self, window: WindowAggregate) -> DetectionEvidence | None:
        assessment = self.assess_change(window)
        if not assessment.changed:
            return None
        severity = "critical" if abs(assessment.effect) >= self.policy.minimum_effect * 2 else "warning"
        fingerprint = stable_id("change-point", window.agent_id, window.metric, window.dimension_key,
                                window.spec_name, assessment.direction)
        return DetectionEvidence(
            evidence_id=stable_id(window.window_id, window.version, "change", assessment.effect),
            agent_id=window.agent_id,
            kind="change_point",
            observed_at=window.end_time,
            severity=severity,
            score=abs(assessment.effect),
            summary=f"confirmed {assessment.direction} level shift in {window.metric}",
            fingerprint=fingerprint,
            payload={"window": window.to_dict(), "assessment": assessment.__dict__},
            status="confirmed",
        )

    def cusum_evidence(self, window: WindowAggregate, baseline: BaselineSnapshot) -> DetectionEvidence | None:
        history = self.store.windows(
            agent_id=window.agent_id, metric=window.metric, spec_name=window.spec_name,
            dimension_key=window.dimension_key, before=window.end_time, limit=self.policy.long_windows,
        )
        history = sorted(history, key=lambda item: item.end_time)
        positive = 0.0
        negative = 0.0
        for item in history:
            score = self.baselines.standardized_score(item, baseline)
            positive = max(0.0, positive + score - self.policy.cusum_drift)
            negative = min(0.0, negative + score + self.policy.cusum_drift)
        statistic = max(positive, abs(negative))
        if statistic < self.policy.cusum_threshold:
            return None
        direction = "increase" if positive >= abs(negative) else "decrease"
        return DetectionEvidence(
            evidence_id=stable_id(window.window_id, window.version, baseline.baseline_id, "cusum"),
            agent_id=window.agent_id,
            kind="cumulative_drift",
            observed_at=window.end_time,
            severity="warning",
            score=statistic,
            summary=f"cumulative {direction} deviation in {window.metric}",
            fingerprint=stable_id("cumulative-drift", window.agent_id, window.metric, window.dimension_key, direction),
            payload={"window": window.to_dict(), "baseline": baseline.to_dict(), "statistic": statistic,
                     "direction": direction},
            status="confirmed",
        )

    def evaluate(self, window: WindowAggregate, created_at: str) -> list[DetectionEvidence]:
        baseline = self.baselines.build(window, created_at)
        if baseline is None:
            return []
        candidates = [self.point_evidence(window, baseline), self.change_evidence(window),
                      self.cusum_evidence(window, baseline)]
        return [item for item in candidates if item is not None]

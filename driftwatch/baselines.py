from __future__ import annotations

from datetime import timedelta
from statistics import median
from typing import Iterable
import math

from .config import BaselinePolicy
from .models import BaselineSnapshot, WindowAggregate, iso, parse_time, stable_id
from .storage import Store
from .windows import median_absolute_deviation


def trimmed(values: list[float], fraction: float) -> list[float]:
    ordered = sorted(values)
    amount = int(len(ordered) * fraction)
    if amount and len(ordered) - amount * 2 >= 3:
        return ordered[amount:-amount]
    return ordered


def robust_location_scale(values: list[float], spread_floor: float, trim_fraction: float) -> tuple[float, float]:
    if not values:
        raise ValueError("values cannot be empty")
    chosen = trimmed(values, trim_fraction)
    center = float(median(chosen))
    mad = median_absolute_deviation(chosen, center)
    spread = max(float(mad * 1.4826), float(spread_floor))
    return center, spread


def season_slot(value: str, period_seconds: int, tolerance_seconds: int) -> str:
    moment = parse_time(value)
    seconds = moment.hour * 3600 + moment.minute * 60 + moment.second
    width = max(1, tolerance_seconds)
    bucket = int(round(seconds / width) * width) % period_seconds
    weekday = moment.weekday() if period_seconds >= 604800 else -1
    return f"p{period_seconds}:d{weekday}:b{bucket}"


class BaselineEngine:
    def __init__(self, store: Store, policy: BaselinePolicy):
        self.store = store
        self.policy = policy

    def candidates(self, target: WindowAggregate) -> tuple[list[WindowAggregate], str, str]:
        history = self.store.windows(
            agent_id=target.agent_id, metric=target.metric, spec_name=target.spec_name,
            dimension_key=target.dimension_key, before=target.start_time, limit=self.policy.history_windows * 4,
        )
        history = [item for item in history if item.finalized and item.window_id != target.window_id]
        slot = season_slot(target.start_time, self.policy.season_period_seconds, self.policy.season_tolerance_seconds)
        seasonal = [item for item in history if season_slot(
            item.start_time, self.policy.season_period_seconds, self.policy.season_tolerance_seconds
        ) == slot]
        if len(seasonal) >= self.policy.minimum_samples:
            return seasonal[:self.policy.history_windows], slot, "seasonal-median-mad"
        return history[:self.policy.history_windows], slot, "fallback-median-mad"

    def build(self, target: WindowAggregate, created_at: str) -> BaselineSnapshot | None:
        candidates, slot, method = self.candidates(target)
        if len(candidates) < self.policy.minimum_samples:
            return None
        values = [item.mean for item in candidates]
        center, spread = robust_location_scale(values, self.policy.spread_floor, self.policy.trim_fraction)
        quality = "strong" if method.startswith("seasonal") and len(values) >= self.policy.minimum_samples * 2 else "usable"
        baseline = BaselineSnapshot(
            baseline_id=stable_id(target.window_id, target.version, slot, method, len(values)),
            agent_id=target.agent_id,
            metric=target.metric,
            dimension_key=target.dimension_key,
            spec_name=target.spec_name,
            season_slot=slot,
            as_of=target.start_time,
            sample_count=len(values),
            center=center,
            spread=spread,
            lower=center - self.policy.warn_z * spread,
            upper=center + self.policy.warn_z * spread,
            quality=quality,
            method=method,
        )
        self.store.save_baseline(baseline, created_at)
        return baseline

    def standardized_score(self, target: WindowAggregate, baseline: BaselineSnapshot) -> float:
        return (target.mean - baseline.center) / max(baseline.spread, self.policy.spread_floor)

    def classify(self, score: float) -> str:
        magnitude = abs(score)
        if magnitude >= self.policy.critical_z:
            return "critical"
        if magnitude >= self.policy.warn_z:
            return "warning"
        return "normal"

    def band(self, baseline: BaselineSnapshot, severity: str = "warning") -> tuple[float, float]:
        multiplier = self.policy.critical_z if severity == "critical" else self.policy.warn_z
        return baseline.center - multiplier * baseline.spread, baseline.center + multiplier * baseline.spread

    def explain(self, target: WindowAggregate, baseline: BaselineSnapshot) -> dict[str, object]:
        score = self.standardized_score(target, baseline)
        return {
            "window_id": target.window_id,
            "observed_mean": target.mean,
            "baseline_center": baseline.center,
            "baseline_spread": baseline.spread,
            "standardized_score": score,
            "classification": self.classify(score),
            "sample_count": baseline.sample_count,
            "quality": baseline.quality,
            "method": baseline.method,
            "season_slot": baseline.season_slot,
        }


class BaselineBackfill:
    def __init__(self, engine: BaselineEngine):
        self.engine = engine

    def run(self, windows: Iterable[WindowAggregate], created_at: str) -> list[BaselineSnapshot]:
        results = []
        for window in sorted(windows, key=lambda item: (item.end_time, item.window_id)):
            if not window.finalized:
                continue
            baseline = self.engine.build(window, created_at)
            if baseline is not None:
                results.append(baseline)
        return results

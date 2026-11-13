from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Iterable

from .config import MonitorConfig
from .models import BehaviorEvent, WindowAggregate, WindowSpec, iso, parse_time, stable_id
from .storage import Store
from .watermarks import WatermarkManager


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def floor_time(value: str | datetime, step_seconds: int) -> datetime:
    timestamp = int((parse_time(value) - EPOCH).total_seconds())
    return EPOCH + timedelta(seconds=(timestamp // step_seconds) * step_seconds)


def window_starts(value: str | datetime, spec: WindowSpec) -> list[datetime]:
    latest = floor_time(value, spec.step_seconds)
    count = spec.size_seconds // spec.step_seconds
    result = []
    event_dt = parse_time(value)
    for offset in range(count):
        start = latest - timedelta(seconds=offset * spec.step_seconds)
        if start <= event_dt < start + timedelta(seconds=spec.size_seconds):
            result.append(start)
    return result


def median_absolute_deviation(values: list[float], center: float | None = None) -> float:
    if not values:
        return 0.0
    chosen = median(values) if center is None else center
    return float(median([abs(item - chosen) for item in values]))


class WindowEngine:
    def __init__(self, store: Store, config: MonitorConfig, watermarks: WatermarkManager):
        self.store = store
        self.config = config
        self.watermarks = watermarks

    def affected_windows(self, event: BehaviorEvent) -> list[tuple[WindowSpec, datetime]]:
        result = []
        for spec in self.config.windows:
            result.extend((spec, start) for start in window_starts(event.event_time, spec))
        return result

    def materialize_event(self, event: BehaviorEvent, correction_reason: str | None = None) -> list[WindowAggregate]:
        results = []
        for spec, start in self.affected_windows(event):
            result = self.materialize(
                event.agent_id, event.metric, event.dimension_key, spec, start, event.arrival_time, correction_reason
            )
            if result is not None:
                results.append(result)
        return results

    def materialize(self, agent_id: str, metric: str, dimension_key: str, spec: WindowSpec,
                    start: datetime, created_at: str, correction_reason: str | None = None) -> WindowAggregate | None:
        end = start + timedelta(seconds=spec.size_seconds)
        events = self.store.active_behavior_events(
            agent_id=agent_id, metric=metric, dimension_key=dimension_key, start=iso(start), end=iso(end)
        )
        if not events:
            return None
        values = [event.value for event in events]
        center = float(median(values))
        watermark = self.watermarks.watermark_for_behavior(agent_id, metric, dimension_key)
        finalized = bool(watermark and parse_time(watermark) >= end)
        window_id = stable_id(agent_id, metric, dimension_key, spec.name, iso(start), iso(end))
        previous = self.store.windows(active_only=True)
        current = next((item for item in previous if item.window_id == window_id), None)
        version = (current.version + 1) if current else 1
        aggregate = WindowAggregate(
            window_id=window_id,
            agent_id=agent_id,
            metric=metric,
            dimension_key=dimension_key,
            spec_name=spec.name,
            start_time=iso(start),
            end_time=iso(end),
            version=version,
            count=len(events),
            total=float(sum(values)),
            mean=float(sum(values) / len(values)),
            minimum=float(min(values)),
            maximum=float(max(values)),
            median=center,
            mad=median_absolute_deviation(values, center),
            first_event_time=events[0].event_time,
            last_event_time=events[-1].event_time,
            finalized=finalized,
            correction_reason=correction_reason,
        )
        if current and self.equivalent(current, aggregate):
            return current
        self.store.save_window(aggregate, created_at)
        return aggregate

    @staticmethod
    def equivalent(left: WindowAggregate, right: WindowAggregate) -> bool:
        fields = ("count", "total", "mean", "minimum", "maximum", "median", "mad",
                  "first_event_time", "last_event_time", "finalized")
        return all(getattr(left, field) == getattr(right, field) for field in fields)

    def rebuild_scope(self, agent_id: str | None = None, metric: str | None = None,
                      start: str | None = None, end: str | None = None, reason: str = "manual") -> list[WindowAggregate]:
        events = self.store.active_behavior_events(agent_id=agent_id, metric=metric, start=start, end=end)
        keys: dict[tuple[str, str, str, str, str], tuple[WindowSpec, datetime, str]] = {}
        for event in events:
            for spec, window_start in self.affected_windows(event):
                key = (event.agent_id, event.metric, event.dimension_key, spec.name, iso(window_start))
                keys[key] = (spec, window_start, event.arrival_time)
        results = []
        for key in sorted(keys):
            agent, item_metric, dimension_key, _, _ = key
            spec, window_start, arrival_time = keys[key]
            aggregate = self.materialize(agent, item_metric, dimension_key, spec, window_start,
                                         arrival_time, correction_reason=reason)
            if aggregate:
                results.append(aggregate)
        return results

    def finalized_windows(self, agent_id: str | None = None) -> list[WindowAggregate]:
        return [item for item in self.store.windows(agent_id=agent_id) if item.finalized]

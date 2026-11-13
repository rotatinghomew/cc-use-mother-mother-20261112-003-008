from __future__ import annotations

from datetime import timedelta
from typing import Any

from .config import MonitorConfig
from .models import BehaviorEvent, CapabilityDeclaration, iso, parse_time
from .storage import Store


class WatermarkManager:
    def __init__(self, store: Store, config: MonitorConfig):
        self.store = store
        self.config = config

    @staticmethod
    def behavior_partition(event: BehaviorEvent) -> str:
        return f"behavior:{event.agent_id}:{event.metric}:{event.dimension_key}"

    @staticmethod
    def capability_partition(declaration: CapabilityDeclaration) -> str:
        return f"capability:{declaration.agent_id}"

    def observe_behavior(self, event: BehaviorEvent, status: str) -> dict[str, Any]:
        allowed = max(item.allowed_lateness_seconds for item in self.config.windows)
        return self._observe(self.behavior_partition(event), event.event_time, event.arrival_time, status, allowed)

    def observe_capability(self, declaration: CapabilityDeclaration, status: str) -> dict[str, Any]:
        allowed = max(item.allowed_lateness_seconds for item in self.config.windows)
        return self._observe(self.capability_partition(declaration), declaration.event_time,
                             declaration.arrival_time, status, allowed)

    def _observe(self, partition_key: str, event_time: str, arrival_time: str,
                 status: str, allowed_lateness_seconds: int) -> dict[str, Any]:
        existing = self.store.get_partition(partition_key)
        event_dt = parse_time(event_time)
        arrival_dt = parse_time(arrival_time)
        if existing:
            previous_watermark = parse_time(existing["watermark"])
            max_event = max(parse_time(existing["max_event_time"]), event_dt)
            max_arrival = max(parse_time(existing["max_arrival_time"]), arrival_dt)
            event_count = int(existing["event_count"]) + (status in {"insert", "revision"})
            duplicate_count = int(existing["duplicate_count"]) + (status in {"duplicate", "stale"})
            late = event_dt < previous_watermark
            late_count = int(existing["late_count"]) + late
        else:
            previous_watermark = event_dt - timedelta(seconds=allowed_lateness_seconds)
            max_event = event_dt
            max_arrival = arrival_dt
            event_count = int(status in {"insert", "revision"})
            duplicate_count = int(status in {"duplicate", "stale"})
            late = False
            late_count = 0
        candidate = max_event - timedelta(seconds=allowed_lateness_seconds)
        watermark = max(previous_watermark, candidate)
        state = {
            "partition_key": partition_key,
            "max_event_time": iso(max_event),
            "max_arrival_time": iso(max_arrival),
            "watermark": iso(watermark),
            "last_activity": iso(arrival_dt),
            "event_count": int(event_count),
            "late_count": int(late_count),
            "duplicate_count": int(duplicate_count),
        }
        self.store.put_partition(state, arrival_time)
        return {**state, "late": bool(late), "previous_watermark": iso(previous_watermark)}

    def watermark_for_behavior(self, agent_id: str, metric: str, dimension_key: str) -> str | None:
        state = self.store.get_partition(f"behavior:{agent_id}:{metric}:{dimension_key}")
        return state["watermark"] if state else None

    def global_watermark(self, now: str | None = None) -> str | None:
        with self.store.connect() as connection:
            rows = connection.execute("SELECT watermark,last_activity FROM partitions").fetchall()
        if not rows:
            return None
        active = rows
        if now is not None and self.config.watermark_idle_seconds:
            cutoff = parse_time(now) - timedelta(seconds=self.config.watermark_idle_seconds)
            recent = [row for row in rows if parse_time(row["last_activity"]) >= cutoff]
            if recent:
                active = recent
        return iso(min(parse_time(row["watermark"]) for row in active))

    def snapshot(self) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            rows = connection.execute("SELECT * FROM partitions ORDER BY partition_key").fetchall()
        return [dict(row) for row in rows]

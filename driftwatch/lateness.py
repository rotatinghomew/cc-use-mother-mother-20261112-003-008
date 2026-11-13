from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Iterable

from .config import MonitorConfig
from .models import BehaviorEvent, iso, parse_time
from .storage import Store
from .windows import window_starts


@dataclass(frozen=True)
class CorrectionTarget:
    agent_id: str
    metric: str
    dimension_key: str
    spec_name: str
    start_time: str
    end_time: str
    reason: str
    event_ids: tuple[str, ...]
    existing_version: int | None
    finalized: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LateDataPlanner:
    def __init__(self, store: Store, config: MonitorConfig):
        self.store = store
        self.config = config

    def plan_event(self, event: BehaviorEvent, reason: str = "late event") -> list[CorrectionTarget]:
        results = []
        for spec in self.config.windows:
            for start in window_starts(event.event_time, spec):
                end = start + timedelta(seconds=spec.size_seconds)
                window_id = self._window_id(event, spec.name, iso(start), iso(end))
                existing = next((item for item in self.store.windows() if item.window_id == window_id), None)
                results.append(CorrectionTarget(
                    agent_id=event.agent_id, metric=event.metric, dimension_key=event.dimension_key,
                    spec_name=spec.name, start_time=iso(start), end_time=iso(end), reason=reason,
                    event_ids=(event.event_id,), existing_version=existing.version if existing else None,
                    finalized=existing.finalized if existing else False,
                ))
        return results

    def coalesce(self, events: Iterable[BehaviorEvent], reason: str) -> list[CorrectionTarget]:
        groups: dict[tuple[str, str, str, str, str, str], set[str]] = {}
        templates: dict[tuple[str, str, str, str, str, str], CorrectionTarget] = {}
        for event in events:
            for target in self.plan_event(event, reason):
                key = (target.agent_id, target.metric, target.dimension_key, target.spec_name,
                       target.start_time, target.end_time)
                groups.setdefault(key, set()).update(target.event_ids)
                templates[key] = target
        results = []
        for key in sorted(groups):
            target = templates[key]
            results.append(CorrectionTarget(**{**target.to_dict(), "event_ids": tuple(sorted(groups[key]))}))
        return results

    def impact(self, targets: Iterable[CorrectionTarget]) -> dict[str, Any]:
        items = list(targets)
        finalized = sum(item.finalized for item in items)
        new_windows = sum(item.existing_version is None for item in items)
        metrics = sorted({item.metric for item in items})
        agents = sorted({item.agent_id for item in items})
        return {
            "target_windows": len(items), "finalized_windows": finalized, "new_windows": new_windows,
            "versioned_corrections": len(items) - new_windows, "agents": agents, "metrics": metrics,
            "requires_alert_reconciliation": bool(finalized),
        }

    def audit_plan(self, targets: Iterable[CorrectionTarget], requested_at: str, actor: str) -> dict[str, Any]:
        items = list(targets)
        plan_id = self._plan_id(items, requested_at)
        with self.store.transaction() as connection:
            self.store.audit(connection, requested_at, actor, "correction_plan", "recomputation", plan_id,
                             {"targets": [item.to_dict() for item in items], "impact": self.impact(items)})
        return {"plan_id": plan_id, "targets": len(items), "impact": self.impact(items)}

    @staticmethod
    def _window_id(event: BehaviorEvent, spec_name: str, start: str, end: str) -> str:
        from .models import stable_id
        return stable_id(event.agent_id, event.metric, event.dimension_key, spec_name, start, end)

    @staticmethod
    def _plan_id(items: list[CorrectionTarget], requested_at: str) -> str:
        from .models import stable_id
        return stable_id(requested_at, [item.to_dict() for item in items])

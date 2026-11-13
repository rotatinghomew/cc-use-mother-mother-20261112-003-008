from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Iterable

from .models import BehaviorEvent, CapabilityDeclaration, iso, parse_time
from .storage import Store


@dataclass(frozen=True)
class Gap:
    agent_id: str
    metric: str
    dimension_key: str
    start_time: str
    end_time: str
    duration_seconds: float
    expected_interval_seconds: float
    missing_estimate: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntegrityFinding:
    code: str
    severity: str
    entity: str
    summary: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IntegrityAnalyzer:
    def __init__(self, store: Store):
        self.store = store

    def event_gaps(self, expected_interval_seconds: int, multiplier: float = 2.5,
                   agent_id: str | None = None) -> list[Gap]:
        if expected_interval_seconds <= 0:
            raise ValueError("expected interval must be positive")
        events = self.store.active_behavior_events(agent_id=agent_id)
        groups: dict[tuple[str, str, str], list[BehaviorEvent]] = defaultdict(list)
        for event in events:
            groups[(event.agent_id, event.metric, event.dimension_key)].append(event)
        results = []
        threshold = expected_interval_seconds * multiplier
        for key, items in groups.items():
            ordered = sorted(items, key=lambda item: (item.event_time, item.event_id))
            for left, right in zip(ordered, ordered[1:]):
                duration = (parse_time(right.event_time) - parse_time(left.event_time)).total_seconds()
                if duration > threshold:
                    missing = max(1, round(duration / expected_interval_seconds) - 1)
                    results.append(Gap(
                        agent_id=key[0], metric=key[1], dimension_key=key[2],
                        start_time=left.event_time, end_time=right.event_time, duration_seconds=duration,
                        expected_interval_seconds=float(expected_interval_seconds), missing_estimate=missing,
                    ))
        return sorted(results, key=lambda item: (item.start_time, item.agent_id, item.metric))

    def arrival_delays(self, agent_id: str | None = None) -> dict[str, Any]:
        events = self.store.active_behavior_events(agent_id=agent_id)
        delays = sorted(max(0.0, (parse_time(item.arrival_time) - parse_time(item.event_time)).total_seconds())
                        for item in events)
        if not delays:
            return {"count": 0, "minimum": 0.0, "median": 0.0, "p95": 0.0, "maximum": 0.0}
        def percentile(fraction: float) -> float:
            index = min(len(delays) - 1, max(0, round((len(delays) - 1) * fraction)))
            return delays[index]
        return {
            "count": len(delays), "minimum": delays[0], "median": percentile(0.5),
            "p95": percentile(0.95), "maximum": delays[-1],
        }

    def revision_history(self) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT event_id,COUNT(*) AS versions,MAX(revision) AS latest_revision,"
                "SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) AS active_versions "
                "FROM behavior_events GROUP BY event_id HAVING COUNT(*)>1 ORDER BY event_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def orphan_windows(self) -> list[dict[str, Any]]:
        results = []
        for window in self.store.windows():
            events = self.store.active_behavior_events(
                agent_id=window.agent_id, metric=window.metric, dimension_key=window.dimension_key,
                start=window.start_time, end=window.end_time,
            )
            if not events:
                results.append({"window_id": window.window_id, "version": window.version,
                                "start_time": window.start_time, "end_time": window.end_time})
        return results

    def stale_windows(self, tolerance: float = 1e-9) -> list[dict[str, Any]]:
        results = []
        for window in self.store.windows():
            events = self.store.active_behavior_events(
                agent_id=window.agent_id, metric=window.metric, dimension_key=window.dimension_key,
                start=window.start_time, end=window.end_time,
            )
            if not events:
                continue
            total = sum(item.value for item in events)
            expected = {"count": len(events), "total": total, "mean": total / len(events),
                        "minimum": min(item.value for item in events), "maximum": max(item.value for item in events)}
            mismatches = {}
            for field, value in expected.items():
                actual = getattr(window, field)
                if abs(actual - value) > tolerance:
                    mismatches[field] = {"stored": actual, "expected": value}
            if mismatches:
                results.append({"window_id": window.window_id, "version": window.version,
                                "mismatches": mismatches})
        return results

    def capability_regressions(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        declarations = self.store.active_capabilities(agent_id)
        groups: dict[str, list[CapabilityDeclaration]] = defaultdict(list)
        for item in declarations:
            groups[item.agent_id].append(item)
        results = []
        for agent, items in groups.items():
            ordered = sorted(items, key=lambda item: (item.event_time, item.declaration_id))
            for left, right in zip(ordered, ordered[1:]):
                if right.schema_version < left.schema_version:
                    results.append({"agent_id": agent, "from_id": left.declaration_id,
                                    "to_id": right.declaration_id, "from_schema": left.schema_version,
                                    "to_schema": right.schema_version})
        return results

    def findings(self, expected_interval_seconds: int = 60) -> list[IntegrityFinding]:
        findings = []
        for gap in self.event_gaps(expected_interval_seconds):
            findings.append(IntegrityFinding(
                "event_gap", "warning", gap.agent_id,
                f"estimated {gap.missing_estimate} missing {gap.metric} events", gap.to_dict(),
            ))
        for item in self.revision_history():
            severity = "critical" if item["active_versions"] != 1 else "info"
            findings.append(IntegrityFinding(
                "revision_history", severity, item["event_id"],
                f"event has {item['versions']} revisions", item,
            ))
        for item in self.stale_windows():
            findings.append(IntegrityFinding(
                "stale_window", "critical", item["window_id"],
                "materialized window differs from active source events", item,
            ))
        for item in self.capability_regressions():
            findings.append(IntegrityFinding(
                "capability_schema_regression", "warning", item["agent_id"],
                "capability declaration schema version moved backward", item,
            ))
        return findings

    def health(self, expected_interval_seconds: int = 60) -> dict[str, Any]:
        findings = self.findings(expected_interval_seconds)
        counts = Counter(item.severity for item in findings)
        status = "failed" if counts["critical"] else "degraded" if counts["warning"] else "healthy"
        return {
            "status": status,
            "finding_counts": dict(counts),
            "arrival_delays": self.arrival_delays(),
            "findings": [item.to_dict() for item in findings],
        }

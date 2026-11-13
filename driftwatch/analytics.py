from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from statistics import median
from typing import Any, Iterable

from .models import AlertRecord, DetectionEvidence, WindowAggregate, parse_time
from .storage import Store


@dataclass(frozen=True)
class DriftEpisode:
    agent_id: str
    kind: str
    fingerprint: str
    start_time: str
    end_time: str
    evidence_count: int
    peak_score: float
    peak_severity: str
    direction: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EpisodeBuilder:
    def __init__(self, maximum_gap_seconds: int = 3600):
        if maximum_gap_seconds < 0:
            raise ValueError("maximum gap cannot be negative")
        self.maximum_gap_seconds = maximum_gap_seconds

    def build(self, evidence: Iterable[DetectionEvidence]) -> list[DriftEpisode]:
        groups: dict[tuple[str, str, str], list[DetectionEvidence]] = defaultdict(list)
        for item in evidence:
            groups[(item.agent_id, item.kind, item.fingerprint)].append(item)
        episodes = []
        for key, items in groups.items():
            ordered = sorted(items, key=lambda item: (item.observed_at, item.evidence_id))
            current: list[DetectionEvidence] = []
            for item in ordered:
                if current:
                    gap = (parse_time(item.observed_at) - parse_time(current[-1].observed_at)).total_seconds()
                    if gap > self.maximum_gap_seconds:
                        episodes.append(self._episode(key, current))
                        current = []
                current.append(item)
            if current:
                episodes.append(self._episode(key, current))
        return sorted(episodes, key=lambda item: (item.start_time, item.agent_id, item.kind))

    @staticmethod
    def _episode(key: tuple[str, str, str], items: list[DetectionEvidence]) -> DriftEpisode:
        severity_order = {"info": 0, "warning": 1, "critical": 2}
        peak = max(items, key=lambda item: (item.score, severity_order.get(item.severity, -1)))
        directions = [str(item.payload.get("direction", "unknown")) for item in items]
        direction = Counter(directions).most_common(1)[0][0]
        return DriftEpisode(key[0], key[1], key[2], items[0].observed_at, items[-1].observed_at,
                            len(items), peak.score, peak.severity, direction)


class FleetAnalytics:
    def __init__(self, store: Store):
        self.store = store

    def agent_scores(self) -> list[dict[str, Any]]:
        evidence = self.store.evidence()
        alerts = self.store.alerts()
        evidence_by_agent: dict[str, list[DetectionEvidence]] = defaultdict(list)
        alerts_by_agent: dict[str, list[AlertRecord]] = defaultdict(list)
        for item in evidence:
            evidence_by_agent[item.agent_id].append(item)
        for item in alerts:
            alerts_by_agent[item.agent_id].append(item)
        agents = sorted(set(evidence_by_agent) | set(alerts_by_agent))
        results = []
        for agent in agents:
            agent_evidence = evidence_by_agent[agent]
            agent_alerts = alerts_by_agent[agent]
            score = sum(item.score * {"info": 0.25, "warning": 1.0, "critical": 2.0}.get(item.severity, 1)
                        for item in agent_evidence)
            open_count = sum(item.state != "resolved" for item in agent_alerts)
            results.append({
                "agent_id": agent, "risk_score": round(score + open_count * 2, 6),
                "evidence_count": len(agent_evidence), "open_alerts": open_count,
                "critical_alerts": sum(item.severity == "critical" for item in agent_alerts),
            })
        return sorted(results, key=lambda item: (-item["risk_score"], item["agent_id"]))

    def metric_trends(self, agent_id: str) -> list[dict[str, Any]]:
        windows = self.store.windows(agent_id=agent_id)
        groups: dict[tuple[str, str], list[WindowAggregate]] = defaultdict(list)
        for item in windows:
            groups[(item.metric, item.spec_name)].append(item)
        results = []
        for key, items in groups.items():
            ordered = sorted(items, key=lambda item: item.end_time)
            values = [item.mean for item in ordered]
            midpoint = max(1, len(values) // 2)
            older = median(values[:midpoint])
            newer = median(values[midpoint:]) if values[midpoint:] else older
            change = (newer - older) / max(abs(older), 1e-9)
            results.append({
                "metric": key[0], "window_spec": key[1], "windows": len(items),
                "older_center": older, "newer_center": newer, "relative_change": change,
                "direction": "increase" if change > 0 else "decrease" if change < 0 else "flat",
            })
        return sorted(results, key=lambda item: (item["metric"], item["window_spec"]))

    def suppression_effectiveness(self) -> dict[str, Any]:
        alerts = self.store.alerts()
        total_occurrences = sum(item.occurrence_count for item in alerts)
        suppressed = sum(item.suppressed_count for item in alerts)
        forced_open = sum("forced open" in item.reason for item in alerts)
        return {
            "alerts": len(alerts), "occurrences": total_occurrences, "suppressed": suppressed,
            "suppression_rate": suppressed / total_occurrences if total_occurrences else 0.0,
            "forced_open_alerts": forced_open,
        }

    def episodes(self, maximum_gap_seconds: int = 3600) -> list[dict[str, Any]]:
        builder = EpisodeBuilder(maximum_gap_seconds)
        return [item.to_dict() for item in builder.build(self.store.evidence())]

    def offline_snapshot(self) -> dict[str, Any]:
        return {
            "agent_scores": self.agent_scores(),
            "suppression": self.suppression_effectiveness(),
            "episodes": self.episodes(),
            "counts": self.store.counts(),
        }

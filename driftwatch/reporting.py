from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import json

from .storage import Store


class Reporter:
    def __init__(self, store: Store):
        self.store = store

    def timeline(self, agent_id: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for declaration in self.store.active_capabilities(agent_id):
            items.append({
                "time": declaration.event_time,
                "type": "capability_declaration",
                "id": declaration.declaration_id,
                "summary": f"declared {len(declaration.capabilities)} capabilities",
                "details": declaration.to_dict(),
            })
        for evidence in self.store.evidence(agent_id=agent_id):
            items.append({
                "time": evidence.observed_at,
                "type": "evidence",
                "id": evidence.evidence_id,
                "summary": evidence.summary,
                "details": evidence.to_dict(),
            })
        for alert in self.store.alerts(agent_id=agent_id):
            items.append({
                "time": alert.updated_at,
                "type": "alert",
                "id": alert.alert_id,
                "summary": f"{alert.state} {alert.severity} {alert.kind}",
                "details": alert.to_dict(),
            })
        for row in self.store.audit_rows(agent_id):
            if row["entity_type"] in {"behavior_event", "window"}:
                items.append({
                    "time": row["occurred_at"],
                    "type": "audit",
                    "id": str(row["sequence"]),
                    "summary": f"{row['action']} {row['entity_type']}",
                    "details": row["details"],
                })
        return sorted(items, key=lambda item: (item["time"], item["type"], item["id"]))

    def summary(self) -> dict[str, Any]:
        alerts = self.store.alerts()
        evidence = self.store.evidence()
        windows = self.store.windows()
        return {
            "counts": self.store.counts(),
            "alerts_by_state": dict(Counter(item.state for item in alerts)),
            "alerts_by_severity": dict(Counter(item.severity for item in alerts)),
            "evidence_by_kind": dict(Counter(item.kind for item in evidence)),
            "agents": sorted({item.agent_id for item in evidence} | {item.agent_id for item in alerts}),
            "window_specs": dict(Counter(item.spec_name for item in windows)),
            "latest_alerts": [item.to_dict() for item in alerts[:20]],
        }

    def agent_report(self, agent_id: str) -> dict[str, Any]:
        windows = self.store.windows(agent_id=agent_id)
        evidence = self.store.evidence(agent_id=agent_id)
        alerts = self.store.alerts(agent_id=agent_id)
        metrics: dict[str, dict[str, Any]] = {}
        grouped: dict[str, list[Any]] = defaultdict(list)
        for item in windows:
            grouped[item.metric].append(item)
        for metric, items in grouped.items():
            ordered = sorted(items, key=lambda item: item.end_time)
            metrics[metric] = {
                "window_count": len(ordered),
                "latest_mean": ordered[-1].mean,
                "latest_end": ordered[-1].end_time,
                "corrections": sum(bool(item.correction_reason) for item in ordered),
            }
        return {
            "agent_id": agent_id,
            "metrics": metrics,
            "capability_versions": [item.to_dict() for item in self.store.active_capabilities(agent_id)],
            "evidence": [item.to_dict() for item in evidence],
            "alerts": [item.to_dict() for item in alerts],
            "timeline": self.timeline(agent_id),
        }

    def write(self, path: str | Path, agent_id: str | None = None) -> dict[str, Any]:
        report = self.agent_report(agent_id) if agent_id else self.summary()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return report

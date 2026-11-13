from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any

from .models import iso, parse_time
from .storage import Store


@dataclass(frozen=True)
class RetentionPolicy:
    raw_event_days: int = 30
    inactive_window_days: int = 45
    resolved_alert_days: int = 90
    audit_days: int = 180
    preserve_revisions: bool = True

    def validate(self) -> None:
        values = (self.raw_event_days, self.inactive_window_days, self.resolved_alert_days, self.audit_days)
        if any(value < 1 for value in values):
            raise ValueError("retention days must be positive")
        if self.audit_days < self.resolved_alert_days:
            raise ValueError("audit retention must cover resolved alert retention")


@dataclass(frozen=True)
class RetentionResult:
    behavior_events: int
    capability_declarations: int
    window_versions: int
    alerts: int
    audit_rows: int
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RetentionManager:
    def __init__(self, store: Store, policy: RetentionPolicy):
        policy.validate()
        self.store = store
        self.policy = policy

    def plan(self, now: str) -> dict[str, tuple[str, list[Any]]]:
        moment = parse_time(now)
        event_cutoff = iso(moment - timedelta(days=self.policy.raw_event_days))
        window_cutoff = iso(moment - timedelta(days=self.policy.inactive_window_days))
        alert_cutoff = iso(moment - timedelta(days=self.policy.resolved_alert_days))
        audit_cutoff = iso(moment - timedelta(days=self.policy.audit_days))
        active_revision_clause = "active=0 AND" if self.policy.preserve_revisions else ""
        return {
            "behavior_events": (f"SELECT event_id,revision FROM behavior_events WHERE {active_revision_clause} event_time<?", [event_cutoff]),
            "capability_declarations": (f"SELECT declaration_id,revision FROM capability_declarations WHERE {active_revision_clause} event_time<?", [event_cutoff]),
            "window_aggregates": ("SELECT window_id,version FROM window_aggregates WHERE active=0 AND end_time<?", [window_cutoff]),
            "alerts": ("SELECT alert_id FROM alerts WHERE state='resolved' AND updated_at<?", [alert_cutoff]),
            "audit_log": ("SELECT sequence FROM audit_log WHERE occurred_at<?", [audit_cutoff]),
        }

    def execute(self, now: str, dry_run: bool = True) -> RetentionResult:
        plan = self.plan(now)
        counts = {}
        with self.store.transaction() as connection:
            for table, (query, params) in plan.items():
                rows = connection.execute(query, params).fetchall()
                counts[table] = len(rows)
                if dry_run or not rows:
                    continue
                if table == "behavior_events":
                    connection.executemany("DELETE FROM behavior_events WHERE event_id=? AND revision=?", rows)
                elif table == "capability_declarations":
                    connection.executemany("DELETE FROM capability_declarations WHERE declaration_id=? AND revision=?", rows)
                elif table == "window_aggregates":
                    connection.executemany("DELETE FROM window_aggregates WHERE window_id=? AND version=?", rows)
                elif table == "alerts":
                    connection.executemany("DELETE FROM alerts WHERE alert_id=?", rows)
                elif table == "audit_log":
                    connection.executemany("DELETE FROM audit_log WHERE sequence=?", rows)
            self.store.audit(connection, now, "retention", "dry_run" if dry_run else "purge",
                             "retention", iso(now), {"counts": counts, "policy": asdict(self.policy)})
        return RetentionResult(
            behavior_events=counts["behavior_events"],
            capability_declarations=counts["capability_declarations"],
            window_versions=counts["window_aggregates"],
            alerts=counts["alerts"], audit_rows=counts["audit_log"], dry_run=dry_run,
        )

    def vacuum(self) -> None:
        connection = self.store.connect()
        try:
            connection.execute("VACUUM")
        finally:
            connection.close()

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator
import json
import sqlite3

from .models import (
    AlertRecord, BaselineSnapshot, BehaviorEvent, CapabilityDeclaration,
    DetectionEvidence, WindowAggregate, iso, stable_id,
)


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS behavior_events (
    event_id TEXT NOT NULL, revision INTEGER NOT NULL, agent_id TEXT NOT NULL,
    event_time TEXT NOT NULL, arrival_time TEXT NOT NULL, metric TEXT NOT NULL,
    value REAL NOT NULL, dimensions_json TEXT NOT NULL, dimension_key TEXT NOT NULL,
    source TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, received_at TEXT NOT NULL,
    PRIMARY KEY(event_id, revision)
);
CREATE INDEX IF NOT EXISTS behavior_active_idx
ON behavior_events(agent_id, metric, dimension_key, event_time) WHERE active = 1;
CREATE TABLE IF NOT EXISTS capability_declarations (
    declaration_id TEXT NOT NULL, revision INTEGER NOT NULL, agent_id TEXT NOT NULL,
    event_time TEXT NOT NULL, arrival_time TEXT NOT NULL, capabilities_json TEXT NOT NULL,
    schema_version INTEGER NOT NULL, issuer TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    received_at TEXT NOT NULL, PRIMARY KEY(declaration_id, revision)
);
CREATE INDEX IF NOT EXISTS capability_active_idx
ON capability_declarations(agent_id, event_time) WHERE active = 1;
CREATE TABLE IF NOT EXISTS partitions (
    partition_key TEXT PRIMARY KEY, max_event_time TEXT NOT NULL, max_arrival_time TEXT NOT NULL,
    watermark TEXT NOT NULL, last_activity TEXT NOT NULL, event_count INTEGER NOT NULL,
    late_count INTEGER NOT NULL, duplicate_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS window_aggregates (
    window_id TEXT NOT NULL, version INTEGER NOT NULL, agent_id TEXT NOT NULL, metric TEXT NOT NULL,
    dimension_key TEXT NOT NULL, spec_name TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL,
    count INTEGER NOT NULL, total REAL NOT NULL, mean REAL NOT NULL, minimum REAL NOT NULL, maximum REAL NOT NULL,
    median REAL NOT NULL, mad REAL NOT NULL, first_event_time TEXT NOT NULL, last_event_time TEXT NOT NULL,
    finalized INTEGER NOT NULL, correction_reason TEXT, active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, PRIMARY KEY(window_id, version)
);
CREATE INDEX IF NOT EXISTS window_active_idx
ON window_aggregates(agent_id, metric, dimension_key, spec_name, end_time) WHERE active = 1;
CREATE TABLE IF NOT EXISTS baselines (
    baseline_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, metric TEXT NOT NULL, dimension_key TEXT NOT NULL,
    spec_name TEXT NOT NULL, season_slot TEXT NOT NULL, as_of TEXT NOT NULL, sample_count INTEGER NOT NULL,
    center REAL NOT NULL, spread REAL NOT NULL, lower_bound REAL NOT NULL, upper_bound REAL NOT NULL,
    quality TEXT NOT NULL, method TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS baseline_lookup_idx
ON baselines(agent_id, metric, dimension_key, spec_name, season_slot, as_of);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, kind TEXT NOT NULL, observed_at TEXT NOT NULL,
    severity TEXT NOT NULL, score REAL NOT NULL, summary TEXT NOT NULL, fingerprint TEXT NOT NULL,
    payload_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_agent_idx ON evidence(agent_id, observed_at);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, agent_id TEXT NOT NULL, kind TEXT NOT NULL,
    state TEXT NOT NULL, severity TEXT NOT NULL, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    last_evidence_at TEXT NOT NULL, occurrence_count INTEGER NOT NULL, suppressed_count INTEGER NOT NULL,
    reason TEXT NOT NULL, context_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_fingerprint_idx ON alerts(fingerprint, updated_at);
CREATE TABLE IF NOT EXISTS suppression_ledger (
    entry_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, occurred_at TEXT NOT NULL, action TEXT NOT NULL,
    cost INTEGER NOT NULL, reason TEXT NOT NULL, alert_id TEXT
);
CREATE INDEX IF NOT EXISTS suppression_budget_idx ON suppression_ledger(fingerprint, occurred_at);
CREATE TABLE IF NOT EXISTS recomputations (
    run_id TEXT PRIMARY KEY, requested_at TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT,
    reason TEXT NOT NULL, scope_json TEXT NOT NULL, status TEXT NOT NULL, windows_rebuilt INTEGER NOT NULL,
    alerts_changed INTEGER NOT NULL, error_text TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
"""


class ManagedConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, factory=ManagedConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def audit(self, connection: sqlite3.Connection, occurred_at: str, actor: str, action: str,
              entity_type: str, entity_id: str, details: dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO audit_log(occurred_at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(occurred_at), actor, action, entity_type, entity_id, self.dumps(details)),
        )

    @staticmethod
    def dumps(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def loads(value: str) -> Any:
        return json.loads(value)

    def put_behavior_event(self, event: BehaviorEvent, received_at: str) -> str:
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM behavior_events WHERE event_id=? ORDER BY revision DESC LIMIT 1",
                (event.event_id,),
            ).fetchone()
            if existing and int(existing["revision"]) > event.revision:
                self.audit(connection, received_at, "ingestion", "stale_revision", "behavior_event", event.event_id,
                           {"received_revision": event.revision, "active_revision": existing["revision"]})
                return "stale"
            if existing and int(existing["revision"]) == event.revision:
                same = (existing["agent_id"] == event.agent_id and existing["event_time"] == event.event_time
                        and existing["metric"] == event.metric and float(existing["value"]) == event.value
                        and existing["dimension_key"] == event.dimension_key)
                if not same:
                    raise ValueError(f"conflicting behavior event revision: {event.event_id}/{event.revision}")
                self.audit(connection, received_at, "ingestion", "duplicate", "behavior_event", event.event_id,
                           {"revision": event.revision})
                return "duplicate"
            if existing:
                connection.execute("UPDATE behavior_events SET active=0 WHERE event_id=?", (event.event_id,))
            connection.execute(
                "INSERT INTO behavior_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (event.event_id, event.revision, event.agent_id, event.event_time, event.arrival_time, event.metric,
                 event.value, self.dumps(event.dimensions), event.dimension_key, event.source, 1, iso(received_at)),
            )
            action = "revision" if existing else "insert"
            self.audit(connection, received_at, "ingestion", action, "behavior_event", event.event_id, event.to_dict())
            return action

    def put_capability_declaration(self, declaration: CapabilityDeclaration, received_at: str) -> str:
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM capability_declarations WHERE declaration_id=? ORDER BY revision DESC LIMIT 1",
                (declaration.declaration_id,),
            ).fetchone()
            if existing and int(existing["revision"]) > declaration.revision:
                self.audit(connection, received_at, "ingestion", "stale_revision", "capability",
                           declaration.declaration_id, {"received_revision": declaration.revision})
                return "stale"
            if existing and int(existing["revision"]) == declaration.revision:
                same = (existing["agent_id"] == declaration.agent_id
                        and existing["event_time"] == declaration.event_time
                        and self.loads(existing["capabilities_json"]) == list(declaration.capabilities))
                if not same:
                    raise ValueError(f"conflicting capability revision: {declaration.declaration_id}")
                return "duplicate"
            if existing:
                connection.execute("UPDATE capability_declarations SET active=0 WHERE declaration_id=?",
                                   (declaration.declaration_id,))
            connection.execute(
                "INSERT INTO capability_declarations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (declaration.declaration_id, declaration.revision, declaration.agent_id, declaration.event_time,
                 declaration.arrival_time, self.dumps(list(declaration.capabilities)), declaration.schema_version,
                 declaration.issuer, 1, iso(received_at)),
            )
            action = "revision" if existing else "insert"
            self.audit(connection, received_at, "ingestion", action, "capability",
                       declaration.declaration_id, declaration.to_dict())
            return action

    def active_behavior_events(self, agent_id: str | None = None, metric: str | None = None,
                               dimension_key: str | None = None, start: str | None = None,
                               end: str | None = None) -> list[BehaviorEvent]:
        clauses = ["active=1"]
        params: list[Any] = []
        for column, value in (("agent_id", agent_id), ("metric", metric), ("dimension_key", dimension_key)):
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        if start is not None:
            clauses.append("event_time>=?")
            params.append(iso(start))
        if end is not None:
            clauses.append("event_time<?")
            params.append(iso(end))
        query = "SELECT * FROM behavior_events WHERE " + " AND ".join(clauses) + " ORDER BY event_time,event_id"
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [BehaviorEvent(
            event_id=row["event_id"], agent_id=row["agent_id"], event_time=row["event_time"],
            arrival_time=row["arrival_time"], metric=row["metric"], value=row["value"],
            dimensions=self.loads(row["dimensions_json"]), revision=row["revision"], source=row["source"],
        ) for row in rows]

    def active_capabilities(self, agent_id: str | None = None) -> list[CapabilityDeclaration]:
        query = "SELECT * FROM capability_declarations WHERE active=1"
        params: list[Any] = []
        if agent_id is not None:
            query += " AND agent_id=?"
            params.append(agent_id)
        query += " ORDER BY agent_id,event_time,declaration_id"
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [CapabilityDeclaration(
            declaration_id=row["declaration_id"], agent_id=row["agent_id"], event_time=row["event_time"],
            arrival_time=row["arrival_time"], capabilities=tuple(self.loads(row["capabilities_json"])),
            revision=row["revision"], schema_version=row["schema_version"], issuer=row["issuer"],
        ) for row in rows]

    def get_partition(self, partition_key: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM partitions WHERE partition_key=?", (partition_key,)).fetchone()
        return dict(row) if row else None

    def put_partition(self, state: dict[str, Any], occurred_at: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO partitions VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(partition_key) DO UPDATE SET "
                "max_event_time=excluded.max_event_time,max_arrival_time=excluded.max_arrival_time,"
                "watermark=excluded.watermark,last_activity=excluded.last_activity,event_count=excluded.event_count,"
                "late_count=excluded.late_count,duplicate_count=excluded.duplicate_count",
                (state["partition_key"], state["max_event_time"], state["max_arrival_time"], state["watermark"],
                 state["last_activity"], state["event_count"], state["late_count"], state["duplicate_count"]),
            )
            self.audit(connection, occurred_at, "watermark", "advance", "partition",
                       state["partition_key"], state)

    def save_window(self, window: WindowAggregate, created_at: str) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE window_aggregates SET active=0 WHERE window_id=? AND active=1",
                               (window.window_id,))
            connection.execute(
                "INSERT INTO window_aggregates VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (window.window_id, window.version, window.agent_id, window.metric, window.dimension_key,
                 window.spec_name, window.start_time, window.end_time, window.count, window.total, window.mean,
                 window.minimum, window.maximum, window.median, window.mad, window.first_event_time,
                 window.last_event_time, int(window.finalized), window.correction_reason, 1, iso(created_at)),
            )
            self.audit(connection, created_at, "window_engine", "materialize", "window", window.window_id,
                       window.to_dict())

    def windows(self, agent_id: str | None = None, metric: str | None = None, spec_name: str | None = None,
                dimension_key: str | None = None, before: str | None = None, active_only: bool = True,
                limit: int | None = None) -> list[WindowAggregate]:
        clauses = ["1=1"]
        params: list[Any] = []
        if active_only:
            clauses.append("active=1")
        for column, value in (("agent_id", agent_id), ("metric", metric), ("spec_name", spec_name),
                              ("dimension_key", dimension_key)):
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        if before is not None:
            clauses.append("end_time<=?")
            params.append(iso(before))
        query = "SELECT * FROM window_aggregates WHERE " + " AND ".join(clauses)
        query += " ORDER BY end_time DESC,version DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._window(row) for row in rows]

    @staticmethod
    def _window(row: sqlite3.Row) -> WindowAggregate:
        return WindowAggregate(
            window_id=row["window_id"], agent_id=row["agent_id"], metric=row["metric"],
            dimension_key=row["dimension_key"], spec_name=row["spec_name"], start_time=row["start_time"],
            end_time=row["end_time"], version=row["version"], count=row["count"], total=row["total"],
            mean=row["mean"], minimum=row["minimum"], maximum=row["maximum"], median=row["median"],
            mad=row["mad"], first_event_time=row["first_event_time"], last_event_time=row["last_event_time"],
            finalized=bool(row["finalized"]), correction_reason=row["correction_reason"],
        )

    def save_baseline(self, baseline: BaselineSnapshot, created_at: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO baselines VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (baseline.baseline_id, baseline.agent_id, baseline.metric, baseline.dimension_key, baseline.spec_name,
                 baseline.season_slot, baseline.as_of, baseline.sample_count, baseline.center, baseline.spread,
                 baseline.lower, baseline.upper, baseline.quality, baseline.method, iso(created_at)),
            )

    def save_evidence(self, evidence: DetectionEvidence, created_at: str) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (evidence.evidence_id, evidence.agent_id, evidence.kind, evidence.observed_at, evidence.severity,
                 evidence.score, evidence.summary, evidence.fingerprint, self.dumps(evidence.payload),
                 evidence.status, iso(created_at)),
            )
            if cursor.rowcount:
                self.audit(connection, created_at, "detector", "evidence", "evidence",
                           evidence.evidence_id, evidence.to_dict())
            return bool(cursor.rowcount)

    def evidence(self, agent_id: str | None = None, status: str | None = None,
                 since: str | None = None) -> list[DetectionEvidence]:
        clauses = ["1=1"]
        params: list[Any] = []
        for column, value in (("agent_id", agent_id), ("status", status)):
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        if since is not None:
            clauses.append("observed_at>=?")
            params.append(iso(since))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE " + " AND ".join(clauses) + " ORDER BY observed_at,evidence_id",
                params,
            ).fetchall()
        return [DetectionEvidence(
            evidence_id=row["evidence_id"], agent_id=row["agent_id"], kind=row["kind"],
            observed_at=row["observed_at"], severity=row["severity"], score=row["score"],
            summary=row["summary"], fingerprint=row["fingerprint"], payload=self.loads(row["payload_json"]),
            status=row["status"],
        ) for row in rows]

    def save_alert(self, alert: AlertRecord) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET "
                "state=excluded.state,severity=excluded.severity,updated_at=excluded.updated_at,"
                "last_evidence_at=excluded.last_evidence_at,occurrence_count=excluded.occurrence_count,"
                "suppressed_count=excluded.suppressed_count,reason=excluded.reason,context_json=excluded.context_json",
                (alert.alert_id, alert.fingerprint, alert.agent_id, alert.kind, alert.state, alert.severity,
                 alert.opened_at, alert.updated_at, alert.last_evidence_at, alert.occurrence_count,
                 alert.suppressed_count, alert.reason, self.dumps(alert.context)),
            )
            self.audit(connection, alert.updated_at, "alert_manager", alert.state, "alert",
                       alert.alert_id, alert.to_dict())

    def alerts(self, fingerprint: str | None = None, agent_id: str | None = None,
               states: Iterable[str] | None = None) -> list[AlertRecord]:
        clauses = ["1=1"]
        params: list[Any] = []
        for column, value in (("fingerprint", fingerprint), ("agent_id", agent_id)):
            if value is not None:
                clauses.append(f"{column}=?")
                params.append(value)
        if states:
            state_values = list(states)
            clauses.append("state IN (" + ",".join("?" for _ in state_values) + ")")
            params.extend(state_values)
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts WHERE " + " AND ".join(clauses) + " ORDER BY updated_at DESC", params
            ).fetchall()
        return [AlertRecord(
            alert_id=row["alert_id"], fingerprint=row["fingerprint"], agent_id=row["agent_id"],
            kind=row["kind"], state=row["state"], severity=row["severity"], opened_at=row["opened_at"],
            updated_at=row["updated_at"], last_evidence_at=row["last_evidence_at"],
            occurrence_count=row["occurrence_count"], suppressed_count=row["suppressed_count"],
            reason=row["reason"], context=self.loads(row["context_json"]),
        ) for row in rows]

    def suppression_cost(self, fingerprint: str, since: str) -> int:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(SUM(cost),0) AS cost FROM suppression_ledger WHERE fingerprint=? AND occurred_at>=?",
                (fingerprint, iso(since)),
            ).fetchone()
        return int(row["cost"])

    def record_suppression(self, fingerprint: str, occurred_at: str, action: str, cost: int,
                           reason: str, alert_id: str | None) -> None:
        entry_id = stable_id(fingerprint, occurred_at, action, reason, alert_id)
        with self.transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO suppression_ledger VALUES(?,?,?,?,?,?,?)",
                               (entry_id, fingerprint, iso(occurred_at), action, cost, reason, alert_id))

    def start_recomputation(self, requested_at: str, reason: str, scope: dict[str, Any]) -> str:
        run_id = stable_id(requested_at, reason, scope)
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO recomputations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (run_id, iso(requested_at), iso(requested_at), None, reason, self.dumps(scope), "running", 0, 0, None),
            )
        return run_id

    def finish_recomputation(self, run_id: str, completed_at: str, status: str, windows_rebuilt: int,
                             alerts_changed: int, error_text: str | None = None) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE recomputations SET completed_at=?,status=?,windows_rebuilt=?,alerts_changed=?,error_text=? "
                "WHERE run_id=?",
                (iso(completed_at), status, windows_rebuilt, alerts_changed, error_text, run_id),
            )

    def audit_rows(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_log"
        params: list[Any] = []
        if agent_id is not None:
            query += " WHERE details_json LIKE ? OR entity_id=?"
            params.extend([f'%"agent_id":"{agent_id}"%', agent_id])
        query += " ORDER BY sequence"
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [{**dict(row), "details": self.loads(row["details_json"])} for row in rows]

    def counts(self) -> dict[str, int]:
        names = ["behavior_events", "capability_declarations", "window_aggregates", "baselines",
                 "evidence", "alerts", "recomputations", "audit_log"]
        with self.connect() as connection:
            return {name: int(connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]) for name in names}

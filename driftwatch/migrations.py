from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable
import sqlite3

from .storage import Store


CURRENT_SCHEMA_VERSION = 3


@dataclass(frozen=True)
class MigrationResult:
    from_version: int
    to_version: int
    applied: tuple[int, ...]
    status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SchemaMigrator:
    def __init__(self, store: Store):
        self.store = store
        self.steps: dict[int, Callable[[sqlite3.Connection], None]] = {
            1: self._to_one,
            2: self._to_two,
            3: self._to_three,
        }

    def version(self) -> int:
        with self.store.connect() as connection:
            row = connection.execute("SELECT value_json FROM metadata WHERE key='schema_version'").fetchone()
        if row is None:
            return 0
        import json
        return int(json.loads(row["value_json"]))

    def migrate(self, target: int = CURRENT_SCHEMA_VERSION) -> MigrationResult:
        if target < 0 or target > CURRENT_SCHEMA_VERSION:
            raise ValueError(f"target schema version must be between 0 and {CURRENT_SCHEMA_VERSION}")
        current = self.version()
        if current > target:
            raise ValueError("schema downgrade is not supported")
        applied = []
        with self.store.transaction() as connection:
            for version in range(current + 1, target + 1):
                step = self.steps.get(version)
                if step is None:
                    raise ValueError(f"missing migration step {version}")
                step(connection)
                connection.execute(
                    "INSERT INTO metadata(key,value_json) VALUES('schema_version',?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json", (str(version),)
                )
                applied.append(version)
        return MigrationResult(current, target, tuple(applied), "migrated" if applied else "current")

    @staticmethod
    def _to_one(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE INDEX IF NOT EXISTS audit_entity_idx ON audit_log(entity_type,entity_id,sequence)")

    @staticmethod
    def _to_two(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE INDEX IF NOT EXISTS evidence_fingerprint_idx ON evidence(fingerprint,observed_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS alerts_state_idx ON alerts(state,severity,updated_at)")

    @staticmethod
    def _to_three(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE INDEX IF NOT EXISTS recompute_status_idx ON recomputations(status,requested_at)")

    def compatibility(self) -> dict[str, Any]:
        required_tables = {"behavior_events", "capability_declarations", "partitions",
                           "window_aggregates", "baselines", "evidence", "alerts",
                           "suppression_ledger", "recomputations", "audit_log", "metadata"}
        with self.store.connect() as connection:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        missing = sorted(required_tables - tables)
        return {
            "compatible": not missing and integrity == "ok",
            "schema_version": self.version(),
            "current_schema_version": CURRENT_SCHEMA_VERSION,
            "missing_tables": missing,
            "integrity": integrity,
            "sqlite_user_version": user_version,
        }

    def stamp_user_version(self) -> int:
        version = self.version()
        with self.store.connect() as connection:
            connection.execute(f"PRAGMA user_version={version}")
        return version

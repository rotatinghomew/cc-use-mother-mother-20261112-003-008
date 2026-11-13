from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import hashlib
import json

from .storage import Store


@dataclass(frozen=True)
class AuditProof:
    sequence: int
    previous_hash: str
    entry_hash: str
    occurred_at: str
    action: str
    entity_type: str
    entity_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditVerifier:
    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def canonical(row: dict[str, Any]) -> bytes:
        selected = {key: row[key] for key in ("sequence", "occurred_at", "actor", "action",
                                                "entity_type", "entity_id", "details_json")}
        return json.dumps(selected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def proofs(self) -> list[AuditProof]:
        with self.store.connect() as connection:
            rows = [dict(row) for row in connection.execute("SELECT * FROM audit_log ORDER BY sequence")]
        previous = "0" * 64
        proofs = []
        for row in rows:
            digest = hashlib.sha256(previous.encode("ascii") + self.canonical(row)).hexdigest()
            proofs.append(AuditProof(row["sequence"], previous, digest, row["occurred_at"], row["action"],
                                     row["entity_type"], row["entity_id"]))
            previous = digest
        return proofs

    def root_hash(self) -> str:
        proofs = self.proofs()
        return proofs[-1].entry_hash if proofs else "0" * 64

    def export(self, path: str | Path) -> dict[str, Any]:
        proofs = self.proofs()
        payload = {"root_hash": proofs[-1].entry_hash if proofs else "0" * 64,
                   "entries": [item.to_dict() for item in proofs]}
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                              encoding="utf-8")
        return payload

    def verify_export(self, path: str | Path) -> dict[str, Any]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = payload.get("entries", [])
        errors = []
        previous = "0" * 64
        for expected_sequence, entry in enumerate(entries, 1):
            if entry.get("sequence") != expected_sequence:
                errors.append(f"unexpected sequence at position {expected_sequence}")
            if entry.get("previous_hash") != previous:
                errors.append(f"broken previous hash at sequence {expected_sequence}")
            previous = entry.get("entry_hash", "")
        if previous != payload.get("root_hash", "0" * 64):
            errors.append("root hash mismatch")
        current = self.proofs()
        if entries and current and entries[-1].get("entry_hash") != current[-1].entry_hash:
            errors.append("export does not match current audit log")
        return {"valid": not errors, "errors": errors, "entries": len(entries),
                "root_hash": payload.get("root_hash")}

    def entity_trace(self, entity_type: str, entity_id: str) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_log WHERE entity_type=? AND entity_id=? ORDER BY sequence",
                (entity_type, entity_id),
            ).fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def action_counts(self) -> dict[str, int]:
        with self.store.connect() as connection:
            rows = connection.execute("SELECT action,COUNT(*) AS count FROM audit_log GROUP BY action ORDER BY action")
            return {row["action"]: int(row["count"]) for row in rows}

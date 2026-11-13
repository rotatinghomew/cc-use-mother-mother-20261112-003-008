from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
import hashlib
import json
import sqlite3

from .models import iso
from .storage import Store


@dataclass(frozen=True)
class CheckpointManifest:
    created_at: str
    database_sha256: str
    database_bytes: int
    counts: dict[str, int]
    high_watermarks: dict[str, str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CheckpointManager:
    def __init__(self, store: Store):
        if store.path == ":memory:":
            raise ValueError("checkpoints require a filesystem database")
        self.store = store

    @staticmethod
    def digest(path: Path) -> str:
        value = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                value.update(block)
        return value.hexdigest()

    def create(self, directory: str | Path, created_at: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        database = target / "driftwatch.sqlite"
        manifest_path = target / "manifest.json"
        with self.store.connect() as source:
            destination = sqlite3.connect(database)
            try:
                source.backup(destination)
                destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                destination.commit()
            finally:
                destination.close()
        high_watermarks = {}
        for item in self._partition_rows():
            high_watermarks[item["partition_key"]] = item["watermark"]
        manifest = CheckpointManifest(
            created_at=iso(created_at), database_sha256=self.digest(database),
            database_bytes=database.stat().st_size, counts=self.store.counts(),
            high_watermarks=high_watermarks, metadata=dict(metadata or {}),
        )
        manifest_path.write_text(json.dumps(manifest.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                                 encoding="utf-8")
        return manifest.to_dict()

    def verify(self, directory: str | Path, deep: bool = True) -> dict[str, Any]:
        target = Path(directory)
        database = target / "driftwatch.sqlite"
        manifest_path = target / "manifest.json"
        if not database.is_file() or not manifest_path.is_file():
            raise ValueError("checkpoint is incomplete")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        actual_digest = self.digest(database)
        errors = []
        if actual_digest != manifest.get("database_sha256"):
            errors.append("database digest mismatch")
        if database.stat().st_size != manifest.get("database_bytes"):
            errors.append("database size mismatch")
        integrity = "not_checked"
        counts = {}
        if deep:
            connection = sqlite3.connect(database)
            connection.row_factory = sqlite3.Row
            try:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                for table in manifest.get("counts", {}):
                    counts[table] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                if counts != manifest.get("counts"):
                    errors.append("table counts mismatch")
                if integrity != "ok":
                    errors.append(f"sqlite integrity check failed: {integrity}")
            finally:
                connection.close()
        return {"valid": not errors, "errors": errors, "integrity": integrity,
                "counts": counts, "database_sha256": actual_digest}

    def restore(self, directory: str | Path, target_database: str | Path, verify: bool = True) -> dict[str, Any]:
        source_dir = Path(directory)
        if verify:
            result = self.verify(source_dir)
            if not result["valid"]:
                raise ValueError("checkpoint verification failed: " + "; ".join(result["errors"]))
        source = sqlite3.connect(source_dir / "driftwatch.sqlite")
        destination_path = Path(target_database)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination = sqlite3.connect(destination_path)
        try:
            source.backup(destination)
            destination.commit()
        finally:
            source.close()
            destination.close()
        restored = Store(destination_path)
        return {"database": str(destination_path), "counts": restored.counts()}

    def compare(self, left: str | Path, right: str | Path) -> dict[str, Any]:
        left_manifest = json.loads((Path(left) / "manifest.json").read_text(encoding="utf-8"))
        right_manifest = json.loads((Path(right) / "manifest.json").read_text(encoding="utf-8"))
        tables = sorted(set(left_manifest["counts"]) | set(right_manifest["counts"]))
        deltas = {table: right_manifest["counts"].get(table, 0) - left_manifest["counts"].get(table, 0)
                  for table in tables}
        watermark_changes = {}
        partitions = sorted(set(left_manifest.get("high_watermarks", {})) |
                            set(right_manifest.get("high_watermarks", {})))
        for partition in partitions:
            before = left_manifest.get("high_watermarks", {}).get(partition)
            after = right_manifest.get("high_watermarks", {}).get(partition)
            if before != after:
                watermark_changes[partition] = {"before": before, "after": after}
        return {"count_deltas": deltas, "watermark_changes": watermark_changes,
                "same_database": left_manifest["database_sha256"] == right_manifest["database_sha256"]}

    def _partition_rows(self) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM partitions ORDER BY partition_key")]

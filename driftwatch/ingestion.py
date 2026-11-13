from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
import json

from .models import BehaviorEvent, CapabilityDeclaration, iso, parse_time
from .storage import Store


@dataclass
class IngestionResult:
    received: int = 0
    inserted: int = 0
    revised: int = 0
    duplicates: int = 0
    stale: int = 0
    invalid: int = 0
    late: int = 0
    errors: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []

    def record(self, status: str) -> None:
        if status == "insert":
            self.inserted += 1
        elif status == "revision":
            self.revised += 1
        elif status == "duplicate":
            self.duplicates += 1
        elif status == "stale":
            self.stale += 1
        else:
            raise ValueError(f"unknown ingestion status: {status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventIngestor:
    def __init__(self, store: Store, watermark_manager: Any):
        self.store = store
        self.watermarks = watermark_manager

    def ingest_records(self, records: Iterable[dict[str, Any]], strict: bool = False) -> IngestionResult:
        result = IngestionResult()
        for index, raw in enumerate(records):
            result.received += 1
            try:
                kind = str(raw.get("type", "behavior")).strip().lower()
                if kind in {"behavior", "event", "metric"}:
                    event = BehaviorEvent.from_dict(raw)
                    status = self.store.put_behavior_event(event, event.arrival_time)
                    result.record(status)
                    observation = self.watermarks.observe_behavior(event, status)
                    if observation["late"]:
                        result.late += 1
                elif kind in {"capability", "capabilities", "declaration"}:
                    declaration = CapabilityDeclaration.from_dict(raw)
                    status = self.store.put_capability_declaration(declaration, declaration.arrival_time)
                    result.record(status)
                    observation = self.watermarks.observe_capability(declaration, status)
                    if observation["late"]:
                        result.late += 1
                else:
                    raise ValueError(f"unsupported record type: {kind}")
            except Exception as exc:
                result.invalid += 1
                result.errors.append({"index": index, "error": str(exc), "record": raw})
                if strict:
                    raise
        return result

    def ingest_jsonl(self, path: str | Path, strict: bool = False) -> IngestionResult:
        records = []
        for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                if strict:
                    raise ValueError(f"invalid JSON line {line_number}: {exc}") from exc
                value = {"type": "invalid", "line_number": line_number, "raw": line}
            if not isinstance(value, dict):
                if strict:
                    raise ValueError(f"line {line_number} must contain an object")
                value = {"type": "invalid", "line_number": line_number, "raw": value}
            records.append(value)
        return self.ingest_records(records, strict=strict)

    def ingest_json(self, path: str | Path, strict: bool = False) -> IngestionResult:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        records = raw.get("records", raw) if isinstance(raw, dict) else raw
        if not isinstance(records, list):
            raise ValueError("JSON fixture must be a list or contain records list")
        return self.ingest_records(records, strict=strict)


def sort_for_replay(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(raw: dict[str, Any]) -> tuple[str, str, int]:
        event_time = iso(raw.get("event_time", raw.get("arrival_time")))
        identifier = str(raw.get("event_id", raw.get("declaration_id", "")))
        revision = int(raw.get("revision", 1))
        return event_time, identifier, revision
    return sorted((dict(item) for item in records), key=key)

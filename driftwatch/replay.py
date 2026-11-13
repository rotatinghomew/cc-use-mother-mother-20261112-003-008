from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable
import json

from .ingestion import EventIngestor, sort_for_replay
from .models import iso
from .storage import Store
from .windows import WindowEngine


@dataclass
class ReplayResult:
    run_id: str
    status: str
    records: int
    inserted: int
    duplicates: int
    invalid: int
    windows_rebuilt: int
    alerts_changed: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReplayCoordinator:
    def __init__(self, store: Store, ingestor: EventIngestor, windows: WindowEngine,
                 evaluate_window: Callable[[Any, str], list[Any]]):
        self.store = store
        self.ingestor = ingestor
        self.windows = windows
        self.evaluate_window = evaluate_window

    def recompute(self, requested_at: str, reason: str, scope: dict[str, Any]) -> ReplayResult:
        run_id = self.store.start_recomputation(requested_at, reason, scope)
        try:
            before = len(self.store.alerts())
            rebuilt = self.windows.rebuild_scope(
                agent_id=scope.get("agent_id"), metric=scope.get("metric"),
                start=scope.get("start"), end=scope.get("end"), reason=reason,
            )
            for window in rebuilt:
                self.evaluate_window(window, requested_at)
            changed = abs(len(self.store.alerts()) - before)
            self.store.finish_recomputation(run_id, requested_at, "completed", len(rebuilt), changed)
            return ReplayResult(run_id, "completed", 0, 0, 0, 0, len(rebuilt), changed)
        except Exception as exc:
            self.store.finish_recomputation(run_id, requested_at, "failed", 0, 0, str(exc))
            return ReplayResult(run_id, "failed", 0, 0, 0, 0, 0, 0, str(exc))

    def replay_fixture(self, path: str | Path, requested_at: str, reason: str = "fixture replay") -> ReplayResult:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        records = raw.get("records", raw) if isinstance(raw, dict) else raw
        if not isinstance(records, list):
            raise ValueError("fixture must contain a record list")
        ordered = sort_for_replay(records)
        run_id = self.store.start_recomputation(requested_at, reason, {"fixture": str(path)})
        try:
            result = self.ingestor.ingest_records(ordered)
            rebuilt = self.windows.rebuild_scope(reason=reason)
            before = len(self.store.alerts())
            for window in rebuilt:
                self.evaluate_window(window, requested_at)
            changed = abs(len(self.store.alerts()) - before)
            self.store.finish_recomputation(run_id, requested_at, "completed", len(rebuilt), changed)
            return ReplayResult(run_id, "completed", len(ordered), result.inserted + result.revised,
                                result.duplicates, result.invalid, len(rebuilt), changed)
        except Exception as exc:
            self.store.finish_recomputation(run_id, requested_at, "failed", 0, 0, str(exc))
            return ReplayResult(run_id, "failed", len(ordered), 0, 0, 0, 0, 0, str(exc))

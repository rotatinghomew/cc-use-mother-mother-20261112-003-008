from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable, Iterable, Sequence, TypeVar
import base64
import json

from .storage import Store


T = TypeVar("T")


@dataclass(frozen=True)
class Page:
    items: tuple[dict[str, Any], ...]
    next_cursor: str | None
    total: int
    snapshot_token: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["items"] = list(self.items)
        return value


class CursorCodec:
    @staticmethod
    def encode(value: dict[str, Any]) -> str:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def decode(value: str) -> dict[str, Any]:
        padding = "=" * (-len(value) % 4)
        try:
            raw = base64.urlsafe_b64decode(value + padding)
            result = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid query cursor") from exc
        if not isinstance(result, dict):
            raise ValueError("query cursor must decode to an object")
        return result


class QueryService:
    def __init__(self, store: Store):
        self.store = store

    def alerts(self, limit: int = 50, cursor: str | None = None, agent_id: str | None = None,
               state: str | None = None, severity: str | None = None) -> Page:
        items = self.store.alerts(agent_id=agent_id, states=(state,) if state else None)
        if severity:
            items = [item for item in items if item.severity == severity]
        rows = [item.to_dict() for item in items]
        return self._page(rows, limit, cursor, lambda item: (item["updated_at"], item["alert_id"]), "alerts")

    def evidence(self, limit: int = 50, cursor: str | None = None, agent_id: str | None = None,
                 kind: str | None = None, status: str | None = None) -> Page:
        items = self.store.evidence(agent_id=agent_id, status=status)
        if kind:
            items = [item for item in items if item.kind == kind]
        rows = [item.to_dict() for item in items]
        return self._page(rows, limit, cursor, lambda item: (item["observed_at"], item["evidence_id"]), "evidence")

    def windows(self, limit: int = 50, cursor: str | None = None, agent_id: str | None = None,
                metric: str | None = None, spec_name: str | None = None, finalized: bool | None = None) -> Page:
        items = self.store.windows(agent_id=agent_id, metric=metric, spec_name=spec_name)
        if finalized is not None:
            items = [item for item in items if item.finalized == finalized]
        rows = [item.to_dict() for item in items]
        return self._page(rows, limit, cursor, lambda item: (item["end_time"], item["window_id"], item["version"]),
                          "windows")

    def search_timeline(self, agent_id: str, text: str = "", kinds: Iterable[str] = (),
                        start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        from .reporting import Reporter
        values = Reporter(self.store).timeline(agent_id)
        allowed = set(kinds)
        query = text.casefold().strip()
        results = []
        for item in values:
            if allowed and item["type"] not in allowed:
                continue
            if start and item["time"] < start:
                continue
            if end and item["time"] > end:
                continue
            haystack = json.dumps(item, ensure_ascii=False, sort_keys=True).casefold()
            if query and query not in haystack:
                continue
            results.append(item)
        return results

    def snapshot_token(self, collection: str) -> str:
        counts = self.store.counts()
        relevant = {
            "alerts": counts["alerts"],
            "evidence": counts["evidence"],
            "windows": counts["window_aggregates"],
        }.get(collection, sum(counts.values()))
        with self.store.connect() as connection:
            audit_sequence = connection.execute("SELECT COALESCE(MAX(sequence),0) FROM audit_log").fetchone()[0]
        return CursorCodec.encode({"collection": collection, "count": relevant, "audit_sequence": audit_sequence})

    def _page(self, rows: list[dict[str, Any]], limit: int, cursor: str | None,
              key: Callable[[dict[str, Any]], Sequence[Any]], collection: str) -> Page:
        if not 1 <= limit <= 500:
            raise ValueError("page limit must be between 1 and 500")
        ordered = sorted(rows, key=key)
        offset = 0
        expected_snapshot = self.snapshot_token(collection)
        if cursor:
            decoded = CursorCodec.decode(cursor)
            if decoded.get("collection") != collection:
                raise ValueError("cursor collection mismatch")
            if decoded.get("snapshot_token") != expected_snapshot:
                raise ValueError("cursor snapshot expired after data changed")
            offset = int(decoded.get("offset", 0))
            if offset < 0 or offset > len(ordered):
                raise ValueError("cursor offset is out of range")
        selected = ordered[offset:offset + limit]
        next_offset = offset + len(selected)
        next_cursor = None
        if next_offset < len(ordered):
            next_cursor = CursorCodec.encode({"collection": collection, "offset": next_offset,
                                              "snapshot_token": expected_snapshot})
        return Page(tuple(selected), next_cursor, len(ordered), expected_snapshot)

    def facets(self) -> dict[str, dict[str, int]]:
        from collections import Counter
        alerts = self.store.alerts()
        evidence = self.store.evidence()
        windows = self.store.windows()
        return {
            "alert_state": dict(Counter(item.state for item in alerts)),
            "alert_severity": dict(Counter(item.severity for item in alerts)),
            "evidence_kind": dict(Counter(item.kind for item in evidence)),
            "evidence_status": dict(Counter(item.status for item in evidence)),
            "window_spec": dict(Counter(item.spec_name for item in windows)),
            "window_metric": dict(Counter(item.metric for item in windows)),
        }

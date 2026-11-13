from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable
import hashlib
import json
import math


UTC = timezone.utc


def parse_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        text = value.strip().replace("Z", "+00:00")
        result = datetime.fromisoformat(text)
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def iso(value: str | datetime) -> str:
    return parse_time(value).isoformat().replace("+00:00", "Z")


def stable_id(*parts: Any, size: int = 24) -> str:
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:size]


def finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


@dataclass(frozen=True)
class BehaviorEvent:
    event_id: str
    agent_id: str
    event_time: str
    arrival_time: str
    metric: str
    value: float
    dimensions: dict[str, str] = field(default_factory=dict)
    revision: int = 1
    source: str = "device"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BehaviorEvent":
        required = ("event_id", "agent_id", "event_time", "arrival_time", "metric", "value")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"behavior event missing: {', '.join(missing)}")
        event_id = str(raw["event_id"]).strip()
        agent_id = str(raw["agent_id"]).strip()
        metric = str(raw["metric"]).strip()
        if not event_id or not agent_id or not metric:
            raise ValueError("event_id, agent_id and metric cannot be empty")
        revision = int(raw.get("revision", 1))
        if revision < 1:
            raise ValueError("revision must be positive")
        dimensions = raw.get("dimensions", {})
        if not isinstance(dimensions, dict):
            raise ValueError("dimensions must be an object")
        normalized = {str(k): str(v) for k, v in dimensions.items()}
        return cls(
            event_id=event_id,
            agent_id=agent_id,
            event_time=iso(raw["event_time"]),
            arrival_time=iso(raw["arrival_time"]),
            metric=metric,
            value=finite_number(raw["value"], "value"),
            dimensions=normalized,
            revision=revision,
            source=str(raw.get("source", "device")),
        )

    @property
    def dimension_key(self) -> str:
        return json.dumps(self.dimensions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilityDeclaration:
    declaration_id: str
    agent_id: str
    event_time: str
    arrival_time: str
    capabilities: tuple[str, ...]
    revision: int = 1
    schema_version: int = 1
    issuer: str = "device"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CapabilityDeclaration":
        required = ("declaration_id", "agent_id", "event_time", "arrival_time", "capabilities")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"capability declaration missing: {', '.join(missing)}")
        items = raw["capabilities"]
        if not isinstance(items, list):
            raise ValueError("capabilities must be a list")
        capabilities = tuple(sorted({str(item).strip() for item in items if str(item).strip()}))
        revision = int(raw.get("revision", 1))
        schema_version = int(raw.get("schema_version", 1))
        if revision < 1 or schema_version < 1:
            raise ValueError("revision and schema_version must be positive")
        return cls(
            declaration_id=str(raw["declaration_id"]).strip(),
            agent_id=str(raw["agent_id"]).strip(),
            event_time=iso(raw["event_time"]),
            arrival_time=iso(raw["arrival_time"]),
            capabilities=capabilities,
            revision=revision,
            schema_version=schema_version,
            issuer=str(raw.get("issuer", "device")),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["capabilities"] = list(self.capabilities)
        return data


@dataclass(frozen=True)
class WindowSpec:
    name: str
    size_seconds: int
    step_seconds: int
    allowed_lateness_seconds: int
    minimum_points: int = 3

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("window name cannot be empty")
        if self.size_seconds <= 0 or self.step_seconds <= 0:
            raise ValueError("window size and step must be positive")
        if self.size_seconds % self.step_seconds:
            raise ValueError("window size must be divisible by step")
        if self.allowed_lateness_seconds < 0:
            raise ValueError("allowed lateness cannot be negative")
        if self.minimum_points < 1:
            raise ValueError("minimum_points must be positive")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "WindowSpec":
        result = cls(
            name=str(raw["name"]),
            size_seconds=int(raw["size_seconds"]),
            step_seconds=int(raw.get("step_seconds", raw["size_seconds"])),
            allowed_lateness_seconds=int(raw.get("allowed_lateness_seconds", 0)),
            minimum_points=int(raw.get("minimum_points", 3)),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class WindowAggregate:
    window_id: str
    agent_id: str
    metric: str
    dimension_key: str
    spec_name: str
    start_time: str
    end_time: str
    version: int
    count: int
    total: float
    mean: float
    minimum: float
    maximum: float
    median: float
    mad: float
    first_event_time: str
    last_event_time: str
    finalized: bool
    correction_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BaselineSnapshot:
    baseline_id: str
    agent_id: str
    metric: str
    dimension_key: str
    spec_name: str
    season_slot: str
    as_of: str
    sample_count: int
    center: float
    spread: float
    lower: float
    upper: float
    quality: str
    method: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionEvidence:
    evidence_id: str
    agent_id: str
    kind: str
    observed_at: str
    severity: str
    score: float
    summary: str
    fingerprint: str
    payload: dict[str, Any]
    status: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AlertRecord:
    alert_id: str
    fingerprint: str
    agent_id: str
    kind: str
    state: str
    severity: str
    opened_at: str
    updated_at: str
    last_evidence_at: str
    occurrence_count: int
    suppressed_count: int
    reason: str
    context: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_unique(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(item).strip() for item in items if str(item).strip()}))

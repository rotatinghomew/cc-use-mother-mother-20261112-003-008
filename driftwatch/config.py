from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json

from .models import WindowSpec


@dataclass(frozen=True)
class BaselinePolicy:
    history_windows: int = 48
    season_period_seconds: int = 86400
    season_tolerance_seconds: int = 3600
    minimum_samples: int = 6
    warn_z: float = 3.5
    critical_z: float = 6.0
    spread_floor: float = 0.01
    trim_fraction: float = 0.1

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BaselinePolicy":
        result = cls(**{key: raw[key] for key in cls.__dataclass_fields__ if key in raw})
        if result.history_windows < 3 or result.minimum_samples < 3:
            raise ValueError("baseline history and minimum samples must be at least three")
        if not 0 <= result.trim_fraction < 0.5:
            raise ValueError("trim_fraction must be in [0, 0.5)")
        if result.warn_z <= 0 or result.critical_z < result.warn_z:
            raise ValueError("invalid baseline thresholds")
        return result


@dataclass(frozen=True)
class ChangePolicy:
    short_windows: int = 3
    long_windows: int = 12
    minimum_effect: float = 0.2
    confirmation_windows: int = 2
    recovery_windows: int = 2
    cusum_drift: float = 0.5
    cusum_threshold: float = 4.0

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ChangePolicy":
        result = cls(**{key: raw[key] for key in cls.__dataclass_fields__ if key in raw})
        if result.short_windows < 1 or result.long_windows <= result.short_windows:
            raise ValueError("long_windows must exceed short_windows")
        if result.confirmation_windows < 1 or result.recovery_windows < 1:
            raise ValueError("confirmation and recovery windows must be positive")
        return result


@dataclass(frozen=True)
class AlertPolicy:
    dedupe_seconds: int = 3600
    suppression_seconds: int = 1800
    budget_window_seconds: int = 86400
    suppression_budget: int = 4
    max_suppression_seconds: int = 7200
    auto_resolve_seconds: int = 14400
    reopen_seconds: int = 86400

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AlertPolicy":
        result = cls(**{key: raw[key] for key in cls.__dataclass_fields__ if key in raw})
        values = [getattr(result, key) for key in cls.__dataclass_fields__]
        if any(value < 0 for value in values):
            raise ValueError("alert policy values cannot be negative")
        if result.max_suppression_seconds < result.suppression_seconds:
            raise ValueError("max suppression must cover base suppression")
        return result


@dataclass(frozen=True)
class MonitorConfig:
    windows: tuple[WindowSpec, ...]
    baseline: BaselinePolicy = field(default_factory=BaselinePolicy)
    change: ChangePolicy = field(default_factory=ChangePolicy)
    alerts: AlertPolicy = field(default_factory=AlertPolicy)
    capability_allowlist: dict[str, tuple[str, ...]] = field(default_factory=dict)
    protected_capabilities: tuple[str, ...] = ()
    watermark_idle_seconds: int = 600

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "MonitorConfig":
        windows = tuple(WindowSpec.from_dict(item) for item in raw.get("windows", []))
        if not windows:
            raise ValueError("at least one window is required")
        names = [item.name for item in windows]
        if len(names) != len(set(names)):
            raise ValueError("window names must be unique")
        allowlist = {}
        for agent, capabilities in raw.get("capability_allowlist", {}).items():
            allowlist[str(agent)] = tuple(sorted({str(item) for item in capabilities}))
        protected = tuple(sorted({str(item) for item in raw.get("protected_capabilities", [])}))
        idle = int(raw.get("watermark_idle_seconds", 600))
        if idle < 0:
            raise ValueError("watermark_idle_seconds cannot be negative")
        return cls(
            windows=windows,
            baseline=BaselinePolicy.from_dict(raw.get("baseline", {})),
            change=ChangePolicy.from_dict(raw.get("change", {})),
            alerts=AlertPolicy.from_dict(raw.get("alerts", {})),
            capability_allowlist=allowlist,
            protected_capabilities=protected,
            watermark_idle_seconds=idle,
        )

    @classmethod
    def load(cls, path: str | Path) -> "MonitorConfig":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "windows": [item.__dict__ for item in self.windows],
            "baseline": self.baseline.__dict__,
            "change": self.change.__dict__,
            "alerts": self.alerts.__dict__,
            "capability_allowlist": {key: list(value) for key, value in self.capability_allowlist.items()},
            "protected_capabilities": list(self.protected_capabilities),
            "watermark_idle_seconds": self.watermark_idle_seconds,
        }

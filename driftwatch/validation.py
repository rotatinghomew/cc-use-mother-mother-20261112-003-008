from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable
import json

from .config import MonitorConfig
from .models import BehaviorEvent, CapabilityDeclaration


@dataclass(frozen=True)
class ValidationIssue:
    location: str
    code: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class FixtureValidator:
    def __init__(self, maximum_records: int = 1_000_000):
        if maximum_records < 1:
            raise ValueError("maximum_records must be positive")
        self.maximum_records = maximum_records

    def load(self, path: str | Path) -> list[dict[str, Any]]:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        records = raw.get("records", raw) if isinstance(raw, dict) else raw
        if not isinstance(records, list):
            raise ValueError("fixture must be a list or contain records")
        if len(records) > self.maximum_records:
            raise ValueError(f"fixture exceeds maximum record count {self.maximum_records}")
        return records

    def validate_records(self, records: list[Any]) -> dict[str, Any]:
        issues = []
        valid = 0
        identifiers: dict[tuple[str, int], int] = {}
        for index, raw in enumerate(records):
            location = f"records[{index}]"
            if not isinstance(raw, dict):
                issues.append(ValidationIssue(location, "not_object", "record must be an object"))
                continue
            kind = str(raw.get("type", "behavior")).lower()
            try:
                if kind in {"behavior", "event", "metric"}:
                    item = BehaviorEvent.from_dict(raw)
                    key = (item.event_id, item.revision)
                elif kind in {"capability", "capabilities", "declaration"}:
                    item = CapabilityDeclaration.from_dict(raw)
                    key = (item.declaration_id, item.revision)
                else:
                    raise ValueError(f"unsupported record type {kind}")
                if key in identifiers:
                    issues.append(ValidationIssue(location, "duplicate_key",
                                                  f"duplicates records[{identifiers[key]}]", "warning"))
                else:
                    identifiers[key] = index
                valid += 1
            except Exception as exc:
                issues.append(ValidationIssue(location, "invalid_record", str(exc)))
        errors = sum(item.severity == "error" for item in issues)
        warnings = len(issues) - errors
        return {"valid": errors == 0, "records": len(records), "accepted": valid,
                "errors": errors, "warnings": warnings,
                "issues": [item.to_dict() for item in issues]}

    def validate_path(self, path: str | Path) -> dict[str, Any]:
        return self.validate_records(self.load(path))


class ConfigValidator:
    def validate(self, raw: dict[str, Any]) -> dict[str, Any]:
        issues = []
        try:
            config = MonitorConfig.from_dict(raw)
        except Exception as exc:
            return {"valid": False, "issues": [ValidationIssue("config", "invalid", str(exc)).to_dict()]}
        largest_lateness = max(item.allowed_lateness_seconds for item in config.windows)
        smallest_window = min(item.size_seconds for item in config.windows)
        if largest_lateness > smallest_window * 10:
            issues.append(ValidationIssue("windows", "large_lateness",
                                          "allowed lateness greatly exceeds smallest window", "warning"))
        if config.alerts.suppression_budget == 0:
            issues.append(ValidationIssue("alerts", "suppression_disabled",
                                          "suppression budget is zero", "warning"))
        if not config.protected_capabilities:
            issues.append(ValidationIssue("protected_capabilities", "empty_protected_set",
                                          "no capability automatically receives elevated risk", "warning"))
        return {"valid": True, "issues": [item.to_dict() for item in issues], "normalized": config.to_dict()}

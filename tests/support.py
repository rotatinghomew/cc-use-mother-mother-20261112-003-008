from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from driftwatch.config import MonitorConfig
from driftwatch.models import BehaviorEvent, CapabilityDeclaration, DetectionEvidence, WindowAggregate, iso
from driftwatch.service import DriftMonitoringService


def test_config(**overrides):
    raw = {
        "windows": [
            {"name": "5m", "size_seconds": 300, "step_seconds": 300,
             "allowed_lateness_seconds": 60, "minimum_points": 1},
            {"name": "15m", "size_seconds": 900, "step_seconds": 300,
             "allowed_lateness_seconds": 120, "minimum_points": 2},
        ],
        "baseline": {"history_windows": 20, "minimum_samples": 3, "season_period_seconds": 86400,
                       "season_tolerance_seconds": 3600, "warn_z": 2.5, "critical_z": 4.0,
                       "spread_floor": 0.1},
        "change": {"short_windows": 2, "long_windows": 4, "minimum_effect": 0.25,
                     "confirmation_windows": 2, "recovery_windows": 2,
                     "cusum_drift": 0.3, "cusum_threshold": 2.0},
        "alerts": {"dedupe_seconds": 600, "suppression_seconds": 300,
                     "budget_window_seconds": 3600, "suppression_budget": 2,
                     "max_suppression_seconds": 1200, "auto_resolve_seconds": 1800,
                     "reopen_seconds": 3600},
        "capability_allowlist": {"a1": ["observe", "summarize"]},
        "protected_capabilities": ["purchase", "send_message"],
        "watermark_idle_seconds": 300,
    }
    raw.update(overrides)
    return MonitorConfig.from_dict(raw)


def event(index, value=10.0, agent="a1", metric="calls", delay=5, revision=1, start=None, dimensions=None):
    base = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    moment = base + timedelta(minutes=5 * index)
    return {
        "type": "behavior", "event_id": f"{agent}-{metric}-{index}", "agent_id": agent,
        "event_time": iso(moment), "arrival_time": iso(moment + timedelta(seconds=delay)),
        "metric": metric, "value": value, "revision": revision,
        "dimensions": dimensions or {"channel": "foreground"},
    }


def capability(index, capabilities, agent="a1", revision=1, start=None, schema_version=1):
    base = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    moment = base + timedelta(hours=index)
    return {
        "type": "capability", "declaration_id": f"{agent}-cap-{index}", "agent_id": agent,
        "event_time": iso(moment), "arrival_time": iso(moment + timedelta(seconds=2)),
        "capabilities": list(capabilities), "revision": revision, "schema_version": schema_version,
    }


def aggregate(index, mean, finalized=True, agent="a1", metric="calls", spec="5m", version=1):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=5 * index)
    end = start + timedelta(minutes=5)
    return WindowAggregate(
        window_id=f"w-{agent}-{metric}-{spec}-{index}", agent_id=agent, metric=metric,
        dimension_key='{"channel":"foreground"}', spec_name=spec, start_time=iso(start), end_time=iso(end),
        version=version, count=3, total=mean * 3, mean=mean, minimum=mean - 1, maximum=mean + 1,
        median=mean, mad=0.5, first_event_time=iso(start), last_event_time=iso(end - timedelta(seconds=1)),
        finalized=finalized, correction_reason=None,
    )


def evidence(index=0, kind="change_point", severity="warning", score=1.0, status="confirmed",
             fingerprint="fp", agent="a1"):
    moment = datetime(2026, 1, 2, tzinfo=timezone.utc) + timedelta(minutes=index)
    return DetectionEvidence(
        evidence_id=f"ev-{kind}-{index}", agent_id=agent, kind=kind, observed_at=iso(moment),
        severity=severity, score=score, summary=f"{kind} summary", fingerprint=fingerprint,
        payload={"direction": "increase", "index": index}, status=status,
    )


class ServiceCase(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.service = DriftMonitoringService(self.root / "test.sqlite", test_config())

    def tearDown(self):
        self.temp.cleanup()

    def write_fixture(self, records, name="fixture.json"):
        path = self.root / name
        path.write_text(json.dumps({"records": records}, ensure_ascii=False), encoding="utf-8")
        return path

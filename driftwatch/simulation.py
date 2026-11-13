from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import json
import math
import random

from .models import iso


@dataclass(frozen=True)
class SimulationPlan:
    seed: int = 7
    agents: tuple[str, ...] = ("agent-alpha", "agent-beta")
    start_time: str = "2026-10-01T00:00:00Z"
    intervals: int = 120
    interval_seconds: int = 300
    duplicate_rate: float = 0.03
    late_rate: float = 0.08
    revision_rate: float = 0.02
    drift_start: int = 70
    drift_factor: float = 2.2
    capability_expansion_at: int = 80

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SimulationPlan":
        values = {key: raw[key] for key in cls.__dataclass_fields__ if key in raw}
        if "agents" in values:
            values["agents"] = tuple(values["agents"])
        result = cls(**values)
        result.validate()
        return result

    def validate(self) -> None:
        if not self.agents or any(not item for item in self.agents):
            raise ValueError("simulation needs named agents")
        if self.intervals < 10 or self.interval_seconds <= 0:
            raise ValueError("simulation horizon is too short")
        if not 0 <= self.duplicate_rate <= 1 or not 0 <= self.late_rate <= 1 or not 0 <= self.revision_rate <= 1:
            raise ValueError("simulation rates must be in [0,1]")
        if self.drift_start < 0 or self.capability_expansion_at < 0:
            raise ValueError("simulation change points cannot be negative")


class StreamSimulator:
    def __init__(self, plan: SimulationPlan):
        self.plan = plan
        self.random = random.Random(plan.seed)

    def generate(self) -> list[dict[str, Any]]:
        records = []
        start = datetime.fromisoformat(self.plan.start_time.replace("Z", "+00:00"))
        for agent_index, agent in enumerate(self.plan.agents):
            capabilities = ["observe", "summarize"]
            records.append(self._capability(agent, start, capabilities, 0))
            for index in range(self.plan.intervals):
                event_time = start + timedelta(seconds=index * self.plan.interval_seconds)
                seasonal = 1.0 + 0.25 * math.sin(index / 12 * math.pi * 2)
                base = 10.0 + agent_index * 3.0
                drift = self.plan.drift_factor if agent_index == 0 and index >= self.plan.drift_start else 1.0
                noise = self.random.uniform(-0.8, 0.8)
                value = max(0.0, base * seasonal * drift + noise)
                arrival_delay = self.random.randint(1, 20)
                if self.random.random() < self.plan.late_rate:
                    arrival_delay += self.plan.interval_seconds * self.random.randint(2, 6)
                event = {
                    "type": "behavior",
                    "event_id": f"{agent}-calls-{index:04d}",
                    "agent_id": agent,
                    "event_time": iso(event_time),
                    "arrival_time": iso(event_time + timedelta(seconds=arrival_delay)),
                    "metric": "tool_calls",
                    "value": round(value, 6),
                    "dimensions": {"tool_group": "application", "channel": "foreground"},
                    "revision": 1,
                }
                records.append(event)
                latency = {**event, "event_id": f"{agent}-latency-{index:04d}", "metric": "latency_ms",
                           "value": round(80 + value * 3 + self.random.uniform(-5, 5), 6)}
                records.append(latency)
                if self.random.random() < self.plan.duplicate_rate:
                    records.append(dict(event))
                if self.random.random() < self.plan.revision_rate:
                    revised = dict(event)
                    revised["revision"] = 2
                    revised["arrival_time"] = iso(event_time + timedelta(seconds=arrival_delay + 30))
                    revised["value"] = round(value + self.random.uniform(-0.3, 0.3), 6)
                    records.append(revised)
                if agent_index == 0 and index == self.plan.capability_expansion_at:
                    capabilities = ["observe", "summarize", "purchase", "send_message"]
                    records.append(self._capability(agent, event_time, capabilities, 1))
        self.random.shuffle(records)
        return records

    def _capability(self, agent: str, moment: datetime, capabilities: list[str], sequence: int) -> dict[str, Any]:
        return {
            "type": "capability",
            "declaration_id": f"{agent}-cap-{sequence}",
            "agent_id": agent,
            "event_time": iso(moment),
            "arrival_time": iso(moment + timedelta(seconds=5)),
            "capabilities": capabilities,
            "revision": 1,
            "schema_version": 1,
            "issuer": "synthetic-device",
        }

    def fixture(self) -> dict[str, Any]:
        return {"plan": asdict(self.plan), "records": self.generate()}

    def write(self, path: str | Path) -> dict[str, Any]:
        fixture = self.fixture()
        Path(path).write_text(json.dumps(fixture, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                              encoding="utf-8")
        return fixture


def compact_fixture() -> dict[str, Any]:
    return StreamSimulator(SimulationPlan(agents=("agent-demo",), intervals=96, drift_start=55,
                                          capability_expansion_at=64, duplicate_rate=0.04, late_rate=0.12)).fixture()

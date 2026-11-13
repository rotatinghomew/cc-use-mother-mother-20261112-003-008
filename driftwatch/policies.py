from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import timedelta
from typing import Any, Iterable

from .models import DetectionEvidence, parse_time


@dataclass(frozen=True)
class EvidenceRule:
    name: str
    kinds: tuple[str, ...]
    minimum_score: float = 0.0
    severities: tuple[str, ...] = ("warning", "critical")
    required_status: str = "confirmed"
    agent_prefix: str = ""
    cooldown_seconds: int = 0

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceRule":
        name = str(raw.get("name", "")).strip()
        kinds = tuple(sorted({str(item) for item in raw.get("kinds", [])}))
        if not name or not kinds:
            raise ValueError("rule requires name and kinds")
        result = cls(
            name=name, kinds=kinds, minimum_score=float(raw.get("minimum_score", 0.0)),
            severities=tuple(raw.get("severities", ("warning", "critical"))),
            required_status=str(raw.get("required_status", "confirmed")),
            agent_prefix=str(raw.get("agent_prefix", "")),
            cooldown_seconds=int(raw.get("cooldown_seconds", 0)),
        )
        if result.minimum_score < 0 or result.cooldown_seconds < 0:
            raise ValueError("rule thresholds cannot be negative")
        return result

    def matches(self, evidence: DetectionEvidence) -> bool:
        return (evidence.kind in self.kinds and evidence.score >= self.minimum_score
                and evidence.severity in self.severities and evidence.status == self.required_status
                and evidence.agent_id.startswith(self.agent_prefix))


@dataclass(frozen=True)
class PolicyDecision:
    rule: str
    evidence_id: str
    matched: bool
    action: str
    reason: str
    tags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    def __init__(self, rules: Iterable[EvidenceRule]):
        self.rules = tuple(rules)
        names = [item.name for item in self.rules]
        if len(names) != len(set(names)):
            raise ValueError("policy rule names must be unique")
        self.last_matches: dict[tuple[str, str], str] = {}

    def evaluate(self, evidence: DetectionEvidence) -> list[PolicyDecision]:
        decisions = []
        for rule in self.rules:
            matched = rule.matches(evidence)
            action = "ignore"
            reason = "conditions did not match"
            if matched:
                key = (rule.name, evidence.fingerprint)
                previous = self.last_matches.get(key)
                if previous and rule.cooldown_seconds:
                    elapsed = (parse_time(evidence.observed_at) - parse_time(previous)).total_seconds()
                    if elapsed < rule.cooldown_seconds:
                        action = "cooldown"
                        reason = "rule matched but remains in cooldown"
                    else:
                        action = "alert"
                        reason = "rule matched after cooldown"
                        self.last_matches[key] = evidence.observed_at
                else:
                    action = "alert"
                    reason = "rule matched"
                    self.last_matches[key] = evidence.observed_at
            tags = (evidence.kind, evidence.severity, rule.name)
            decisions.append(PolicyDecision(rule.name, evidence.evidence_id, matched, action, reason, tags))
        return decisions

    def filter_alertable(self, evidence: Iterable[DetectionEvidence]) -> list[DetectionEvidence]:
        results = []
        for item in evidence:
            decisions = self.evaluate(item)
            if not self.rules or any(decision.action == "alert" for decision in decisions):
                results.append(item)
        return results

    def matrix(self, evidence: Iterable[DetectionEvidence]) -> list[dict[str, Any]]:
        rows = []
        for item in evidence:
            for decision in self.evaluate(item):
                rows.append({"agent_id": item.agent_id, "kind": item.kind, "severity": item.severity,
                             **decision.to_dict()})
        return rows


def default_rules() -> tuple[EvidenceRule, ...]:
    return (
        EvidenceRule("confirmed-behavior", ("change_point", "cumulative_drift"), 0.2,
                     ("warning", "critical"), "confirmed", cooldown_seconds=300),
        EvidenceRule("capability-growth", ("capability_expansion",), 2.0,
                     ("warning", "critical"), "confirmed", cooldown_seconds=60),
        EvidenceRule("critical-point", ("behavior_drift",), 6.0,
                     ("critical",), "candidate", cooldown_seconds=120),
    )

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
import json

from .alerts import AlertManager
from .analytics import FleetAnalytics
from .audit import AuditVerifier
from .baselines import BaselineEngine
from .capabilities import CapabilityDiffer
from .checkpoints import CheckpointManager
from .config import MonitorConfig
from .detectors import DriftDetector
from .correlation import IncidentCorrelator
from .explanations import ExplanationBuilder
from .ingestion import EventIngestor, IngestionResult
from .integrity import IntegrityAnalyzer
from .lateness import LateDataPlanner
from .models import BehaviorEvent, CapabilityDeclaration, DetectionEvidence, WindowAggregate, iso
from .migrations import SchemaMigrator
from .metrics import MetricsCollector
from .policies import PolicyEngine, default_rules
from .replay import ReplayCoordinator, ReplayResult
from .query import QueryService
from .review import ReviewQueue
from .reporting import Reporter
from .storage import Store
from .watermarks import WatermarkManager
from .windows import WindowEngine


class DriftMonitoringService:
    def __init__(self, database: str | Path, config: MonitorConfig):
        self.config = config
        self.store = Store(database)
        self.watermarks = WatermarkManager(self.store, config)
        self.ingestor = EventIngestor(self.store, self.watermarks)
        self.windows = WindowEngine(self.store, config, self.watermarks)
        self.baselines = BaselineEngine(self.store, config.baseline)
        self.detectors = DriftDetector(self.store, self.baselines, config.change)
        self.capabilities = CapabilityDiffer(self.store, config)
        self.alerts = AlertManager(self.store, config.alerts)
        self.policies = PolicyEngine(default_rules())
        self.integrity = IntegrityAnalyzer(self.store)
        self.reporter = Reporter(self.store)
        self.analytics = FleetAnalytics(self.store)
        self.audit = AuditVerifier(self.store)
        self.correlator = IncidentCorrelator(self.store)
        self.explanations = ExplanationBuilder(self.store)
        self.lateness = LateDataPlanner(self.store, config)
        self.migrations = SchemaMigrator(self.store)
        self.migrations.migrate()
        self.query = QueryService(self.store)
        self.review = ReviewQueue(self.store)
        self.metrics = MetricsCollector(self.store)
        self.replay = ReplayCoordinator(self.store, self.ingestor, self.windows, self.evaluate_window)

    @classmethod
    def from_paths(cls, database: str | Path, config_path: str | Path) -> "DriftMonitoringService":
        return cls(database, MonitorConfig.load(config_path))

    def ingest_records(self, records: Iterable[dict[str, Any]], strict: bool = False,
                       process: bool = True) -> dict[str, Any]:
        raw_records = [dict(item) for item in records]
        result = self.ingestor.ingest_records(raw_records, strict=strict)
        processed_windows = []
        evidence = []
        alert_ids = []
        if process:
            for raw in raw_records:
                try:
                    kind = str(raw.get("type", "behavior")).lower()
                    if kind in {"behavior", "event", "metric"}:
                        event = BehaviorEvent.from_dict(raw)
                        windows = self.windows.materialize_event(
                            event, correction_reason="late-or-revision" if self._is_correction(event) else None
                        )
                        processed_windows.extend(windows)
                        for window in windows:
                            evidence.extend(self.evaluate_window(window, event.arrival_time))
                    elif kind in {"capability", "capabilities", "declaration"}:
                        declaration = CapabilityDeclaration.from_dict(raw)
                        item = self.capabilities.evidence(declaration)
                        if item and self.store.save_evidence(item, declaration.arrival_time):
                            evidence.append(item)
                            alert = self.route_evidence(item)
                            if alert:
                                alert_ids.append(alert.alert_id)
                except Exception:
                    if strict:
                        raise
        alert_ids.extend(alert.alert_id for alert in self.store.alerts() if alert.updated_at in
                         {item.observed_at for item in evidence})
        return {
            "ingestion": result.to_dict(),
            "windows": len({(item.window_id, item.version) for item in processed_windows}),
            "evidence": len({item.evidence_id for item in evidence}),
            "alerts": sorted(set(alert_ids)),
            "counts": self.store.counts(),
        }

    def ingest_fixture(self, path: str | Path, strict: bool = False) -> dict[str, Any]:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        records = raw.get("records", raw) if isinstance(raw, dict) else raw
        if not isinstance(records, list):
            raise ValueError("fixture must be a list or contain records")
        return self.ingest_records(records, strict=strict)

    def _is_correction(self, event: BehaviorEvent) -> bool:
        partition = self.store.get_partition(self.watermarks.behavior_partition(event))
        return bool(partition and event.event_time < partition["watermark"]) or event.revision > 1

    def evaluate_window(self, window: WindowAggregate, created_at: str) -> list[DetectionEvidence]:
        if not window.finalized or window.count < self._minimum_points(window.spec_name):
            return []
        results = []
        for evidence in self.detectors.evaluate(window, created_at):
            if self.store.save_evidence(evidence, created_at):
                results.append(evidence)
                self.route_evidence(evidence)
        return results

    def _minimum_points(self, spec_name: str) -> int:
        spec = next(item for item in self.config.windows if item.name == spec_name)
        return spec.minimum_points

    def route_evidence(self, evidence: DetectionEvidence):
        decisions = self.policies.evaluate(evidence)
        if not decisions or any(item.action == "alert" for item in decisions):
            return self.alerts.consume(evidence)
        return None

    def recompute(self, requested_at: str, reason: str, scope: dict[str, Any]) -> dict[str, Any]:
        return self.replay.recompute(requested_at, reason, scope).to_dict()

    def replay_fixture(self, path: str | Path, requested_at: str) -> dict[str, Any]:
        return self.replay.replay_fixture(path, requested_at).to_dict()

    def maintain(self, now: str) -> dict[str, Any]:
        resolved = self.alerts.auto_resolve(now)
        health = self.integrity.health()
        return {"auto_resolved": [item.alert_id for item in resolved], "health": health,
                "watermarks": self.watermarks.snapshot()}

    def status(self) -> dict[str, Any]:
        return {
            "summary": self.reporter.summary(),
            "watermarks": self.watermarks.snapshot(),
            "health": self.integrity.health(),
            "analytics": self.analytics.offline_snapshot(),
        }

    def report(self, output: str | Path, agent_id: str | None = None) -> dict[str, Any]:
        return self.reporter.write(output, agent_id)

    def lifecycle(self, action: str, alert_id: str, occurred_at: str, actor: str, reason: str = "") -> dict[str, Any]:
        if action == "acknowledge":
            return self.alerts.acknowledge(alert_id, occurred_at, actor, reason).to_dict()
        if action == "resolve":
            return self.alerts.resolve(alert_id, occurred_at, actor, reason).to_dict()
        raise ValueError(f"unsupported lifecycle action: {action}")


def default_config() -> MonitorConfig:
    return MonitorConfig.from_dict({
        "windows": [
            {"name": "15m", "size_seconds": 900, "step_seconds": 300,
             "allowed_lateness_seconds": 600, "minimum_points": 2},
            {"name": "1h", "size_seconds": 3600, "step_seconds": 900,
             "allowed_lateness_seconds": 1200, "minimum_points": 4},
        ],
        "baseline": {"history_windows": 48, "minimum_samples": 6, "season_period_seconds": 86400,
                       "season_tolerance_seconds": 3600, "warn_z": 3.0, "critical_z": 5.0},
        "change": {"short_windows": 3, "long_windows": 10, "minimum_effect": 0.35,
                     "confirmation_windows": 2, "cusum_threshold": 4.0},
        "alerts": {"dedupe_seconds": 1800, "suppression_seconds": 900,
                     "budget_window_seconds": 86400, "suppression_budget": 3,
                     "max_suppression_seconds": 3600, "auto_resolve_seconds": 10800},
        "capability_allowlist": {"agent-demo": ["observe", "summarize"]},
        "protected_capabilities": ["purchase", "send_message", "install_application"],
    })

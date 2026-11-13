from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import json

from .audit import AuditVerifier
from .checkpoints import CheckpointManager
from .correlation import IncidentCorrelator
from .service import DriftMonitoringService, default_config


def run(fixture: str | Path, output: str | Path) -> dict[str, Any]:
    target = Path(output)
    target.mkdir(parents=True, exist_ok=True)
    database = target / "acceptance.sqlite"
    service = DriftMonitoringService(database, default_config())
    ingestion = service.ingest_fixture(fixture, strict=True)
    recompute = service.recompute("2026-11-12T12:00:00Z", "acceptance consistency rebuild", {})
    maintenance = service.maintain("2026-11-13T00:00:00Z")
    report = service.report(target / "offline-report.json")
    audit = AuditVerifier(service.store)
    audit_export = audit.export(target / "audit-proof.json")
    audit_verification = audit.verify_export(target / "audit-proof.json")
    checkpoint = CheckpointManager(service.store)
    checkpoint_manifest = checkpoint.create(target / "checkpoint", "2026-11-13T00:00:01Z",
                                            {"purpose": "offline acceptance"})
    checkpoint_verification = checkpoint.verify(target / "checkpoint")
    incidents = [item.to_dict() for item in IncidentCorrelator(service.store).build()]
    checks = {
        "ingested": ingestion["ingestion"]["inserted"] > 0,
        "windows": ingestion["counts"]["window_aggregates"] > 0,
        "baselines": ingestion["counts"]["baselines"] > 0,
        "evidence": ingestion["counts"]["evidence"] > 0,
        "alerts": ingestion["counts"]["alerts"] > 0,
        "recompute_completed": recompute["status"] == "completed",
        "audit_valid": audit_verification["valid"],
        "checkpoint_valid": checkpoint_verification["valid"],
        "report_written": (target / "offline-report.json").is_file(),
        "incidents": bool(incidents),
    }
    result = {
        "passed": all(checks.values()), "checks": checks, "ingestion": ingestion,
        "recompute": recompute, "maintenance_status": maintenance["health"]["status"],
        "report_counts": report["counts"], "audit_root": audit_export["root_hash"],
        "checkpoint": checkpoint_manifest, "incidents": incidents[:10],
    }
    (target / "acceptance-result.json").write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    if not result["passed"]:
        raise RuntimeError("acceptance checks failed")
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.fixture, args.output), ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

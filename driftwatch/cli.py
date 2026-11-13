from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys

from .config import MonitorConfig
from .service import DriftMonitoringService, default_config
from .simulation import SimulationPlan, StreamSimulator


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="driftwatch", description="offline agent behavior drift monitor")
    root.add_argument("--db", default="driftwatch.sqlite")
    root.add_argument("--config")
    sub = root.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest")
    ingest.add_argument("fixture")
    ingest.add_argument("--strict", action="store_true")
    replay = sub.add_parser("replay")
    replay.add_argument("fixture")
    replay.add_argument("--at", required=True)
    recompute = sub.add_parser("recompute")
    recompute.add_argument("--at", required=True)
    recompute.add_argument("--reason", required=True)
    recompute.add_argument("--agent")
    recompute.add_argument("--metric")
    recompute.add_argument("--start")
    recompute.add_argument("--end")
    status = sub.add_parser("status")
    status.add_argument("--output")
    report = sub.add_parser("report")
    report.add_argument("output")
    report.add_argument("--agent")
    maintain = sub.add_parser("maintain")
    maintain.add_argument("--at", required=True)
    lifecycle = sub.add_parser("alert")
    lifecycle.add_argument("action", choices=("acknowledge", "resolve"))
    lifecycle.add_argument("alert_id")
    lifecycle.add_argument("--at", required=True)
    lifecycle.add_argument("--actor", required=True)
    lifecycle.add_argument("--reason", default="")
    simulate = sub.add_parser("simulate")
    simulate.add_argument("output")
    simulate.add_argument("--seed", type=int, default=7)
    simulate.add_argument("--intervals", type=int, default=120)
    return root


def service_from_args(args: argparse.Namespace) -> DriftMonitoringService:
    config = MonitorConfig.load(args.config) if args.config else default_config()
    return DriftMonitoringService(args.db, config)


def emit(value) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "simulate":
        plan = SimulationPlan(seed=args.seed, intervals=args.intervals)
        emit({"output": args.output, "records": len(StreamSimulator(plan).write(args.output)["records"])})
        return 0
    service = service_from_args(args)
    if args.command == "ingest":
        emit(service.ingest_fixture(args.fixture, strict=args.strict))
    elif args.command == "replay":
        emit(service.replay_fixture(args.fixture, args.at))
    elif args.command == "recompute":
        scope = {key: value for key, value in {"agent_id": args.agent, "metric": args.metric,
                                               "start": args.start, "end": args.end}.items() if value}
        emit(service.recompute(args.at, args.reason, scope))
    elif args.command == "status":
        value = service.status()
        if args.output:
            Path(args.output).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        emit(value)
    elif args.command == "report":
        emit(service.report(args.output, args.agent))
    elif args.command == "maintain":
        emit(service.maintain(args.at))
    elif args.command == "alert":
        emit(service.lifecycle(args.action, args.alert_id, args.at, args.actor, args.reason))
    else:
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

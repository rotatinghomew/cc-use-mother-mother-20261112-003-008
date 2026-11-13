from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from typing import Any

from .storage import Store


@dataclass(frozen=True)
class OperationalMetric:
    name: str
    value: float
    unit: str
    labels: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MetricsCollector:
    def __init__(self, store: Store):
        self.store = store

    def collect(self) -> list[OperationalMetric]:
        metrics = []
        counts = self.store.counts()
        for name, value in counts.items():
            metrics.append(OperationalMetric(f"driftwatch_{name}_total", float(value), "records", {}))
        partitions = self._partitions()
        for partition in partitions:
            labels = {"partition": partition["partition_key"]}
            metrics.append(OperationalMetric("driftwatch_partition_events_total",
                                             float(partition["event_count"]), "events", labels))
            metrics.append(OperationalMetric("driftwatch_partition_late_total",
                                             float(partition["late_count"]), "events", labels))
            metrics.append(OperationalMetric("driftwatch_partition_duplicates_total",
                                             float(partition["duplicate_count"]), "events", labels))
        for state, count in Counter(item.state for item in self.store.alerts()).items():
            metrics.append(OperationalMetric("driftwatch_alerts", float(count), "alerts", {"state": state}))
        for kind, count in Counter(item.kind for item in self.store.evidence()).items():
            metrics.append(OperationalMetric("driftwatch_evidence", float(count), "records", {"kind": kind}))
        return sorted(metrics, key=lambda item: (item.name, sorted(item.labels.items())))

    def snapshot(self) -> dict[str, Any]:
        values = self.collect()
        return {"metrics": [item.to_dict() for item in values], "metric_count": len(values)}

    def text(self) -> str:
        lines = []
        for metric in self.collect():
            labels = ""
            if metric.labels:
                pairs = [f'{key}="{value.replace(chr(34), chr(92)+chr(34))}"'
                         for key, value in sorted(metric.labels.items())]
                labels = "{" + ",".join(pairs) + "}"
            lines.append(f"{metric.name}{labels} {metric.value:g}")
        return "\n".join(lines) + ("\n" if lines else "")

    def _partitions(self) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM partitions ORDER BY partition_key")]

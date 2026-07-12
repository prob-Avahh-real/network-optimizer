"""Metrics collection — gather raw timing data for all layers."""

import time
import statistics
from dataclasses import dataclass, field


@dataclass
class Metric:
    name: str
    unit: str
    values: list[float] = field(default_factory=list)

    @property
    def min(self) -> float | None:
        return min(self.values) if self.values else None

    @property
    def max(self) -> float | None:
        return max(self.values) if self.values else None

    @property
    def avg(self) -> float | None:
        return statistics.mean(self.values) if self.values else None

    @property
    def p50(self) -> float | None:
        if not self.values:
            return None
        return statistics.median(self.values)

    @property
    def p95(self) -> float | None:
        if len(self.values) < 2:
            return (self.values[0] if self.values else None)
        sorted_vals = sorted(self.values)
        idx = int(len(sorted_vals) * 0.95)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]

    @property
    def p99(self) -> float | None:
        if len(self.values) < 2:
            return (self.values[0] if self.values else None)
        sorted_vals = sorted(self.values)
        idx = int(len(sorted_vals) * 0.99)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]

    @property
    def count(self) -> int:
        return len(self.values)

    def record(self, value: float) -> None:
        self.values.append(value)


@dataclass
class MetricSnapshot:
    """A full set of metrics from one measurement round."""
    dns_ms: float = 0
    tcp_ms: float = 0
    tls_ms: float = 0
    ttfb_ms: float = 0
    total_ms: float = 0
    status_code: int = 0
    body_size_bytes: int = 0
    redirect_count: int = 0
    http_version: str = ""
    tls_version: str = ""
    error: str = ""


@dataclass
class MetricsStore:
    """Accumulates metric snapshots for statistical analysis."""
    dns: Metric = field(default_factory=lambda: Metric("dns", "ms"))
    tcp: Metric = field(default_factory=lambda: Metric("tcp", "ms"))
    tls: Metric = field(default_factory=lambda: Metric("tls", "ms"))
    ttfb: Metric = field(default_factory=lambda: Metric("ttfb", "ms"))
    total: Metric = field(default_factory=lambda: Metric("total", "ms"))
    body_size: Metric = field(default_factory=lambda: Metric("body_size", "bytes"))
    error_count: int = 0
    total_samples: int = 0

    def record(self, snap: MetricSnapshot) -> None:
        self.total_samples += 1
        if snap.error:
            self.error_count += 1
            return
        self.dns.record(snap.dns_ms)
        self.tcp.record(snap.tcp_ms)
        self.tls.record(snap.tls_ms)
        self.ttfb.record(snap.ttfb_ms)
        self.total.record(snap.total_ms)
        if snap.body_size_bytes > 0:
            self.body_size.record(snap.body_size_bytes)

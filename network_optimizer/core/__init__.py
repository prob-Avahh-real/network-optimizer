"""Layer definitions and diagnostic interfaces for network optimization."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional
import time


class Severity(Enum):
    OK = "ok"
    WARN = "warn"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Single diagnostic finding at any layer."""
    layer: str
    check: str
    severity: Severity
    value: str
    threshold: str
    recommendation: str


@dataclass
class LayerDiagnosis:
    """Complete diagnosis for one optimization layer."""
    layer_name: str
    layer_index: int
    duration_ms: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARN)


@dataclass
class NetworkProfile:
    """Full network profile including all layer diagnoses and a summary score."""
    target: str
    timestamp: float = field(default_factory=time.time)
    layers: list[LayerDiagnosis] = field(default_factory=list)

    @property
    def total_duration_ms(self) -> float:
        return sum(l.duration_ms for l in self.layers)

    @property
    def total_critical(self) -> int:
        return sum(l.critical_count for l in self.layers)

    @property
    def health_score(self) -> int:
        """0-100 score based on findings severity."""
        total = sum(len(l.findings) for l in self.layers)
        if total == 0:
            return 100
        critical = self.total_critical
        warn = sum(l.warn_count for l in self.layers)
        score = 100 - (critical * 20) - (warn * 5)
        return max(0, min(100, score))


# Layer diagnostic function type
LayerFn = Callable[[str], LayerDiagnosis]

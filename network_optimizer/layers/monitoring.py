"""Layer 5: 监测层 — Continuous monitoring and alerting

Checks:
  - Real User Monitoring (RUM) setup
  - Synthetic monitoring intervals
  - Alert thresholds
  - Performance budget enforcement
  - Long-term trend tracking
"""

import time
import statistics
from typing import Optional

from ..core import LayerDiagnosis, Finding, Severity

# Budget thresholds (ms)
BUDGET_DNS = 50
BUDGET_TCP = 30
BUDGET_TLS = 50
BUDGET_TTFB = 200
BUDGET_TOTAL_PAGE = 1000
BUDGET_API = 300


def _evaluate_budget(name: str, value_ms: float, budget_ms: float) -> Finding:
    """Evaluate a single performance budget item."""
    if value_ms < 0:
        return Finding(
            layer="监测", check=f"{name} 预算",
            severity=Severity.WARN,
            value="无法测量",
            threshold=f"<{budget_ms}ms",
            recommendation=f"无法获取 {name} 耗时，检查测量环境"
        )
    if value_ms <= budget_ms:
        return Finding(
            layer="监测", check=f"{name} 预算",
            severity=Severity.OK,
            value=f"{value_ms:.1f}ms",
            threshold=f"<{budget_ms}ms",
            recommendation=f"{name} 在预算内"
        )
    over = (value_ms - budget_ms) / budget_ms * 100
    if over < 50:
        return Finding(
            layer="监测", check=f"{name} 预算",
            severity=Severity.WARN,
            value=f"{value_ms:.1f}ms (超预算 {over:.0f}%)",
            threshold=f"<{budget_ms}ms",
            recommendation=f"{name} 超出预算 {over:.0f}%，关注优化空间"
        )
    # Over 50% — warn in monitoring layer; the source layer already flagged it
    return Finding(
        layer="监测", check=f"{name} 预算",
        severity=Severity.WARN,
        value=f"{value_ms:.1f}ms (超预算 {over:.0f}%)",
        threshold=f"<{budget_ms}ms",
        recommendation=f"{name} 严重超出预算。参见对应层的具体修复建议"
    )


def diagnose(target: str, layer_results: list = None) -> LayerDiagnosis:
    """Run Layer 5 monitoring diagnostics.

    Uses previous layer results to evaluate performance budgets
    and suggest monitoring setup.
    """
    diag = LayerDiagnosis(layer_name="监测层", layer_index=5, duration_ms=0)
    findings = []

    # Extract timings from previous layers if available
    dns_ms = 0.0
    tcp_ms = 0.0
    tls_ms = 0.0
    http_ms = 0.0

    if layer_results:
        for layer in layer_results:
            if hasattr(layer, "layer_name"):
                name = layer.layer_name.lower()
                dur = float(layer.duration_ms)
                if "dns" in name:
                    dns_ms = dur
                elif "tcp" in name:
                    tcp_ms = dur
                elif "http" in name:
                    http_ms = dur

    # Check 1: Performance budgets
    findings.append(_evaluate_budget("DNS 解析", dns_ms, BUDGET_DNS))
    findings.append(_evaluate_budget("TCP 握手", tcp_ms, BUDGET_TCP))
    findings.append(_evaluate_budget("HTTP 总响应", http_ms, BUDGET_TTFB))

    # Calculate total and evaluate total budget
    total_ms = dns_ms + tcp_ms + tls_ms + http_ms
    diag.duration_ms = round(total_ms, 1)

    findings.append(_evaluate_budget("页面加载总耗时", total_ms, BUDGET_TOTAL_PAGE))

    # Check 2: RUM recommendation
    findings.append(Finding(
        layer="监测", check="RUM 建议",
        severity=Severity.OK,
        value="建议实施",
        threshold="N/A",
        recommendation=(
            "推荐部署 RUM (Real User Monitoring): "
            "使用 Web Vitals API 采集 LCP/CLS/INP 指标。"
            "上报到 Grafana/Prometheus/Datadog 等可观测平台。"
            "按地区、设备、网络类型分段分析"
        )
    ))

    # Check 3: Synthetic monitoring
    findings.append(Finding(
        layer="监测", check="主动监测",
        severity=Severity.OK,
        value="建议配置",
        threshold="N/A",
        recommendation=(
            "从多个地理区域定期发起合成请求 (每 5-15 分钟)。"
            "记录各层耗时趋势，设置 P95/P99 告警阈值。"
            "触发条件: DNS > 200ms | TCP > 300ms | HTTP > 1000ms"
        )
    ))

    # Check 4: Alert thresholds
    findings.append(Finding(
        layer="监测", check="告警配置",
        severity=Severity.OK,
        value="建议阈值",
        threshold="N/A",
        recommendation=(
            "WARN: 任意层耗时超过预算 50%。"
            "CRITICAL: 任意层耗时超过预算 200% 或错误率 > 1%。"
            "告警通道: Slack/PagerDuty/邮件。"
            "监控指标: 连接成功率、TLS 错误率、超时率"
        )
    ))

    # Check 5: Long-term trend
    findings.append(Finding(
        layer="监测", check="趋势分析",
        severity=Severity.OK,
        value="建议定期",
        threshold="N/A",
        recommendation=(
            "每周审查各层 P50/P95/P99 趋势。"
            "对比不同地区的性能差异。"
            "在部署前后对比基线，防止性能回归"
        )
    ))

    # Check 6: Health score
    total_findings = len(findings)
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    warn = sum(1 for f in findings if f.severity == Severity.WARN)

    if critical == 0 and warn == 0:
        overall = Severity.OK
    elif critical == 0:
        overall = Severity.WARN
    else:
        overall = Severity.CRITICAL

    findings.append(Finding(
        layer="监测", check="整体评估",
        severity=overall,
        value=f"{'优秀' if overall == Severity.OK else '需关注' if overall == Severity.WARN else '需立即优化'}",
        threshold="N/A",
        recommendation=(
            "所有指标正常，持续监控即可"
            if overall == Severity.OK
            else f"共 {warn} 项警告, {critical} 项严重，请按优先级逐个优化"
        )
    ))

    diag.findings = findings
    return diag

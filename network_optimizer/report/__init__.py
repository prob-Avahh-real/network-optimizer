"""Report generation — formats diagnostic results into readable output."""

from datetime import datetime
from typing import TextIO
import sys

from ..core import NetworkProfile, Severity, Finding, LayerDiagnosis
from ..metrics import MetricsStore

# ANSI colors
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_ICON = {
    Severity.OK: f"{GREEN}✓{RESET}",
    Severity.WARN: f"{YELLOW}⚠{RESET}",
    Severity.CRITICAL: f"{RED}✗{RESET}",
}


def print_header(text: str, width: int = 70) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}\n")


def print_layer_header(layer: LayerDiagnosis) -> None:
    print(f"{BOLD}── Layer {layer.layer_index}: {layer.layer_name} ({layer.duration_ms:.1f}ms){RESET}")
    print(f"{DIM}{'─' * 60}{RESET}")


def print_finding(finding: Finding) -> None:
    icon = SEVERITY_ICON[finding.severity]
    sev_color = {"ok": GREEN, "warn": YELLOW, "critical": RED}
    color = sev_color[finding.severity.value]
    print(f"  {icon} {color}{finding.check}{RESET}: {finding.value}")
    if finding.recommendation:
        # Wrap long recommendations
        rec = finding.recommendation
        if len(rec) > 90:
            lines = []
            while rec:
                if len(rec) <= 90:
                    lines.append(rec)
                    break
                split_at = rec.rfind("。", 0, 90)
                if split_at < 0:
                    split_at = rec.rfind(".", 0, 90)
                if split_at < 0:
                    split_at = 89
                lines.append(rec[:split_at + 1].strip())
                rec = rec[split_at + 1:].strip()
            for i, line in enumerate(lines):
                prefix = "    ↳ " if i == 0 else "      "
                print(f"{DIM}{prefix}{line}{RESET}")
        else:
            print(f"    {DIM}↳ {rec}{RESET}")


def print_summary(profile: NetworkProfile, store: MetricsStore | None = None) -> None:
    """Print summary health report."""
    print_header(f"📊 诊断摘要 — {profile.target}")

    # Overall health
    score = profile.health_score
    if score >= 80:
        score_color = GREEN
        verdict = "网络健康"
    elif score >= 50:
        score_color = YELLOW
        verdict = "建议优化"
    else:
        score_color = RED
        verdict = "需要立即优化"

    print(f"  健康评分: {score_color}{score}/100{RESET} — {verdict}")
    print(f"  诊断时间: {datetime.fromtimestamp(profile.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  总耗时:   {profile.total_duration_ms:.1f}ms")
    print()

    # Layer breakdown
    print(f"  {BOLD}各层耗时分解:{RESET}")
    max_name = max(len(l.layer_name) for l in profile.layers)
    for layer in profile.layers:
        bar_len = max(1, int(layer.duration_ms / max(1, profile.total_duration_ms) * 30))
        bar = f"{'█' * bar_len}{'░' * (30 - bar_len)}"
        c_count = layer.critical_count
        w_count = layer.warn_count
        flags = f"  {RED}✗{c_count}{RESET}" if c_count > 0 else ""
        flags += f"  {YELLOW}⚠{w_count}{RESET}" if w_count > 0 else ""
        if not flags:
            flags = f"  {GREEN}✓{RESET}"
        print(f"  {layer.layer_name:<{max_name}}  {bar}  {layer.duration_ms:6.1f}ms{flags}")
    print()

    # Critical findings summary
    all_critical = []
    all_warn = []
    for layer in profile.layers:
        for f in layer.findings:
            if f.severity == Severity.CRITICAL:
                all_critical.append(f)
            elif f.severity == Severity.WARN:
                all_warn.append(f)

    if all_critical:
        print(f"  {RED}{BOLD}🚨 严重问题 ({len(all_critical)} 项):{RESET}")
        for f in all_critical:
            print(f"     [{f.layer}] {f.check}: {f.value}")
        print()

    if all_warn:
        print(f"  {YELLOW}{BOLD}⚠ 需关注 ({len(all_warn)} 项):{RESET}")
        for f in all_warn:
            print(f"     [{f.layer}] {f.check}: {f.value}")
        print()

    # Optimization priority
    print(f"  {BOLD}优化优先级建议:{RESET}")
    print(f"    1. 先解决所有严重问题 (✗)")
    print(f"    2. 再优化警告项 (⚠)")
    print(f"    3. 最后微调 OK 项中的建议")
    print()


def print_metrics(store: MetricsStore) -> None:
    """Print statistical metrics summary."""
    print_header("📈 性能统计 (多轮采样)")

    for metric in [store.dns, store.tcp, store.tls, store.ttfb, store.total]:
        if metric.count == 0:
            continue
        print(f"  {BOLD}{metric.name.upper()}{RESET} ({metric.count} 次采样):")
        print(f"    Avg: {metric.avg:.1f}{metric.unit}  "
              f"P50: {metric.p50:.1f}{metric.unit}  "
              f"P95: {metric.p95:.1f}{metric.unit}  "
              f"P99: {metric.p99:.1f}{metric.unit}  "
              f"Min: {metric.min:.1f}{metric.unit}  "
              f"Max: {metric.max:.1f}{metric.unit}")
        print()

    if store.error_count > 0:
        print(f"  {YELLOW}错误率: {store.error_count / max(1, store.total_samples) * 100:.1f}%{RESET}\n")


def print_findings_detail(profile: NetworkProfile) -> None:
    """Print full findings table."""
    print_header("🔍 详细诊断结果")

    for layer in profile.layers:
        print_layer_header(layer)
        for f in layer.findings:
            print_finding(f)
        print()


def generate_markdown_report(profile: NetworkProfile, store: MetricsStore | None = None) -> str:
    """Generate a markdown report that can be saved to file."""
    lines = []
    lines.append(f"# 🔍 网络延迟优化诊断报告")
    lines.append(f"")
    lines.append(f"**目标:** `{profile.target}`  ")
    lines.append(f"**时间:** {datetime.fromtimestamp(profile.timestamp).strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**健康评分:** {profile.health_score}/100  ")
    lines.append(f"**总耗时:** {profile.total_duration_ms:.1f}ms  ")
    lines.append(f"")

    # Layer breakdown table
    lines.append(f"## 各层耗时分解")
    lines.append(f"")
    lines.append(f"| 层级 | 耗时 | 严重 | 警告 | 正常 |")
    lines.append(f"|------|------|------|------|------|")
    for layer in profile.layers:
        ok = sum(1 for f in layer.findings if f.severity == Severity.OK)
        lines.append(
            f"| {layer.layer_name} | {layer.duration_ms:.1f}ms | "
            f"{layer.critical_count} | {layer.warn_count} | {ok} |"
        )
    lines.append(f"")

    # Detailed findings
    lines.append(f"## 详细诊断")
    lines.append(f"")
    for layer in profile.layers:
        lines.append(f"### Layer {layer.layer_index}: {layer.layer_name}")
        lines.append(f"")
        for f in layer.findings:
            icon = {"ok": "✅", "warn": "⚠️", "critical": "🚨"}[f.severity.value]
            lines.append(f"- {icon} **{f.check}**: {f.value}")
            if f.recommendation:
                lines.append(f"  > {f.recommendation}")
        lines.append(f"")

    # Optimization plan
    lines.append(f"## 优化行动计划")
    lines.append(f"")
    lines.append(f"1. **紧急**: 解决所有严重问题")
    lines.append(f"2. **重要**: 修复警告项")
    lines.append(f"3. **优化**: 按建议微调")
    lines.append(f"")

    # Metrics if available
    if store and store.total_samples > 0:
        lines.append(f"## 性能统计")
        lines.append(f"")
        lines.append(f"| 指标 | 采样数 | Avg | P50 | P95 | P99 | Min | Max |")
        lines.append(f"|------|--------|-----|-----|-----|-----|-----|-----|")
        for metric in [store.dns, store.tcp, store.tls, store.ttfb, store.total]:
            if metric.count == 0:
                continue
            lines.append(
                f"| {metric.name.upper()} | {metric.count} | "
                f"{metric.avg:.1f}{metric.unit} | {metric.p50:.1f}{metric.unit} | "
                f"{metric.p95:.1f}{metric.unit} | {metric.p99:.1f}{metric.unit} | "
                f"{metric.min:.1f}{metric.unit} | {metric.max:.1f}{metric.unit} |"
            )
        lines.append(f"")

    return "\n".join(lines)

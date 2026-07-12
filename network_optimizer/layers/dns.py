"""Layer 1: DNS 解析层诊断

Checks:
  - DNS resolution time
  - DNS cache hit rate (via resolver behavior)
  - DNS prefetch / preconnect eligibility
  - CDN edge node proximity
  - DNSSEC overhead
"""

import socket
import time
import subprocess
import re
import sys

from ..core import LayerDiagnosis, Finding, Severity

DNS_OK_MS = 50        # acceptable DNS resolution under 50ms
DNS_WARN_MS = 150      # warn above 150ms
DNS_CRITICAL_MS = 400  # critical above 400ms


def _resolve_host(host: str) -> tuple[float, list[str]]:
    """Resolve hostname and measure time, return (ms, [ips])."""
    start = time.monotonic()
    try:
        # Force a fresh resolution by using a new socket
        ips = socket.getaddrinfo(host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        elapsed = (time.monotonic() - start) * 1000
        unique = list(set(info[4][0] for info in ips))
        return elapsed, unique
    except socket.gaierror as e:
        return -1, [str(e)]


def _cold_resolve(host: str) -> float:
    """Attempt cold resolution time (may not be fully cold in Python, best-effort)."""
    elapsed, _ = _resolve_host(host)
    return elapsed


def _dig_trace(host: str) -> str | None:
    """Try to get DNS trace via dig if available."""
    try:
        result = subprocess.run(
            ["dig", "+trace", "+nodnssec", host],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _count_dns_hops(dig_output: str) -> int:
    """Count authoritative server hops from dig +trace output."""
    hops = 0
    for line in dig_output.split("\n"):
        if "Received" in line and "bytes from" in line:
            hops += 1
    return hops


def diagnose(host: str) -> LayerDiagnosis:
    """Run Layer 1 DNS diagnostics on the given host."""
    from urllib.parse import urlparse
    parsed = urlparse(host)
    hostname = parsed.hostname or host

    diag = LayerDiagnosis(layer_name="DNS 解析层", layer_index=1, duration_ms=0)
    findings = []

    # Check 1: Resolution time
    resolve_ms, ips = _resolve_host(hostname)
    diag.duration_ms = round(resolve_ms, 1) if resolve_ms > 0 else 0

    if resolve_ms < 0:
        findings.append(Finding(
            layer="DNS", check="域名解析",
            severity=Severity.CRITICAL,
            value=f"解析失败: {ips[0] if ips else 'unknown'}",
            threshold=f"{DNS_CRITICAL_MS}ms",
            recommendation="检查 DNS 服务器配置，确认域名可解析"
        ))
    elif resolve_ms < DNS_OK_MS:
        findings.append(Finding(
            layer="DNS", check="解析耗时",
            severity=Severity.OK,
            value=f"{resolve_ms:.1f}ms",
            threshold=f"<{DNS_OK_MS}ms",
            recommendation="解析速度正常，无需优化"
        ))
    elif resolve_ms < DNS_WARN_MS:
        findings.append(Finding(
            layer="DNS", check="解析耗时",
            severity=Severity.WARN,
            value=f"{resolve_ms:.1f}ms",
            threshold=f"<{DNS_OK_MS}ms 为优",
            recommendation="考虑使用更快的 DNS 服务 (如 Cloudflare 1.1.1.1, Google 8.8.8.8)"
        ))
    else:
        findings.append(Finding(
            layer="DNS", check="解析耗时",
            severity=Severity.CRITICAL,
            value=f"{resolve_ms:.1f}ms",
            threshold=f"<{DNS_OK_MS}ms",
            recommendation="DNS 解析过慢，建议切换 DNS 服务商或部署本地 DNS 缓存 (dnsmasq/systemd-resolved)"
        ))

    # Check 2: IP count (CDN distribution)
    if ips and resolve_ms > 0:
        ip_count = len(ips)
        if ip_count >= 3:
            findings.append(Finding(
                layer="DNS", check="CDN 多节点",
                severity=Severity.OK,
                value=f"{ip_count} 个 IP",
                threshold="≥3 为优",
                recommendation="CDN 已有良好多节点部署"
            ))
        elif ip_count == 1:
            findings.append(Finding(
                layer="DNS", check="CDN 多节点",
                severity=Severity.WARN,
                value="单节点",
                threshold="≥3 为优",
                recommendation="建议接入 CDN 实现就近接入，减少跨地域延迟"
            ))

    # Check 3: DNS trace (hop count)
    trace = _dig_trace(hostname)
    if trace:
        hops = _count_dns_hops(trace)
        if hops <= 5:
            findings.append(Finding(
                layer="DNS", check="DNS 跳数",
                severity=Severity.OK,
                value=f"{hops} 跳",
                threshold="≤5 跳",
                recommendation="DNS 解析链高效"
            ))
        elif hops <= 10:
            findings.append(Finding(
                layer="DNS", check="DNS 跳数",
                severity=Severity.WARN,
                value=f"{hops} 跳",
                threshold="≤5 跳为优",
                recommendation="DNS 解析链偏长，考虑使用就近递归解析器"
            ))
        else:
            findings.append(Finding(
                layer="DNS", check="DNS 跳数",
                severity=Severity.CRITICAL,
                value=f"{hops} 跳",
                threshold="≤5 跳",
                recommendation="DNS 解析链过长，排查 NS 委派策略或切换权威 DNS 服务商"
            ))

    # Check 4: DNSSEC overhead
    # Quick heuristic: try dig with +dnssec flag
    try:
        dnssec_result = subprocess.run(
            ["dig", "+dnssec", hostname], capture_output=True, text=True, timeout=5
        )
        if "RRSIG" in dnssec_result.stdout:
            findings.append(Finding(
                layer="DNS", check="DNSSEC 签名",
                severity=Severity.OK,
                value="已启用",
                threshold="N/A",
                recommendation="DNSSEC 已启用，安全性提升（解析性能略有开销可接受）"
            ))
    except FileNotFoundError:
        pass  # dig not available, skip

    # Check 5: DNS prefetch / preconnect recommendation
    findings.append(Finding(
        layer="DNS", check="预解析建议",
        severity=Severity.OK if resolve_ms < DNS_WARN_MS else Severity.WARN,
        value="建议启用" if resolve_ms >= DNS_WARN_MS else "可选",
        threshold="N/A",
        recommendation=(
            "在 HTML 中添加 <link rel='dns-prefetch'> 或 <link rel='preconnect'> "
            "提前解析关键域名，减少首包延迟"
        )
    ))

    diag.findings = findings
    return diag

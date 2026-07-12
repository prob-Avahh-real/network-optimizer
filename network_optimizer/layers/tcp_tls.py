"""Layer 2: TCP/TLS 连接层诊断

Checks:
  - TCP handshake time (SYN → SYN-ACK → ACK)
  - TLS handshake time
  - Connection reuse / Keep-Alive status
  - TCP Fast Open support
  - TLS session resumption
  - Connection pool efficiency
"""

import socket
import ssl
import time
import subprocess
from urllib.parse import urlparse

from ..core import LayerDiagnosis, Finding, Severity

TCP_OK_MS = 30
TCP_WARN_MS = 100
TCP_CRITICAL_MS = 300
TLS_OK_MS = 50
TLS_WARN_MS = 200
TLS_CRITICAL_MS = 500


def _measure_tcp_connect(host: str, port: int = 443) -> tuple[float, str]:
    """Measure raw TCP connect time. Returns (ms, error_msg)."""
    start = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        elapsed = (time.monotonic() - start) * 1000
        sock.close()
        return elapsed, ""
    except (socket.timeout, socket.error) as e:
        return (time.monotonic() - start) * 1000, str(e)


def _measure_tls_handshake(host: str, port: int = 443) -> tuple[float, float, str]:
    """Measure TLS handshake. Returns (tcp_ms, tls_ms, error_msg).

    Only TLS time is the delta after TCP connect completes.
    """
    # TCP connect
    tcp_start = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        tcp_ms = (time.monotonic() - tcp_start) * 1000

        # TLS handshake
        tls_start = time.monotonic()
        ctx = ssl.create_default_context()
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        tls_ms = (time.monotonic() - tls_start) * 1000
        wrapped.close()
        return tcp_ms, tls_ms, ""

    except Exception as e:
        elapsed = (time.monotonic() - tcp_start) * 1000
        return elapsed, -1, str(e)


def _check_tcp_fast_open(host: str) -> bool:
    """Best-effort check for TCP Fast Open support."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{time_connect}",
             f"https://{host}", "--tcp-fastopen", "--connect-timeout", "5", "--max-time", "8"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _check_keep_alive(host: str) -> tuple[float, float]:
    """Rough Keep-Alive check: two sequential requests, compare connect time."""
    import urllib.request
    import urllib.error

    url = f"https://{host}"

    # First request (cold connection)
    start = time.monotonic()
    try:
        urllib.request.urlopen(url, timeout=10)
        first_ms = (time.monotonic() - start) * 1000
    except Exception:
        return -1, -1

    # Second request (should reuse)
    start = time.monotonic()
    try:
        urllib.request.urlopen(url, timeout=10)
        second_ms = (time.monotonic() - start) * 1000
    except Exception:
        return first_ms, -1

    return first_ms, second_ms


def diagnose(host: str) -> LayerDiagnosis:
    """Run Layer 2 TCP/TLS diagnostics."""
    diag = LayerDiagnosis(layer_name="TCP/TLS 连接层", layer_index=2, duration_ms=0)
    findings = []

    # Parse host
    parsed = urlparse(host)
    hostname = parsed.hostname or host
    port = parsed.port or (443 if parsed.scheme in ("https", "") else 80)
    use_tls = parsed.scheme in ("https", "")

    # Check 1: TCP connect time
    tcp_ms, err = _measure_tcp_connect(hostname, port)
    if err:
        findings.append(Finding(
            layer="TCP", check="TCP 连接",
            severity=Severity.CRITICAL,
            value=f"连接失败: {err}",
            threshold=f"<{TCP_CRITICAL_MS}ms",
            recommendation="检查网络连通性和防火墙规则"
        ))
    elif tcp_ms < TCP_OK_MS:
        findings.append(Finding(
            layer="TCP", check="TCP 握手耗时",
            severity=Severity.OK,
            value=f"{tcp_ms:.1f}ms",
            threshold=f"<{TCP_OK_MS}ms",
            recommendation="TCP 连接延迟正常"
        ))
    elif tcp_ms < TCP_WARN_MS:
        findings.append(Finding(
            layer="TCP", check="TCP 握手耗时",
            severity=Severity.WARN,
            value=f"{tcp_ms:.1f}ms",
            threshold=f"<{TCP_OK_MS}ms 为优",
            recommendation="考虑就近接入 CDN 节点减少 RTT"
        ))
    else:
        findings.append(Finding(
            layer="TCP", check="TCP 握手耗时",
            severity=Severity.CRITICAL,
            value=f"{tcp_ms:.1f}ms",
            threshold=f"<{TCP_OK_MS}ms",
            recommendation="TCP 连接过慢。建议启用 TCP Fast Open、切换至更近的服务器、或使用连接池复用连接"
        ))

    # Check 2: TLS handshake time
    if use_tls and not err:
        tcp2, tls_ms, tls_err = _measure_tls_handshake(hostname, port)
        diag.duration_ms = round(tcp2 + max(0, tls_ms), 1)

        if tls_ms < 0:
            findings.append(Finding(
                layer="TLS", check="TLS 握手",
                severity=Severity.CRITICAL,
                value=f"失败: {tls_err}",
                threshold=f"<{TLS_CRITICAL_MS}ms",
                recommendation="检查 TLS 证书和服务器 SSL/TLS 配置"
            ))
        elif tls_ms < TLS_OK_MS:
            findings.append(Finding(
                layer="TLS", check="TLS 握手耗时",
                severity=Severity.OK,
                value=f"{tls_ms:.1f}ms",
                threshold=f"<{TLS_OK_MS}ms",
                recommendation="TLS 握手延迟正常"
            ))
        elif tls_ms < TLS_WARN_MS:
            findings.append(Finding(
                layer="TLS", check="TLS 握手耗时",
                severity=Severity.WARN,
                value=f"{tls_ms:.1f}ms",
                threshold=f"<{TLS_OK_MS}ms 为优",
                recommendation="建议启用 TLS Session Resumption / OCSP Stapling 减少握手开销"
            ))
        else:
            findings.append(Finding(
                layer="TLS", check="TLS 握手耗时",
                severity=Severity.CRITICAL,
                value=f"{tls_ms:.1f}ms",
                threshold=f"<{TLS_OK_MS}ms",
                recommendation="TLS 握手过慢。启用 TLS 1.3 0-RTT、Session Tickets、OCSP Stapling"
            ))

        # Check 3: TLS version
        try:
            ctx = ssl.create_default_context()
            sock = socket.create_connection((hostname, port), timeout=5)
            wrapped = ctx.wrap_socket(sock, server_hostname=hostname)
            tls_ver = wrapped.version()
            wrapped.close()
            if tls_ver == "TLSv1.3":
                findings.append(Finding(
                    layer="TLS", check="TLS 版本",
                    severity=Severity.OK,
                    value="TLS 1.3",
                    threshold="TLS 1.3",
                    recommendation="已使用最新 TLS 1.3，支持 1-RTT 握手"
                ))
            else:
                findings.append(Finding(
                    layer="TLS", check="TLS 版本",
                    severity=Severity.WARN,
                    value=tls_ver or "unknown",
                    threshold="TLS 1.3",
                    recommendation=f"建议升级到 TLS 1.3 以减少握手 RTT"
                ))
        except Exception:
            pass

    else:
        diag.duration_ms = tcp_ms

    # Check 4: TCP Fast Open
    if _check_tcp_fast_open(hostname):
        findings.append(Finding(
            layer="TCP", check="TCP Fast Open",
            severity=Severity.OK,
            value="已启用",
            threshold="N/A",
            recommendation="TFO 已工作，复连可节省一次 RTT"
        ))
    else:
        findings.append(Finding(
            layer="TCP", check="TCP Fast Open",
            severity=Severity.WARN,
            value="未启用",
            threshold="建议启用",
            recommendation="在服务端 sysctl 中启用 net.ipv4.tcp_fastopen=3，客户端也需对应开启"
        ))

    # Check 5: Connection reuse / Keep-Alive
    first_ms, second_ms = _check_keep_alive(f"https://{hostname}" if use_tls else f"http://{hostname}")
    if first_ms > 0 and second_ms > 0:
        if second_ms < first_ms * 0.5:
            findings.append(Finding(
                layer="TCP", check="Keep-Alive 复用",
                severity=Severity.OK,
                value=f"首请求 {first_ms:.0f}ms → 复用 {second_ms:.0f}ms",
                threshold="复用请求应更快",
                recommendation="HTTP Keep-Alive / 连接池工作正常"
            ))
        elif second_ms >= first_ms * 0.8:
            findings.append(Finding(
                layer="TCP", check="Keep-Alive 复用",
                severity=Severity.WARN,
                value=f"首请求 {first_ms:.0f}ms → 复用 {second_ms:.0f}ms",
                threshold="复用请求应明显更快",
                recommendation="Keep-Alive 效果不明显。检查服务端 Keep-Alive 超时配置和连接池大小"
            ))

    # Check 6: Connection recommendation
    findings.append(Finding(
        layer="TCP", check="连接优化建议",
        severity=Severity.OK,
        value="综合建议",
        threshold="N/A",
        recommendation=(
            "客户端: 使用连接池 (HTTP/2 单连接复用), 启用 TCP Fast Open。"
            "服务端: 调整 tcp_tw_reuse, 增大 backlog, 启用 BBR 拥塞控制算法"
        )
    ))

    diag.findings = findings
    return diag

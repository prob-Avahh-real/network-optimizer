"""Layer 3: HTTP/传输层诊断

Checks:
  - HTTP version (1.1 vs 2 vs 3)
  - Compression (Content-Encoding / Brotli)
  - Cache headers (Cache-Control, ETag, Last-Modified)
  - Request batching / multiplexing
  - Redirect chains
  - Response size
"""

import time
import urllib.request
import urllib.error
import ssl
from urllib.parse import urlparse
import http.client
import json

from ..core import LayerDiagnosis, Finding, Severity


def _http_request(url: str, method: str = "GET", headers: dict | None = None) -> tuple[float, int, dict, str]:
    """Perform HTTP request, return (ms, status_code, headers_dict, body_text)."""
    start = time.monotonic()
    headers = headers or {}
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            elapsed = (time.monotonic() - start) * 1000
            body = resp.read().decode("utf-8", errors="replace")
            return elapsed, resp.status, dict(resp.headers), body[:5000]
    except urllib.error.HTTPError as e:
        return (time.monotonic() - start) * 1000, e.code, dict(e.headers), str(e)
    except Exception as e:
        return (time.monotonic() - start) * 1000, 0, {}, str(e)


def _check_compression(headers: dict, body: str) -> tuple[str, str]:
    """Check compression encoding from response headers."""
    encoding = headers.get("Content-Encoding", headers.get("content-encoding", "none"))
    return encoding.lower(), ""


def _check_cache(headers: dict) -> list[Finding]:
    """Analyze cache headers and return findings."""
    results = []
    cache_control = headers.get("Cache-Control", headers.get("cache-control", ""))
    etag = headers.get("ETag", headers.get("etag", ""))
    last_mod = headers.get("Last-Modified", headers.get("last-modified", ""))
    expires = headers.get("Expires", headers.get("expires", ""))

    if cache_control:
        if "max-age=" in cache_control or "s-maxage=" in cache_control:
            results.append(Finding(
                layer="HTTP", check="缓存策略",
                severity=Severity.OK,
                value=cache_control[:60],
                threshold="显式 max-age 更优",
                recommendation="Cache-Control 已设置，缓存策略明确"
            ))
        elif "no-cache" in cache_control or "no-store" in cache_control:
            results.append(Finding(
                layer="HTTP", check="缓存策略",
                severity=Severity.WARN,
                value=cache_control[:60],
                threshold="应设置合理的 max-age",
                recommendation="静态资源不应使用 no-store，建议设置合理的 max-age 并配合版本化 URL"
            ))
    else:
        results.append(Finding(
            layer="HTTP", check="缓存策略",
            severity=Severity.WARN,
            value="未设置 Cache-Control",
            threshold="应至少设置 max-age",
            recommendation="所有静态资源应设置 Cache-Control header，推荐 max-age=31536000 (1年) 配合版本化 URL"
        ))

    if etag or last_mod:
        results.append(Finding(
            layer="HTTP", check="条件请求",
            severity=Severity.OK,
            value=f"ETag: {'✓' if etag else '✗'}, Last-Modified: {'✓' if last_mod else '✗'}",
            threshold="至少 ETag",
            recommendation="条件请求已支持，可避免不必要的完整响应传输"
        ))
    else:
        results.append(Finding(
            layer="HTTP", check="条件请求",
            severity=Severity.WARN,
            value="ETag & Last-Modified 均缺失",
            threshold="至少 ETag",
            recommendation="建议服务端返回 ETag 或 Last-Modified，减少不必要的数据传输"
        ))

    return results


def diagnose(host: str) -> LayerDiagnosis:
    """Run Layer 3 HTTP/传输层 diagnostics."""
    parsed = urlparse(host)
    url = host if "://" in host else f"https://{host}"
    hostname = parsed.hostname or host

    diag = LayerDiagnosis(layer_name="HTTP/传输层", layer_index=3, duration_ms=0)
    findings = []

    # Check 0: Redirect chain
    chain_count = 0
    current_url = url
    max_redirects = 5
    while max_redirects > 0:
        elapsed, status, headers, body = _http_request(current_url, method="HEAD")
        max_redirects -= 1
        if status in (301, 302, 303, 307, 308):
            chain_count += 1
            loc = headers.get("Location", headers.get("location", ""))
            if loc:
                current_url = loc
                continue
        break

    if chain_count == 0:
        findings.append(Finding(
            layer="HTTP", check="重定向链",
            severity=Severity.OK,
            value="无重定向",
            threshold="0 次",
            recommendation="无多余重定向，请求直达"
        ))
    elif chain_count <= 2:
        findings.append(Finding(
            layer="HTTP", check="重定向链",
            severity=Severity.WARN,
            value=f"{chain_count} 次重定向",
            threshold="≤1 次",
            recommendation="减少 HTTP → HTTPS 跳转等必要重定向，客户端直接使用 HTTPS URL"
        ))
    else:
        findings.append(Finding(
            layer="HTTP", check="重定向链",
            severity=Severity.CRITICAL,
            value=f"{chain_count} 次重定向",
            threshold="≤1 次",
            recommendation="重定向链过长，每次重定向增加一次 RTT，建议简化或使用最终的 canonical URL"
        ))

    # Check 1: Full response timing
    elapsed_ms, status, headers, body = _http_request(current_url)
    diag.duration_ms = round(elapsed_ms, 1)

    if elapsed_ms < 200:
        findings.append(Finding(
            layer="HTTP", check="总响应时间",
            severity=Severity.OK,
            value=f"{elapsed_ms:.0f}ms",
            threshold="<200ms",
            recommendation="HTTP 响应时间正常"
        ))
    elif elapsed_ms < 800:
        findings.append(Finding(
            layer="HTTP", check="总响应时间",
            severity=Severity.WARN,
            value=f"{elapsed_ms:.0f}ms",
            threshold="<200ms 为优",
            recommendation="建议启用 Gzip/Brotli 压缩、CDN 缓存、HTTP/2 多路复用"
        ))
    else:
        findings.append(Finding(
            layer="HTTP", check="总响应时间",
            severity=Severity.CRITICAL,
            value=f"{elapsed_ms:.0f}ms",
            threshold="<200ms",
            recommendation="响应过慢。综合优化：启用 HTTP/2, 压缩, CDN, 减少响应体大小"
        ))

    # Check 2: HTTP version
    try:
        http_ver_url = current_url if "://" in current_url else f"https://{current_url}"
        parsed_req = urlparse(http_ver_url)
        hname = parsed_req.hostname or current_url
        hport = parsed_req.port or 443
        ctx_c = ssl.create_default_context()
        raw_sock = __import__("socket").create_connection((hname, hport), timeout=5)
        wrapped = ctx_c.wrap_socket(raw_sock, server_hostname=hname)
        conn = http.client.HTTPSConnection(hname, hport, timeout=5)
        conn.sock = wrapped
        conn.request("HEAD", parsed_req.path or "/")
        resp = conn.getresponse()
        ver_num = resp.version  # http.client: 10=HTTP/1.0, 11=HTTP/1.1, 20=HTTP/2
        # Format version for display
        if ver_num == 20:
            http_ver_str = "HTTP/2"
        elif ver_num == 11:
            http_ver_str = "HTTP/1.1"
        elif ver_num == 10:
            http_ver_str = "HTTP/1.0"
        else:
            http_ver_str = f"HTTP/{ver_num}"
        conn.close()

        if ver_num >= 20:
            findings.append(Finding(
                layer="HTTP", check="HTTP 版本",
                severity=Severity.OK,
                value=http_ver_str,
                threshold="HTTP/2+",
                recommendation="HTTP/2 多路复用已启用，减少队头阻塞"
            ))
        elif ver_num == 11:
            findings.append(Finding(
                layer="HTTP", check="HTTP 版本",
                severity=Severity.OK,
                value="HTTP/1.1",
                threshold="HTTP/2+",
                recommendation="HTTP/1.1 可用，建议升级到 HTTP/2 支持多路复用和头部压缩"
            ))
        else:
            findings.append(Finding(
                layer="HTTP", check="HTTP 版本",
                severity=Severity.WARN,
                value=http_ver_str,
                threshold="HTTP/2+",
                recommendation="建议启用 HTTP/2 或 HTTP/3，支持多路复用和头部压缩"
            ))
    except Exception as exc:
        findings.append(Finding(
            layer="HTTP", check="HTTP 版本检测",
            severity=Severity.WARN,
            value=f"检测失败: {exc}",
            threshold="HTTP/2+",
            recommendation="确保服务端和反向代理 (Nginx/Cloudflare) 已启用 HTTP/2"
        ))

    # Check 3: Compression
    if headers:
        encoding, _ = _check_compression(headers, body)
        if encoding in ("gzip", "br", "deflate", "zstd"):
            findings.append(Finding(
                layer="HTTP", check="内容压缩",
                severity=Severity.OK,
                value=encoding.upper(),
                threshold="gzip/br/zstd",
                recommendation=f"已启用 {encoding.upper()} 压缩，传输体积已优化"
            ))
        elif encoding == "none":
            findings.append(Finding(
                layer="HTTP", check="内容压缩",
                severity=Severity.WARN,
                value="未压缩",
                threshold="gzip/br/zstd",
                recommendation="在 Nginx/CDN 中启用 gzip 或 brotli 压缩，可减少 60-80% 传输体积"
            ))
    else:
        findings.append(Finding(
            layer="HTTP", check="内容压缩",
            severity=Severity.WARN,
            value="无法检测",
            threshold="gzip/br/zstd",
            recommendation="建议启用 Gzip 或 Brotli 压缩"
        ))

    # Check 4: Cache headers
    if headers:
        findings.extend(_check_cache(headers))

    # Check 5: Response body size
    if body:
        body_size = len(body.encode("utf-8"))
        if body_size < 50000:
            findings.append(Finding(
                layer="HTTP", check="响应体积",
                severity=Severity.OK,
                value=f"{body_size / 1024:.1f} KB",
                threshold="<50KB",
                recommendation="响应体积合理"
            ))
        elif body_size < 200000:
            findings.append(Finding(
                layer="HTTP", check="响应体积",
                severity=Severity.WARN,
                value=f"{body_size / 1024:.1f} KB",
                threshold="<50KB 为优",
                recommendation="考虑分页、懒加载、或 GraphQL 精确查询减少响应体积"
            ))
        else:
            findings.append(Finding(
                layer="HTTP", check="响应体积",
                severity=Severity.CRITICAL,
                value=f"{body_size / 1024:.1f} KB",
                threshold="<50KB",
                recommendation="响应体积过大。实施分页、字段裁剪、增量加载或 SSR 分块传输"
            ))

    # Check 6: Request merging
    findings.append(Finding(
        layer="HTTP", check="请求合并",
        severity=Severity.OK,
        value="建议启用",
        threshold="N/A",
        recommendation=(
            "前端: 使用 HTTP/2 多路复用减少连接数。"
            "API: 实施 BFF (Backend for Frontend) 或 GraphQL 减少多次请求。"
            "关键资源: 使用 Resource Hints (prefetch, preload)"
        )
    ))

    diag.findings = findings
    return diag

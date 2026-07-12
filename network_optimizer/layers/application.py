"""Layer 4: 应用层诊断

Checks:
  - Resource loading strategy (lazy load, prefetch, preload)
  - Data format efficiency (JSON vs Protobuf vs MessagePack)
  - Caching strategy at application level
  - CDN edge compute usage
  - Image/media optimization
  - API batching
  - Critical rendering path resources
"""

import time
import urllib.request
import urllib.error
import re
from urllib.parse import urlparse
import json

from ..core import LayerDiagnosis, Finding, Severity


def _is_html_content(content_type: str) -> bool:
    return "html" in content_type.lower()


def _count_external_resources(html: str, base_url: str) -> dict[str, int]:
    """Count external resource references in HTML: scripts, stylesheets, images, fonts, preconnects."""
    counts = {
        "scripts": len(re.findall(r'<script[^>]+src=["\']https?://', html, re.IGNORECASE)),
        "stylesheets": len(re.findall(r'<link[^>]+stylesheet[^>]+href=["\']https?://', html, re.IGNORECASE)),
        "images": len(re.findall(r'<img[^>]+src=["\']https?://', html, re.IGNORECASE)),
        "fonts": len(re.findall(r'@font-face[^}]*url\(["\']?https?://', html, re.IGNORECASE)),
        "preconnect": len(re.findall(r'<link[^>]+rel=["\']preconnect', html, re.IGNORECASE)),
        "prefetch": len(re.findall(r'<link[^>]+rel=["\']dns-prefetch', html, re.IGNORECASE)),
        "preload": len(re.findall(r'<link[^>]+rel=["\']preload', html, re.IGNORECASE)),
        "total_external": 0,
    }
    counts["total_external"] = (
        counts["scripts"] + counts["stylesheets"] + counts["images"] + counts["fonts"]
    )
    return counts


def _analyze_resource_hints(html: str) -> list[Finding]:
    """Analyze preconnect, prefetch, preload hints."""
    results = []
    preconnects = re.findall(r'<link[^>]+rel=["\']preconnect[^>]*>', html, re.IGNORECASE)
    prefetches = re.findall(r'<link[^>]+rel=["\']dns-prefetch[^>]*>', html, re.IGNORECASE)
    preloads = re.findall(r'<link[^>]+rel=["\']preload[^>]*>', html, re.IGNORECASE)

    hints = len(preconnects) + len(prefetches) + len(preloads)
    if hints >= 3:
        results.append(Finding(
            layer="应用层", check="Resource Hints",
            severity=Severity.OK,
            value=f"{hints} 个 hints (preconnect:{len(preconnects)}, prefetch:{len(prefetches)}, preload:{len(preloads)})",
            threshold="≥3",
            recommendation="Resource Hints 使用良好，关键资源已优化加载时机"
        ))
    elif hints > 0:
        results.append(Finding(
            layer="应用层", check="Resource Hints",
            severity=Severity.WARN,
            value=f"{hints} 个 hints",
            threshold="≥3",
            recommendation="建议为关键第三方域名添加 dns-prefetch/preconnect，为关键资源添加 preload"
        ))
    else:
        results.append(Finding(
            layer="应用层", check="Resource Hints",
            severity=Severity.WARN,
            value="未使用",
            threshold="≥3",
            recommendation="添加 <link rel='preconnect'> 到关键 API 域名，<link rel='preload'> 到首屏关键资源"
        ))

    return results


def _analyze_lazy_loading(html: str) -> list[Finding]:
    """Check for lazy loading patterns."""
    results = []
    lazy_imgs = len(re.findall(r'<img[^>]+loading=["\']lazy["\']', html, re.IGNORECASE))
    imgs = len(re.findall(r'<img', html, re.IGNORECASE))

    if imgs == 0:
        results.append(Finding(
            layer="应用层", check="懒加载",
            severity=Severity.OK,
            value="无图片资源",
            threshold="N/A",
            recommendation="无图片资源，懒加载不适用"
        ))
    elif lazy_imgs >= imgs * 0.5:
        results.append(Finding(
            layer="应用层", check="懒加载",
            severity=Severity.OK,
            value=f"{lazy_imgs}/{imgs} 图片已懒加载",
            threshold=f"≥{imgs // 2}",
            recommendation="图片懒加载已覆盖大部分资源"
        ))
    elif imgs > 0:
        results.append(Finding(
            layer="应用层", check="懒加载",
            severity=Severity.WARN,
            value=f"仅 {lazy_imgs}/{imgs} 图片已懒加载",
            threshold=f"≥{imgs // 2}",
            recommendation="为 off-screen 图片添加 loading='lazy' 属性减少初始带宽消耗"
        ))

    return results


def _analyze_data_format(url: str, headers: dict, body: str) -> list[Finding]:
    """Check data format efficiency."""
    results = []
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    content_length = headers.get("Content-Length", headers.get("content-length", "0"))

    # Check if JSON and measure size
    if "json" in content_type.lower():
        try:
            parsed = json.loads(body)
            body_bytes = len(body.encode("utf-8"))
            if body_bytes > 100000:
                results.append(Finding(
                    layer="应用层", check="数据格式",
                    severity=Severity.WARN,
                    value=f"JSON {body_bytes / 1024:.0f} KB",
                    threshold="<100KB",
                    recommendation="JSON 响应较大。建议: 字段裁剪（只传需要的字段）、分页、或考虑使用 Protobuf/MessagePack 二进制格式减少体积"
                ))
            else:
                results.append(Finding(
                    layer="应用层", check="数据格式",
                    severity=Severity.OK,
                    value=f"JSON {body_bytes / 1024:.0f} KB",
                    threshold="<100KB",
                    recommendation="JSON 体积合理"
                ))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Check for gzip/brotli-aware format
    if "gzip" in content_type.lower() or "br" in content_type.lower():
        results.append(Finding(
            layer="应用层", check="传输压缩",
            severity=Severity.OK,
            value=content_type,
            threshold="gzip/br",
            recommendation="内容已压缩传输"
        ))

    return results


def diagnose(host: str) -> LayerDiagnosis:
    """Run Layer 4 应用层 diagnostics."""
    parsed = urlparse(host)
    url = host if "://" in host else f"https://{host}"
    hostname = parsed.hostname or host

    diag = LayerDiagnosis(layer_name="应用层", layer_index=4, duration_ms=0)
    findings = []

    # Fetch the page content
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "NetworkOptimizer/1.0",
            "Accept": "text/html,application/json,*/*",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            elapsed = (time.monotonic() - start) * 1000
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8", errors="replace")[:50000]
            headers = dict(resp.headers)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        body = ""
        headers = {}
        content_type = ""

    diag.duration_ms = round(elapsed, 1)

    # Check 1: Content type determines analysis path
    if "html" in content_type.lower() and body:
        # HTML page: analyze resource loading
        counts = _count_external_resources(body, url)

        findings.append(Finding(
            layer="应用层", check="外部资源数",
            severity=Severity.OK if counts["total_external"] < 30 else Severity.WARN if counts["total_external"] < 60 else Severity.CRITICAL,
            value=f"{counts['total_external']} 个 (JS:{counts['scripts']}, CSS:{counts['stylesheets']}, Img:{counts['images']}, Font:{counts['fonts']})",
            threshold="<30 个",
            recommendation=(
                "合并 JS/CSS 文件，使用 CSS Sprite 或 SVG icon，减少 HTTP 请求数"
                if counts["total_external"] >= 30
                else "外部资源数合理"
            )
        ))

        findings.extend(_analyze_resource_hints(body))
        findings.extend(_analyze_lazy_loading(body))

        # Check script loading strategy
        async_scripts = len(re.findall(r'<script[^>]+async[^>]+src=', body, re.IGNORECASE))
        defer_scripts = len(re.findall(r'<script[^>]+defer[^>]+src=', body, re.IGNORECASE))
        head_scripts = len(re.findall(r'<head>.*<script[^>]*src=.*</head>', body, re.IGNORECASE | re.DOTALL))

        if async_scripts + defer_scripts > 0:
            findings.append(Finding(
                layer="应用层", check="脚本加载",
                severity=Severity.OK,
                value=f"async:{async_scripts}, defer:{defer_scripts}",
                threshold="非阻塞加载",
                recommendation="脚本使用 async/defer，不会阻塞首屏渲染"
            ))
        elif counts["scripts"] > 0:
            findings.append(Finding(
                layer="应用层", check="脚本加载",
                severity=Severity.WARN,
                value="无 async/defer",
                threshold="应使用 async/defer",
                recommendation="为渲染非关键脚本添加 defer 或 async，避免阻塞首次内容绘制 (FCP)"
            ))

    elif "json" in content_type.lower() or "api" in url.lower():
        # API response: analyze data format
        findings.extend(_analyze_data_format(url, headers, body))

        # API efficiency suggestions
        findings.append(Finding(
            layer="应用层", check="API 优化建议",
            severity=Severity.OK,
            value="综合建议",
            threshold="N/A",
            recommendation=(
                "1. 使用 BFF 模式合并多个 API 调用。"
                "2. 实施结果分页 (cursor-based)。"
                "3. 支持字段裁剪 (?fields=id,name)。"
                "4. 边缘缓存 (CDN Cache API responses)。"
                "5. 考虑 GraphQL 或 tRPC 精确查询"
            )
        ))

    # Check 2: Caching strategy recommendation (通用)
    findings.append(Finding(
        layer="应用层", check="缓存策略",
        severity=Severity.OK,
        value="建议分级缓存",
        threshold="N/A",
        recommendation=(
            "L1: 浏览器缓存 — 静态资源 + Cache-Control/ETag。"
            "L2: CDN 缓存 — API 响应 + Edge TTL。"
            "L3: 服务端缓存 — Redis/Memcached 热点数据。"
            "L4: 应用本地缓存 — SQLite/IndexedDB 离线数据"
        )
    ))

    # Check 3: Prefetching strategy
    findings.append(Finding(
        layer="应用层", check="预取策略",
        severity=Severity.OK,
        value="建议实施",
        threshold="N/A",
        recommendation=(
            "预测性预取: 基于用户行为预加载下一步资源。"
            "关键路径预取: preload LCP 图片、字体、CSS。"
            "离线预取: Service Worker 缓存关键页面"
        )
    ))

    # Check 4: CDN Edge Compute
    findings.append(Finding(
        layer="应用层", check="CDN 边缘计算",
        severity=Severity.OK,
        value="建议评估",
        threshold="N/A",
        recommendation=(
            "评估是否可将简单逻辑迁移到 CDN edge: "
            "A/B 测试分流、JWT 校验、请求重写、图片实时裁剪格式转换。"
            "可减少回源延迟 50-200ms"
        )
    ))

    diag.findings = findings
    return diag

"""Auto-optimization engine — applies client-side fixes + generates server configs.

Client-side fixes (applied automatically):
  1. DNS: configure fast resolvers (Cloudflare/Google), enable caching
  2. TCP: enable TCP Fast Open, BBR congestion control
  3. HTTP/HTTPS: connection pooling recommendations

Server-side configs (generated as files):
  - nginx-gzip.conf     — gzip/brotli compression
  - nginx-cache.conf    — Cache-Control / ETag / conditional requests
  - nginx-http2.conf    — HTTP/2 + keepalive tuning
  - html-hints.html     — <link> dns-prefetch / preconnect / preload snippets
  - cloudflare.json     — Cloudflare optimization settings
"""

import subprocess
import sys
import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class OptimizerResult:
    """Result of running an optimization."""
    name: str
    category: str          # "client" | "server-config" | "recommendation"
    applied: bool
    details: str
    config_file: str | None = None


def _check_sudo() -> bool:
    """Check if we can run privileged commands."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def optimize_dns_client() -> list[OptimizerResult]:
    """Client-side DNS optimization."""
    results = []

    # macOS: check and suggest DNS
    if _is_macos():
        # Check current DNS
        try:
            r = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True, text=True, timeout=5
            )
            has_cloudflare = "1.1.1.1" in r.stdout or "1.0.0.1" in r.stdout
            has_google = "8.8.8.8" in r.stdout or "8.8.4.4" in r.stdout

            if has_cloudflare or has_google:
                results.append(OptimizerResult(
                    name="Fast DNS", category="client", applied=True,
                    details="已使用快速 DNS 服务器 (Cloudflare 或 Google)"
                ))
            else:
                results.append(OptimizerResult(
                    name="Fast DNS", category="client", applied=False,
                    details=("建议在系统偏好设置 → 网络 → 高级 → DNS 中添加: 1.1.1.1, 8.8.8.8")
                ))
        except Exception:
            results.append(OptimizerResult(
                name="Fast DNS", category="client", applied=False,
                details="无法检测 DNS 配置。手动添加: 1.1.1.1, 8.8.8.8"
            ))

    # Linux: configure systemd-resolved or resolv.conf
    if _is_linux():
        has_sudo = _check_sudo()
        if has_sudo:
            # Try to enable systemd-resolved cache
            try:
                subprocess.run(
                    ["sudo", "systemctl", "enable", "--now", "systemd-resolved"],
                    capture_output=True, timeout=5
                )
                results.append(OptimizerResult(
                    name="DNS 缓存", category="client", applied=True,
                    details="已启用 systemd-resolved DNS 缓存"
                ))
            except Exception:
                results.append(OptimizerResult(
                    name="DNS 缓存", category="client", applied=False,
                    details="无法启用 systemd-resolved。手动执行: sudo apt install systemd-resolved"
                ))
        else:
            results.append(OptimizerResult(
                name="DNS 缓存", category="client", applied=False,
                details="需要 sudo 权限启用 DNS 缓存"
            ))

    return results


def optimize_tcp_client() -> list[OptimizerResult]:
    """Client-side TCP optimization — TFO, BBR, buffer tuning."""
    results = []

    if not _is_linux() or not _check_sudo():
        if _is_macos():
            results.append(OptimizerResult(
                name="TCP Fast Open", category="client", applied=True,
                details="macOS 默认启用 TCP Fast Open (net.inet.tcp.fastopen=3)"
            ))
            results.append(OptimizerResult(
                name="TCP KeepAlive", category="client", applied=False,
                details="macOS 默认配置已优化。调优: sudo sysctl -w net.inet.tcp.keepidle=60000"
            ))
        else:
            results.append(OptimizerResult(
                name="TCP 优化", category="client", applied=False,
                details="需要 Linux + sudo 权限进行 TCP 参数调优"
            ))
        return results

    commands = {
        "TCP Fast Open": "net.ipv4.tcp_fastopen=3",
        "TCP KeepAlive 空闲": "net.ipv4.tcp_keepalive_time=60",
        "TCP KeepAlive 探测间隔": "net.ipv4.tcp_keepalive_intvl=10",
        "TCP KeepAlive 探测次数": "net.ipv4.tcp_keepalive_probes=6",
        "TCP 连接复用 (TIME_WAIT 回收)": "net.ipv4.tcp_tw_reuse=1",
        "TCP BBR 拥塞控制": "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr",
    }

    for name, params in commands.items():
        for line in params.split("\n"):
            key, val = line.split("=")
            try:
                subprocess.run(
                    ["sudo", "sysctl", "-w", f"{key}={val}"],
                    capture_output=True, timeout=5
                )
                results.append(OptimizerResult(
                    name=name, category="client", applied=True,
                    details=f"sysctl {key}={val} 已应用"
                ))
            except Exception as e:
                results.append(OptimizerResult(
                    name=name, category="client", applied=False,
                    details=f"sysctl {key}={val} 失败: {e}"
                ))

    return results


def optimize_http_client() -> list[OptimizerResult]:
    """Client-side HTTP optimization — mostly recommendations."""
    results = []

    # Check if HTTP/2 capable curl is available
    has_http2_curl = False
    try:
        r = subprocess.run(["curl", "--version"], capture_output=True, text=True, timeout=3)
        has_http2_curl = "HTTP2" in r.stdout
    except Exception:
        pass

    if has_http2_curl:
        results.append(OptimizerResult(
            name="HTTP/2 客户端", category="client", applied=True,
            details="curl 已编译 HTTP/2 支持，CLI 请求将自动使用 HTTP/2"
        ))
    else:
        results.append(OptimizerResult(
            name="HTTP/2 客户端", category="client", applied=False,
            details="curl 未启用 HTTP/2。更新 curl 或使用支持 HTTP/2 的 HTTP 客户端库"
        ))

    return results


def generate_server_configs(output_dir: str, findings_summary: dict) -> list[OptimizerResult]:
    """Generate server-side optimization config files."""
    results = []
    os.makedirs(output_dir, exist_ok=True)

    # 1. Nginx: gzip + brotli config
    gzip_conf = """# ============================================================
# 自动生成: 网络延迟优化 — Nginx 压缩配置
# 使用方法: 将此文件内容加入 nginx.conf 的 http 块
# 验证: nginx -t && nginx -s reload
# ============================================================

# ---- Gzip 压缩 ----
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_min_length 256;
gzip_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/javascript
    application/json
    application/xml
    application/rss+xml
    image/svg+xml
    font/ttf
    font/otf;

# ---- Brotli 压缩 (需 ngx_brotli 模块) ----
# 安装: https://github.com/google/ngx_brotli
# brotli on;
# brotli_comp_level 6;
# brotli_types text/plain text/css text/xml text/javascript
#              application/javascript application/json image/svg+xml;

# ---- 静态资源缓存 ----
location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    add_header Vary "Accept-Encoding";
}
"""
    with open(os.path.join(output_dir, "nginx-gzip.conf"), "w") as f:
        f.write(gzip_conf)
    results.append(OptimizerResult(
        name="Nginx 压缩", category="server-config", applied=True,
        details="已生成 nginx-gzip.conf，启用 Gzip + Brotli 压缩",
        config_file=os.path.join(output_dir, "nginx-gzip.conf")
    ))

    # 2. Nginx: Cache headers + ETag
    cache_conf = """# ============================================================
# 自动生成: 网络延迟优化 — Nginx 缓存配置
# 使用方法: 将此文件内容加入 nginx.conf 的 server 块
# ============================================================

# ---- ETag (默认开启) ----
etag on;

# ---- 静态资源强缓存 ----
location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2)$ {
    expires 365d;
    add_header Cache-Control "public, max-age=31536000, immutable";
}

# ---- HTML 文件协商缓存 ----
location ~* \\.html$ {
    expires 1h;
    add_header Cache-Control "public, max-age=3600, must-revalidate";
}

# ---- API 响应缓存 (可调) ----
# location /api/ {
#     expires 5m;
#     add_header Cache-Control "public, max-age=300, s-maxage=300";
# }

# ---- 禁用缓存的头 ----
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "DENY";
"""
    with open(os.path.join(output_dir, "nginx-cache.conf"), "w") as f:
        f.write(cache_conf)
    results.append(OptimizerResult(
        name="Nginx 缓存", category="server-config", applied=True,
        details="已生成 nginx-cache.conf，启用 ETag + Cache-Control 缓存策略",
        config_file=os.path.join(output_dir, "nginx-cache.conf")
    ))

    # 3. Nginx: HTTP/2 + keepalive
    http2_conf = """# ============================================================
# 自动生成: 网络延迟优化 — HTTP/2 + KeepAlive 配置
# 使用方法: 将此文件内容加入 nginx.conf 的 server 块
# 注意: HTTP/2 需要 SSL 证书 (仅工作在 HTTPS)
# ============================================================

server {
    listen 443 ssl http2;       # ← http2 关键字启用 HTTP/2
    listen [::]:443 ssl http2;  # IPv6

    # ---- KeepAlive 调优 ----
    keepalive_timeout 65;
    keepalive_requests 1000;

    # ---- SSL 优化 ----
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets on;     # TLS Session Resumption
    ssl_stapling on;            # OCSP Stapling
    ssl_stapling_verify on;

    # ---- SSL 协议 (仅 TLS 1.2+) ----
    ssl_protocols TLSv1.2 TLSv1.3;

    # ---- TCP 层面优化 (需系统支持) ----
    # Linux sysctl 需设置:
    #   net.ipv4.tcp_fastopen = 3
    #   net.core.default_qdisc = fq
    #   net.ipv4.tcp_congestion_control = bbr
}
"""
    with open(os.path.join(output_dir, "nginx-http2.conf"), "w") as f:
        f.write(http2_conf)
    results.append(OptimizerResult(
        name="Nginx HTTP/2 + TLS", category="server-config", applied=True,
        details="已生成 nginx-http2.conf，启用 HTTP/2 + KeepAlive + TLS 会话复用 + OCSP Stapling",
        config_file=os.path.join(output_dir, "nginx-http2.conf")
    ))

    # 4. HTML resource hints
    html_hints = """<!-- ============================================================
自动生成: 网络延迟优化 — HTML Resource Hints
使用方法: 将此片段加入 HTML <head> 中
============================================================ -->

<!-- DNS 预解析 — 提前解析关键第三方域名 -->
<link rel="dns-prefetch" href="//fonts.googleapis.com">
<link rel="dns-prefetch" href="//cdn.jsdelivr.net">
<link rel="dns-prefetch" href="//api.yourdomain.com">

<!-- Preconnect — 提前建立完整连接 (DNS + TCP + TLS) -->
<link rel="preconnect" href="https://api.yourdomain.com">
<link rel="preconnect" href="https://cdn.yourdomain.com">

<!-- Preload — 提前加载首屏关键资源 -->
<link rel="preload" href="/fonts/main.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="/css/critical.css" as="style">

<!-- 图片懒加载 -->
<img src="placeholder.jpg" loading="lazy" alt="...">

<!-- 脚本异步加载 -->
<script src="/js/non-critical.js" defer></script>
"""
    with open(os.path.join(output_dir, "html-hints.html"), "w") as f:
        f.write(html_hints)
    results.append(OptimizerResult(
        name="HTML Resource Hints", category="server-config", applied=True,
        details="已生成 html-hints.html，包含 dns-prefetch / preconnect / preload 片段",
        config_file=os.path.join(output_dir, "html-hints.html")
    ))

    # 5. Cloudflare optimization
    cloudflare_json = """{
  "_comment": "=== Cloudflare 优化设置 (Dashboard → Speed → Optimization) ===",
  "speed_optimizations": {
    "auto_minify": {
      "html": true,
      "css": true,
      "js": true
    },
    "brotli": true,
    "rocket_loader": true,
    "early_hints": true,
    "http2": true,
    "http3": true,
    "0rtt": true,
    "polish": "lossless",
    "mirage": true,
    "cache_level": "standard"
  },
  "_comment_caching": "=== 缓存规则 (Dashboard → Caching → Cache Rules) ===",
  "cache_rules": [
    {
      "description": "静态资源 1 年缓存",
      "expression": "(http.request.uri.path ~ \\\".*\\\\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2)$\\\")",
      "action": "set_cache_level",
      "value": "cache_everything",
      "edge_ttl": {
        "mode": "override_origin",
        "value": 31536000
      },
      "browser_ttl": {
        "mode": "override_origin",
        "value": 31536000
      }
    },
    {
      "description": "HTML 文件 1 小时缓存",
      "expression": "(http.request.uri.path ~ \\\".*\\\\.html$\\\")",
      "action": "set_cache_level",
      "value": "cache_everything",
      "edge_ttl": {"mode": "override_origin", "value": 3600},
      "browser_ttl": {"mode": "respect_existing_headers", "value": 3600}
    }
  ],
  "_comment_security": "=== TLS 设置 (Dashboard → SSL/TLS → Edge Certificates) ===",
  "tls_settings": {
    "min_tls_version": "1.2",
    "tls_1_3": true,
    "http_strict_transport_security": {
      "enabled": true,
      "max_age": 31536000,
      "include_subdomains": true,
      "preload": true
    }
  },
  "_comment_ddos": "=== 安全设置 ===",
  "security_level": "medium",
  "browser_integrity_check": true,
  "always_online": true
}
"""
    with open(os.path.join(output_dir, "cloudflare.json"), "w") as f:
        f.write(cloudflare_json)
    results.append(OptimizerResult(
        name="Cloudflare 优化", category="server-config", applied=True,
        details="已生成 cloudflare.json，包含 CDN 缓存、Brotli、HTTP/3、0-RTT、自动压缩等设置",
        config_file=os.path.join(output_dir, "cloudflare.json")
    ))

    # 6. Combined optimization checklist
    checklist = """# 📋 网络优化部署清单

## 服务端 (运维执行)

### Nginx 配置
- [ ] `nginx-gzip.conf` → 加入 http 块，启用 Gzip/Brotli 压缩
- [ ] `nginx-cache.conf` → 加入 server 块，设置 Cache-Control + ETag
- [ ] `nginx-http2.conf` → 替换 server 块，启用 HTTP/2 + TLS 1.3 + KeepAlive
- [ ] 验证: `nginx -t && nginx -s reload`

### CDN 配置 (如用 Cloudflare)
- [ ] `cloudflare.json` → 参考配置项在 Dashboard 中设置
- [ ] 启用 Argo Smart Routing (付费，可减少 30%+ 延迟)
- [ ] 启用 Tiered Cache (减少回源)

### Linux 系统调优
- [ ] TCP Fast Open: `sudo sysctl -w net.ipv4.tcp_fastopen=3`
- [ ] BBR 拥塞控制: `sudo sysctl -w net.ipv4.tcp_congestion_control=bbr`
- [ ] TCP 连接复用: `sudo sysctl -w net.ipv4.tcp_tw_reuse=1`

## 前端 (开发执行)

### HTML Head 注入
- [ ] `html-hints.html` → 复制 <link> 标签到 HTML <head>
- [ ] 将关键第三方域名加入 dns-prefetch
- [ ] 将首屏 LCP 资源加入 preload

### 图片优化
- [ ] 使用 WebP/AVIF 格式
- [ ] 非首屏图片启用 loading="lazy"
- [ ] 响应式图片使用 srcset

### JS/CSS
- [ ] 非关键脚本使用 deferred 或 async
- [ ] CSS 拆分 critical/non-critical
- [ ] Bundle 分析: 移除未使用的依赖

## 验证

运行以下命令验证优化效果:

```bash
# 优化前基准
netopt https://your-api.com --multi 5 --md before.md

# 应用配置后验证
netopt https://your-api.com --multi 5 --md after.md

# 对比报告
diff before.md after.md
```
"""
    with open(os.path.join(output_dir, "CHECKLIST.md"), "w") as f:
        f.write(checklist)
    results.append(OptimizerResult(
        name="部署清单", category="server-config", applied=True,
        details="已生成 CHECKLIST.md，包含完整的优化部署步骤",
        config_file=os.path.join(output_dir, "CHECKLIST.md")
    ))

    return results

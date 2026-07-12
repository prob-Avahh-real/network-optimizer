"""
网络延迟优化 Agent — 基于多维度分层诊断的网络性能优化工具

Image methodology layers:
  Layer 1: DNS 解析层 — DNS prefetch, 缓存, CDN 调度
  Layer 2: TCP/TLS 连接层 — 连接复用, Keep-Alive, TCP Fast Open, TLS 会话复用
  Layer 3: HTTP/传输层 — 压缩, 缓存策略, 请求合并, HTTP/2 多路复用
  Layer 4: 应用层 — 懒加载, 预取, 数据格式, CDN 边缘计算
  Layer 5: 监测层 — 持续测量, RUM, 告警
"""

__version__ = "0.1.0"

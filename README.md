# 🔧 网络延迟优化 Agent (Network Optimizer)

> 基于 5 层诊断方法论，全自动分析和优化网络延迟的 CLI 工具

## 5 层诊断模型

| 层级 | 名称 | 诊断重点 | 关键指标 |
|------|------|----------|----------|
| L1 | DNS 解析层 | DNS 耗时、缓存命中、CDN 节点分布、预解析 | <50ms |
| L2 | TCP/TLS 连接层 | 握手耗时、Keep-Alive 复用、TFO、TLS 版本 | <80ms |
| L3 | HTTP/传输层 | HTTP 版本、压缩、缓存头、响应体积 | <200ms |
| L4 | 应用层 | Resource Hints、懒加载、预取、数据格式 | 请求数/体积 |
| L5 | 监测层 | 性能预算、RUM、合成监测、告警阈值 | P95 趋势 |

## 快速开始

```bash
cd network_optimizer

# 诊断一个网站
python -m network_optimizer https://example.com

# 生成 JSON 报告
python -m network_optimizer https://example.com --json 2>/dev/null

# 多轮采样统计 (10 轮)
python -m network_optimizer https://example.com --multi 10

# 导出 Markdown 报告
python -m network_optimizer https://example.com --md report.md

# 安静模式 (只输出摘要)
python -m network_optimizer https://example.com --quiet
```

## 输出示例

```
🔧 网络延迟优化 Agent v0.1.0

── Layer 1: DNS 解析层 (12.0ms)
  ✓ 解析耗时: 12.0ms (预算 <50ms)
  ✓ CDN 多节点: 4 个 IP
  ⚠ 预解析建议: 可选

── Layer 2: TCP/TLS 连接层 (45.0ms)
  ✓ TCP 握手耗时: 15.0ms
  ✓ TLS 握手耗时: 30.0ms (TLS 1.3)
  ⚠ TCP Fast Open: 未启用

📊 诊断摘要
  健康评分: 85/100 — 网络健康
  总耗时: 187.0ms
```

## 项目结构

```
network_optimizer/
├── network_optimizer/
│   ├── __init__.py          # 包入口 + 版本
│   ├── __main__.py          # CLI 主入口
│   ├── core/
│   │   └── __init__.py      # 数据模型 (Finding, Severity, NetworkProfile)
│   ├── layers/
│   │   ├── dns.py           # Layer 1: DNS 解析层
│   │   ├── tcp_tls.py       # Layer 2: TCP/TLS 连接层
│   │   ├── http.py          # Layer 3: HTTP/传输层
│   │   ├── application.py   # Layer 4: 应用层
│   │   └── monitoring.py    # Layer 5: 监测层
│   ├── metrics/
│   │   └── __init__.py      # 统计指标 (Metric, MetricsStore)
│   └── report/
│       └── __init__.py      # 报告生成 (控制台 + Markdown)
├── SKILL.md                 # Claude Skill 指令
├── pyproject.toml
└── README.md
```

## 健康评分规则

- 基础分: 100
- 每个严重问题: -20
- 每个警告: -5
- ≥80: 网络健康 | 50-79: 建议优化 | <50: 需要立即优化

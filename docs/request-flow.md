# 请求处理流程

本文档描述一个 DNS 请求从进入服务到响应返回的完整链路，对应 `config.yaml` 中
`listens` / `domains` / `proxy` / `filters` 等配置块的协作顺序。

## 设计原则

1. **热路径最短**：缓存放在最前，命中即返回，跳过后续所有处理；
2. **本地权威优先**：本地配置（`domains`、`zone_file`）的优先级高于过滤和上游；
3. **失败前置过滤**：过滤逻辑放在代理前面，命中黑名单的请求不应消耗上游配额；
4. **白名单先于黑名单**：`@@` 例外规则优先于 `||` 黑名单，符合 AdBlock 语义。

## 处理顺序

```
        ┌─────────────────────────┐
        │   Client Request        │
        │   (UDP / DoH / DoT)     │
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │ [1] Listen 层接入        │
        │   - 反序列化 DNSPacket   │
        │   - 提取 Question        │
        └────────────┬────────────┘
                     │
                     ▼
        ┌─────────────────────────┐         命中
        │ [2] Cache 查询           │──────────────┐
        │   key = (qname, qtype)   │              │
        └────────────┬────────────┘              │
                     │ 未命中                     │
                     ▼                            │
        ┌─────────────────────────┐         命中  │
        │ [3] Local Domains        │──────────────┤
        │   - 内联 records         │              │
        │   - zone_file            │              │
        └────────────┬────────────┘              │
                     │ 未命中                     │
                     ▼                            │
        ┌─────────────────────────┐               │
        │ [4] Filter 过滤          │               │
        │   ① allowlist 命中? 放行 │               │
        │   ② blocklist 命中? 阻断 │──┐           │
        │   ③ 自定义 rules         │  │           │
        └────────────┬────────────┘  │           │
                     │ 未命中         │ 命中       │
                     ▼                ▼           │
        ┌─────────────────────────┐  ┌──────────┐│
        │ [5] Proxy Upstream       │  │ 合成响应 ││
        │   按 strategy 选 upstream│  │ NXDOMAIN ││
        │   ├─ DoH                 │  │ / 0.0.0.0││
        │   ├─ UDP primary         │  └────┬─────┘│
        │   └─ UDP fallback        │       │      │
        └────────────┬────────────┘       │      │
                     │                     │      │
                     ▼                     │      │
        ┌─────────────────────────┐       │      │
        │ [6] Cache 写入           │       │      │
        │   按响应 TTL 入缓存      │       │      │
        └────────────┬────────────┘       │      │
                     │                     │      │
                     ▼                     ▼      ▼
        ┌─────────────────────────────────────────┐
        │ [7] EDNS 后处理 + WriteResponse          │
        │   - 客户端不支持 EDNS 时剥离 OPT 记录    │
        │   - 序列化并发回                          │
        └────────────────────┬────────────────────┘
                             ▼
                     ┌──────────────┐
                     │   Client     │
                     └──────────────┘
```

## 各阶段说明

### [1] Listen 层接入

由 `server.ListenUDP` / `server.ListenHTTP` 等接入 goroutine 完成：
- 读取原始字节并通过 `packet.FromBytes` 解码为 `DNSPacket`；
- 包装成 `PackConn` 交给 handler。

`config.yaml` 中的 `listens` 数组每一项启动一个独立的 listener，共享同一个
handler（也就是同一条 pipeline）。

### [2] Cache 查询

最热的路径，直接返回。
- **Key**：`(qname, qtype, qclass)`，建议小写化 qname；
- **TTL**：使用响应中各 RR 的 TTL 最小值，并受 `cache.min_ttl` / `cache.max_ttl`
  约束；
- **命中后**：直接构造响应，跳过 [3]–[6]，进入 [7]；
- **不缓存的项**：本地 records 命中的结果（已经是 O(1) 内存查找）、被 filter 阻断
  的合成响应（避免规则热更新后残留旧判定）。

### [3] Local Domains

匹配 `domains[].domain` 中配置的任一 zone：
- 命中 zone 后在内存索引里查找具体的 record；
- 若 `zone_file` 指定，启动时解析并缓存到内存（`zone.ParseFile`）；
- 命中即构造响应，**不进入 filter**——本地权威记录视为可信，不应被黑名单
  误伤。

### [4] Filter 过滤

按以下子顺序执行：

1. **Allowlist**：命中 `allowlists` 任一规则或自定义规则中的 `@@||...^` 例外，
   则直接进入 [5]，跳过黑名单；
2. **Blocklist**：命中 `blocklists` 任一规则或自定义规则中的 `||...^`，则合成
   响应：A 记录返回 `0.0.0.0`，AAAA 返回 `::`，其它返回 NXDOMAIN；
3. **`$important` 修饰符**：带 `$important` 的黑名单规则可以反过来覆盖
   allowlist（按 AdBlock 语义）。

阻断响应直接进入 [7]，不写入缓存。

### [5] Proxy Upstream

按 `proxy.strategy` 决定多个 upstream 之间的关系（建议显式新增此字段）：

| 策略 | 行为 |
|------|------|
| `failover` | 按数组顺序，前一个超时/失败再尝试下一个 |
| `parallel` | 并发查询所有 upstream，返回最先到达的成功响应 |
| `random` | 每次随机选一个 |
| `conditional` | 按 qname 后缀路由（如 `*.cn` → 国内 UDP，其它 → DoH） |

每个 upstream 独立配置 `type`（doh/udp/dot/tcp）、`addr`、`timeout` 和（仅 DoH
有效的）`method`（建议把现在的 `strategy: post` 改名为 `method: post` 避免歧义）。

### [6] Cache 写入

仅缓存来自 upstream 的成功响应：
- 失败响应（`SERVFAIL`、超时）默认不缓存，避免抖动放大；
- `NXDOMAIN` 可按 `cache.negative_ttl` 短期缓存（建议 60s）。

### [7] EDNS 后处理 + 写回

参考 `examples/relay/main.go:104-123` 的现有逻辑：
- 如果客户端请求里没有 OPT 伪记录，但响应里有，则剥离响应里的 OPT 并修正
  `ARCount`；
- 通过 `conn.WriteResponse(res)` 序列化回客户端。

## 与 `config.yaml` 的对应关系

```yaml
listens:        # 阶段 [1]
domains:        # 阶段 [3]
filters:        # 阶段 [4]
proxy:          # 阶段 [5]
cache:          # 阶段 [2] 和 [6]（建议补充该配置块）
```

## 关键决策点

- **缓存优先级最高**：拒绝在 cache 之前做任何昂贵操作，包括 filter trie 匹配；
- **本地 records 不走 filter**：避免用户配的本地解析被远端规则集误伤；
- **filter 在 proxy 之前**：阻断的请求不消耗上游配额、不暴露给上游；
- **EDNS 透传需要兼容老客户端**：响应里的 OPT 在客户端未声明 EDNS 时必须剥离。

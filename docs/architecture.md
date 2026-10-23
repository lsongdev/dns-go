# 架构

## 包划分

```
cmd/dns-go   命令行：读配置、开监听、SIGHUP 热加载、证书重载
api          HTTP 管理 API（/api）：以配置文件为唯一数据源的变更、统计与查询日志
web          嵌入的 Web 控制面板（Preact + htm，ES modules，无构建步骤）
access       访问控制：网络 allow/deny 与客户端身份
engine       解析引擎 Engine（实现 server.Handler）与按配置组装的 Service
zone         zone 文件 / hosts 解析，以及可增删改查的 zone 存储 Store
filter       AdBlock 规则匹配 Filter，以及列表订阅 Subscriptions
cache        上游应答的 LRU 缓存
proxy        上游池（顺序 failover）
client       UDP / TCP / DoT / DoH 客户端
server       UDP / TCP / DoT / DoH 监听；截断与分帧在这一层完成
packet       DNS 报文编解码、名字压缩、截断打包、EDNS
config       YAML 配置结构与校验（只做结构校验，不构建组件）
```

依赖方向是单向的：`packet` ← `client`/`server`/`zone`/`filter`/`cache` ← `proxy` ← `engine` ← `cmd`。
`config` 只被 `engine.Service` 和 `cmd` 引用，其余包都不依赖配置格式，
所以管理 API 可以直接从数据库构建 `zone.Zone`、`filter.List` 等对象，不需要经过 YAML。

## 请求处理流程

```
transport (server)          engine.Resolve                                   transport
──────────────────          ──────────────────────────────────────────────   ─────────
解码 → ServeDNS(ctx) ──→ 校验 → zones → filter → cache → upstream → finalize ──→ WriteMsg
                          │        │        │        │        │
                          │        │        │        │        └ 新建上游查询（随机 ID、RD=1、
                          │        │        │        │          透传 DO/CD，不带客户端选项）
                          │        │        │        └ 命中则直接返回（TTL 已扣减）
                          │        │        └ Block → 合成应答（不进缓存、不访问上游）
                          │        └ static zone：区内一切由本地回答（含 NXDOMAIN）
                          │          transparent zone：只回答有数据的名字，其余继续往下
                          │          CNAME 指向本地数据之外时（仅转发模式）继续解析目标
                          └ FORMERR / NOTIMP / BADVERS / AXFR→REFUSED
```

- **权威模式**：Engine 不配置 upstream。zone 之外一律 REFUSED，RA=0。
- **转发模式**：RA=1。过滤在缓存**之前**，新增的规则立即对已缓存的名字生效。
- **finalize** 统一处理协议细节：AA；RA；AD（只透传上游的 AD，且仅当客户端设置了 AD 或 DO，RFC 6840）；
  回显 OPT（UDP 大小 1232，回显 DO）；扩展 RCODE；DO=0 时剥离 RRSIG/NSEC/NSEC3。
- **截断**由传输层负责：UDP 写入时按 `min(客户端 EDNS 大小, 1232)` 打包（无 EDNS 时为 512）。
  放不下时先丢弃可选的附加记录；如果是委派且 glue 放不下（RFC 9471），或者答案本身放不下，则只返回问题与 OPT 并设置 TC。

## zone 的两种类型

| Kind | 区内未知名字 | 用途 |
|------|-------------|------|
| `static` | NXDOMAIN / NODATA（带 SOA） | 权威 zone、完全自管的内网域名 |
| `transparent` | 交给后续阶段（过滤、缓存、上游） | 覆盖个别公网名字、hosts 文件（根 zone） |

最长匹配的 zone 生效。所以根上的 hosts zone 和 `home.lan` 这样的 static zone 可以共存，
`home.lan` 下的名字由后者负责。

## 编程接口（给管理 API / Web 面板）

`engine.Service` 持有全部组件。管理 API 直接调用组件自己的方法，变更**立即生效且是原子的**：

```go
svc, _ := engine.NewService(cfg, engine.Hooks{
	OnQuery:      func(ev engine.QueryEvent) { /* 查询日志、统计；不得阻塞 */ },
	OnListUpdate: func(s filter.SourceStatus) { /* 订阅更新结果 */ },
})

// 域名解析：以 zone 为单位增删改查，编译失败时不影响正在服务的数据
svc.Zones.List() / Get(origin) / Put(*zone.Zone) / Delete(origin) / Replace([]*zone.Zone)
zone.ParseString(origin, text)    // 把面板里的 zone 文本解析成 *zone.Zone
zone.ParseHosts(reader)

// 过滤规则
svc.Filter.SetList(filter.List{Name: "custom", Kind: filter.BlockList, Rules: rules})
svc.Filter.RemoveList(name) / Lists() / Match(name)
filter.ParseRule(line)            // 逐条校验用户输入，区分不支持的语法和格式错误
svc.Subscriptions.Set([]filter.Source{...}) / Refresh(ctx, name) / Status()

// 其它
svc.Engine.SetBlockMode(engine.BlockNXDomain)
svc.Engine.Resolve(ctx, req)      // “测试解析”：返回应答、来源阶段、命中的规则
svc.Cache.Flush()
svc.Access.Set(access.Rules{...}) / Rules() / Check(req)
```

并发模型：`zone.Store` 和 `filter.Filter` 的读路径无锁（`atomic.Pointer` 指向不可变快照），
写操作在旁边编译好新快照后整体替换。`Store.Put` 只重新编译被修改的那个 zone。
传入和取出的 zone 都会深拷贝，调用方可以放心复用自己的对象。

`QueryEvent` 包含时间、耗时、客户端地址、传输方式、问题、RCODE、来源阶段（zone/filter/cache/upstream/…）、
命中的过滤规则（所属列表和规则原文）以及上游错误，查询日志和统计面板所需的字段都在这里。

## 当前的边界

以下功能**尚未实现**：

- 区域传送（AXFR/IXFR/NOTIFY/TSIG）：主从同步需要手动同步配置；
- DNSSEC 在线签名：可以托管预签名的 zone（RRSIG 随应答返回），但不会自己签名；
- 从根开始的迭代递归：转发模式依赖上游；
- 并发相同查询的合并（singleflight）、过期缓存兜底（serve-stale）、预取；
- 响应速率限制（RRL）与按客户端的查询限速；
- 按客户端的策略（例如某个设备不过滤）：身份已经识别，策略尚未实现；
- 拦截 CNAME cloaking（过滤只检查问题中的名字）。

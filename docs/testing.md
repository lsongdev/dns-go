# 测试

## 单元测试

```bash
go test ./...
go test -race ./...    # zone.Store / filter.Filter 的无锁快照与并发客户端都有竞态测试
go vet ./...
```

| 包 | 覆盖内容 |
|----|---------|
| `packet` | 编解码、名字压缩、截断打包（TC、OPT 保留、referral glue）、扩展 RCODE、AD/CD、并发编码只读、fuzz |
| `zone` | 解析（含相对名字补全）、static/transparent 语义、通配符、委派、RRSIG 附带、CRUD、原子替换、hosts |
| `filter` | 规则语法与优先级、allow 列表、命中规则上报、订阅（文件/URL/磁盘缓存/失败保留） |
| `cache` | TTL 钳制与递减、RFC 2308 负缓存、不缓存 SERVFAIL/TC、DO/CD 分键、LRU |
| `client` | 真实 UDP/TCP 监听：TC 回退 TCP、并发不串行、连接复用、伪造报文忽略、context |
| `server` | UDP 大小上限、TCP 分帧/管线/空闲超时、关闭监听即返回、DoH GET/POST/Cache-Control |
| `proxy` | failover（错误与 SERVFAIL/REFUSED）、context 取消 |
| `engine` | 完整请求路径：EDNS/BADVERS/AD、权威与转发、transparent+CNAME 追踪、过滤在缓存前、真实 UDP 截断、QueryEvent、Service 热加载 |
| `config` | 默认值与各类校验错误 |

## 端到端冒烟测试

```bash
./scripts/smoke.sh               # 默认端口 15353（macOS 的 5353 被 mDNSResponder 占用）
PORT=15400 ./scripts/smoke.sh
```

脚本会编译并启动转发模式的实例，用 `dig` 校验 static zone、transparent 覆盖、过滤、上游加缓存，
以及截断、OPT 回显、BADVERS、AXFR 拒绝等协议行为。上游相关的用例需要联网。
任一用例失败时，脚本会打印服务端日志并以状态码 1 退出。

AdGuard 列表文件（`testdata/blocklists/adguard-dns.txt`）不存在时会跳过并记录日志，
过滤用例由内联规则兜底。如需完整列表，可以下载：

```bash
mkdir -p testdata/blocklists
curl -sSL -o testdata/blocklists/adguard-dns.txt \
  https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
```

## 手工验证

```bash
dig @127.0.0.1 -p 15353 +noedns +ignore big.example.net TXT   # 期望 flags 含 tc、≤512 字节
dig @127.0.0.1 -p 15353 +edns=1 +noednsneg example.com        # 期望 status: BADVERS
./dns-go -config config.yaml -log-queries                      # 每条查询的来源阶段与命中规则
```

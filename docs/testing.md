# 测试指南

dns-go 有两种测试: 单元测试 (Go 标准 `go test`) 和端到端冒烟测试
(`scripts/smoke.sh`,启动真实 server + dig 校验)。

## 单元测试

```bash
go test ./...
```

按包跑某一组:

```bash
go test ./pipeline/...        # pipeline (cache→local→filter→proxy)
go test ./filter/... -v       # AdBlock 规则解析
go test ./config/...          # YAML 配置加载/校验
go test ./cache/...           # TTL 钳制 / 过期 / 容量淘汰
go test ./proxy/...           # failover 上游池
```

`go vet ./...` 与 `go build ./...` 默认会一起跑通。

## 端到端冒烟测试

`scripts/smoke.sh` 启动一份 dns-go 实例,用 `dig` 跑 4 类查询, 校验
响应是否符合预期:

1. 本地 zone (BIND `zone_file`) 命中 — `nas.example.com → 192.168.1.100` 等
2. Filter 阻断 — `doubleclick.net → 0.0.0.0`、`ad.doubleclick.net → 0.0.0.0`
3. Proxy 上游解析 — `cloudflare.com → 真实 IP`
4. 第二次查询 cache 命中

```bash
./scripts/smoke.sh

# 改端口 (默认 15353,macOS 上 5353 被 mDNSResponder 占着):
PORT=15400 ./scripts/smoke.sh
```

输出形如:

```
[1] local zone (BIND zone_file)
  ✓ nas.example.com           A      -> 192.168.1.100
  ✓ mail.example.com          A      -> 192.168.1.2
  ...
[2] filter block
  ✓ doubleclick.net           A      -> 0.0.0.0
  ...
──────── result ────────
  pass: 10
  fail: 0
```

任一 case 失败时,脚本 exit 1 并把 server log 转出来。

### 准备数据

脚本默认引用:

- `testdata/zones/example.com.zone` — 已 commit
- `testdata/blocklists/adguard-dns.txt` — `.gitignore` 排除,需手动下载

如果列表不存在, pipeline 会 log warn 后跳过, 但 `[2]` 用例会依赖默认
`rules:` 块里的 `||doubleclick.net^` 兜底, 不会失败。

下载真实 AdGuard 列表 (~3.7MB):

```bash
mkdir -p testdata/blocklists
curl -sSL -o testdata/blocklists/adguard-dns.txt \
  https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
```

更多列表和 zone 文件示例参见 `testdata/README.md`。

## 排错

**`bind: address already in use`** — 之前的 dns-go 实例没退干净:

```bash
pkill -f "cmd/dns-go"
lsof -nP -iUDP:15353       # 找进程
```

**MacOS 5353 端口被占** — `mDNSResponder` 用 5353 提供 mDNS,
`config.yaml` 默认监听 `:5353`,本地直接 `go run ./cmd/dns-go` 会
bind 失败。改 `addr: ":15353"` 或者用 `scripts/smoke.sh`。

**dig 显示意外的 IP (例如 `198.18.x.x`)** — 这是 1.1.1.1 的拒绝/
篡改响应,说明请求确实走到了上游。如果你期望命中本地 zone, 检查
zone 文件是否真的被加载 (`go vet`/`server log` 里看 `local zones` 报错)。

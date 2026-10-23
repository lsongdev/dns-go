# dns-go

用 Go 实现的 DNS 协议栈与服务器，一个二进制两种角色：

- **权威服务器**（`mode: authoritative`）：部署在公网作为域名的 NS，只回答自己的 zone，区外 REFUSED，不提供递归。
- **转发解析器**（`mode: forwarding`）：给手机/家庭网络用的 DoH/DoT 解析器，支持本地 zone 与覆盖、AdBlock 规则过滤、缓存、加密上游与 failover。

除标准库外只依赖 `gopkg.in/yaml.v3`。

## 快速开始

```bash
go build -o dns-go ./cmd/dns-go
./dns-go -config config.yaml                # 转发解析器
./dns-go -config config.authoritative.yaml  # 权威服务器
./dns-go -config config.yaml -log-queries   # 打印每条查询
kill -HUP <pid>                             # 热加载 zone、过滤列表和证书
```

```bash
dig @127.0.0.1 -p 15353 nas.home.lan        # UDP
dig @127.0.0.1 -p 15353 +tcp nas.home.lan   # TCP
```

DoH 的端点是 `/dns-query`，手机上填 `https://dns.example.com/dns-query`。

配置说明见 [docs/configuration.md](docs/configuration.md)。

## 协议支持

| 方面 | 支持情况 |
|------|---------|
| 传输 | UDP、TCP（RFC 7766，管线化、空闲超时）、DoT（RFC 7858）、DoH（RFC 8484，GET/POST，HTTP/2） |
| 编码 | 名字压缩（RFC 1035 §4.1.4；RFC 3597 之后的类型不压缩 RDATA） |
| 截断 | 按客户端 EDNS 大小截断，上限 1232（DNS Flag Day 2020），无 EDNS 时 512；按需设置 TC |
| EDNS | 回显 OPT、DO 位、BADVERS、扩展 RCODE；不向上游泄漏客户端选项 |
| DNSSEC | 记录编解码；按 DO 位附带或剥离 RRSIG/NSEC；AD 位遵循 RFC 6840 |
| 记录类型 | A、AAAA、CNAME、NS、SOA、MX、TXT、PTR、SRV、CAA、TLSA、SVCB/HTTPS、DS、DNSKEY、RRSIG、NSEC，以及未知类型（RFC 3597） |
| 权威语义 | 最长 zone 匹配、CNAME 链、通配符（RFC 4592）、委派与 glue、NXDOMAIN/NODATA 带 SOA |

## 作为库使用

```go
// 客户端
c := client.NewUDPClient("1.1.1.1:53")
q := packet.NewPacket()
q.AddQuestionA("example.com")
res, err := c.Query(ctx, q)

// 自定义服务器
server.ListenUDP(":5353", server.HandlerFunc(func(ctx context.Context, w server.ResponseWriter, req *packet.DNSPacket) {
	res := packet.NewReply(req)
	// ...
	w.WriteMsg(res) // 传输层负责截断与分帧
}))
```

完整的解析引擎可以在代码中组装，见 [examples/relay](examples/relay/main.go)；包结构与扩展接口见 [docs/architecture.md](docs/architecture.md)。

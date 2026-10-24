# dns-go

用 Go 实现的 DNS 协议栈与服务器。同一个二进制可以承担不同角色，适用于不同的部署环境和使用者：

| 场景 | 角色 | 典型配置 |
|------|------|---------|
| 路由器 / 旁路由，替代 dnsmasq 的解析部分 | 局域网转发解析 | UDP/TCP 53，`domains` 放内网域名与 hosts，`access.allow: [private]` |
| NAS / homelab，替代 AdGuard Home 的拦截 | 局域网转发 + 过滤 | 加上 `filters.lists` 订阅，按设备区分 `clients` |
| 云主机（AWS、阿里云等）上的私人解析服务 | 公网 DoH/DoT | 只开 DoH/DoT，设备用 client ID 认证 |
| 域名的权威 NS | 权威服务器 | `mode: authoritative`，zone 文件 |

各平台都可以直接接入，不需要安装客户端：macOS、Windows、Linux、iOS、Android、路由器以及浏览器都支持普通 DNS 或 DoH/DoT。

内置 Web 控制面板与 HTTP API（`api.addr`），可以管理 zone 与记录、过滤规则与订阅、客户端与访问控制、服务设置（监听、上游、缓存，在线生效），
并提供仪表盘、查询日志和解析测试。面板文件嵌入在二进制中，可以离线使用。
同一套服务和面板也可以作为模块挂载到其它面板中（如 OhMyServer），见 [docs/architecture.md](docs/architecture.md#作为面板模块)。

依赖只有标准库和 `gopkg.in/yaml.v3`（面板使用随附的 Preact + htm，无构建步骤）。

## 构建

```bash
make                 # 当前平台，生成 dist/dns-go
make test            # go vet（包括 nosqlite 构建）+ go test -race
make release         # 全部平台：dist/*.tar.gz、*.zip 和 SHA256SUMS
make release PLATFORMS="linux/arm64 linux/mipsle"
make linux/arm/v7    # 只构建单个平台，输出为 dist/ 下的目录
```

平台包括 linux（amd64、arm64、armv6/v7、386、riscv64、loong64、mips/mipsle）、darwin、windows 和 freebsd。
所有二进制都是静态链接，面板已经嵌入，无需其它文件。MIPS 默认使用 softfloat，适配多数路由器。
纯 Go 的 SQLite 驱动不支持 MIPS，所以 MIPS 版本只能使用配置文件存储；需要更小的二进制时，也可以用 `TAGS=nosqlite` 去掉 SQLite 支持。
Linux 的发布包中附带 systemd unit（`contrib/systemd/dns-go.service`），其中已配置最小权限：只有绑定低端口的能力，并启用了沙箱。

## 快速开始

```bash
go build -o dns-go ./cmd/dns-go
./dns-go -config config.yaml                # 转发解析器
./dns-go -config config.authoritative.yaml  # 权威服务器
./dns-go -config config.yaml -log-queries   # 打印每条查询（来源、命中规则、客户端）
open http://127.0.0.1:8080                  # Web 控制面板
kill -HUP <pid>                             # 热加载 zone、访问控制、过滤列表和证书
```

```bash
dig @127.0.0.1 -p 15353 nas.home.lan        # UDP
dig @127.0.0.1 -p 15353 +tcp nas.home.lan   # TCP
```

DoH 端点为 `/dns-query`，带身份的写法是 `/dns-query/<client-id>`。
配置与各场景的部署方法见 [docs/configuration.md](docs/configuration.md)。

## 能力

| 方面 | 支持情况 |
|------|---------|
| 传输 | UDP、TCP（RFC 7766，管线化、空闲超时）、DoT（RFC 7858）、DoH（RFC 8484，GET/POST，HTTP/2） |
| 编码 | 名字压缩（RFC 1035 §4.1.4；RFC 3597 之后的类型不压缩 RDATA） |
| 截断 | 按客户端 EDNS 大小截断，上限 1232（DNS Flag Day 2020），无 EDNS 时 512；按需设置 TC |
| EDNS / DNSSEC | 回显 OPT、DO、BADVERS、扩展 RCODE；按 DO 附带或剥离 RRSIG；AD 位遵循 RFC 6840 |
| 本地数据 | static / transparent zone、BIND zone 文件、hosts 文件、通配符、委派与 glue |
| 过滤 | AdGuard DNS 规则子集，URL 订阅定时刷新并缓存到磁盘，可上报命中的规则 |
| 访问控制 | 网络 allow/deny，客户端身份（DoH 路径 / DoT SNI / 源网络），信任反向代理的 X-Forwarded-For |
| 记录类型 | A、AAAA、CNAME、NS、SOA、MX、TXT、PTR、SRV、CAA、TLSA、SVCB/HTTPS、DS、DNSKEY、RRSIG、NSEC，以及未知类型 |

## 作为库使用

```go
c := client.NewUDPClient("1.1.1.1:53")
q := packet.NewPacket()
q.AddQuestionA("example.com")
res, err := c.Query(ctx, q)

server.ListenUDP(":5353", server.HandlerFunc(func(ctx context.Context, w server.ResponseWriter, req *packet.DNSPacket) {
	res := packet.NewReply(req)
	// ...
	w.WriteMsg(res) // 传输层负责截断与分帧
}))
```

完整的解析引擎可以在代码中组装，见 [examples/relay](examples/relay/main.go)；包结构与运行时接口见 [docs/architecture.md](docs/architecture.md)。

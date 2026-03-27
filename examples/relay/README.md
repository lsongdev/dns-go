# DNS Relay

DNS 转发器/代理，将 DNS 查询转发到上游 DNS 服务器（默认 Cloudflare 1.1.1.1）。

## 功能

- **UDP 转发**: 监听 UDP 5353 端口，转发到上游 DNS
- **DoH 支持**: 监听 HTTP 8080 端口，支持 DNS over HTTPS
- **连接复用**: 与上游服务器保持长连接
- **EDNS 兼容**: 自动处理客户端 EDNS 支持
- **详细日志**: 可选的查询/响应日志
- **优雅关闭**: 支持 SIGINT/SIGTERM 信号

## 运行

```bash
# 基本运行（UDP 转发到 1.1.1.1）
go run ./examples/relay/

# 使用 DoH 上游（阿里云 - 推荐国内使用）
go run ./examples/relay/ -upstream https://dns.alidns.com/dns-query

# 使用 DoH 上游（Cloudflare）
go run ./examples/relay/ -upstream https://cloudflare-dns.com/dns-query

# 使用 DoH 上游（Google）
go run ./examples/relay/ -upstream https://dns.google/dns-query

# 使用 DoT 上游（阿里云，端口 853）
go run ./examples/relay/ -upstream dot://dns.alidns.com:853

# 使用 DoT 上游（Cloudflare，端口 853）
go run ./examples/relay/ -upstream dot://1.1.1.1:853

# 使用 DoT 上游（Google，端口 853）
go run ./examples/relay/ -upstream dot://8.8.8.8:853

# 使用 UDP 上游（Google）
go run ./examples/relay/ -upstream 8.8.8.8:53

# 详细日志模式
go run ./examples/relay/ -v

# 自定义监听端口
go run ./examples/relay/ -udp :5353 -http :8080
```

## 测试

```bash
# 使用 dig 测试
dig @127.0.0.1 -p 5353 google.com

# 使用 nslookup 测试
nslookup -port=5353 google.com 127.0.0.1

# 测试 DoH
curl "http://localhost:8080?dns=AAABAAABAAAAAAABZ29vZ2xlA2NvbQAAAQAB"
```

## 命令行选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-udp` | `:5353` | UDP 监听地址 |
| `-http` | `:8080` | HTTP/DoH 监听地址 |
| `-upstream` | `1.1.1.1:53` | 上游 DNS 服务器 |
| `-timeout` | `5s` | 查询超时时间 |
| `-v` | `false` | 详细日志模式 |

## 发现的实际问题

运行此 relay 可以帮助发现以下现实世界中的 DNS 问题：

1. **EDNS 兼容性**: 某些客户端不支持 EDNS，但上游返回 EDNS 记录
2. **UDP 截断**: 大响应可能被截断，需要 TCP fallback
3. **超时处理**: 网络延迟导致查询超时
4. **连接复用问题**: UDP 连接状态管理
5. **DNSSEC 验证**: DO 标志的处理
6. **IPv6 支持**: AAAA 记录查询和响应

## 示例输出

```
2024/01/01 12:00:00 Starting DNS relay...
2024/01/01 12:00:00   UDP listen:  :5353
2024/01/01 12:00:00   HTTP listen: :8080
2024/01/01 12:00:00   Upstream:    1.1.1.1:53
2024/01/01 12:00:00   Timeout:     5s
2024/01/01 12:00:00 Listening on UDP :5353
2024/01/01 12:00:00 Listening on HTTP :8080
2024/01/01 12:00:01 [127.0.0.1:12345] Query: google.com A
2024/01/01 12:00:01 [127.0.0.1:12345] Response: 1 answers, 0 authorities, 1 additionals (15ms)
```

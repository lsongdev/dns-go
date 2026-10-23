# relay

不使用配置文件、直接用库组装的最小转发器：一个上游、一个缓存，UDP 和明文 HTTP DoH 两个监听。
用来演示 `engine.New` 的编程接口；需要完整功能时请用 `cmd/dns-go`。

```bash
go run ./examples/relay/                                              # UDP 上游 1.1.1.1:53
go run ./examples/relay/ -upstream https://dns.alidns.com/dns-query   # DoH 上游
go run ./examples/relay/ -upstream dot://1.1.1.1:853                  # DoT 上游
go run ./examples/relay/ -upstream tcp://8.8.8.8:53 -v                # TCP 上游，打印每条查询

dig @127.0.0.1 -p 5353 example.com
```

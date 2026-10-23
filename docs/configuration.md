# 配置与部署

示例见仓库根目录的 [`config.yaml`](../config.yaml)（转发）和
[`config.authoritative.yaml`](../config.authoritative.yaml)（权威）。

## 配置项

```yaml
mode: forwarding            # authoritative | forwarding（默认）

listens:
  - type: udp               # udp | tcp | dot | doh
    addr: ":53"
  - type: doh
    addr: ":443"
    cert_file: fullchain.pem  # dot 必填；doh 不填则以明文 HTTP 服务（放在反向代理后）
    key_file: privkey.pem

upstreams:                  # 仅转发模式，按顺序尝试；出错或返回 SERVFAIL/REFUSED 时换下一个
  - type: doh               # udp | tcp | dot | doh
    addr: "https://doh.pub/dns-query"
    method: post            # doh：get | post（默认 post）
    timeout: 5s             # 默认 5s

cache:                      # 仅转发模式
  enabled: true
  min_ttl: 0s               # 正向应答的最短缓存时间（默认 0，不改变上游 TTL）
  max_ttl: 24h
  negative_ttl: 5m          # NXDOMAIN/NODATA 的上限；实际取 min(SOA TTL, SOA MINIMUM, 该值)
  max_entries: 10000

domains:
  - domain: home.lan
    kind: static            # static（默认）| transparent
    records: ["nas 300 IN A 192.168.1.100"]
  - domain: example.org
    zone_file: ./example.org.zone
  - hosts_file: /etc/hosts  # 总是 transparent；domain 省略时为根

filters:                    # 仅转发模式
  block_mode: zero_ip       # zero_ip（A→0.0.0.0、AAAA→::、其它类型 NODATA）| nxdomain | refused
  cache_dir: ./data/filters # 保存已下载的列表，重启后不需要联网就能立即生效
  lists:
    - name: adguard-dns
      url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
      refresh: 24h          # url 默认 24h；file 默认只加载一次
      kind: block           # block（默认）| allow：allow 列表里的每条规则都是例外
      enabled: true
  rules:                    # 内联规则，作为名为 "rules" 的列表安装
    - "||doubleclick.net^"
    - "@@||example.com^"
```

每个 domain 的数据来源只能是 `records`、`zone_file`、`hosts_file` 三者之一。
权威模式只允许 static zone，每个 zone 必须有且只有一条 apex SOA，并且至少有一条 apex NS；
也不允许配置 cache、upstreams 或 filters。

规则语法是 AdGuard DNS 过滤器使用的子集：`||domain^`、`@@||domain^`、`$important`、纯域名（只匹配该名字本身）。
优先级为 `$important` > 例外 > 拦截。元素隐藏、正则、通配符和其它修饰符会被跳过并计数。
hosts 格式（`0.0.0.0 name`）不属于过滤器，请用 `domains[].hosts_file`。

## 热加载

`kill -HUP <pid>` 会重新读取配置文件，并应用 domains、filters（列表、规则、block_mode）以及 TLS 证书。
新配置无效时会记录日志并继续使用旧配置。`mode`、`listens`、`upstreams` 和 cache 容量的修改需要重启。

## 部署：公网权威 NS

1. 使用 `config.authoritative.yaml`，同时监听 UDP 和 TCP 的 53 端口（截断后客户端会改用 TCP）。
2. 在注册商处添加 glue 并设置 NS。大多数注册商要求至少两台 NS：目前可以在两台机器上部署同一份配置（区域传送尚未实现）。
3. 用 [DNSViz](https://dnsviz.net) 和 `dig +norec @your-ns example.com SOA` 验证。

## 部署：手机 DoH / DoT

1. 使用 `config.yaml`，为域名申请证书（例如 Let's Encrypt），在 `doh` 和 `dot` 监听上配置 `cert_file`/`key_file`。
   续期后执行 `kill -HUP` 即可，监听不会中断。
2. iOS：通过描述文件（`.mobileconfig`）配置 DoH 地址 `https://dns.example.com/dns-query`。
   Android：设置 →“私人 DNS”填写 `dns.example.com`（DoT，853 端口）。
3. 注意：目前没有访问控制。部署在公网上就是一个开放解析器，只建议用于 DoH/DoT，并且不要对公网开放 UDP/TCP 53。

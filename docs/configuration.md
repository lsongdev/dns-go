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
    hostname: dns.example.com # 可选：从 SNI "<id>.dns.example.com" 识别客户端（需泛域名证书）
  - type: dot
    addr: ":853"
    tls: true                 # 不用证书文件，使用宿主程序提供的证书（例如面板中的证书管理器）
  - type: doh
    addr: "127.0.0.1:8053"
    trusted_proxies: [127.0.0.1]  # 反向代理的地址，信任其 X-Forwarded-For / X-Real-IP

upstreams:                  # 仅转发模式，按顺序尝试；出错或返回 SERVFAIL/REFUSED 时换下一个
  - type: doh               # udp | tcp | dot | doh
    addr: "https://doh.pub/dns-query"
    method: post            # doh：get | post（默认 post）
    timeout: 5s             # 默认 5s

data_dir: ./data            # 已下载的过滤列表（重启后无需联网即可生效）；sqlite 数据库的默认位置

storage:                    # domains / filters / access 这三部分数据存放在哪里
  type: config              # config（默认，存在本配置文件中）| sqlite
  # path: ./data/dns-go.db  # sqlite 数据库路径，默认为 <data_dir>/dns-go.db

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
  lists:
    - name: adguard-dns
      url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
      refresh: 24h          # url 默认 24h；file 默认只加载一次
      kind: block           # block（默认）| allow：allow 列表里的每条规则都是例外
      enabled: true
  rules:                    # 内联规则，作为名为 "rules" 的列表安装
    - "||doubleclick.net^"
    - "@@||example.com^"

access:                     # 网络项可以写 CIDR、单个地址或关键字 private
  allow: [private]          # 不写时：转发模式默认 private，权威模式默认所有人；写 [] 表示只允许带身份的客户端
  deny: [192.168.1.66]      # 优先级最高，带身份也会被拒绝
  deny_action: refuse       # refuse（返回 REFUSED）| drop（UDP 不回应，避免被用来反射；TCP/DoT/DoH 仍返回 REFUSED）
  clients:
    - name: laptop
      ids: [k8f3j2q9]       # DoH：/dns-query/k8f3j2q9；DoT：k8f3j2q9.dns.example.com。公网上应视为密钥
    - name: living-room-tv
      networks: [192.168.1.50]
```

每个 domain 的数据来源只能是 `records`、`zone_file`、`hosts_file` 三者之一。
权威模式只允许 static zone，每个 zone 必须有且只有一条 apex SOA，并且至少有一条 apex NS；
也不允许配置 cache、upstreams 或 filters。

规则语法是 AdGuard DNS 过滤器使用的子集：`||domain^`、`@@||domain^`、`$important`、纯域名（只匹配该名字本身）。
优先级为 `$important` > 例外 > 拦截。元素隐藏、正则、通配符和其它修饰符会被跳过并计数。
hosts 格式（`0.0.0.0 name`）不属于过滤器，请用 `domains[].hosts_file`。

## 数据存储

配置分为两部分：

- **服务设置**：mode、listens、upstreams、cache。可以在 Web 面板的“服务设置”中在线修改，立即生效（只重新绑定改动过的监听），并写回配置文件（只改写这四段）。
- **进程设置**：api、data_dir、storage。只从配置文件读取，修改后需要重启。
- **运行数据**：domains、filters、access。可以通过 Web 面板和 API 在线修改，存放位置由 `storage` 决定：
  - `config`（默认）：数据就存放在这个配置文件中。通过 API 修改时只会改写这三段，其它段落和注释保持原样；手工编辑后执行 `kill -HUP` 即可生效。
  - `sqlite`：数据存放在数据库中（`dns_zones`、`dns_records`、`dns_filter_lists`、`dns_filter_rules`、`dns_clients`、`dns_client_ids`、`dns_client_networks`、`dns_settings` 这几张表，版本记录在 `dns_schema`；
    表名带前缀，所以数据库可以与其它程序共用。早期版本创建的无前缀数据库会在首次打开时自动改名）。
    首次启动时，会用配置文件中的这三段初始化数据库；之后以数据库为准，配置文件里的这三段会被忽略，启动时会打印提示。
    数据库文件的权限为 0600，因为客户端 ID 属于密钥。备份时复制 `dns-go.db` 即可（建议先停服务，或使用 `sqlite3 .backup`）。

解析引擎只接收一份数据，并不知道它来自文件还是数据库。以后增加 PostgreSQL 等后端，只需要实现 `store.Store` 接口。

## 热加载

`kill -HUP <pid>` 会从存储中重新加载运行数据（`config` 存储即重新读取配置文件），重新读取由文件加载的 zone，并重新加载 TLS 证书。
新配置无效时会记录日志并继续使用旧配置。`mode`、`listens`、`upstreams` 和 cache 不随 SIGHUP 重新读取：在面板中修改，或修改配置文件后重启。

## 访问控制

判断顺序为：deny 网络 → 客户端出示的 ID（必须是已知 ID，未知 ID 一律拒绝）→ 客户端所属网络 → allow 网络 → 拒绝。
识别出的客户端名称会写入查询事件（`-log-queries` 和后续的管理 API）。

客户端 ID 的来源：

| 传输 | 方式 | 设置方法 |
|------|------|---------|
| DoH | URL 路径 `/dns-query/<id>` | 所有支持自定义 DoH 地址的系统和浏览器 |
| DoT | SNI `<id>.<hostname>` | 只能填主机名的系统（例如 Android“私人 DNS”）；需要泛域名证书 `*.dns.example.com` |
| UDP/TCP | 源地址匹配 `clients[].networks` | 局域网设备的 DHCP 保留地址 |

DoH 部署在反向代理之后时必须配置 `trusted_proxies`。否则所有请求的来源都是代理地址（通常是 127.0.0.1），
会被 `private` 放行。

转发模式下，如果 allow 允许所有地址，并且 UDP/TCP 监听在非回环地址上，启动时会打印开放解析器（open resolver）警告。

## 部署场景

### 路由器 / 旁路由（替代 dnsmasq 的解析部分）

- 监听 `:53` 的 UDP 与 TCP，使用默认的 `access.allow: [private]`。
- 内网域名用 static zone（例如 `home.lan`），零散的覆盖用 transparent zone 或 `hosts_file`。
- DHCP 下发的 DNS 指向本机。注意：dns-go 不提供 DHCP，也不会自动登记 DHCP 租约对应的主机名。

### NAS / homelab（替代 AdGuard Home 的拦截）

- 在上一种场景的基础上配置 `filters.lists` 订阅和 `cache_dir`。
- 需要区分设备时，在 `clients[].networks` 里写设备的固定地址，查询日志会显示设备名。

### 云主机上的私人解析（AWS、阿里云等）

- **不要**对公网开放 UDP/TCP 53。只开 DoH（443）和 DoT（853），并设置 `access.allow: []`，让所有设备都通过 client ID 认证。
- 为 `dns.example.com` 和 `*.dns.example.com` 申请证书。续期后执行 `kill -HUP`，监听不会中断。
- 各平台的设置方式：
  - macOS / iOS：用描述文件（`.mobileconfig`）配置 DoH `https://dns.example.com/dns-query/<id>`。
  - Windows 11：在网络设置中开启“DNS over HTTPS”并填写模板。
  - Android：在“私人 DNS”中填写 `<id>.dns.example.com`。
  - 浏览器：在安全 DNS 设置中填写 DoH 地址。

### 权威 NS

1. 使用 `config.authoritative.yaml`，同时监听 UDP 和 TCP 的 53 端口（截断后客户端会改用 TCP）。
2. 在注册商处添加 glue 并设置 NS。大多数注册商要求至少两台 NS：目前可以在两台机器上部署同一份配置（区域传送尚未实现）。
3. 用 [DNSViz](https://dnsviz.net) 和 `dig +norec @your-ns example.com SOA` 验证。

# HTTP 管理 API

在配置中启用后，API 位于 `/api`，Web 控制面板位于 `/`。
面板是 `web/static` 下的 ES modules（Preact + htm，已随附在 `web/static/vendor`），通过 `embed` 编译进二进制，没有构建步骤。
在开发时修改这些文件后需要重新编译。

```yaml
api:
  addr: "127.0.0.1:8080"   # 监听在非回环地址时必须设置 token
  token: "change-me"       # 请求头：Authorization: Bearer <token>
  # cert_file / key_file：可选，直接以 HTTPS 提供
```

`api.*` 的修改需要重启进程才能生效。

## 一致性模型

配置文件是唯一的数据源。每个写操作的流程如下：

1. 复制当前配置并修改副本；
2. 校验新配置；
3. 应用到正在运行的服务（立即生效，原子替换）；
4. 原子写回配置文件。

任何一步失败，运行状态和文件都保持不变。手工编辑配置文件后执行 `kill -HUP` 仍然有效，两种方式不会出现分歧。
注意：通过 API 写回配置时，文件中的注释不会保留。

## 约定

- 请求和响应都是 JSON。出错时返回 `{"error": "...", "details": ...}`。
  状态码含义：400 校验失败，401 未认证，404 不存在，409 冲突（重名、对象由文件管理、当前模式不支持）。
- 记录的格式为 `{"name", "ttl", "type", "data"}`：
  - `data` 是 zone 文件格式的 RDATA；其中的相对名字会用 zone 的 origin 补全，返回时一律是绝对名字（以点结尾）。
  - 在 zone 内，`name` 是相对名字，apex 写作 `@`；在其它场景下是绝对名字。
- 在 URL 中，zone 用 origin 标识，根 zone（hosts 文件）写作 `@`。

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 版本、模式、运行时长、监听、上游、zone 数、过滤规则数、缓存条目数 |
| GET | `/api/stats?top=10&bucket=10` | 总数、按来源计数、24 小时序列（每 `bucket` 分钟一个点）、热门域名/被拦截域名/客户端 |
| GET | `/api/querylog?limit=100&search=&source=&client=` | 查询日志，最新的在前（内存中保留 5000 条） |
| POST | `/api/resolve` | `{"name","type","do"}`：走完整解析流程（不经过访问控制），返回应答、来源阶段和命中的规则 |
| DELETE | `/api/cache` | 清空缓存 |
| GET | `/api/zones` | zone 列表：`id`、`origin`、`kind`、`source`（records / zone_file / hosts_file）、`editable`、记录数 |
| POST | `/api/zones` | `{"origin","kind","records":[...]}`：创建 zone |
| GET | `/api/zones/{zone}` | zone 详情，包含 `record_list` |
| PUT | `/api/zones/{zone}` | `{"kind","records":[...]}`：整体替换 |
| POST | `/api/zones/{zone}/records` | 追加一条记录 |
| DELETE | `/api/zones/{zone}` | 删除 zone |
| GET | `/api/filters` | `block_mode`、自定义 `rules`、`lists`（含下载状态） |
| PUT | `/api/filters/rules` | `{"rules":[...]}`：整体替换自定义规则；有无效规则时返回 400，`details` 中逐行列出 `{line, rule, error}` |
| PUT | `/api/filters/block_mode` | `{"block_mode":"zero_ip|nxdomain|refused"}` |
| GET | `/api/filters/check?name=` | 某个名字会命中哪条规则 |
| POST | `/api/filters/lists` | `{"name","kind","url"|"file","enabled","refresh"}` |
| PUT | `/api/filters/lists/{name}` | 修改订阅（不支持改名） |
| DELETE | `/api/filters/lists/{name}` | 删除订阅 |
| POST | `/api/filters/lists/{name}/refresh` | 立即刷新 |
| GET | `/api/access` | `allow`（null 表示使用模式默认值）、`deny`、`deny_action`、`clients` |
| PUT | `/api/access` | 整体替换访问控制 |

由文件加载的 zone（`zone_file`、`hosts_file`）是只读的，修改时返回 409。
过滤相关的端点只在转发模式下可用。

## 示例

```bash
T="Authorization: Bearer change-me"
curl -H "$T" localhost:8080/api/zones
curl -H "$T" -X POST localhost:8080/api/zones/home.lan/records \
     -d '{"name":"nas","type":"A","data":"192.168.1.10"}'
curl -H "$T" -X POST localhost:8080/api/resolve -d '{"name":"nas.home.lan"}'
```

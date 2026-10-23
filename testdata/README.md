# testdata

手动运行服务和测试时使用的本地数据。

- `zones/` — BIND 格式的 zone 文件，供 `domains[].zone_file` 使用。
- `blocklists/` — AdBlock 格式的过滤列表，供 `filters.lists[].file` 使用（已被 `.gitignore` 排除，需要时手动下载，见 `docs/testing.md`）。

通常不需要手动下载：在 `filters.lists[]` 里写 `url`，服务会自动下载、定时刷新，
并缓存到 `filters.cache_dir`。

hosts 格式（`0.0.0.0 name`）不是过滤规则，请用 `domains[].hosts_file` 加载为 transparent zone。

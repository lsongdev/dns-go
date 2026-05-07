# testdata

`testdata/` 是手动跑服务/测试时用的本地数据目录。Go 工具链不会把
这里的内容编进 build 产物，但 `_test.go` 可以用相对路径读取它们。

## 目录布局

- `zones/` — BIND 风格的 zone 文件示例，给 `domains[].zone_file` 用。
- `blocklists/` — AdBlock 风格的过滤规则文件，给 `filters.blocklists[].file` 用。

## 更新过滤规则

下面这些大文件已经在 `.gitignore` 里排除掉，需要时手动下载：

```bash
mkdir -p testdata/blocklists
curl -sSL -o testdata/blocklists/adguard-dns.txt \
  https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
```

仓库根目录的 `config.yaml` 默认引用 `testdata/blocklists/adguard-dns.txt`。
列表不存在时 pipeline 会 log warn 后跳过，不影响启动。

## hosts 文件

不要把 `/etc/hosts` 风格的 `0.0.0.0 domain` 文件喂给 `filters.blocklists`
—— filter 包只解析 AdBlock 规则。这类文件如果将来支持，会作为 zone 的
另一种输入格式归到 `domains` 那一侧。

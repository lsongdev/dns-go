#!/usr/bin/env bash
# scripts/smoke.sh — 端到端冒烟测试 dns-go pipeline。
#
# 启动一份 dns-go 实例（监听 127.0.0.1:$PORT），跑一组 dig 查询,
# 校验响应是否符合预期: 本地 zone / filter 阻断 / 上游 / 缓存。
#
# 用法:
#   ./scripts/smoke.sh                # 默认端口 15353
#   PORT=15400 ./scripts/smoke.sh     # 自定义端口
#
# 依赖: dig (bind-tools / dnsutils)、go (用于 go run)、curl (下载列表)

set -euo pipefail

PORT="${PORT:-15353}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$(mktemp -t dns-go-smoke.log.XXXXXX)"
CFG="$(mktemp -t dns-go-smoke.yaml.XXXXXX)"
PASS=0
FAIL=0

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$LOG" "$CFG"
}
trap cleanup EXIT

# 写入临时配置, 引用 testdata/。AdGuard 列表不存在不影响启动 (pipeline 会 log warn)。
cat > "$CFG" <<EOF
listens:
  - type: udp
    addr: "127.0.0.1:${PORT}"

cache:
  enabled: true
  min_ttl: 60s
  max_ttl: 24h
  negative_ttl: 60s
  max_entries: 1000

domains:
  - domain: example.com
    zone_file: ${ROOT}/testdata/zones/example.com.zone

proxy:
  strategy: failover
  upstreams:
    - addr: "https://doh.pub/dns-query"   # DoH
      type: doh
      timeout: 5s
    - addr: "1.1.1.1:53"
      type: udp
      timeout: 3s

filters:
  blocklists:
    - name: "AdGuard DNS filter"
      file: "${ROOT}/testdata/blocklists/adguard-dns.txt"
      enabled: true
  rules:
    - "||doubleclick.net^"
EOF

cd "$ROOT"
echo "▶ starting dns-go on 127.0.0.1:${PORT}..."
go run ./cmd/dns-go --config "$CFG" >"$LOG" 2>&1 &
SERVER_PID=$!

# 等服务起来 (最多 5s)
for i in $(seq 1 50); do
    if dig "@127.0.0.1" -p "$PORT" example.com +short +time=1 +tries=1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# 服务起不来就早停
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "✘ server failed to start, log:"
    cat "$LOG"
    exit 1
fi

# expect <name> <type> <pattern>: 期望 dig 输出包含正则 <pattern>
expect() {
    local name="$1" qtype="$2" pattern="$3"
    local got
    got=$(dig "@127.0.0.1" -p "$PORT" "$name" "$qtype" +short +time=2 +tries=1 2>/dev/null || true)
    if echo "$got" | grep -qE "$pattern"; then
        printf "  ✓ %-30s %-6s -> %s\n" "$name" "$qtype" "$(echo "$got" | head -1)"
        PASS=$((PASS+1))
    else
        printf "  ✘ %-30s %-6s -> %q (want match: %q)\n" "$name" "$qtype" "$got" "$pattern"
        FAIL=$((FAIL+1))
    fi
}

echo
echo "[1] local zone (BIND zone_file)"
expect "nas.example.com"     A    "^192\\.168\\.1\\.100$"
expect "mail.example.com"    A    "^192\\.168\\.1\\.2$"
expect "printer.example.com" A    "^192\\.168\\.1\\.101$"
expect "router.example.com"  A    "^192\\.168\\.1\\.1$"
expect "example.com"         A    "^192\\.168\\.1\\.1$"
expect "example.com"         AAAA "^fd00::1$"

echo
echo "[2] filter block (rules + AdGuard list if available)"
expect "doubleclick.net"     A    "^0\\.0\\.0\\.0$"
expect "ad.doubleclick.net"  A    "^0\\.0\\.0\\.0$"

echo
echo "[3] proxy upstream (real DNS lookup)"
expect "cloudflare.com"      A    "^[0-9.]+$"

echo
echo "[4] cache hit (re-query should still resolve)"
expect "cloudflare.com"      A    "^[0-9.]+$"

echo
echo "──────── result ────────"
echo "  pass: $PASS"
echo "  fail: $FAIL"
echo
if [[ $FAIL -gt 0 ]]; then
    echo "server log:"
    cat "$LOG" | sed 's/^/  /'
    exit 1
fi

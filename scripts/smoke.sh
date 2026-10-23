#!/usr/bin/env bash
# scripts/smoke.sh — 端到端冒烟测试。
#
# 启动一份转发模式的 dns-go（监听 127.0.0.1:$PORT 的 UDP+TCP），用 dig 校验:
# static zone / transparent 覆盖 / 过滤 / 上游+缓存 / 协议行为(截断、EDNS、BADVERS、AXFR)。
#
# 用法:
#   ./scripts/smoke.sh                # 默认端口 15353
#   PORT=15400 ./scripts/smoke.sh     # 自定义端口
#
# 依赖: dig、go。[2] 和 [4] 需要访问公网上游。

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

long() { printf "$1%.0s" $(seq 1 200); }

# AdGuard 列表不存在不影响启动 (只记录日志)，[3] 由内联规则兜底。
cat > "$CFG" <<YAML
mode: forwarding
listens:
  - type: udp
    addr: "127.0.0.1:${PORT}"
  - type: tcp
    addr: "127.0.0.1:${PORT}"

upstreams:
  - type: doh
    addr: "https://doh.pub/dns-query"
  - type: udp
    addr: "1.1.1.1:53"
    timeout: 3s

cache:
  enabled: true

domains:
  - domain: example.com
    zone_file: ${ROOT}/testdata/zones/example.com.zone
  - domain: example.net
    kind: transparent
    records:
      - 'dev 60 IN A 192.168.1.50'
      - 'big 60 IN TXT "$(long x)"'
      - 'big 60 IN TXT "$(long y)"'
      - 'big 60 IN TXT "$(long z)"'

filters:
  lists:
    - name: adguard-dns
      file: "${ROOT}/testdata/blocklists/adguard-dns.txt"
  rules:
    - "||doubleclick.net^"
YAML

cd "$ROOT"
echo "▶ starting dns-go on 127.0.0.1:${PORT}..."
go build -o "${LOG}.bin" ./cmd/dns-go
"${LOG}.bin" -config "$CFG" >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'cleanup; rm -f "${LOG}.bin"' EXIT

for _ in $(seq 1 50); do
    if dig "@127.0.0.1" -p "$PORT" nas.example.com +short +time=1 +tries=1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "✘ server failed to start, log:"
    cat "$LOG"
    exit 1
fi

# expect <name> <type> <pattern>: dig +short 的第一行或任意行匹配 <pattern>
expect() {
    local name="$1" qtype="$2" pattern="$3" got
    got=$(dig "@127.0.0.1" -p "$PORT" "$name" "$qtype" +short +time=3 +tries=1 2>/dev/null || true)
    if echo "$got" | grep -qE "$pattern"; then
        printf "  ✓ %-28s %-5s -> %s\n" "$name" "$qtype" "$(echo "$got" | head -1)"
        PASS=$((PASS+1))
    else
        printf "  ✘ %-28s %-5s -> %q (want match: %q)\n" "$name" "$qtype" "$got" "$pattern"
        FAIL=$((FAIL+1))
    fi
}

# check <description> <pattern> <dig args...>: 完整 dig 输出匹配 <pattern>
check() {
    local desc="$1" pattern="$2"
    shift 2
    if dig "@127.0.0.1" -p "$PORT" +time=3 +tries=1 "$@" 2>/dev/null | grep -qE "$pattern"; then
        printf "  ✓ %s\n" "$desc"
        PASS=$((PASS+1))
    else
        printf "  ✘ %s (want match: %q)\n" "$desc" "$pattern"
        FAIL=$((FAIL+1))
    fi
}

echo
echo "[1] static zone (BIND zone_file)"
expect "nas.example.com"     A    '^192\.168\.1\.100$'
expect "mail.example.com"    A    '^192\.168\.1\.2$'
expect "example.com"         AAAA '^fd00::1$'
check  "unknown name in a static zone -> NXDOMAIN" 'status: NXDOMAIN' missing.example.com

echo
echo "[2] transparent override"
expect "dev.example.net"     A    '^192\.168\.1\.50$'
expect "www.example.net"     A    '^[0-9.]+$'

echo
echo "[3] filter"
expect "doubleclick.net"     A    '^0\.0\.0\.0$'
expect "ad.doubleclick.net"  AAAA '^::$'

echo
echo "[4] upstream + cache"
expect "cloudflare.com"      A    '^[0-9.]+$'
expect "cloudflare.com"      A    '^[0-9.]+$'

echo
echo "[5] protocol"
check "no EDNS: truncated to 512 with TC"  'flags: qr aa tc'  +noedns +ignore big.example.net TXT
check "TCP: complete answer"               'ANSWER: 3,'       +tcp big.example.net TXT
check "OPT echoed with udp 1232"           'udp: 1232'        nas.example.com
check "EDNS version 1 -> BADVERS"          'status: BADVERS'  +edns=1 +noednsneg nas.example.com
check "AXFR refused"                       'Transfer failed'  example.com AXFR

echo
echo "──────── result ────────"
echo "  pass: $PASS"
echo "  fail: $FAIL"
echo
if [[ $FAIL -gt 0 ]]; then
    echo "server log:"
    sed 's/^/  /' "$LOG"
    exit 1
fi

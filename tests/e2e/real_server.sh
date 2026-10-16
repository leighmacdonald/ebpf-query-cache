#!/usr/bin/env bash
# Phase 8: validation against real TF2 dedicated servers.
#
# Same veth/netns harness as run.sh: the client sits in the netns (a "remote"
# client, in the same position a Steam server browser entry would sit in),
# the a2scache program is attached on the host-side veth ingress, and the
# backends are the real srcds instances on this host.
#
# The cached address is the attached veth's IP ($IP_H), not another of the
# host's IPs: srcds binds 0.0.0.0, so a pass-through reply to the netns
# client leaves via the veth and the kernel sources it with the veth's
# address — the client must target that address for the dance to complete.
# (Same reason 127.0.0.1 cannot be a backend: the Source engine ignores
# A2S with a 127/8 source.)
#
# Verifies:
#   1. INFO/PLAYER challenge dances served from cache for two real TF2
#      servers (per-(ip,port) isolation: distinct names/maps)
#   2. cached INFO is byte-identical to the server's direct response
#   3. stats: cache hits with zero pass-through/drops during the cached
#      window; stale entry -> both request datagrams pass through
#   4. tracker/browser path unaffected: the program only intercepts
#      ingress on the test veth, so server<->tracker traffic on the host's
#      main interface is untouched; both servers keep answering direct
#      queries afterwards
#
# Best with idle servers (0 players): player lists that change between
# queries would make the byte-comparison flaky.
#
# Usage: real_server.sh [PORT1 PORT2]   (default 27015 27025)
# Requires: root, python3, both srcds instances running.
set -euo pipefail
export RUST_LOG=${RUST_LOG:-info}

PORT1=${1:-27015}
PORT2=${2:-27025}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

BIN=${A2SCACHE_BIN:-}
if [ -z "$BIN" ]; then
	for c in "$ROOT/result/bin/a2scache" "$ROOT/target/release/a2scache"; do
		if [ -x "$c" ]; then
			BIN=$c
			break
		fi
	done
fi
[ -n "$BIN" ] || {
	echo "real: no a2scache binary (set A2SCACHE_BIN)" >&2
	exit 1
}
echo "real: using binary $BIN"

NS=a2sctest
VH=a2s-h
VT=a2s-t
IP_H=10.200.1.1
IP_T=10.200.1.2
TTL=8

# BPF_OBJ_PIN requires the parent to be a bpffs mount.
PINS=/sys/fs/bpf/a2scache-real
SCRATCH=$(mktemp -d /tmp/a2scache-real.XXXXXX)
DAEMON_PID=""

cleanup() {
	local rc=$?
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
	wait 2>/dev/null || true
	"$BIN" clean "$VH" --pin-dir "$PINS" >/dev/null 2>&1 || true
	rm -rf "$PINS" 2>/dev/null || true
	ip link del "$VH" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	rm -rf "$SCRATCH"
	return "$rc"
}
trap cleanup EXIT

PASS=0
FAIL=0
check() {
	local desc=$1
	shift
	if "$@"; then
		echo "  PASS: $desc"
		PASS=$((PASS + 1))
	else
		echo "  FAIL: $desc"
		FAIL=$((FAIL + 1))
	fi
}

check_client() {
	local desc=$1
	shift
	if ip netns exec "$NS" python3 "$SCRIPT_DIR/client.py" "$@"; then
		echo "  PASS: $desc"
		PASS=$((PASS + 1))
	else
		echo "  FAIL: $desc"
		FAIL=$((FAIL + 1))
	fi
}

snap_stats() { "$BIN" stats --pin-dir "$PINS" --json >"$1"; }

delta() {
	python3 -c '
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
print(b[sys.argv[3]] - a[sys.argv[3]])' "$1" "$2" "$3"
}

name_of() { sed -n "s/^info-ok name='\([^']*\)'.*/\1/p" <<<"$1" | head -1; }
map_of() { sed -n "s/^info-ok .*map='\([^']*\)'.*/\1/p" <<<"$1" | head -1; }

ip netns del "$NS" 2>/dev/null || true
ip link del "$VH" 2>/dev/null || true
rm -rf "$PINS" 2>/dev/null || true

echo "real: topology $VH ($IP_H/24) <-> $VT (netns $NS, $IP_T/24)"
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VT"
ip link set "$VT" netns "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "$IP_T/24" dev "$VT"
ip netns exec "$NS" ip link set "$VT" up
ip netns exec "$NS" ip route add default via "$IP_H"
ip addr add "$IP_H/24" dev "$VH"
ip link set "$VH" up

echo "real: baseline direct queries (host -> $IP_H, no BPF)"
BASE1=$(python3 "$SCRIPT_DIR/client.py" info "$IP_H:$PORT1" \
	--hex-out "$SCRATCH/base1.info" --timeout 5)
BASEP1=$(python3 "$SCRIPT_DIR/client.py" players "$IP_H:$PORT1" \
	--hex-out "$SCRATCH/base1.players" --timeout 5)
BASE2=$(python3 "$SCRIPT_DIR/client.py" info "$IP_H:$PORT2" \
	--hex-out "$SCRATCH/base2.info" --timeout 5)
echo "  $BASE1"
echo "  $BASE2"
NAME1=$(name_of "$BASE1")
NAME2=$(name_of "$BASE2")
[ -n "$NAME1" ] && [ -n "$NAME2" ] || {
	echo "real: could not parse server names from baseline" >&2
	exit 1
}

echo "real: attach + daemon (backends $IP_H:$PORT1, $IP_H:$PORT2, ttl ${TTL}s)"
"$BIN" attach "$VH" --pin-dir "$PINS" --ttl-sec "$TTL"

cat >"$SCRATCH/daemon.toml" <<EOF
[bpf]
pin_dir = "$PINS"

[defaults]
ttl_secs = $TTL
interval_secs = 2
timeout_ms = 3000

[[server]]
ip = "$IP_H"
port = $PORT1

[[server]]
ip = "$IP_H"
port = $PORT2
EOF

"$BIN" serve --config "$SCRATCH/daemon.toml" >"$SCRATCH/daemon.log" 2>&1 &
DAEMON_PID=$!

warm=""
for _ in $(seq 1 60); do
	sleep 1
	ni=$("$BIN" status --pin-dir "$PINS" 2>/dev/null | grep -c 'info_len=[1-9]' || true)
	if [ "${ni:-0}" -ge 2 ]; then
		warm=yes
		break
	fi
	kill -0 "$DAEMON_PID" 2>/dev/null || break
done
if [ -z "$warm" ]; then
	echo "real: cache never warmed (daemon log):" >&2
	cat "$SCRATCH/daemon.log" >&2
	exit 1
fi
echo "real: both real servers cached"

# Stop the daemon: the BPF keeps serving the fresh entries, and once they
# go stale the stale-scenario below gets a clean pass-through (nothing
# re-caches).
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo "real: cached queries from the netns (through the BPF)"
snap_stats "$SCRATCH/s1"
check_client "INFO :$PORT1 served from cache, name matches" \
	info "$IP_H:$PORT1" --expect-name "$NAME1" --hex-out "$SCRATCH/cache1.info"
check_client "PLAYERS :$PORT1 served from cache" \
	players "$IP_H:$PORT1" --hex-out "$SCRATCH/cache1.players"
check_client "INFO :$PORT2 served from cache, name matches (isolation)" \
	info "$IP_H:$PORT2" --expect-name "$NAME2" --hex-out "$SCRATCH/cache2.info"
check_client "PLAYERS :$PORT2 served from cache" \
	players "$IP_H:$PORT2" --hex-out "$SCRATCH/cache2.players"
check_client "repeat INFO :$PORT1 still cached (idempotent)" \
	info "$IP_H:$PORT1" --expect-name "$NAME1"
snap_stats "$SCRATCH/s2"

d_si=$(delta "$SCRATCH/s1" "$SCRATCH/s2" served_info)
d_sp=$(delta "$SCRATCH/s1" "$SCRATCH/s2" served_player)
d_pt=$(delta "$SCRATCH/s1" "$SCRATCH/s2" pass_through)
echo "real: cached window stats served_info=+$d_si served_player=+$d_sp pass_through=+$d_pt"

check "INFO served from cache (>=2)" test "$d_si" -ge 2
check "PLAYERS served from cache (>=2)" test "$d_sp" -ge 2
check "no pass-through in cached window" test "$d_pt" -eq 0
check "no drops" test "$(python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))
print(sum(b[k] for k in b if k.startswith("dropped_")))' "$SCRATCH/s2")" -eq 0
check "per-(ip,port) isolation: distinct servers" \
	test "$(map_of "$BASE1")" != "$(map_of "$BASE2")"
check "cached INFO :$PORT1 byte-identical to direct" \
	cmp -s "$SCRATCH/base1.info" "$SCRATCH/cache1.info"

echo "real: stale entry -> pass-through to the real server"
sleep $((TTL + 2))
snap_stats "$SCRATCH/s3"
check_client "stale INFO :$PORT1 passed through to the real server" \
	info "$IP_H:$PORT1" --expect-name "$NAME1" --timeout 10
snap_stats "$SCRATCH/s4"
# A2S INFO dance = two request datagrams (unchallenged + challenged).
check "both request datagrams passed through" \
	test "$(delta "$SCRATCH/s3" "$SCRATCH/s4" pass_through)" -eq 2

echo "real: tracker/browser path unaffected (direct queries after test)"
check "server 1 still answers direct queries" \
	python3 "$SCRIPT_DIR/client.py" info "$IP_H:$PORT1" --expect-name "$NAME1"
check "server 2 still answers direct queries" \
	python3 "$SCRIPT_DIR/client.py" info "$IP_H:$PORT2" --expect-name "$NAME2"

echo "real: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

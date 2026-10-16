#!/usr/bin/env bash
# e2e harness: veth + netns topology with fake TF2 backends, the BPF program
# attached on the host-side veth ingress, and the refresh daemon warming the
# cache. Scenarios:
#   1. per-(ip,port) isolation (two backends, distinct payloads)
#   2. challenge dance fully served from cache (backend counters stay flat)
#   3. fragmented (FE FF FF FF) PLAYER response cached and re-emitted as one
#      datagram
#   4. stale entry -> pass-through to the real backend
#   5. backend A down -> B unaffected (daemon keeps B warm, A fails)
#   6. rate-limit burst -> drops + stats (shared per-source-IP bucket)
#
# Requires: root (CAP_BPF/CAP_NET_ADMIN), kernel >= 5.2 (BTF + netlink
# clsact attach), python3, and a mounted bpffs at /sys/fs/bpf (pins).
# The a2scache binary is located via $A2SCACHE_BIN or the usual build
# outputs.
set -euo pipefail

# env_logger defaults to error-level without RUST_LOG; the harness greps the
# daemon log for info/warn lines.
export RUST_LOG=${RUST_LOG:-info}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

[ "$(id -u)" = 0 ] || {
	echo "e2e: must run as root (CAP_BPF/CAP_NET_ADMIN)" >&2
	exit 1
}

KERN=$(uname -r)
if ! [ "$(printf '%s\n5.2\n' "$KERN" | sort -V | head -1)" = "5.2" ]; then
	echo "e2e: kernel $KERN < 5.2 (BTF + netlink clsact attach)" >&2
	exit 1
fi

BIN=${A2SCACHE_BIN:-}
if [ -z "$BIN" ]; then
	for c in "$REPO_ROOT/.tmp/cargo-target/release/a2scache" "$REPO_ROOT/result/bin/a2scache"; do
		if [ -x "$c" ]; then
			BIN=$c
			break
		fi
	done
fi
[ -n "$BIN" ] || {
	echo "e2e: no a2scache binary (set A2SCACHE_BIN)" >&2
	exit 1
}
echo "e2e: using binary $BIN"

NS=a2sctest
VH=a2s-h
VT=a2s-t
IP_H=10.200.1.1
IP_T=10.200.1.2
# Ports deliberately distinct from 27015/27016: a real srcds may bind
# 0.0.0.0:27015 on the same host.
PORT_A=27115
PORT_B=27116
TTL=8

SCRATCH=$(mktemp -d /tmp/a2scache-e2e.XXXXXX)
# BPF_OBJ_PIN requires the parent directory to be a bpffs mount, so the pin
# dir must live under /sys/fs/bpf (not the /tmp scratch dir).
PINS=/sys/fs/bpf/a2scache-e2e
DAEMON_PID=""
FAKE_A_PID=""
FAKE_B_PID=""

cleanup() {
	local rc=$?
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
	[ -n "$FAKE_A_PID" ] && kill "$FAKE_A_PID" 2>/dev/null || true
	[ -n "$FAKE_B_PID" ] && kill "$FAKE_B_PID" 2>/dev/null || true
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

# Run the client inside the netns; record pass/fail (safe under set -e).
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

stop_daemon() {
	if [ -n "$DAEMON_PID" ]; then
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
		DAEMON_PID=""
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

cnt() { cat "$1" 2>/dev/null || echo 0; }

echo "e2e: cleaning stale smoke-test state (a2ssmoke netns / veth-h)"
ip netns del a2ssmoke 2>/dev/null || true
ip link del veth-h 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true
ip link del "$VH" 2>/dev/null || true

echo "e2e: building topology: $VH (host, $IP_H/24) <-> $VT (netns $NS, $IP_T/24)"
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VT"
ip link set "$VT" netns "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "$IP_T/24" dev "$VT"
ip netns exec "$NS" ip link set "$VT" up
ip netns exec "$NS" ip route add default via "$IP_H"
ip addr add "$IP_H/24" dev "$VH"
ip link set "$VH" up

echo "e2e: starting fake TF2 backends on $IP_H"
python3 "$SCRIPT_DIR/fake_server.py" --bind "$IP_H" --port "$PORT_A" \
	--name FakeServerAlpha --players 2 --player-prefix Alpha \
	--counter "$SCRATCH/counter-a" >"$SCRATCH/fake-a.log" 2>&1 &
FAKE_A_PID=$!
python3 "$SCRIPT_DIR/fake_server.py" --bind "$IP_H" --port "$PORT_B" \
	--name FakeServerBeta --players 30 --player-prefix Beta --fragment --chunk 300 \
	--counter "$SCRATCH/counter-b" >"$SCRATCH/fake-b.log" 2>&1 &
FAKE_B_PID=$!
sleep 0.5
if ! kill -0 "$FAKE_A_PID" 2>/dev/null || ! kill -0 "$FAKE_B_PID" 2>/dev/null; then
	echo "e2e: fake server failed to start"
	cat "$SCRATCH"/fake-*.log
	exit 1
fi

echo "e2e: attaching a2scache on $VH (ttl ${TTL}s)"
"$BIN" attach "$VH" --pin-dir "$PINS" --ttl-sec "$TTL"

cat >"$SCRATCH/daemon.toml" <<EOF
[bpf]
pin_dir = "$PINS"

[defaults]
ttl_secs = $TTL
interval_secs = 2
timeout_ms = 1000
per_ip_capacity = 5000
per_ip_refill_per_s = 5000
global_capacity = 100000
global_refill_per_s = 50000

[[server]]
ip = "$IP_H"
port = $PORT_A

[[server]]
ip = "$IP_H"
port = $PORT_B
EOF

echo "e2e: starting refresh daemon"
"$BIN" serve --config "$SCRATCH/daemon.toml" >"$SCRATCH/daemon.log" 2>&1 &
DAEMON_PID=$!

wait_warm() {
	local i out ni np
	for i in $(seq 1 60); do
		out=$("$BIN" status --pin-dir "$PINS" 2>/dev/null || true)
		ni=$(grep -c 'info_len=[1-9]' <<<"$out" || true)
		np=$(grep -c 'player_len=[1-9]' <<<"$out" || true)
		if [ "${ni:-0}" -ge 2 ] && [ "${np:-0}" -ge 2 ]; then
			echo "e2e: cache warmed after ~$((i / 2))s"
			return 0
		fi
		sleep 0.5
	done
	echo "e2e: cache never warmed"
	"$BIN" status --pin-dir "$PINS" || true
	tail -20 "$SCRATCH/daemon.log"
	return 1
}
wait_warm

# ---------------------------------------------------------------------------
echo
echo "== 1-3. challenge dance served from cache (isolation, fragments)"
stop_daemon
sleep 0.3
CA=$(cnt "$SCRATCH/counter-a")
CB=$(cnt "$SCRATCH/counter-b")
snap_stats "$SCRATCH/s1"

check_client "INFO A served from cache (name/appid/players)" info "$IP_H:$PORT_A" \
	--expect-name FakeServerAlpha --players-count 2
check_client "PLAYER A served from cache" players "$IP_H:$PORT_A" \
	--players-count 2 --name-prefix Alpha --expect-single
check_client "INFO B served from cache (distinct entry)" info "$IP_H:$PORT_B" \
	--expect-name FakeServerBeta --players-count 30
check_client "PLAYER B fragmented response re-emitted as one datagram" players \
	"$IP_H:$PORT_B" --players-count 30 --name-prefix Beta --expect-single

snap_stats "$SCRATCH/s2"
check "served_info == 2" test "$(delta "$SCRATCH/s1" "$SCRATCH/s2" served_info)" -eq 2
check "served_player == 2" test "$(delta "$SCRATCH/s1" "$SCRATCH/s2" served_player)" -eq 2
check "sent_challenge_info == 2" test "$(delta "$SCRATCH/s1" "$SCRATCH/s2" sent_challenge_info)" -eq 2
check "sent_challenge_player == 2" test "$(delta "$SCRATCH/s1" "$SCRATCH/s2" sent_challenge_player)" -eq 2
check "pass_through == 0 (cache hid everything)" test "$(delta "$SCRATCH/s1" "$SCRATCH/s2" pass_through)" -eq 0
check "no drops" test "$(delta "$SCRATCH/s1" "$SCRATCH/s2" dropped_rate_ip)" -eq 0
check "backend A saw nothing (counter flat)" test "$(cnt "$SCRATCH/counter-a")" -eq "$CA"
check "backend B saw nothing (counter flat)" test "$(cnt "$SCRATCH/counter-b")" -eq "$CB"

# ---------------------------------------------------------------------------
echo
echo "== 4. stale entry -> pass-through"
sleep $((TTL + 1))
snap_stats "$SCRATCH/s3"
check_client "stale INFO A passed through and answered by backend" info \
	"$IP_H:$PORT_A" --expect-name FakeServerAlpha --players-count 2
snap_stats "$SCRATCH/s4"
check "2 request datagrams passed through" test "$(delta "$SCRATCH/s3" "$SCRATCH/s4" pass_through)" -eq 2
check "stale challenge drop counted" test "$(delta "$SCRATCH/s3" "$SCRATCH/s4" dropped_stale)" -eq 1
check "backend A served exactly one answer" test "$(cnt "$SCRATCH/counter-a")" -eq $((CA + 1))

# ---------------------------------------------------------------------------
echo
echo "== 5. backend A down -> B unaffected"
"$BIN" serve --config "$SCRATCH/daemon.toml" >"$SCRATCH/daemon2.log" 2>&1 &
DAEMON_PID=$!
wait_warm
kill "$FAKE_A_PID"
FAKE_A_PID=""
# Let the daemon fail A (entry goes stale) while B keeps refreshing.
sleep $((TTL + 1))
check "daemon logged A refresh failures" grep -q "10.200.1.1:$PORT_A] refresh failed" "$SCRATCH/daemon2.log"
check "daemon kept refreshing B" grep -q "10.200.1.1:$PORT_B] refreshed" "$SCRATCH/daemon2.log"
stop_daemon
sleep 0.3
CA=$(cnt "$SCRATCH/counter-a")
CB=$(cnt "$SCRATCH/counter-b")
snap_stats "$SCRATCH/s5"

check_client "INFO B still served after A died" info "$IP_H:$PORT_B" \
	--expect-name FakeServerBeta --players-count 30
check_client "PLAYER B still served (single datagram) after A died" players \
	"$IP_H:$PORT_B" --players-count 30 --name-prefix Beta --expect-single
check_client "INFO A now times out (backend dead, entry stale)" timeout "$IP_H:$PORT_A"
snap_stats "$SCRATCH/s6"
check "B fully cached (counter flat)" test "$(cnt "$SCRATCH/counter-b")" -eq "$CB"
check "A stays dead (counter flat)" test "$(cnt "$SCRATCH/counter-a")" -eq "$CA"
check "A query passed through (1 datagram)" test "$(delta "$SCRATCH/s5" "$SCRATCH/s6" pass_through)" -eq 1
check "B queries served from cache" test "$(delta "$SCRATCH/s5" "$SCRATCH/s6" served_info)" -eq 1
check "no B drops" test "$(delta "$SCRATCH/s5" "$SCRATCH/s6" dropped_stale)" -eq 0

# ---------------------------------------------------------------------------
echo
echo "== 6. rate-limit burst (unknown port, 5 tokens @ 5/s per source IP)"
snap_stats "$SCRATCH/s7"
ip netns exec "$NS" python3 "$SCRIPT_DIR/client.py" burst "$IP_H:27099" 25
sleep 0.5
snap_stats "$SCRATCH/s8"
DRIP=$(delta "$SCRATCH/s7" "$SCRATCH/s8" dropped_rate_ip)
PT=$(delta "$SCRATCH/s7" "$SCRATCH/s8" pass_through)
UK=$(delta "$SCRATCH/s7" "$SCRATCH/s8" unknown_key)
check "burst seen by classifier (unknown_key == 25)" test "$UK" -eq 25
check "burst dropped at rate limit (>= 15 drops)" test "$DRIP" -ge 15
check "burst limited pass-through (<= 10)" test "$PT" -le 10

# ---------------------------------------------------------------------------
echo
echo "e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

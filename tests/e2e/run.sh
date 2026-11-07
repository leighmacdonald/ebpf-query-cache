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
#   7. per-instance TTL: a short-ttl instance goes stale (pass-through) while
#      a long-ttl instance stays fresh (served from cache)
#   8. scale: N game instances (fake backends) cached, isolated, and served
#      from cache simultaneously; `status` reports count/capacity + names
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
# Backend ports. Deliberately distinct from 27015/27016 first (a real srcds
# may bind 0.0.0.0:27015 on the same host). Host firewalls may drop INPUT
# UDP to arbitrary ports (NixOS default-deny), which would silently kill
# scenario 4's pass-through replies, so the harness probes each candidate
# pair with a real datagram dance before using it (below); the fallback
# pair uses the standard A2S port and the GBANS port, the ones such
# firewalls typically whitelist for game-adjacent traffic.
PORT_A=27115
PORT_B=27116
PORT_PAIRS=("27115 27116" "27015 27715")
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
	[ -n "${SCALE_PIDS:-}" ] && kill $SCALE_PIDS 2>/dev/null || true
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

# PIDs of the scenario-8 scale fake servers (all killed by `cleanup`).
SCALE_PIDS=""

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

# --- port reachability probe ------------------------------------------------
# Pass-through replies from the backends traverse the host's INPUT chain. A
# host firewall that drops INPUT UDP to arbitrary ports (e.g. NixOS
# default-deny) would silently eat scenario 4's stale query. Probe each
# candidate pair with a real unchallenged-INFO dance from the netns (BPF is
# not attached yet, so this is a pure netns->veth->host-IP-stack round trip)
# and use the first pair that completes.
probe_port() {
	local port=$1 pid ok=1
	python3 "$SCRIPT_DIR/fake_server.py" --bind "$IP_H" --port "$port" \
		--name probe --players 1 --counter "$SCRATCH/probe-cnt" \
		>"$SCRATCH/probe.log" 2>&1 &
	pid=$!
	sleep 0.3
	if ! kill -0 "$pid" 2>/dev/null; then
		return 1 # bind failed (port already in use on $IP_H)
	fi
	ip netns exec "$NS" python3 "$SCRIPT_DIR/client.py" info "$IP_H:$port" \
		--timeout 2 >/dev/null 2>&1 || ok=0
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	[ "$ok" = 1 ]
}

PICKED=0
for pair in "${PORT_PAIRS[@]}"; do
	read -r PA PB <<<"$pair"
	if probe_port "$PA" && probe_port "$PB"; then
		PORT_A=$PA
		PORT_B=$PB
		PICKED=1
		break
	fi
done
[ "$PICKED" = 1 ] || {
	echo "e2e: no reachable A2S port pair (host firewall dropping INPUT UDP?)" >&2
	exit 1
}
echo "e2e: backend ports $PORT_A / $PORT_B (probe ok)"

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
	local min=${1:-2} log=${2:-"$SCRATCH/daemon.log"}
	local i out ni np
	for i in $(seq 1 60); do
		out=$("$BIN" status --pin-dir "$PINS" 2>/dev/null || true)
		ni=$(grep -c 'info_len=[1-9]' <<<"$out" || true)
		np=$(grep -c 'player_len=[1-9]' <<<"$out" || true)
		if [ "${ni:-0}" -ge "$min" ] && [ "${np:-0}" -ge "$min" ]; then
			echo "e2e: $min instance(s) warmed after ~$((i / 2))s"
			return 0
		fi
		sleep 0.5
	done
	echo "e2e: only ${ni:-0}/${min} instances warmed (need $min with INFO + PLAYER)"
	"$BIN" status --pin-dir "$PINS" || true
	tail -20 "$log"
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
echo "== 7. per-instance TTL (A short, B long)"
# Scenario 5 killed fake A; scenario 6's burst drained the per-IP
# pass-through bucket. Restart A and give the config a roomy pass-through
# budget so this scenario measures cache-vs-staleness, not rate limiting.
python3 "$SCRIPT_DIR/fake_server.py" --bind "$IP_H" --port "$PORT_A" \
	--name FakeServerAlpha --players 2 --player-prefix Alpha \
	--counter "$SCRATCH/counter-a7" >"$SCRATCH/fake-a2.log" 2>&1 &
FAKE_A_PID=$!
sleep 0.3
kill -0 "$FAKE_A_PID" 2>/dev/null
cat >"$SCRATCH/daemon-ttl.toml" <<EOF
[bpf]
pin_dir = "$PINS"

[defaults]
ttl_secs = 30
interval_secs = 1
timeout_ms = 1000
# Big pass-through bucket: the stale-A dance below must not be blocked by
# scenario 6's leftover token drain (and scenario 8 probes inherit this).
per_ip_capacity = 100000
per_ip_refill_per_s = 5000

[[server]]
ip = "$IP_H"
port = $PORT_A
ttl_secs = 2

[[server]]
ip = "$IP_H"
port = $PORT_B
ttl_secs = 30
EOF
"$BIN" serve --config "$SCRATCH/daemon-ttl.toml" >"$SCRATCH/daemon-ttl.log" 2>&1 &
DAEMON_PID=$!
wait_warm 2 "$SCRATCH/daemon-ttl.log"
# wait_warm exits as soon as entries exist; A/B may still carry the old
# 30s TTL from the earlier scenarios, so wait for A's first refresh with
# the per-instance TTL actually landing in the entry.
for i in $(seq 1 40); do
	if "$BIN" status --pin-dir "$PINS" 2>/dev/null | grep -q ":$PORT_A  .*ttl=2s"; then
		break
	fi
	sleep 0.5
done
"$BIN" status --pin-dir "$PINS" >"$SCRATCH/status-ttl.txt"
check "A entry carries its per-instance TTL (2s)" \
	grep -q ":$PORT_A  .*ttl=2s" "$SCRATCH/status-ttl.txt"
check "B entry carries its per-instance TTL (30s)" \
	grep -q ":$PORT_B  .*ttl=30s" "$SCRATCH/status-ttl.txt"
stop_daemon
sleep 3
CA=$(cnt "$SCRATCH/counter-a7")
CB=$(cnt "$SCRATCH/counter-b")
snap_stats "$SCRATCH/s9"
check_client "stale A (ttl 2s) passed through to the backend" \
	info "$IP_H:$PORT_A" --expect-name FakeServerAlpha --players-count 2 --timeout 6
snap_stats "$SCRATCH/s10"
check "both stale-A request datagrams passed through" \
	test "$(delta "$SCRATCH/s9" "$SCRATCH/s10" pass_through)" -eq 2
check "A answered by the backend (counter +1)" \
	test "$(cnt "$SCRATCH/counter-a7")" -eq $((CA + 1))
check_client "fresh B (ttl 30s) still served from cache" \
	info "$IP_H:$PORT_B" --expect-name FakeServerBeta --players-count 30
snap_stats "$SCRATCH/s11"
check "B answered from cache (backend counter flat)" \
	test "$(cnt "$SCRATCH/counter-b")" -eq "$CB"
check "B never passed-through while fresh" \
	test "$(delta "$SCRATCH/s10" "$SCRATCH/s11" pass_through)" -eq 0
check "at least one B cache hit recorded" \
	test "$(delta "$SCRATCH/s9" "$SCRATCH/s11" served_info)" -ge 1

# ---------------------------------------------------------------------------
echo
echo "== 8. scale: 8 instances cached, isolated, and served from cache"
sleep 1
SCALE_PORTS=()
for port in 27220 27221 27222 27223 27224 27225 27226 27227 \
	27061 27062 27063 27064 27065 27066 27067 27068; do
	[ "${#SCALE_PORTS[@]}" -lt 8 ] || break
	if probe_port "$port"; then SCALE_PORTS+=("$port"); fi
done
[ "${#SCALE_PORTS[@]}" -eq 8 ] || {
	echo "e2e: found only ${#SCALE_PORTS[@]} usable backend ports (need 8)" >&2
	exit 1
}
echo "e2e: scale backend ports ${SCALE_PORTS[*]}"
NAMES=(Alpha Bravo Charlie Delta Echo Foxtrot Golf Hotel)
SCALE_PIDS=""
SCALE_COUNTERS=()
for i in "${!SCALE_PORTS[@]}"; do
	port=${SCALE_PORTS[i]}
	counter="$SCRATCH/counter-s$i"
	python3 "$SCRIPT_DIR/fake_server.py" --bind "$IP_H" --port "$port" \
		--name "Scale${NAMES[i]}" --players $((3 + i)) \
		--player-prefix "S${NAMES[i]}" --counter "$counter" \
		>"$SCRATCH/fake-s$i.log" 2>&1 &
	SCALE_PIDS+="$! "
	SCALE_COUNTERS+=("$counter")
done
sleep 0.8
for pid in $SCALE_PIDS; do
	if ! kill -0 "$pid" 2>/dev/null; then
		echo "e2e: scale fake server failed to start"
		cat "$SCRATCH"/fake-s*.log
		exit 1
	fi
done
SCALE_PIDS="${SCALE_PIDS% }"

{
	echo '[bpf]'
	echo "pin_dir = \"$PINS\""
	echo '[defaults]'
	echo 'ttl_secs = 30'
	echo 'interval_secs = 2'
	echo 'timeout_ms = 1000'
	echo 'per_ip_capacity = 100000'
	echo 'per_ip_refill_per_s = 5000'
	for port in "${SCALE_PORTS[@]}"; do
		echo "[[server]]"
		echo "ip = \"$IP_H\""
		echo "port = $port"
	done
} >"$SCRATCH/daemon-scale.toml"
"$BIN" serve --config "$SCRATCH/daemon-scale.toml" >"$SCRATCH/daemon-scale.log" 2>&1 &
DAEMON_PID=$!
# 10 warmed entries: the 8 scale instances + the still-present A/B entries.
wait_warm 10 "$SCRATCH/daemon-scale.log"
# Stop the daemon before the client queries: the fakes' counters must not
# move while they are watched (scenarios 1-5 use the same pattern).
stop_daemon
sleep 0.3
SCA=()
for i in "${!SCALE_COUNTERS[@]}"; do
	SCA+=("$(cnt "${SCALE_COUNTERS[i]}")")
done

"$BIN" status --pin-dir "$PINS" >"$SCRATCH/status-scale.txt"
check "status summary shows instance count over the 4096 capacity" \
	grep -q "cache entries: 10 / 4096" "$SCRATCH/status-scale.txt"
check "status lists per-instance names" \
	grep -q "name=ScaleAlpha" "$SCRATCH/status-scale.txt"
check "status entry carries per-instance TTL" \
	grep -q "ttl=30s" "$SCRATCH/status-scale.txt"

for i in "${!SCALE_PORTS[@]}"; do
	port=${SCALE_PORTS[i]}
	check_client "scale:${port} served from cache as 'Scale${NAMES[i]}'" \
		info "$IP_H:$port" --expect-name "Scale${NAMES[i]}" \
		--players-count $((3 + i))
done

"$BIN" status --json --pin-dir "$PINS" >"$SCRATCH/status.json"
check "status --json reports all 8 instances with capacity/names" python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d["capacity"] == 4096, d
assert len(d["entries"]) == d["count"] >= 10, d  # 8 scale + backends A/B
scale = {e["name"] for e in d["entries"] if e["name"].startswith("Scale")}
want = {"ScaleAlpha", "ScaleBravo", "ScaleCharlie", "ScaleDelta",
        "ScaleEcho", "ScaleFoxtrot", "ScaleGolf", "ScaleHotel"}
assert scale == want, scale
for e in d["entries"]:
	assert e["ip"].count(".") == 3, e
	assert e["info_len"] > 0 and e["info_age_s"] is not None, e
	assert e["ttl_s"] > 0, e
' "$SCRATCH/status.json"

snap_stats "$SCRATCH/s12"
for i in "${!SCALE_PORTS[@]}"; do
	port=${SCALE_PORTS[i]}
	check_client "scale:${port} repeat INFO still served from cache" \
		info "$IP_H:$port" --expect-name "Scale${NAMES[i]}" --players-count $((3 + i))
done
snap_stats "$SCRATCH/s13"
check "8 repeat cache hits, zero pass-through" \
	test "$(delta "$SCRATCH/s12" "$SCRATCH/s13" pass_through)" -eq 0
check "8 repeat cache hits counted" \
	test "$(delta "$SCRATCH/s12" "$SCRATCH/s13" served_info)" -eq 8
for i in "${!SCALE_COUNTERS[@]}"; do
	check "scale backend ${SCALE_PORTS[i]} saw nothing (counter flat)" \
		test "$(cnt "${SCALE_COUNTERS[i]}")" -eq "${SCA[i]}"
done
stop_daemon

# ---------------------------------------------------------------------------
echo
echo "e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

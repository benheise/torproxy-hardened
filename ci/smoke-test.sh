#!/usr/bin/env bash
# Smoke test for the torproxy image, run with the same hardening as compose.yaml.
#
#   ci/smoke-test.sh IMAGE
#
#   REQUIRE_TOR=1     also require a live Tor bootstrap: the healthcheck must
#                     pass and check.torproject.org must report IsTor through
#                     the published SOCKS5 port (CI sets this)
#   TOR_TIMEOUT=300   seconds to wait for the bootstrap
set -euo pipefail

image=${1:?usage: smoke-test.sh IMAGE}
require_tor=${REQUIRE_TOR:-0}
tor_timeout=${TOR_TIMEOUT:-300}

suffix="$$-$RANDOM"
main="torproxy-smoke-$suffix"
bridge="torproxy-smoke-br-$suffix"
vol="torproxy-smoke-$suffix"
tmp=$(mktemp -d)
failures=0

cleanup() {
  docker rm -f "$main" "$bridge" >/dev/null 2>&1 || true
  docker volume rm "$vol" "$vol-br" "$vol-cfg" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
hardened=(--read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128)

# --- image metadata -----------------------------------------------------------
user=$(docker image inspect "$image" --format '{{.Config.User}}')
if [[ "$user" == "65532:65532" ]]; then pass "image user is 65532:65532"; else fail "image user is '$user'"; fi

stopsig=$(docker image inspect "$image" --format '{{.Config.StopSignal}}')
if [[ "$stopsig" == "SIGINT" ]]; then pass "stop signal is SIGINT"; else fail "stop signal is '$stopsig'"; fi

if docker run --rm --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1; then
  fail "image contains a working /bin/sh"
else
  pass "no shell in the image"
fi

label=$(docker image inspect "$image" --format '{{index .Config.Labels "dev.torproxy.arti.version"}}')
ver=$(docker run --rm --entrypoint /usr/bin/arti "$image" --version 2>/dev/null | sed -n 's/^Arti //p' | head -1 || true)
if [[ -n "$label" && "$ver" == "$label" ]]; then pass "arti $ver matches the image label"; else fail "arti '$ver' does not match label '$label'"; fi

# --- hardened start -----------------------------------------------------------
if ! docker run -d --name "$main" "${hardened[@]}" -v "$vol:/var/lib/arti" -p 127.0.0.1::9050 "$image" >/dev/null; then
  fail "container did not start"
  exit 1
fi
sleep 5
state=$(docker inspect "$main" --format '{{.State.Status}}')
if [[ "$state" == running ]]; then
  pass "runs with a read-only rootfs, no capabilities and no-new-privileges"
else
  fail "container is '$state' after start"; docker logs --tail 30 "$main" || true
  exit 1
fi

puser=$(docker top "$main" -o pid,user,args 2>/dev/null | awk 'NR > 1 && $3 ~ /arti$/ {print $2}' | head -1 || true)
if [[ "$puser" == 65532 ]]; then pass "arti runs as UID 65532"; else fail "arti runs as '$puser'"; fi

port=$(docker port "$main" 9050/tcp | head -1 | sed 's/.*://')
greeting=$(python3 - "$port" 2>/dev/null <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.sendall(b"\x05\x01\x00")          # SOCKS5, one method: no authentication
print(s.recv(2).hex())
PY
) || greeting="no answer"
if [[ "$greeting" == 0500 ]]; then pass "SOCKS5 handshake on 9050"; else fail "SOCKS5 handshake returned '$greeting'"; fi

# --- live Tor -----------------------------------------------------------------
if [[ "$require_tor" == 1 ]]; then
  deadline=$((SECONDS + tor_timeout)); hc=""
  until hc=$(docker exec "$main" /usr/bin/healthcheck 2>&1); do
    if (( SECONDS >= deadline )); then break; fi
    sleep 10
  done
  if [[ "$hc" == healthy:* ]]; then
    pass "Tor bootstrap and in-container healthcheck ($hc, ${SECONDS}s)"
    istor=$(curl -sS --max-time 60 --socks5-hostname "127.0.0.1:$port" https://check.torproject.org/api/ip | jq -r '.IsTor' || true)
    if [[ "$istor" == true ]]; then pass "host client via socks5h reports IsTor=true"; else fail "host client via socks5h: IsTor='$istor'"; fi
  else
    fail "no Tor connectivity within ${tor_timeout}s: $hc"
    docker logs --tail 30 "$main" || true
  fi
else
  echo "SKIP  live Tor bootstrap (set REQUIRE_TOR=1)"
fi

# --- shutdown and restart -----------------------------------------------------
t0=$(date +%s%N)
docker stop -t 10 "$main" >/dev/null
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
code=$(docker inspect "$main" --format '{{.State.ExitCode}}')
if [[ "$code" == 0 && "$ms" -lt 5000 ]]; then pass "clean stop in ${ms} ms (exit 0)"; else fail "stop took ${ms} ms, exit $code"; fi

docker start "$main" >/dev/null
sleep 5
if [[ "$(docker inspect "$main" --format '{{.State.Status}}')" == running ]]; then
  pass "restarts on the existing data volume"
else
  fail "restart on the existing data volume"; docker logs --tail 20 "$main" || true
fi
docker stop -t 10 "$main" >/dev/null

# --- bridges: arti launches lyrebird ------------------------------------------
# TEST-NET addresses: nothing connects; this only proves the PT launch path.
cat > "$tmp/bridges.toml" <<'EOF'
[bridges]
enabled = true
bridges = [
  "obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
]

[[bridges.transports]]
protocols = ["obfs4", "webtunnel"]
path = "/usr/bin/lyrebird"
run_on_startup = false
EOF
chmod 0644 "$tmp/bridges.toml"
# Arti only trusts config files owned by root or by its own user (65532); a
# file created with sudoedit on the host is root-owned. A file made by this
# script belongs to whoever runs it (UID 1001 on GitHub runners), so stream it
# into a volume as a tar archive with owner 0:0. docker cp -a applies the
# ownership (the image maps it to its user, 65532), no sudo needed.
docker volume create "$vol-cfg" >/dev/null
helper=$(docker create -v "$vol-cfg:/cfg" "$image")
tar --owner=0 --group=0 --numeric-owner -C "$tmp" -cf - bridges.toml | docker cp -a - "$helper:/cfg/"
docker rm "$helper" >/dev/null
launched=0
if ! docker run -d --name "$bridge" "${hardened[@]}" -v "$vol-br:/var/lib/arti" \
  -v "$vol-cfg:/etc/arti/arti.d:ro" "$image" >/dev/null; then
  echo "bridge test container did not start"
fi
for _ in $(seq 1 30); do
  if docker logs "$bridge" 2>&1 | grep -q 'Successfully launched PT'; then launched=1; break; fi
  [[ "$(docker inspect "$bridge" --format '{{.State.Status}}' 2>/dev/null)" == running ]] || break
  sleep 1
done
if (( launched )) && docker top "$bridge" -o pid,user,args 2>/dev/null | grep -q '/usr/bin/lyrebird'; then
  pass "bridges config starts lyrebird as a managed transport"
else
  fail "lyrebird not started for bridges"; docker logs --tail 20 "$bridge" || true
fi

echo
if (( failures )); then echo "smoke test: $failures check(s) failed"; exit 1; fi
echo "smoke test: all checks passed"

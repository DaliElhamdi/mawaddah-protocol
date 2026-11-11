#!/usr/bin/env bash
# The Dart relay client against the real relay: starts the Worker with
# `wrangler dev` (local runtime, fresh empty storage, no network needed),
# runs packages/mawaddah_protocol/test/relay/relay_integration_test.dart
# against it, then stops it.
# Usage: scripts/relay-integration.sh        (port: RELAY_PORT, default 8799)
set -u
cd "$(dirname "$0")/.."
port="${RELAY_PORT:-8799}"
url="http://127.0.0.1:$port"

for tool in dart npx curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "   FAIL: $tool is required"; exit 1; }
done
if curl -s -m 1 -o /dev/null "$url/health"; then
  echo "   FAIL: something already answers on port $port (set RELAY_PORT)"; exit 1
fi

work=$(mktemp -d)
pid=""
stop() {
  if [ -n "$pid" ]; then
    # wrangler starts workerd as a child: stop the whole process group.
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
    # Still there after 5 s: force it.
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  fi
  rm -rf "$work"
}
trap stop EXIT
trap 'exit 130' INT TERM

[ -d relay/node_modules ] || (cd relay && npm ci --silent) || { echo "   FAIL: npm ci"; exit 1; }

# setsid: own process group, so `stop` reaches workerd too.
(cd relay && WRANGLER_SEND_METRICS=false exec setsid npx wrangler dev \
  --ip 127.0.0.1 --port "$port" --persist-to "$work/state" --log-level warn) \
  >"$work/wrangler.log" 2>&1 &
pid=$!

up=0
for _ in $(seq 1 120); do
  if curl -s -m 1 "$url/health" | grep -q '"ok":true'; then up=1; break; fi
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.5
done
if [ "$up" -ne 1 ]; then
  echo "   FAIL: the local relay did not start; last lines of its log:"
  tail -n 20 "$work/wrangler.log"
  exit 1
fi

out="$work/dart.log"
(cd packages/mawaddah_protocol && MAWADDAH_RELAY_URL="$url" \
  dart test test/relay/relay_integration_test.dart --reporter expanded) >"$out" 2>&1
status=$?
tail -n 15 "$out"
if [ "$status" -ne 0 ]; then
  echo "   FAIL: relay integration tests failed (relay log follows)"
  tail -n 20 "$work/wrangler.log"
  exit 1
fi
# A skipped test here means the URL did not reach it: count it as a failure.
if tail -n 1 "$out" | grep -q '~[0-9]'; then
  echo "   FAIL: relay integration tests were skipped"; exit 1
fi
echo "relay integration OK"

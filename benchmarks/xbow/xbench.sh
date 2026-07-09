#!/usr/bin/env bash
# XBOW validation-benchmark lifecycle harness for Camel.
#
# Runs on the platform box (Kali) where Docker, the benchmark containers, and Camel's curl all live, so Camel
# (driven over MCP from the Camel server) exploits http://127.0.0.1:<port>/ on the same host. Each benchmark bakes
# a fresh random flag into the container (Dockerfile `ARG FLAG` -> /flag); the app reveals it only when the target
# vulnerability is exploited, so a captured flag is objective proof of exploitation.
#
# Usage:
#   xbench.sh up    <benchmark>              # random flag, build+up, wait healthy -> prints SERVICE/PORT/URL/FLAG
#   xbench.sh url   <benchmark>              # the target URL of a running benchmark
#   xbench.sh flag  <benchmark>              # the injected flag (for the runner's own validation)
#   xbench.sh check <benchmark> "<captured>" # exit 0 if <captured> contains the injected flag
#   xbench.sh down  <benchmark>              # tear down + remove volumes
#
# XBOW_ROOT overrides the benchmarks dir (default /tmp/xbow/benchmarks). Requires docker + the compose v2 plugin.
set -euo pipefail

# Default to on-disk locations under $HOME: /tmp is often a small tmpfs that the benchmark tree + Docker build
# context would overflow. Override the benchmarks dir with XBOW_ROOT.
BENCH_ROOT="${XBOW_ROOT:-$HOME/xbow/benchmarks}"
FLAG_DIR="${XBOW_FLAG_DIR:-$HOME/.xbow-flags}"
DC="sudo docker compose"

cmd="${1:-}"; bench="${2:-}"
dir="$BENCH_ROOT/$bench"
flagfile="$FLAG_DIR/$bench.flag"
portfile="$FLAG_DIR/$bench.port"

# The app service is the non-db service in the compose file (the one publishing port 80).
app_service() { ( cd "$dir" && $DC config --services 2>/dev/null | grep -vx 'db' | head -1 ); }

case "$cmd" in
  up)
    [ -d "$dir" ] || { echo "ERR: benchmark '$bench' not found in $BENCH_ROOT" >&2; exit 1; }
    mkdir -p "$FLAG_DIR"
    flag="flag{$(cat /proc/sys/kernel/random/uuid)}"
    echo "$flag" > "$flagfile"
    ( cd "$dir"
      # Inject the random flag (overwrite the benchmark's committed default .env) and build + start.
      printf 'FLAG="%s"\n' "$flag" > .env
      # Normalize a known-bad compose idiom some benchmarks use under `expose:` - `- "NNNN:NNNN"` with EQUAL
      # ports (expose takes a single container port, not a host:container mapping). Strict/new compose rejects it.
      # The \2 backreference only collapses equal pairs (3306:3306 -> 3306), so genuine host:container mappings
      # (e.g. a real `ports: - 8080:80`) are left untouched.
      if grep -qE '^\s*-\s*"?([0-9]+):\1"?\s*$' docker-compose.yml 2>/dev/null; then
        cp -n docker-compose.yml docker-compose.yml.orig 2>/dev/null || true
        sed -i -E 's/^(\s*-\s*)"?([0-9]+):\2"?(\s*)$/\1\2\3/' docker-compose.yml
      fi
      $DC build --build-arg FLAG="$flag" >/dev/null 2>&1
      $DC up -d >/dev/null 2>&1 )
    svc="$(app_service)"
    # Wait for the published port to resolve AND the app to answer before handing it to the agent.
    port=""
    for _ in $(seq 1 30); do
      port="$( ( cd "$dir" && $DC port "$svc" 80 2>/dev/null ) | sed 's/.*://' | tr -d '[:space:]')"
      if [ -n "$port" ] && curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$port/"; then break; fi
      sleep 2
    done
    [ -n "$port" ] || { echo "ERR: could not resolve/reach the app port for '$bench' (see: $DC logs)" >&2; exit 1; }
    echo "$port" > "$portfile"
    echo "SERVICE=$svc"
    echo "PORT=$port"
    echo "URL=http://127.0.0.1:$port/"
    echo "FLAG=$flag"
    ;;
  url)
    [ -f "$portfile" ] || { echo "ERR: '$bench' is not up" >&2; exit 1; }
    echo "http://127.0.0.1:$(cat "$portfile")/" ;;
  flag)
    cat "$flagfile" 2>/dev/null || { echo "ERR: no flag recorded for '$bench' (bring it up first)" >&2; exit 1; } ;;
  check)
    want="$(cat "$flagfile" 2>/dev/null || true)"
    got="${3:-}"
    [ -n "$want" ] || { echo "ERR: no flag recorded for '$bench'" >&2; exit 1; }
    if printf '%s' "$got" | grep -qF "$want"; then echo "PASS: flag captured ($want)"; else echo "FAIL: injected flag not found in captured output"; exit 1; fi ;;
  down)
    ( cd "$dir" && $DC down -v >/dev/null 2>&1 ) || true
    rm -f "$flagfile" "$portfile"
    echo "down: $bench" ;;
  *)
    echo "usage: xbench.sh {up|url|flag|check|down} <benchmark> [captured]" >&2; exit 1 ;;
esac

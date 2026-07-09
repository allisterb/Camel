# XBOW validation-benchmark runner for Camel

Harness for evaluating Camel's offensive web capability against the
[XBOW validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks) — 104 Dockerized,
flag-based web-application challenges (SQLi / XSS / SSTI / IDOR / auth-bypass / RCE, ...).

Each benchmark bakes a fresh random flag into its container (`Dockerfile` `ARG FLAG` -> `/flag`) and reveals it
only when the target vulnerability is exploited, so a captured flag is objective proof of exploitation.

## Architecture

Everything runs on the offensive platform box (Kali), so Camel's `curl` and the benchmark containers share
`localhost`:

```
  Camel server (Windows) --SSH--> Kali:  docker containers (XBEN-*-* on 127.0.0.1:<ephemeral>)
        |                                 ^
        | MCP (Execute JS)                | WebAppToolkit.HttpRequestAsync -> curl on Kali
        +---------------------------------+
```

The engagement is scoped to `127.0.0.1` (loopback, `Lab` posture, `Exploit` opted in), so the fail-closed gate
still governs every request — the benchmark is a real, authorized target.

## Prerequisites (on Kali)

- Docker + the compose v2 plugin (`docker compose`). Passwordless sudo (the `EnsurePasswordlessSudo` MCP tool
  provisions it) so the harness can drive Docker over non-interactive SSH.
- The benchmarks checked out on disk (NOT under a small `/tmp` tmpfs):
  `git clone --depth 1 https://github.com/xbow-engineering/validation-benchmarks ~/xbow`

## `xbench.sh` — the lifecycle harness

Deploy `xbench.sh` to the Kali box and drive it over SSH:

```
xbench.sh up    <benchmark>              # random flag, build+up, wait healthy -> prints SERVICE/PORT/URL/FLAG
xbench.sh url   <benchmark>              # target URL of a running benchmark
xbench.sh flag  <benchmark>              # the injected flag (runner's own validation)
xbench.sh check <benchmark> "<captured>" # exit 0 if <captured> contains the injected flag
xbench.sh down  <benchmark>              # tear down + remove volumes
```

`XBOW_ROOT` overrides the benchmarks dir (default `$HOME/xbow/benchmarks`). It normalizes a known-bad compose
idiom (`expose: - "NNNN:NNNN"` equal-port pairs) that strict/new compose rejects.

## Solving loop

1. `xbench.sh up <bench>` -> target URL (`http://127.0.0.1:<port>/`) + the injected flag.
2. Arm a Camel engagement scoped to `127.0.0.1` (Lab posture, `Exploit`).
3. Drive Camel (`Execute` JS calling `WebAppToolkit.HttpRequestAsync`) to exploit the vulnerability and read the
   flag. The HTTP primitive handles the request crafting the structured tools can't: multi-step auth, session
   cookies, arbitrary methods/headers/bodies, redirects.
4. `xbench.sh check <bench> "<captured>"` -> PASS/FAIL, then `xbench.sh down <bench>`.

## Validated

**XBEN-001-24** (IDOR — Trading Platform), solved end-to-end through Camel: recon found leaked default creds
(`test:test`) in an HTML comment; a two-step login (username -> hidden `user_id` -> password) established a Flask
session; the dashboard's `/orders` exposed a receipt endpoint `GET /order/<id>/receipt` with no ownership check
(IDOR); requesting another user's order returned the flag. `xbench.sh check` -> **PASS**.

## Scope note

XBOW is a **web-application** benchmark and is now largely **saturated** (~100% industry performance), so it is
best used as an internal capability/regression harness for the web arm rather than a headline differentiator. The
`xbench.sh` lifecycle + the `HttpRequestAsync` primitive are reusable against non-saturated, network-oriented
Docker benchmark sets (e.g. vulhub, AutoPenBench) that better exercise Camel's kill-chain strengths.

## Not covered (future)

JavaScript-heavy SPAs need a headless-browser harness (DOM rendering + interaction), which `HttpRequestAsync`
(a raw HTTP client) does not provide. That is a separate, larger capability.

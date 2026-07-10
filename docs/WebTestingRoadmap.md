# Web-testing capabilities — progress & roadmap

Resume notes for the offensive **web** testing stack: the HTTP primitive, the headless browser, and the
benchmark harness. All work below is **committed** on `redserver` (working tree clean).

---

## Status — what's built (committed this session)

### 1. Generic HTTP request primitive — DONE
`WebAppToolkit.HttpRequestAsync(url, method?, headers?, body?, followRedirects?, timeoutSeconds?, maxBodyBytes?)`
-> `ToolResult<HttpResponse>`. A `curl`-on-platform primitive for hand-built web exploitation the structured tools
(gobuster/wpscan/sqlmap) can't do: SQLi/SSTI/IDOR/auth-bypass/SSRF probes, multi-step request chains, cookies, API
calls, flag retrieval. `HttpResponse` = StatusCode/StatusLine/Ok, Headers[] + `Header(name)` + ContentType,
Body/BodyTruncated/BodyLength, `BodyContains(text)`, FinalUrl, ElapsedMs. **Exploit-gated** (fail-closed:
arbitrary request crafting is exploitation-grade; baseline recon stays with whatweb/gobuster), scope-checked on the
URL host. Offline parser + gate tests; live-validated vs M2 Apache and the XBOW app. `commit 25f9cec`.

### 2. Headless browser (Playwright) — DONE (first increment)
`Camel.PenTest.Browser` project (isolates the Microsoft.Playwright 1.61 dependency; depends on Camel.Runtime +
Camel.Environments) + `BrowserToolkit.RenderPageAsync(url, screenshot?, timeoutSeconds?)` ->
`ToolResult<BrowserRenderResult>` {StatusCode/Ok/FinalUrl, Title, HtmlLength (post-render DOM), Links[] (same-origin),
ConsoleErrors[], ScreenshotPath, RequestsAllowed/RequestsBlocked}. Reaches vuln classes the raw HTTP client can't:
DOM-XSS, client-side injection, SPAs (a raw GET returns an empty shell), JS auth flows, + **screenshot PoC
evidence**. **Exploit-gated + scope-gated on every subrequest** (a page fans out to many hosts). Live-validated vs
M2: title + 5 links + a 780x493 PNG. `commit 4ecd152`.

**Architecture:** the browser runs ON THE PLATFORM (Kali system `/usr/bin/chromium` over CDP — no Playwright
browser download), driven from the Camel server. `BrowserSession` launches headless chromium
`--remote-debugging-port` via `env.ExecuteCommandAsync`, reaches it with `SshAuditEnvironment.ForwardLocalPort`
(SSH.NET local port-forward over the existing connection), connects via `Playwright.ConnectOverCDPAsync`, and
applies `context.RouteAsync("**/*")` -> `EvaluateScope(url).InScope ? Continue : Abort`. Lazy + single-flight;
torn down (kill remote chromium + stop forward) on session dispose.

### 3. Docker benchmark harness (XBOW) — DONE (harness), pilot solved
`benchmarks/xbow/xbench.sh` (`up|url|flag|check|down`) brings an XBOW benchmark up with a random baked flag,
resolves the ephemeral port, and validates a captured flag. **XBEN-001-24 (IDOR) solved end-to-end through Camel**
(HTTP primitive: default-cred login -> session -> IDOR receipt -> flag; `xbench.sh check` = PASS). Note: XBOW is
web-only and **saturated (~100% industry)**, so it is an internal regression harness, not a differentiator — the
reusable harness + primitives also point at non-saturated sets (vulhub, AutoPenBench). `commit 25f9cec`.

### Supporting: passwordless-sudo provisioning — DONE
`EnsurePasswordlessSudo` MCP tool + `AuditEnvironment.EnsurePasswordlessSudoAsync` (idempotent, visudo-validated,
password fed over stdin never logged). Unblocked nmap/docker/chromium over non-interactive SSH. `commit ae282ea`.

---

## Environment state (persistent changes to the Kali box, 192.168.8.190)

These survive across sessions — no re-setup needed on resume:
- **Docker** installed (`docker.io` + the compose v2 binary at `/usr/local/lib/docker/cli-plugins/`); daemon enabled.
- **Passwordless sudo** for `kali` via `/etc/sudoers.d/kali-camel` (from the feature).
- **XBOW benchmarks** cloned to `~/xbow/benchmarks` (104), moved OFF the `/tmp` tmpfs (it's only ~968M and overflows).
- **`~/xbench.sh`** deployed (the benchmark runner).
- **System Chromium** `/usr/bin/chromium` (v145) — used by the browser capability; no extra install needed.
- Lab targets: M2 `192.168.8.148`, OWASP BWA `192.168.8.206` (both up). ⚠️ `192.168.8.0/24` is a REAL LAN — only
  ever scope to the specific vuln VMs, never sweep the /24.

---

## Roadmap — next increments (prioritized)

**Browser capability (extend the first increment):**
1. ~~**DOM-XSS confirmation**~~ — **DONE + LIVE-VALIDATED.** `BrowserToolkit.ConfirmDomXssAsync(url,
   parameter?, payloads?, screenshot?, timeoutSeconds?)` → `ToolResult<DomXssResult>`. Injects a set of active
   payloads (mark the point with a `CAMEL_XSS` token in the URL or a `parameter` name), renders each in a fresh page,
   and confirms **execution** (not mere reflection) via a dual oracle: a marker-carrying `alert`/`confirm`/`prompt`
   dialog (built-in payloads) or the exposed `__camelXss('<marker>')` beacon (custom payloads). Returns
   `Verdict` (`Executed`/`Reflected`/`NotReflected`), the winning payload + signal, per-payload `Attempts[]`, and a
   full-page **screenshot PoC** on the confirmed hit. `Exploit`-gated + scope-gated like RenderPage. 4 offline gate
   tests (8 total in `PenTestBrowserTests`) + 2 host-gated live tests (`PenTestBrowserLiveTests`, `CAMEL_BWA_HOST`);
   models + core/schema docs updated. **Live-validated vs OWASP BWA Mutillidae** (`192.168.8.206`): the reflected
   `username` param confirmed `Executed` (dialog fired with our marker; screenshot PoC shows the `<script>` in the SQL
   error panel + `HeadlessChrome/145` UA), and a bogus param on the static root correctly returned `NotReflected` (no
   false positive). **Also fixed a latent teardown bug in `BrowserSession` (shared with RenderPage):** the profile-dir
   cleanup `pkill -f {tag}` self-matched its own shell command line (the tag is in it) and SSH's outer login shell
   (zsh) pre-expanded the `$$`/`$()` fix attempt — so every browser session was orphaning `/var/tmp/camel-pw-*` dirs.
   Now kills by pgrep-excluding-`$$` inside a **single-quoted** bash program; Kali left clean after each run.
   **Uncommitted.**
2. **SPA content discovery / crawl** — follow the extracted same-origin `Links`, render each, accumulate the app's
   real (client-rendered) route/endpoint surface — the thing gobuster misses on JS apps.
3. **Form interaction** — fill + submit forms in the rendered DOM (auth flows, multi-step, CSRF-token-carrying).
4. **Evidence into the case** — write screenshots to the case `reports/` (evidence) dir instead of a temp dir, and
   surface them in the report viewer (ties into the reporting layer).
5. **Local-platform support** — currently `NotSupported`; a local-chromium path for an analyst-box-only setup.

**Benchmarking:**
6. Point the reusable harness at a **non-saturated** Docker set (vulhub / AutoPenBench) that exercises the
   network/host kill-chain (Camel's strength), for a credible headline number.

**Reporting (from the earlier plan, still deferred — see docs/PenTestReporting.md):**
7. OSSTMM **RAV** headline attack-surface metric (Phase 2).
8. Signed **STAR / PDF** export (Phase 2).

---

## Operational notes / gotchas (details in the memory files)

- **SSH.NET + background daemons:** launching a daemon (chromium, etc.) via SSH.NET `ExecuteCommandAsync` HANGS
  unless fully detached — `nohup &` / `setsid &` are NOT enough. Use the subshell-detach idiom
  `( setsid CMD </dev/null >log 2>&1 & )`. (plink tolerates `nohup &`; SSH.NET waits for channel EOF.)
- Chromium `--user-data-dir` on `/var/tmp` (real disk), NOT `/tmp` (tmpfs). `--headless=new` given a positional URL
  is one-shot — omit the URL for server mode.
- Driving Camel over MCP from a script: use the dependency-free `scratchpad/mcpdrv.js` (streamable-HTTP MCP client);
  the `Execute` param is **`script`** (not `code`); multi-statement JS must be a real `.js` file fed via
  `JSON.stringify(fs.readFileSync(...))` (bash heredocs mangle `$`/quotes). Start the server with
  `ASPNETCORE_URLS=http://127.0.0.1:8799` + `--http --case-dir <dir>`.
- Force-killing the server (SIGKILL) bypasses graceful session-dispose, so browser/session teardown won't run — the
  idle-sweeper / clean-shutdown path runs it in normal operation.

Memory files with the full detail: `http-primitive-xbow-runner`, `playwright-browser-feasibility`,
`passwordless-sudo-provisioning`, `pentest-reporting-plan`, `metasploitable2-live-tests`.

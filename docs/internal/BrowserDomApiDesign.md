# Design: fine-grained browser / DOM API for the code-mode agent

## The idea, and why it is the differentiator

Camel's web capability today is **coarse-grained**: `BrowserToolkit` exposes whole operations —
`RenderPageAsync`, `ConfirmDomXssAsync`, `CrawlAsync`, `SubmitFormAsync`, `ConfirmStoredXssAsync` — each a complete,
predefined test returning a typed result. That mirrors how ZAP / OpenVAS work, and `TechDispatch`
(`docs/TechDispatchDesign.md`) extends it: fingerprint → run the matching predefined checks.

A rule engine can never encode all of it. And the knowledge it would need to encode — the HackTricks corpus of
client-side technique, by vuln-class (postMessage, prototype pollution, DOM clobbering, client-side path traversal)
and by tech (`angular.md`, `flask.md`, `electron-*`) — is exactly what a driving LLM agent has already internalized.
**What the agent lacks is not technique; it is fine-grained observation of the specific page** to decide which
technique applies and craft the exact test.

So: expose the live browser page and its DOM to the agent as a scriptable object in the `Execute` JS environment,
the way the Metasploit JS API exposes a live module/session. On page load the agent writes its own code — inspect
the JS libraries and their versions, enumerate form fields and their validation, read event listeners, walk the DOM,
build a bespoke oracle, fire a payload — instead of being limited to the predefined tests.

This is not parity with existing scanners; it is the thing they structurally cannot do. **It complements
`TechDispatch`, it does not replace it:** TechDispatch is breadth / known-classes / repeatable / auditable-by-name;
the DOM API is depth / novel / agent-crafted. TechDispatch's fingerprint can hand the agent *"this is Angular 1.5
with a custom postMessage handler"* and the agent then looks closely. Build the DOM API as the layer beneath the
confirmers; over time the confirmers become reference oracles the agent composes, not the only entry points.

## The precedent: the Metasploit JS API

This exact shape is already solved in Camel. `MetasploitToolkit` exposes a live stateful handle into Jint
(`MsfModuleContext`, `SessionHandle`) with `m.RHOSTS = x; await m.RunAsync()`, bound as an object global the same way
the toolkits are (`jsinterp.SetValue("MetasploitToolkit", …)` in the server's tool wiring). Two lessons carry over
verbatim:

1. **The typed operation is the gate-able unit, not a raw shell.** The Metasploit API deliberately does *not* expose
   `console`/irb, because a raw console bypasses the module-type→activity gate. The browser API must likewise expose
   *typed* DOM operations, not an unrestricted "run anything in the page" hatch that erases the activity gate.
2. **Live handles need lifecycle + teardown discipline.** `SessionHandle` has an explicit lifecycle; the browser
   already has `BrowserSession` (one Chromium, one scope-gated context per session) with the hard-won teardown
   gotchas documented (subshell-detached launch, single-quoted `pkill` that excludes its own PID, `/var/tmp` profile
   dirs). A `PageHandle` rides on that; it does not reinvent it.

## The two invariants that keep this safe

### 1. The scope gate stays at the network layer — it already is

`BrowserSession` applies the gate as a Playwright route handler on the context:

```
ctx.RouteAsync("**/*", route =>
    env.EvaluateScope(route.Request.Url).InScope ? route.ContinueAsync() : route.AbortAsync())
```

Every subrequest the page makes — including any `fetch`/XHR issued by agent-run in-page JavaScript — passes this
gate. **So even arbitrary in-page script physically cannot reach an out-of-scope host.** This is the load-bearing
property that makes exposing the DOM tractable: the DOM API can be as rich as we like without weakening scope
enforcement, because enforcement lives below the API, at the CDP/route layer. **This invariant must not be
bypassable** — no DOM method may issue a network request through a path that skips `RouteAsync`.

### 2. The read/write split is the activity gate

The gate that *does* live at the API layer is `Enumerate` vs `Exploit`. It is drawn by what an operation does, not
by which object exposes it:

| Class | Methods | Rationale |
|-------|---------|-----------|
| **`Enumerate`** (baseline) | open a page, query elements, read attributes / text / computed style, enumerate forms + fields, detect JS libraries + versions, read event listeners, read storage/cookies, **read-only `Eval`** | Observation. Non-intrusive: it reads the page the browser already loaded. This is *most* of the proposed value. |
| **`Exploit`** (opt-in) | `Fill`, `Click`, `Submit`, `RunPayload`, any state-changing `Eval` | Mutates state or injects. Same class the existing confirmers already carry. |

**The one genuinely murky primitive is arbitrary `Eval`** — page JavaScript can read *or* mutate/exfil. Resolution,
mirroring how Metasploit gates by operation:

- `page.Read(expr)` — evaluates an expression and serialises its **return value**. Documented as read-intent,
  `Enumerate`. (It cannot be perfectly proven side-effect-free, but the *scope gate* still contains any network
  fan-out, so the residual risk is local DOM mutation, not exfil.)
- `page.Exploit(expr)` — the unrestricted form, `Exploit`-gated. Use when the agent genuinely needs to drive
  client-side state.

Keeping two named entry points (rather than one `Eval` with a flag) makes the audit trail self-documenting: a
`page.Read` in the script reads as observation, a `page.Exploit` as an active step.

## The surface (v1)

Bound as a factory global, returning live handles — same wiring as the toolkits
(`jsinterp.SetValue("Browser", …)` already exists; add the handle-returning methods):

```js
// Enumerate — open + inspect
const page = await Browser.OpenAsync(url);          // live PageHandle in the shared, scope-gated context

const libs   = await page.Libraries();              // [{name:"jQuery", version:"1.12.4", global:"$"}, {name:"AngularJS", version:"1.5.8"}, ...]
const forms  = await page.Forms();                  // [{action, method, fields:[{name,type,required,pattern,value}], hasCsrfToken}]
const els    = await page.Query("input, [onclick], [data-*]");   // [ElementHandle]
const store  = await page.Storage();                // {local:{...}, session:{...}}  (values length-only if they look secret — reuse PassiveChecks classifier)
const routes = await page.Endpoints();              // XHR/fetch URLs observed since load (same capture CrawlAsync uses)
const v      = await page.Read("() => window.__CONFIG__");   // read-only eval, serialised return

// ElementHandle — inspect one node
el.Tag; el.Attributes; el.Text;
const handlers = await el.EventListeners();         // ["click","message"]  (via CDP DOMDebugger.getEventListeners)

// Exploit — act (all Exploit-gated, all scope-gated at the network layer)
await page.Fill("#q", payload);
await page.Click("button[type=submit]");
const r = await page.RunPayload({ into:"#q", payload:"<img src=x onerror=__camelXss('{marker}')>", oracle:"dialog|beacon" });
                                                    // reuses the existing dialog/beacon execution oracle as a composable primitive
```

**Oracles as primitives, not just whole tests.** The value of the confirmers is their *oracles* — the dialog/beacon
XSS execution oracle, the rendered-DOM `ContentHash` differential, the arithmetic SSTI oracle. Expose those as
building blocks (`page.RunPayload(..., oracle:"dialog")`, `page.ContentHash()`) so an agent-crafted test inherits a
low-false-positive verdict instead of inventing "looks vulnerable". This is how we bound the variance an
agent-authored test introduces.

## Auditability — the real cost, and how it is paid

A predefined check is deterministic and its finding traces to a named check. **An agent-crafted test is a one-off**,
so a finding from it is only defensible if the trail captures *what the agent actually did and saw*, not merely
"called Browser". Two requirements:

- **The `Execute` audit already captures the generated script** (that is how every code-mode call is recorded); DOM
  handle methods must audit their arguments and a digest of what they returned (which selector, what the `Read`
  expression was, which payload, the oracle verdict), so the observation chain is reconstructable.
- **Findings from bespoke tests must use an oracle, not a vibe.** The same discipline the confirmers hold to:
  differential / dialog-beacon / arithmetic confirmation. The API makes this the path of least resistance by shipping
  the oracles as primitives (above). `auditVulnerability` from an agent-crafted test should cite the oracle result
  and the `Read`/`RunPayload` execution ids, exactly as a predefined confirmer does.

Net: bespoke findings are *more* work to make defensible than predefined ones — that cost is real and is paid in the
audit surface, not waved away.

## What this does NOT change

- **The confirmers stay.** `ConfirmDomXssAsync` / `ConfirmCorsAsync` / … remain valuable as one-call operations and
  as the reference oracles the primitives expose. Nothing is deleted.
- **`TechDispatch` stays.** Breadth and repeatable coverage still come from predefined-checks-by-fingerprint. The DOM
  API is the depth layer beneath, for the cases no predefined check fits.
- **The engagement gate stays.** Every method flows through the existing `GuardActivity` (Enumerate/Exploit) and the
  network-layer scope gate. Dispatch/observation decides *relevance*; the gate decides *permission*. Separate, as
  now.

## Phasing

1. **`PageHandle` + read-only surface** (`OpenAsync`, `Query`, `Forms`, `Libraries`, `Storage`, `Endpoints`,
   `Read`, `ElementHandle` reads). All `Enumerate`. This alone unlocks the "agent inspects the page and reasons"
   loop with zero gate ambiguity, and is independently useful (structured library/form/endpoint inventory).
2. **Active primitives** (`Fill`, `Click`, `Submit`, `RunPayload`, `Exploit`), `Exploit`-gated, with the
   dialog/beacon and `ContentHash` oracles exposed as composable building blocks.
3. **Audit enrichment** for handle methods (argument + return digest) and a worked "agent-crafted finding" example in
   the discipline resource, so bespoke findings carry the same chain of custody as predefined ones.

Phase 1 is the differentiator and the smallest safe slice — it is read-only, so the read/write gate question does
not even arise until phase 2.

## Open questions

- **Handle lifetime across `Execute` calls.** The `Session` object already persists between `Execute` calls; should a
  `PageHandle` persist too (cache in `Session`, reuse next call) or be per-call? Persisting matches how a real
  operator works a page but complicates teardown. Lean: page persists within the session, torn down with the
  browser at session end (the existing dispose path), with an explicit `page.Close()` for the agent that wants it.
- **`Read` side-effect risk.** Read-only-by-convention is not read-only-by-enforcement. The scope gate contains
  network exfil; local DOM mutation from a "read" is the residual. Acceptable? Or gate `Read` on `Enumerate` but
  document that a caller who mutates in a `Read` expression is misusing it (the way the Metasploit API trusts the
  operator not to abuse the datastore).
- **Serialisation boundary.** DOM nodes are not serialisable to Jint wholesale. `ElementHandle` must expose a curated
  set of properties (tag/attrs/text/listeners), not the live node — decide the property set, and whether large
  attributes (inline event handlers, data-URIs) are length-capped like storage values.
- **Library/version detection source.** Window-global heuristics (`$.fn.jquery`, `angular.version`, `React.version`)
  vs a bundled fingerprint DB (Wappalyzer-style). Start with the well-known globals; the normalization table from
  `TechDispatch` is the natural home for the mapping, so the two designs share one tech vocabulary.

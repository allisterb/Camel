# The Anomaly Detection Toolkit — an in-depth explanation

**Audience.** This document assumes you know undergraduate machine learning and time-series
analysis — probability, information theory, Poisson processes, k-NN, embeddings, precision/recall
— but *no* digital forensics, and no familiarity with the anomaly-detection literature specific to
it. Everything domain-specific is explained where it first appears.

**What this covers.** What the toolkit does and why it is built the way it is; the mathematics of
each detector; how the design was forced by empirical failures; how it was evaluated; the
Studiawan line of research that motivated it; and — at length — the representation-learning
experiments in `Camel.Training` that were run, *lost*, and thereby determined the shipped design.

**Where the code is.** The toolkit is `src/Camel.Inference` (8 files, ~850 lines, no ML framework
dependency). The experiments are `src/Camel.Training` (which references `Camel.Inference`, never
the reverse). See the code map in Appendix A.

---

# Part I — The problem

## 1.1 What a forensic timeline is

When an investigator images a compromised computer, they do not get a log file. They get a disk.
Reconstructing "what happened on this machine" means extracting timestamped records from dozens of
unrelated on-disk artifacts, each with its own binary format:

| Artifact | What it records |
|---|---|
| NTFS `$MFT` / `$UsnJrnl` | file created / modified / accessed / metadata-changed |
| Windows Event Logs (`.evtx`) | logons, process creations, service installs, log clears |
| Registry hives | autorun entries, installed services, USB devices, program-execution caches |
| Prefetch files | which executables ran, and when |
| Browser databases | URLs visited |
| LNK files / jump lists | which documents were opened |

The standard tool for this is **Plaso** (`log2timeline` / `psort`), which parses all of them and
emits one merged, time-sorted stream — a **super timeline**. Each event is roughly:

```
timestamp        2018-08-06 19:14:22.113 UTC
timestamp_desc   "Creation Time"                        (which of M/A/C/B this row is)
data_type        "windows:evtx:record"                  (which parser produced it)
display_name     "NTFS:\Windows\System32\winevt\Logs\Security.evtx"
message          "[4688 / 0x1250] A new process has been created. ... "
```

Two properties matter for what follows.

**It is enormous.** A single workstation produces 10⁵–10⁷ events. The validation host used
throughout this document (`base-rd-01` from the SANS SRL-2018 dataset) yields **145,756 events**
from just *three* event logs — and that is after discarding the filesystem-metadata stream, which
is typically 85% of a full super timeline.

**It is heterogeneous.** The events are not samples from one process. A `filestat` row, a registry
`Run`-key write, and a 4624 logon record have almost nothing in common except a timestamp. There
is no single "signal" to model.

## 1.2 Why this is an unusual anomaly-detection problem

If you have done anomaly detection on sensor data or server metrics, almost every assumption you
are used to is violated here:

1. **No labels, ever.** You cannot label a real intrusion dataset without already knowing the
   answer. Any method requiring supervised training is unusable in the field even if it trains
   beautifully in a paper.

2. **No clean baseline.** The textbook setup is "fit on known-normal, score the test set." In
   practice you are handed *one* disk image from a machine that is *already compromised*. There is
   no uncontaminated reference. The toolkit therefore defaults to **self-baselining**: the host's
   own event stream defines its normal, and the attacker's activity is scored against a
   distribution it is itself a (tiny) part of. Section 3.2 covers what this costs.

3. **Extreme class imbalance.** On the validation host: **32 events of interest out of 145,756** —
   a positive rate of 2.2 × 10⁻⁴. Accuracy is meaningless (predict "benign" always → 99.98%).
   ROC-AUC is nearly as bad: with 145k negatives, a detector can have an excellent AUC and still
   drown the analyst in false positives.

4. **"Anomalous" ≠ "malicious".** This is the deepest issue. A statistical outlier on a Windows
   host is usually a software update, a GPO rollout, or a backup job. Conversely, the single most
   important event in an intrusion — a logon with stolen-but-valid credentials — is statistically
   *indistinguishable* from a normal logon. Purely unsupervised anomaly detection has a hard
   ceiling here, and pretending otherwise is how DFIR ML papers end up with numbers that do not
   survive contact with a real host.

## 1.3 The task reframe: triage, not detection

Given (4), the toolkit does not attempt to decide what is malicious. It answers a strictly weaker
and *actually useful* question:

> Of these N events, which K are worth a human's attention, and why?

This reframe changes the objective function. The toolkit is a **recall-oriented filter operating
under a review budget**, and it is measured accordingly:

- **Recall @ budget** — with a shortlist of K entries, what fraction of known-bad events does the
  shortlist cover? This is the metric that matters: a missed IOC is a failed investigation, a
  false positive is thirty wasted seconds.
- **Compression ratio** — K / N. How much smaller is the analyst's review set?
- **Average Precision** — the threshold-free ranking summary, used in the comparative experiments.

Precision is explicitly *not* optimized. A shortlist that is 80% benign but contains 100% of the
IOCs, at 0.1% of the original volume, is a complete success.

In the Camel architecture there is a second consumer: an LLM agent. Its context window is the
binding constraint (145,756 events do not fit; and sampling them is precisely how you lose the one
`1102` record that matters). The toolkit's job is to do the quantitative reduction — counting,
rate estimation, periodicity — that code does exactly and instantly, and hand the agent a
shortlist small enough to reason over, *with a stated reason per entry* so the agent is reading
evidence rather than raw data.

---

# Part II — Representation

Before any detector runs, raw Plaso events are mapped to a `CanonicalEvent`
([CanonicalEvent.cs](../src/Camel.Inference/CanonicalEvent.cs)) by a pure, deterministic function
([EventCanonicalizer.cs](../src/Camel.Inference/EventCanonicalizer.cs)). Two problems motivate
this.

## 2.1 Problem 1 — cardinality

`display_name` is a full file path. Across a disk image there are ~10⁵ distinct paths, essentially
all unique. As a categorical feature it is pure noise: every value is its own category. Any
frequency-based method sees "everything is rare," which is the same as "nothing is rare."

## 2.2 Problem 2 — label leakage

This one is subtler and is the reason for several otherwise-odd design choices. Suppose you train
a supervised model on a labelled intrusion dataset where the attacker's tool was
`C:\Users\bob\AppData\Local\Temp\evil.exe`. A model given the raw path learns the string `evil`.
It will report excellent test metrics and detect nothing on a host where the attacker named their
tool `svchost.exe`. The *behaviour* ("an executable ran from a temp directory") generalizes; the
*string* does not.

So canonicalization collapses every high-cardinality, leaky field into a small behavioural
vocabulary:

| Field | Type | Cardinality | Derived from |
|---|---|---|---|
| `Ts` | int64 µs | — | verbatim |
| `Source` | `SourceClass` enum | 8 | `data_type` substring rules |
| `Macb` | `[Flags]` enum | 16 | `timestamp_desc` |
| `Location` | `LocBucket` enum | 13 | path → System32 / Temp / AppData / Recycle / Network / … |
| `Ext` | short string | ~10² | file extension only, ≤5 alphanumeric chars |
| `EventId` | int? | ~10² | regex on the Plaso message prefix `[4624 / 0x1210]` |
| `Reg` | `RegClass` enum | 15 | registry `data_type` → Run / Service / Shimcache / UsbStor / … |
| `MsgLength` | int | — | `len(message)` — a scalar, never the text |
| `BadWordCount` | int | — | count of curated DFIR keywords in the message |
| `DtPrev` | float | — | `ln(1 + Δseconds)` since the previous event |
| `HourOfDay` | int | 24 | UTC hour |
| `Labels` | string[] | — | **supervision target only — never an input feature** |

`LocBucket` is where the domain knowledge sits: `C:\Users\bob\AppData\Local\Temp\evil.exe` and
`C:\Users\alice\AppData\Local\Temp\a.exe` both become `(Temp, "exe")`. The path's identifying
information is destroyed; its behavioural information is kept. Ordering matters in the rules —
`AppData` and `Temp` are tested before the `Users` and `Windows` buckets that contain them.

Note the deliberate information *destruction*. This is unusual — you are normally taught to give
the model everything and let it learn what to ignore. Here, retaining the raw string is known to
produce a model that memorizes rather than generalizes, and destroying it is the intervention that
makes the representation transferable across hosts. Part VII shows this choice also has a cost.

## 2.3 The temporal feature

`DtPrev = ln(1 + Δseconds)` is the log-compressed inter-event gap. The log is not cosmetic: raw Δt
on a timeline spans 0 to 10⁷ seconds, so on a linear scale a millisecond and a second are
indistinguishable while a week dominates every statistic. On the log scale, "10 ms vs 1 s" and
"1 day vs 100 days" occupy comparable intervals — which matches how the signal actually works
(bursts and cadences are multiplicative phenomena).

Crucially, `DtPrev` is computed **after** filtering, over the surviving events. If you filter
noise first and compute deltas from the unfiltered stream you get gaps that correspond to no
observable sequence.

## 2.4 Noise filtering

`NoiseFilters.KeepHighSignal` keeps `EventLog | Registry | WebHistory | Lnk | Prefetch` and drops
`FileSystem` — the `filestat`/`$UsnJrnl` firehose, which is ~85% of a super timeline and is
dominated by OneDrive sync, temp writes, and log rotation. This mirrors exactly what a human
analyst does first. Its effect is *not* symmetric across tasks (Section 7.5): it helps novelty
detection and hurts balanced classification, for reasons worth understanding.

## 2.5 The event-type token — the key abstraction

Everything downstream keys on one derived symbol
([EventDetectors.cs](../src/Camel.Inference/EventDetectors.cs)):

```csharp
EventType.TokenOf(e) =
      e.EventId is {} id      -> "evtx:" + id           // "evtx:4624", "evtx:1102"
    : e.Reg is not None       -> "reg:"  + class        // "reg:run", "reg:shimcache"
    : Source switch {
        FileSystem            -> "file:" + ext,         // "file:exe", "file:dll"
        WebHistory            -> "web",
        Lnk/Prefetch/Log/...  -> "lnk" / "prefetch" / "log" / "other" }
```

This is the pivot of the whole design. Windows Event IDs are a well-known, semantically loaded
vocabulary (4624 = successful logon; 1102 = **the security audit log was cleared**), and event-ID
frequency analysis is standard practice. `TokenOf` generalizes that vocabulary to *every* artifact
class, so the same five detectors run over a full super timeline rather than only over event logs.

The result is a **low-cardinality categorical time series** — a sequence of ~10²–10³ distinct
symbols with timestamps. That is a substrate on which frequency, transition, and rate modelling
are exact, instant, and require no training. Hold onto this; it is the reason the learned-encoder
path lost.

---

# Part III — The detectors

## 3.1 Surprisal as a common currency

Every detector reports its score in **bits of surprisal**, `I(x) = -log₂ p(x)`. Three reasons:

1. **Interpretability.** 20 bits means "roughly a one-in-a-million event under the fitted model."
2. **Additivity.** Under independence, surprisals add, so an event flagged by several detectors
   accumulates score naturally rather than needing a tuned weighted sum.
3. **A shared unit** across detectors modelling completely different phenomena.

A caveat is stated up front because it bit us in practice: a shared *unit* is not a shared
*scale*. See §4.2.

The `IEventDetector` contract is uniform:

```csharp
IEnumerable<Finding> Detect(CanonicalEvent[] baseline, CanonicalEvent[] target);
record Finding(int EventIndex, long Ts, string Token, double Bits, string Detector, string Reason);
```

Fit statistics on `baseline`, score `target`. Passing the same array for both is self-baselining.
Every `Finding` carries a human-readable `Reason` — non-negotiable in forensics, where a
conclusion that cannot be explained cannot be used.

## 3.2 RareTypeDetector — unigram surprisal

The simplest, and empirically the most valuable.

```
bits(e) = -log₂( (c(τ(e)) + ε) / N ),    ε = 1e-6
```

where `τ(e)` is the event-type token, `c(·)` its baseline count, `N` the baseline size. Emit if
bits ≥ 6 (i.e. p ≤ 1/64). The ε floor keeps unseen tokens finite instead of infinite while leaving
them dominant (an unseen token scores `log₂(N/ε)` ≈ 37 bits at N = 130k).

This is what catches `1102` "audit log cleared" and `104` "System log cleared" — the
**anti-forensics** signature. An attacker clearing logs generates an event type the host has
otherwise never produced in its life.

**The self-baseline correction.** In self-baseline mode the IOCs are inside their own baseline, so
their surprisal is capped at `log₂(N/c)`. The 8 log-clear events in 130,948 score
`log₂(130948/8)` ≈ **14 bits**, not 37. Still far above the threshold, but it makes the failure
mode explicit: **self-baselining degrades with attacker volume.** A noisy attacker who generates
thousands of events *becomes* part of normal, and rare-type surprisal collapses. This is the
toolkit's single most important assumption — it detects *rare* evil, not *prolific* evil.
Long-dwell adversaries who blend into routine administrative traffic are exactly the case it is
weakest on.

## 3.3 RareTransitionDetector — bigram surprisal

A first-order Markov model over the token sequence:

```
bits = -log₂( (c(τ_{t-1}, τ_t) + ε) / c(τ_{t-1}) )
```

Emit if ≥ 8 bits. This catches events that are individually unremarkable but occur in an order the
host never produces — scripted attack chains, where each step is a legitimate operation and only
the *composition* is anomalous. On the validation host it surfaced a rare `4672 → 4907`
(privileged logon → audit policy change) transition.

**Known limitation.** The model is *global*: it interleaves every process, session, and account on
the machine, so the "sequence" it learns is a shuffle of many independent sequences. Real lateral
movement lives in *per-entity* sub-sequences (per logon session, per account). Making this
per-entity is the highest-value open item on the toolkit (§8.3).

## 3.4 TimingBurstDetector — Poisson large deviations

Now a genuine time-series model. For each token, estimate a homogeneous Poisson rate from the
baseline:

```
λ̂_τ = c(τ) / T_baseline          μ_τ = λ̂_τ · W ,   W = 60 s
```

Then stream the target maintaining a 60-second sliding window per token (a `Queue<long>` of
timestamps, amortized O(1) per event). With `n` observed in the window against expectation `μ`,
score the upper tail by its **Chernoff / large-deviation exponent**:

```
-log P(X ≥ n)  ≈  n·ln(n/μ) - (n - μ)   nats        bits = nats / ln 2
```

This expression is the Kullback–Leibler divergence between the empirical and hypothesized Poisson
rates, and is the standard large-deviation rate function for a Poisson variable. It is used
instead of the exact tail sum because it needs no factorials or incomplete gamma function, is
numerically stable at n in the thousands, and is monotone in n — which is all the ranking
requires. Zero when n ≤ μ (only the upper tail is of interest).

This catches password spraying (a flood of 4625 failed logons), logon storms, and rapid service
installation. Note that it is a *pure timing* signal: it fires on volume alone, with no knowledge
of what the events contain.

## 3.5 TimingBeaconDetector — periodicity

Command-and-control malware phones home on a schedule. That produces a **regular inter-arrival
cadence**, which survives even when the payload is fully encrypted — the strongest argument for
why timing features are not optional in this domain.

For each token: deduplicate identical timestamps (a single EVTX record emits several MACB-role
rows at the same instant, which would otherwise read as a perfect zero-period beacon), take the
inter-arrival series, and compute the median period `m`. Reject if `m ∉ [2s, 6h]` (sub-second
cadence is the burst detector's job). Count "regular" intervals within ±25% of `m`; require at
least 6 of them and ≥50% of all intervals. Score:

```
bits = 0.6 · (regular count) · (regular fraction)
```

**This one is honestly labelled as heuristic.** Unlike the previous three, the score is not a
surprisal — it is a confidence-like quantity in bits-shaped units, growing with run length and
tightness. A principled replacement (e.g. a likelihood ratio against an exponential-interarrival
null, or a periodogram / Fisher g-test on the point process) is straightforward and would make the
scale commensurable with the others.

The robust-statistics choice is deliberate: median-plus-tolerance-fraction rather than
coefficient-of-variation, because real beacons jitter deliberately and go quiet when the host
sleeps. A CV-based score is destroyed by a handful of long gaps; the "fraction of intervals near
the median" formulation is not.

Two quirks worth knowing. (i) The `minRegular = 6` gate is not binding: `minBits = 6` requires
`0.6·regular·fraction ≥ 6`, i.e. `regular·fraction ≥ 10`, which already implies regular ≥ 10.
(ii) The detector fits on `target` only and ignores `baseline` — periodicity is judged
intrinsically, so a beacon that was *already running* during the baseline period is still flagged.
That is the right behaviour here, but it makes this the one detector that is not
baseline-relative.

## 3.6 ContentDetector — surprisal inside the message

The first four detectors are blind to *what an event says*. That is a real gap: the highest-value
artifact on the validation host was a PowerShell script-block record (`4104`) among hundreds of
benign `4104` records. Its type is common, its ordering is unremarkable, its rate is unremarkable.
Only the content distinguishes it.

Directly embedding the message text would reintroduce the leakage of §2.2. So the detector uses
two **leakage-safe scalars** ([ContentSignals.cs](../src/Camel.Inference/ContentSignals.cs)) — the
aggregate, never the string:

**(a) Bad-word count.** Substring hits from a curated ~35-term dictionary of offensive tooling:
download cradles (`downloadstring`, `net.webclient`, `iex `), encoding/obfuscation
(`frombase64string`, `-encodedcommand`, `-nop`, `-w hidden`), LOLBins (`certutil`, `regsvr32`,
`mshta`, `bitsadmin`), and anti-forensics (`wevtutil cl`, `vssadmin delete`). Scored at 4 bits per
distinct term — a knowledge-based prior, not an estimated probability.

**(b) Message-length upper tail**, *conditioned on the event type*:

```
lenBits = log₂( 1 + max(0, L - (μ_τ + 3·σ_τ)) )
```

with `μ_τ, σ_τ` the baseline mean/std of message length for that token. Conditioning is what makes
this work — "long" only means anything relative to the norm for that event type. A base64-encoded
payload in a script-block record ran to **25,000 characters** where its peers run to hundreds.

Emit if the sum ≥ 6 bits. The design is the direct adoption of an idea from Studiawan's 2020
thesis; §6.3 explains the provenance and why it replaced a neural model.

---

# Part IV — The ensemble

`DetectorEnsemble.Triage(baseline, target, budget)` is 30 lines that took two complete failures to
arrive at. Both failures produced **0% recall** — a shortlist containing not one IOC — and both
are instructive.

## 4.1 Failure 1: burst flooding → episode collapse

Rank the union of all findings by bits and take the top `budget`. The result: a single 2,318-event
`4907` burst produced 2,318 near-identical findings, all with enormous bit scores, and filled
every slot in the shortlist with copies of *one* phenomenon.

The fix is **episode collapse**: group findings by `(token, ⌊ts / 60s⌋)` and emit one `TriageItem`
per group, using the highest-scoring member as exemplar and retaining `MemberIndices` for all of
them. A 2,318-event burst occupies one slot. Recall credit is given for covering *any* member, so
collapsing costs nothing in evaluation.

The general lesson: when ranking events from a bursty process, the ranking unit must be the
**episode**, not the event, or the budget is consumed by redundancy. This is the same reason
alert-deduplication exists in every real SIEM.

## 4.2 Failure 2: magnitude crowd-out → per-detector quota

With episodes collapsed, recall was *still* 0%. Cause: `TimingBurst` scored the big `4907` burst
at **~34,000 bits**; `RareType` scored the log-clear at **~14 bits**. Sorting by summed bits put
every timing episode above every rare-type episode.

Both numbers are correctly computed surprisals. The problem is that they are surprisals **under
different models**, and the models have wildly different dynamic ranges. A unigram over ~200
tokens can never exceed ~37 bits. A Poisson tail exponent scales with `n log n` and is unbounded.
Sharing a unit does not make two quantities comparable — you are comparing "how surprised is a
frequency model" with "how surprised is a rate model," and the latter is capable of much larger
numbers for reasons that have nothing to do with forensic importance.

The fix is a **per-detector quota**: each detector independently collapses its findings into
episodes, sorts, and contributes only its top `⌈budget / #detectors⌉`. Episodes that several
detectors agree on (same token + bucket) are then merged, summing bits and unioning members, and
the merged list is ranked and truncated to `budget`.

This buys detector **diversity** — a guaranteed slice of the shortlist for each *kind* of anomaly
— at the cost of strict global optimality under the (wrong) assumption that bits are globally
comparable. It is a rank-fusion strategy, closely related to using per-list rank rather than raw
score (as in Reciprocal Rank Fusion), and it was mandatory: without it, recall is zero.

A cleaner future variant is per-detector rank-percentile normalization, or calibrating each
detector's score to a common empirical scale, rather than a hard quota.

## 4.3 The output

```csharp
record TriageItem(int EventIndex, long Ts, string Token, double TotalBits,
                  int Count, int[] MemberIndices, Finding[] Findings);
record TriageReport { TriageItem[] Shortlist; int TotalEvents; int Candidates;
                      double CompressionRatio => Shortlist.Length / TotalEvents; }
```

rendered for the agent as:

```
[  34012.3 bits ×2318 ] 2018-08-06 19:14:02Z evtx:4907 — 2318 'evtx:4907' events in 60s (≈0.31 expected, 34012.3 bits)
[     14.0 bits ×8    ] 2018-08-06 03:22:11Z evtx:1102 — event type 'evtx:1102' is rare (8/130948 in baseline, 14.0 bits)
```

Everything above is pure computation over arrays — no I/O, no model, no network. A 145,756-event
triage runs in about **2 seconds**.

---

# Part V — Evaluation

## 5.1 Metrics

Implemented in `AnomalyDetectionEval`:

- **`ScoreTriage(report, isPositive[])` → recall @ budget + compression + first-hit rank.** The
  primary metric. An episode covers every positive among its members.
- **`RankingMetrics(...)` → precision@k, recall@k, Average Precision, best rank, chance AP.** Used
  for the comparative experiments, since AP is threshold-free and, unlike ROC-AUC, is sensitive to
  performance in the extreme-imbalance regime.

Accuracy is never used for anomaly ranking. It is used only in the *balanced*
action-classification proxy of §7.4, where it is appropriate.

## 5.2 The validation host

**SANS SRL-2018**, host `base-rd-01` (a compromised Remote Desktop Services server). Ground truth
is derived post hoc and never enters the model:

- **8 log-clear events** — `EventId ∈ {1102, 104}` (anti-forensics).
- **24 C2 PowerShell events** — records whose message contains the attacker's domain
  `squirreldirectory`, carried as a `Label` (labels are a supervision target and are never
  rendered or featurized).

This is *non-circular* ground truth: we did not synthesize the malicious events, only identify
them for scoring. Data staging (the full Plaso JSON export is 486 MB, too large to marshal) is
documented in the `SrlAnomalyEvalTests` header.

## 5.3 Results — the shipped detectors

**Two logs (Security + System), 130,948 events, self-baseline, log-clear ground truth:**

| Budget | Shortlist | Compression | Recall | First hit at rank |
|---|---|---|---|---|
| 50 | 50 | 0.04% | 25% (2/8) | — |
| **200** | **182** | **0.14%** (≈720×) | **100% (8/8)** | 86 |
| 500 | 448 | 0.34% | 100% (8/8) | 86 |

**Three logs (+ PowerShell Operational), 145,756 events, both IOC classes:**

| Configuration | C2 recall | Log-clear recall | All | Shortlist |
|---|---|---|---|---|
| ContentDetector alone, budget 500 | 100% (24/24), first at rank 8 | — | — | 65 |
| Full 5-detector ensemble, budget 200 | **100% (24/24)** | **100% (8/8)** | **100% (32/32)** | **148** (0.10%, ≈985×) |

So: **145,756 events → a 148-event review set containing every known IOC**, each with a written
reason, in ~2 seconds.

## 5.4 Honest caveats

These results are good but they are not a benchmark, and the document would be dishonest without
stating the limits:

- **n = 1 host, 2 IOC classes.** Both classes are, by construction, the kind of thing these
  detectors are designed to find (a rare event type; a keyword-laden message). This validates the
  mechanism; it does not estimate performance on unseen intrusions. Adding the attacker's service
  installs (`7045`) and lateral-movement logons as further labelled positives is an open item.
- **The top of the shortlist is probably benign.** The highest-scoring episodes are bulk
  audit-policy changes (`4907`/`4945`), most likely a GPO deployment. They are *interesting* — a
  real analyst would look — but they illustrate that ranking by surprisal ranks by surprise, not
  by importance. Down-weighting bursts of *common* types is a known improvement (§8.4).
- **Recall @ budget is a permissive metric.** It should be: the alternative — demanding autonomous
  precision from an unsupervised method on a problem where "anomalous ≠ malicious" — is the
  failure mode of much of the published literature.
- **Self-baselining is doing real work here** because this attacker was quiet. §3.2 explains why
  it degrades for a prolific one.

---

# Part VI — The Studiawan line of work

Hudan Studiawan (Murdoch University / ITS Surabaya) and collaborators produced the most sustained
research program on machine learning over forensic timelines. Their papers are the main external
influence on this toolkit — including where we deliberately went the other way. Copies are in
`reference/papers/timelineml/`.

## 6.1 The papers

**Automatic Log Parser to Support Forensic Analysis** and **Automatic Event Log Abstraction to
Support Forensic Investigation** (Studiawan, Sohel, Payne). Learned log-field extraction —
`nerlogparser` (BiLSTM NER) and graph-clustering-based templating (F = 95.35%). This is the
learned equivalent of our rule-based `EventCanonicalizer`.
*Not adopted:* Plaso already parses to structured fields, so the learning problem they solve does
not arise for us. Their message-templating idea remains attractive as a way to capture message
signal without the raw-string leakage we avoid.

**Sentiment Analysis in a Forensic Timeline With Deep Learning** (Studiawan, Sohel, Payne, *IEEE
Access* 2020). The foundational idea of the program: treat each log message as a sentence, run a
sentiment classifier (word embeddings + content/context attention + softmax), and treat **negative
sentiment as an event of interest**. `pylogsentiment` (GRU + Tomek-link undersampling for
imbalance) is the OS-log variant.

**Zero-Shot Anomaly Detection in a Forensic Timeline** (Putra, Achmad, Studiawan, ICSCC 2024).
Removes the training requirement: convert each message to natural language via regex templates
(falling back to `nerlogparser` NER), then classify with a pretrained zero-shot NLI model
(best: `sileod/deberta-v3-base-tasksource-nli`). Reported F1 **98% on one honeynet corpus and
0–47% on others** — a large and honestly-reported variance that says the approach is highly
sensitive to the match between dataset and pretrained model.

**Studiawan (2020), PhD thesis, Murdoch University.** Four methods plus a fusion stage: the NER log
parser, graph clustering, a **deep autoencoder over five statistical features (Ch. 7)**, the GRU
sentiment model, and weighted-majority-voting fusion (Ch. 10). This is the single most influential
document on our design.

**GenDFIR** (Loumachi, Ghanem, Ferrag, arXiv 2409.02572). RAG over event logs: embed events, let a
retrieval agent fetch relevant ones, have an LLM reason in prose.

**Felix (2025), IJFEI.** Classical/deep ensemble (autoencoders, LSTM, isolation forest, random
forest) over ELK/Splunk; RF and LSTM best; supervised.

## 6.2 The paradigm split

Every one of these systems puts the model **on the raw timeline text** — a per-event NL classifier,
or an LLM reading events directly (or via retrieval). Camel inverts this: classical, cheap methods
build a **structured representation and do the quantitative reduction**, and the LLM writes *code*
over a typed SDK rather than reading events.

The disagreement is substantive, not stylistic. Sentiment analysis presumes log messages carry
affect — true for Linux syslog ("authentication failure", "segfault"), which is what these papers
evaluate on. It is largely **false for Windows forensic artifacts**: a Shimcache entry, a Prefetch
record, or an `$MFT` timestamp carries no sentiment whatsoever, and the majority of a Windows
super timeline is exactly those. Zero-shot NLI's 0–47% floor is, we think, this mismatch showing
up empirically.

## 6.3 What we took: thesis Chapter 7

Chapter 7 feeds a deep autoencoder five per-event statistical features, among them a **bad-word
count** (from a curated suspicious-keyword dictionary) and **message length**.

That pair is the most actionable idea in the literature for our purposes, and it is what
`ContentSignals` implements. The reasoning for taking the features and dropping the autoencoder:

- The bad-word dictionary is effectively an **unsupervised distillation of their own GRU sentiment
  model** — it captures "this message contains alarming vocabulary" with zero training, zero
  labels, and complete explainability.
- Both features are **scalars**, which is exactly the leakage-safe form §2.2 demands.
- An autoencoder over five scaled features is a learned multivariate scorer: heavier, less
  explainable, and — this matters in forensics — it cannot tell you *why*. Per-detector bits with
  a written reason can.

Result: adding these two scalars took C2 recall from **0% (structurally undetectable) to 100%**.
The idea works.

## 6.4 Independent convergence, and what we declined

Chapter 7 also uses `inter-arrival rate = frequency / duration`, and Chapter 5 a cluster score of
`frequency × inter-arrival`. These are, independently derived, our `TimingBurst` — a reassuring
convergence. The thesis notes both tails of the frequency distribution are anomalous; we cover the
low tail with `RareType` and the high tail with `TimingBurst`, but have **no "went silent"
detector** for a service that stops (a real gap — log forwarding going quiet is a classic tell).

Chapter 10's finding that weighted-majority fusion beats the best single detector by only ~0.2–1
F1 is why our merge stage is deliberately simple.

**Declined:** the μ + c·σ score threshold (Ch. 7). It is tuned on labelled data via F1; we are
unsupervised, so we use a review budget. Worse, a *global* μ/σ over summed bits would be dominated
by `TimingBurst`'s magnitudes — the same incommensurability §4.2 describes. Applied per detector
it would be defensible, and remains an open option.

---

# Part VII — The experiments that lost: representation learning in `Camel.Training`

This part documents work that **did not ship**. It occupies a third of this document because the
negative results are what justify the shipped design, and because the failure modes generalize.

## 7.1 The hypothesis

The obvious modern approach: don't hand-engineer detectors — learn a representation.

1. Cut the canonical stream into windows (an *episode* — logon, then file write, then execution —
   is the unit an analyst reasons about, not a single event).
2. Render each window to text.
3. Embed with a sentence encoder.
4. Score novelty as distance to a baseline of benign window vectors.

Everything needed for this exists in `Camel.Training`:

- **Windowing** — `Windower.SlidingByCount(size, stride)`, `WindowSpec.Tiled(n)`.
- **Renderers** (three, because the render turned out to matter as much as the encoder):
  - `TextRenderer` — compact token salad: `evtx record eid: 4624 loc: system32 macb: ...b dt: burst h: 14`
  - `NaturalRenderer` — prose: *"Moments later, a successful logon (event 4624) in the System32 directory was recorded, at 14:00."*
  - `SemanticRenderer` — terse expanded phrases, no field labels, structural facts bracket-delimited: `windows event log process creation system folder [m...] [hour 3]`
- **Embedders** behind one interface `IEventEmbedder { int Dimension; float[] Embed(string); }`,
  all returning L2-normalized vectors so cosine = dot:
  - `HashingEmbedder` — signed FNV-1a feature hashing into 256 dims. No model, no training, stable across processes.
  - `MiniLmEmbedder` — all-MiniLM-L6-v2, 384-d, ONNX.
  - `NomicEmbedder` — nomic-embed-text-v1.5, 4-bit quantized, 768-d, with task-instruction prefixes (`classification:` / `clustering:` / `search_document:`), trained for retrieval and clustering rather than sentence similarity.
- **`NoveltyScorer`** — fit on benign window vectors; score a query by `1 − mean(top-k cosine
  similarity)`. Near 0 = looks like normal; near 1 = unlike anything seen.
- **`TimelineNoveltyBaseline`** — the whole pipeline, embedder injected.
- **Eval harnesses** — `AnomalyDetectionEval` (ranking metrics) and `DatasetEvaluator` +
  `ActionClassificationEval` (leave-one-out k-NN over labelled windows).

This is a reasonable, well-instrumented unsupervised anomaly detection design. It lost anyway.

## 7.2 Experiment 1 — synthetic injection (it works)

Take a 600k-row prefix of a real timeline (→ 61,251 high-signal events), splice in five synthetic
malicious episodes (encoded PowerShell `4104`, log clear `1102`/`104`, credential dumping
`4672`/`4663`/`4648`, service persistence `7045`, rogue account `4720`), and rank windows by
novelty. `HashingEmbedder` + `TextRenderer`:

| Window | AP | Chance AP | P@20 | R@20 | Best rank |
|---|---|---|---|---|---|
| Tiled(5) | **23.3%** | 0.2% | 35% | 78% (7/9) | **2** / 3681 |
| Tiled(10) | 20.6% | — | — | 71% (5/7) | 8 |
| Tiled(20) | 9.6% | 0.7% | — | 33% (2/6) | 5 |

AP ~117× chance. **Small windows win** — the opposite of the classification proxy — because a
short malicious burst *concentrates* into a near-pure window instead of being averaged into benign
churn. Since a window vector is essentially a mean of its events' token statistics, window size
directly controls the signal-to-noise ratio of that average. This is the central trade-off in
window-based anomaly detection and it is worth internalizing.

Encouraging. Then we ran it on real data.

## 7.3 Experiment 2 — the real host (it fails completely)

Same pipeline, `base-rd-01`, 130,948 real events, real log-clear IOCs. Baseline fit on a disjoint
later 70k slice, scoring an early 20k slice. (The log-clears are the *oldest* surviving records —
clearing a log resets it — so they sit at the front of the time-sorted stream.) Against a trivial
control, `EventIdRarityScorer`, which is just `max −log₂ p(EventId)` over the window:

| Window | Embedding novelty AP | Embedding best rank | Rarity AP | Rarity best rank |
|---|---|---|---|---|
| Tiled(3) | 0.3% | 542 / 6667 | **100%** | **1** |
| Tiled(5) | 0.3% | 338 / 4000 | **100%** | **1** |
| Tiled(20) | 0.2% | 608 / 1000 | **100%** | **1** |

Embedding novelty is **at chance**. Every log-clear window sits mid-pack. A one-line frequency
count ranks all of them first, at every window size.

**Why.** Render a window containing the log clear:

```
eventlog record eid: 104 macb: ...b dt: burst h: 3 | eventlog record eid: 4624 ...
```

versus any benign event-log window. They share `eventlog`, `record`, `macb`, `dt`, `h`, and the
structural scaffolding — **five of six tokens**. The single discriminative token, `eid: 104`, is
one component of a bag-of-tokens vector that is then *averaged* over the window and L2-normalized.
Its contribution is O(1/window_size) of the vector. Meanwhile a busy, type-diverse host has
thousands of benign windows, so the IOC window has plenty of near neighbours in the embedding
space, and mean top-k cosine distance — the novelty score — comes out unremarkable.

The synthetic experiment succeeded only because its baseline was homogeneous and its injections
were pure bursts of *never-before-seen* IDs. That combination is not what a real host looks like.
**This is a cautionary result about synthetic validation in general**, and it is the reason the
project rebuilt on explicit surprisal.

The diagnosis generalizes: *pooling destroys sparse signal*. When the discriminative information is
concentrated in one rare categorical feature, any representation that averages over a window will
attenuate it by roughly the window size — while an explicit `−log p` on that feature has unbounded
sensitivity to exactly the rare values you care about.

## 7.4 Experiment 3 — is a better encoder the answer?

Maybe feature hashing was the problem. The natural test: a *balanced, labelled* proxy task, so
ordinary classification metrics apply. The **Studiawan Windows 11 dataset** (from arXiv 2505.03100,
in `reference/datasets/scenario-1/`) provides exactly this — a 2.2M-event timeline with
~2,000-event segments carved out per user action, with video ground truth: `launch-edge`,
`launch-cmd`, `firefox-install`, `open-google`, `search-sql-injection`, `shutdown`, and so on
(15 classes, chance = 6.7%).

Task: window the events, embed, and classify the action by leave-one-out k-NN (k = 5). This
measures **representation quality** directly — do windows of the same activity embed near each
other?

Unfiltered, `Tiled(20)`, 1,608 windows:

| Embedder + render | Accuracy | Macro-F1 |
|---|---|---|
| nomic-v1.5-q4 + natural + `classification:` prefix | **23.9%** | **23.2%** |
| HashingEmbedder + token render | 23.5% | 22.2% |
| MiniLM + natural | 23.4% | 22.2% |
| MiniLM + token render (spaced `eid: 4624`) | 21.1% | 20.0% |
| MiniLM + token render (glued `eid4624`) | 19.6% | — |

Every model is 3.5× chance, and **every model lands at 23–24%**. A 768-d instruction-tuned
transformer beats 256-d feature hashing by 0.4 points, for roughly **10× the inference cost**
(13.5 min vs 82 s for the same 1,608 windows).

Two useful side findings:

- **Tokenization is worth more than model capacity here.** Simply putting a space in `eid: 4624`
  instead of `eid4624` lifted MiniLM by 1.5 points — a bigger gain than upgrading MiniLM to nomic.
  A WordPiece tokenizer cannot segment a glued alphanumeric token; feature hashing is unaffected
  because it whitespace-splits regardless. If you feed engineered tokens to a pretrained NL model,
  its tokenizer is part of your model.
- **Render style is embedder-specific, and matters more than the embedder.** On filtered
  `Tiled(5)` data with MiniLM: natural prose **22.1 / 17.3**, terse semantic **15.7 / 11.1**,
  semantic + bracketed structural **16.1 / 16.4**. Expanding compound values ("Shimcache" →
  "application compatibility cache") helps — a WordPiece model has no vocabulary for enum
  spellings. But *dropping* grammatical scaffolding and *bracketing* structural facts
  (`[m...] [hour 0]`) hurts: the model was pretrained on prose and wants facts woven into
  sentences. Structural data does carry signal (macro-F1 16.4 with it vs 11.1 without) — it just
  has to be expressed as language. Meanwhile, for `HashingEmbedder` prose is actively *worse* than
  token salad, because grammatical filler dilutes the discriminative tokens in the bag.

## 7.5 The ceiling is the representation, not the encoder

Why does everything stop at 23–24%? Because **~80% of every window is the same filesystem-metadata
churn** — OneDrive sync, temp writes, log rotation — regardless of which action generated it. Every
class shares most of its mass. No encoder can separate classes whose inputs are 80% identical; the
information is not there to recover.

The obvious fix — `NoiseFilters.KeepHighSignal` — produces a genuinely nuanced result:

| Configuration | hashing + token | MiniLM + natural | Windows |
|---|---|---|---|
| unfiltered, Tiled(20) | 23.5 / 22.2 | 23.4 / 22.2 | 1608 |
| filtered, Tiled(20) | 23.9 / 17.1 | 23.5 / 16.0 | 238 |
| filtered, Tiled(5) | 17.7 / 17.4 | **22.1** / 17.3 | 923 |

Filtering sharpens the discriminative classes (`launch-explorer` F1: 37% → 54%) and nudges accuracy
up, but **collapses macro-F1** — because it exposes severe class imbalance. Some actions (e.g.
`open-google`) generate almost no high-signal events, yielding 2–6 windows and F1 = 0. The
filesystem "noise" had been inadvertently *balancing* the classes. A cautionary tale about
macro-averaged metrics on a dataset whose per-class support changes when you change preprocessing.

One clean signal did emerge: on small, sparse filtered windows, **MiniLM decisively beats hashing
(22.1 vs 17.7)**. Semantic embedding earns its keep precisely when there is little lexical signal
to count. That is the boundary condition worth remembering.

And note the asymmetry: filtering's real payoff is for *novelty*, where class balance is irrelevant
and removing ubiquitous churn makes genuine anomalies stand out — not for this balanced
classification proxy.

## 7.6 What this means

There is an information-theoretic reading that ties Parts II and VII together.

Canonicalization (§2.2) **deliberately destroyed** the high-entropy fields — paths, message text —
because they were leaky. What survives is a low-dimensional, discrete substrate: a handful of enums
and one categorical token. A learned sentence encoder's advantage is its prior over *natural
language semantics* — it maps distributionally-similar prose to nearby vectors. That prior has
almost nothing to grip on a rendered enum tuple, and it cannot recover information the
representation already threw away.

So the two shipped uses of content are precisely the two that *don't* need an encoder:
`BadWordCount` (a knowledge prior, no training) and `MsgLength` (a scalar the canonical form
retains). The learned-encoder path was not beaten by a better model; it was beaten by having
nothing left to model.

Three transferable lessons:

1. **Match the method to the substrate.** Embeddings are for dense semantic text. Sparse
   categorical sequences want counting: unigram/bigram surprisal, rate models. Reaching for the
   neural method by default cost 10× compute for a rounding error.
2. **Distrust synthetic validation.** The embedding pipeline scored 117× chance on injected
   anomalies and *at chance* on real ones. The synthetic data had accidentally satisfied the
   method's assumptions.
3. **A trivial baseline is a load-bearing part of the experiment.** `EventIdRarityScorer` is one
   line. It is the reason we know the sophisticated pipeline had failed, rather than concluding
   "the problem is hard."

## 7.7 Status of the code

All of `Camel.Training` remains in the repository, builds, and is tested. `Camel.Inference` does
**not** reference it (or `Camel.Search`, or ONNX Runtime) — the dependency is one-way, so the
shipped toolkit carries none of this weight. The heavy evaluations are `[Fact(Skip = …)]` one-offs,
run manually with `--filter`, writing metrics to temp files, with results recorded in code
comments — deliberately kept out of the permanent suite, which stays at a few seconds.

---

# Part VIII — Limitations and open work

Stated plainly, roughly in order of how much they should worry you.

**8.1 Self-baselining fails against a prolific attacker.** §3.2. If the adversary's activity is a
material fraction of the stream, it becomes "normal" and rarity-based detection collapses.
Mitigable with a cross-host baseline (the two-argument `Triage` overload exists) or a known-good
reference image — neither of which is usually available.

**8.2 "Anomalous" is not "malicious."** §1.2(4). The shortlist top on the validation host is
probably a benign GPO rollout. Statistically-normal-but-malicious activity — logon with valid
stolen credentials — is invisible to every one of these detectors by construction.

**8.3 Transitions are global, not per-entity.** §3.3. The bigram model interleaves all sessions and
accounts. Real lateral movement lives in per-session sub-sequences, and a bare event ID discards
the discriminators (logon type, whether the target is privileged). Fixing this requires extracting
EVTX event parameters into `CanonicalEvent`, which is currently not done. **Highest-value open
item.**

**8.4 Bursts of common types dominate.** A burst of a *rare* type is more interesting than a burst
of an ordinary one, but `TimingBurst` does not know that. Folding rare-type bits into the timing
score, or normalizing per detector by rank-percentile instead of raw bits, would fix the
shortlist's top.

**8.5 Summed bits assume detector independence.** They are not independent — a burst of a rare type
fires both `RareType` and `TimingBurst` on correlated evidence, and summing double-counts. The
per-detector quota limits the damage; a proper treatment would model the dependence (a noisy-OR
combination, or likelihood ratios with an explicit correlation structure).

**8.6 The beacon score is not a surprisal.** §3.5. `0.6 · regular · fraction` is a heuristic in
bits-shaped units, which makes it the one detector whose scale is not even nominally principled.

**8.7 The bad-word dictionary is precision-oriented.** ~35 hand-curated terms. High precision, no
recall against novel or renamed tooling, and trivially evadable by anyone who reads it. It is a
useful prior, not a detector of unknown-unknowns.

**8.8 No "went silent" detector.** §6.4. Only the upper tail of the rate distribution is modelled.
A log source that stops reporting is a classic anti-forensics tell and is currently invisible.

**8.9 No threshold mode.** Budget-based cutoff only. A per-detector μ + c·σ threshold (Studiawan
Ch. 7) is a reasonable alternative; a global one is not (§4.2).

**8.10 Evaluation breadth.** §5.4. One host, two IOC classes, both well-matched to the detectors.

---

# Appendix A — Code map

**`src/Camel.Inference`** — the shipped toolkit. No ONNX, no `Camel.Search`, no ML framework.

| File | Contents |
|---|---|
| `CanonicalEvent.cs` | the canonical record + `SourceClass` / `Macb` / `LocBucket` / `RegClass` |
| `EventCanonicalizer.cs` | Plaso → canonical; field normalizers; Δt computation |
| `ContentSignals.cs` | bad-word dictionary, `MsgLength`, `BadWordCount` |
| `NoiseFilters.cs` | `KeepHighSignal`, `DropFilesystemChurn` |
| `EventWindow.cs` / `Windower.cs` | windowing (`SlidingByCount`, `AroundPivot`, `WindowSpec`) |
| `EventDetectors.cs` | `EventType`, the 5 detectors, `DetectorEnsemble`, `TriageItem`/`TriageReport` |
| `AnomalyDetectionToolkit.cs` | the agent-facing façade |

**`src/Camel.Training`** — experiments only; references `Camel.Inference` and `Camel.Search`.
`IEventEmbedder`/`HashingEmbedder`, `MiniLmEmbedder`, `NomicEmbedder`, `TextRenderer`,
`NaturalRenderer`, `SemanticRenderer`, `NoveltyScorer`, `TimelineNoveltyBaseline`,
`AnomalyDetectionEval` (+ `EventIdRarityScorer`, `SyntheticIntrusion`), `ActionClassificationEval`,
`DatasetEvaluator`, `CsvTimelineLoader`.

**`tests/Camel.Tests.Training`** — fast permanent tests plus the `[Skip]` real-data one-offs whose
header comments record every measurement quoted in this document.

# Appendix B — The agent-facing API

Bound into the code-mode JavaScript engine as the global `anomaly` (see `DFIRMCPTools.cs`), so a
generated script can go from acquisition to explained shortlist in three lines:

```javascript
const events = await timeline.PsortAsync(plasoFile);
const report = anomaly.TriageTimeline(events, 200, /* highSignalOnly */ true);
log(anomaly.Summarize(report, 25));
```

| Method | Purpose |
|---|---|
| `Triage(events, budget = 200)` | self-baseline triage of a canonical stream |
| `Triage(baseline, target, budget)` | score a target against a separate benign baseline |
| `TriageTimeline(rawEvents, budget, highSignalOnly)` | canonicalize raw Plaso events, then triage |
| `Summarize(report, topN = 25)` | compact agent/LLM-readable rendering with reasons |

# Appendix C — References

1. Studiawan, H., Sohel, F., Payne, C. **Sentiment Analysis in a Forensic Timeline With Deep Learning.** *IEEE Access*, 2020. DOI 10.1109/ACCESS.2020.2983435.
2. Studiawan, H. **PhD thesis**, Murdoch University, 2020 — Ch. 5 (cluster scoring), **Ch. 7 (statistical features: bad-word count, message length, inter-arrival rate)**, Ch. 10 (fusion). *The source of `ContentSignals`.*
3. Putra, I.K.A.A., Achmad, R.M., Studiawan, H. **Zero-Shot Anomaly Detection in a Forensic Timeline.** ICSCC, 2024.
4. Studiawan, H., Breitinger, F., Scanlon, M. **Towards a standardized methodology and dataset for evaluating LLM-based digital forensic timeline analysis.** arXiv:2505.03100. *Source of the Windows 11 per-action dataset used in §7.4.*
5. Studiawan, H., Sohel, F., Payne, C. **Automatic Event Log Abstraction to Support Forensic Investigation.** ACSW, 2020.
6. Studiawan, H., Sohel, F., Payne, C. **Automatic Log Parser to Support Forensic Analysis** (`nerlogparser`).
7. Loumachi, F.Y., Ghanem, M.C., Ferrag, M.A. **GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval-Augmented Generation and Large Language Models.** arXiv:2409.02572.
8. Felix, A.O. **Enhancing Digital Forensics Investigations Using AI Driven Anomaly Detection and Log Correlation: A Mixed Methods Approach.** *IJFEI*, 2025.

Local copies: `reference/papers/timelineml/`. Dataset: `reference/datasets/scenario-1/`.
Companion document: [MachineLearning.md](MachineLearning.md) (the short version).

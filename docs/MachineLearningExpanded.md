# The Anomaly Detection Toolkit — an in-depth explanation

**Audience.** This document is for anyone who wants to understand what the toolkit actually does, how it decides, and where it can
be trusted. No prior knowledge is required and everything domain-specific is explained where it first appears. The anomaly detection, information theory, and time-series analysis concepts are all explained, needing nothing beyond logarithms and basic probability:
# The Anomaly Detection Toolkit — an in-depth explanation

| Primer | Covers |
|---|---|
| [§1.2 Anomaly detection](#12-what-anomaly-detection-is) | what it is, how it differs from signatures and rules, the taxonomy that explains why there are five detectors, and why its usual metrics mislead at forensic scale |
| [§1.5 The event stream](#15-the-timeline-as-a-stream-of-events) | inter-arrival times, arrival rates, periodicity, windows |
| [§3.1 Bits of surprisal](#31-surprisal-the-common-currency) | the unit every detector scores in |
| [§7.1 Representations](#71-background-representations-similarity-and-k-nn) | vectors, embeddings, cosine similarity, k-NN, and the scores the experiments report |

Skip whichever you already know. A forensic reader can skim §1.1 (what a super timeline is); an ML
reader can skim §1.2, §3.1, and §7.1.

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

## 1.2 What anomaly detection is

Anomaly detection is a specialist corner of machine learning, and one an ML course can easily skip.
This section is the background; if you already work in it, skip to §1.3.

### The premise

> Identify the observations that do not conform to expected behaviour — **without being told in
> advance what non-conformity looks like.**

That last clause is what separates it from the two techniques a forensic examiner already uses
daily:

| Approach | You supply | Catches | Misses |
|---|---|---|---|
| **Signature / IOC matching** | a specific thing to find — a hash, a filename, a YARA or Sigma rule | exactly what is on the list, with near-zero false positives | everything not on the list |
| **Rules / heuristics** | a condition an expert wrote — "more than 10 × 4625 in a minute" | the patterns someone thought to encode | the ones nobody thought of; needs tuning per environment |
| **Anomaly detection** | nothing but the data | departures from *this host's* normal, including behaviour never seen before | anything an attacker makes look routine — and it flags plenty of benign oddities |

Camel does all three. The YARA toolkit and hayabusa are signature matching; the workflows encode
analyst heuristics; this toolkit is the third row. It exists for the case the other two cannot
serve: **"I have no signature, no keyword, and no lead — where do I even start looking?"**

### Three learning settings

The standard taxonomy (Chandola, Banerjee & Kumar's survey is the usual reference) splits by what
labels you have:

- **Supervised** — labelled examples of both normal *and* anomalous behaviour; train a classifier.
  Requires a labelled corpus of attacks, which in practice means you are detecting last year's
  intrusion.
- **Semi-supervised (one-class)** — train only on data known to be clean, flag what deviates. The
  textbook setup, and what most published methods assume.
- **Unsupervised** — no labels at all. Assume only that anomalies are *rare* and *different*, and
  let the data define its own normal.

Camel is unsupervised, and §1.3 explains why the first two are not available on a real case.

### Three kinds of anomaly

The same survey splits by the *shape* of the anomaly, and this taxonomy is why the toolkit has
five detectors rather than one — each shape needs different machinery:

| Kind | Meaning | Forensic example | Detector |
|---|---|---|---|
| **Point** | one observation is odd on its own | event ID 1102, "the audit log was cleared", on a host that has never logged one | `RareType` (§3.2) |
| **Contextual** | ordinary in general, odd *in this context* | a 25,000-character message — unremarkable for a crash dump, bizarre for a PowerShell script block | `Content` (§3.6) |
| **Collective** | no single member is odd; the *group* is | 2,000 failed logons in a minute — each one utterly routine; or a chain of ordinary events in an order this host has never produced | `TimingBurst` (§3.4), `TimingBeacon` (§3.5), `RareTransition` (§3.3) |

Most real intrusion evidence is collective or contextual, which is precisely why a per-event rule
list struggles with it.

### The usual methods — and why none of them is used here

The standard unsupervised toolbox, roughly by family:

| Family | Idea | Typical assumption |
|---|---|---|
| Distance / density | anomalies sit far from their neighbours (k-NN distance, Local Outlier Factor) | points live in a metric space where distance means something |
| Clustering | fit clusters, flag what belongs to none | the same, plus a sensible cluster count |
| Isolation | random splits isolate an outlier quickly (Isolation Forest) | numeric features |
| Reconstruction | compress and re-expand; large error = anomaly (PCA, autoencoder) | a learnable low-dimensional structure |
| Statistical / probabilistic | fit a distribution, flag low-probability observations | you can name a distribution that fits |

Almost all of them expect **numeric feature vectors of independent samples**. A forensic timeline
is a *categorical, irregularly-timed, unlabelled, non-independent* stream, so most of the toolbox
does not apply off the shelf — you must first invent a numeric representation, and that step is
where the information gets lost.

Camel took the last row: fit explicit probability models by counting, and score observations by how
improbable they are. It did also try the first row — k-NN distance over learned embeddings, the
conventional modern answer — and that is Part VII, which is a record of it failing.

### How anomaly detection is evaluated, and the trap that matters most

Because anomalies are rare, the familiar metrics mislead badly. This is worth working through
concretely, because it is the reason "99% accurate" security ML is so often useless.

Take our validation host: 145,756 events, 32 of them of interest. Suppose a detector achieves
100% recall (it finds all 32) with a 1% false-positive rate — which sounds excellent.

```
false positives = 1% × 145,724 benign events = 1,457
true positives  = 32
precision       = 32 / (32 + 1,457) = 2.1%
```

Every alert has a **98% chance of being noise**, from a detector with a 1% error rate. This is the
base-rate fallacy, and at forensic scale it is unavoidable rather than a sign of a bad model.
Consequences, all of which the rest of this document leans on:

- **Accuracy is meaningless.** Always predicting "benign" scores 99.98%.
- **ROC-AUC flatters.** It plots recall against false-*positive rate*; with 145k negatives, a
  visually excellent curve still hides thousands of false alarms.
- **Use ranking metrics.** Precision@k, recall@k, and Average Precision measure what a human
  actually experiences: the quality of the top of a ranked list.

The honest conclusion is not "build a better detector until precision is high." It is to change
what the system is for — §1.4.

## 1.3 Why this is an unusual anomaly-detection problem

With that framing in place, notice how many of its standard assumptions this particular problem
violates:

1. **No labels, ever — so the supervised setting is out.** You cannot label a real intrusion
   dataset without already knowing the answer. Any method requiring supervised training is
   unusable in the field even if it trains beautifully in a paper.

2. **No clean baseline — so the semi-supervised setting is out too.** "Fit on known-normal, score
   the test set" presumes a known-normal to fit on. In practice you are handed *one* disk image
   from a machine that is *already compromised*, with no uncontaminated reference. That leaves the
   unsupervised setting, and the toolkit therefore defaults to **self-baselining**: the host's own
   event stream defines its normal, and the attacker's activity is scored against a distribution it
   is itself a (tiny) part of. §3.2 covers what this costs, and it is not free.

3. **Extreme class imbalance.** On the validation host: **32 events of interest out of 145,756** —
   a positive rate of 2.2 × 10⁻⁴, well inside the regime where §1.2's base-rate arithmetic bites.
   Any detector here will produce far more false alarms than findings.

4. **"Anomalous" ≠ "malicious".** This is the deepest issue. A statistical outlier on a Windows
   host is usually a software update, a GPO rollout, or a backup job. Conversely, the single most
   important event in an intrusion — a logon with stolen-but-valid credentials — is statistically
   *indistinguishable* from a normal logon. Purely unsupervised anomaly detection has a hard
   ceiling here, and pretending otherwise is how DFIR ML papers end up with numbers that do not
   survive contact with a real host.

## 1.4 The task reframe: triage, not detection

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

## 1.5 The timeline as a stream of events

Three of the five detectors reason about *when* things happened rather than *what* happened. This
section introduces the handful of time-series ideas they need. If you have only met regularly
sampled series — one temperature reading per minute, one closing price per day — the first point
below is the one that matters, because it rules most of that toolbox out.

### It is a point process, not a sampled signal

A forensic timeline has no sampling interval. Events occur at whatever irregular instants they
occur, and long stretches contain nothing at all. The object is a **point process**: a set of
timestamps on a line. Each point also carries a category (its event-type token, §2.5), which makes
it a *marked* point process.

The practical consequence: techniques that assume a fixed grid — autocorrelation at lag *k*,
ARIMA, seasonal decomposition, the FFT — do not apply directly, because there is no "lag 1" when
consecutive events can be 3 milliseconds or 3 weeks apart. Instead you work with the **gaps
between events**, which carry the same information in a form that survives irregular spacing.

### Inter-arrival times

The gap between consecutive events:

```
Δtᵢ = tᵢ − tᵢ₋₁
```

The whole temporal signal lives in this sequence, and three regimes of it carry forensic meaning:

| Regime | Looks like | Forensically |
|---|---|---|
| **Burst** | many gaps near zero | password spray, logon storm, mass file access, bulk policy change |
| **Cadence** | gaps nearly constant | automation — a C2 beacon, a scheduled task, a polling agent |
| **Quiet** | one very large gap | the host was off, or a log source stopped (§8.8) |

`TimingBurstDetector` (§3.4) looks for the first, `TimingBeaconDetector` (§3.5) for the second.

### Why the gaps are stored on a log scale

`CanonicalEvent.DtPrev` is `ln(1 + Δseconds)`, not `Δseconds`. Gaps on a real host span roughly
`10⁻³` to `10⁶` seconds — nine orders of magnitude. On a linear scale one week-long gap
(604,800) swamps every sub-minute gap in any average or distance computation, and everything under
a minute collapses indistinguishably towards zero. The log compresses that range so *ratios*
become comparable distances:

| Δ | `ln(1 + Δ)` |
|---|---|
| 0 s (same instant) | 0.00 |
| 1 s | 0.69 |
| 1 min | 4.11 |
| 1 hour | 8.19 |
| 1 day | 11.37 |

"10 ms → 1 s" and "1 day → 100 days" now occupy comparable intervals, which matches how the
underlying phenomena work: bursts and cadences are multiplicative, not additive. The `+1` simply
keeps `Δ = 0` finite. (`TextRenderer`'s bucket boundaries in §7.2 — 2.5, 4.2, 8.3, 11.5 — are
read straight off this scale: roughly 11 s, 66 s, 75 min, 1.1 days.)

### Arrival rates and the Poisson model

To say a burst is *surprising*, a detector needs a notion of the normal rate. The simplest
adequate model, and the only one §3.4 uses:

> If events of a given type arrive independently of one another at a constant average rate `λ`,
> then the number falling in any window of `W` seconds has mean `μ = λ·W`.

That is a **homogeneous Poisson process**. Both parameters come from counting — no fitting, no
optimizer. If a token occurred `c` times across a baseline spanning `T` seconds:

```
λ̂ = c / T                     (events per second)
μ  = λ̂ · W                     (expected count per window)
```

Worked, with the token from §3.4's example: 1,425 occurrences across a 30-day baseline
(T = 2,592,000 s) gives `λ̂ = 5.5 × 10⁻⁴` per second, so in a `W = 60 s` window you expect
`μ = 0.033` events — about one every half hour. Observing **2,318** in a single 60-second window is
the burst, and §3.4 turns that gap between 0.033 and 2,318 into a score.

Two properties of a Poisson process are worth carrying forward. Its inter-arrival times are
exponentially distributed, so *some* clustering is normal and a couple of near-simultaneous events
mean nothing. And its variance equals its mean, which is what makes a count of 2,318 against an
expectation of 0.033 so extreme rather than merely high.

**The assumption is wrong, and knowingly so.** Real hosts are not homogeneous: logons cluster at
9 a.m., backups run at 2 a.m., patch cycles land on Tuesdays. A single constant `λ` fitted over a
month averages all of that away, so a genuinely periodic *benign* workload can read as a burst.
This is one reason the shortlist's top entries skew benign (§5.4, §8.11).

### Periodicity without a spectrum

The textbook way to find a period is spectral — a periodogram or autocorrelation — and it needs a
regularly sampled signal — which, as the first point above says, we do not have. So `TimingBeaconDetector`
works directly on the inter-arrival series instead: if a process fires every ≈ `m` seconds, then
most of its gaps will sit close to `m`. Take the **median** gap as the candidate period and count
how many gaps fall within ±25% of it.

The median matters. A natural alternative is the **coefficient of variation** — `CV = σ/μ` of the
gaps, which is ≈ 1 for a Poisson process and 0 for a perfectly regular one, and so looks like an
ideal regularity score. It is useless here: a real beacon goes quiet when the host sleeps, and two
or three eight-hour gaps in an otherwise metronomic series inflate `σ` enough to hide it
completely. "What fraction of gaps sit near the median" degrades gracefully where `CV` collapses.

### Order versus timing

The same stream yields two independent kinds of signal, and the toolkit models both:

- **Timing** — where the points fall (§3.4, §3.5). Content-free: a beacon's cadence is visible even
  when its payload is encrypted.
- **Order** — the sequence of marks, ignoring the clock. §3.3 fits a **bigram** model: the
  probability of each token given the one before it, `P(τₜ | τₜ₋₁)`, estimated by counting adjacent
  pairs in the baseline. (This is a first-order Markov model — "the next symbol depends only on the
  current one." It is the same machinery as a character-level language model, applied to event
  types.) It catches chains whose every individual step is routine but whose *order* the host has
  never produced.

### Windows

Parts IV and VII operate on **windows** — contiguous runs of consecutive events, because a single
event rarely means anything while an episode (logon → file write → execution) does.

Camel windows by **event count**, not by duration: `WindowSpec.Tiled(20)` means 20 consecutive
events per window, advancing 20 at a time; `Overlapping(size, stride)` slides with `stride < size`.
Fixed-*duration* windows would be the more conventional choice and are a poor fit here, because
event density varies by orders of magnitude across a timeline — most fixed-duration windows would
be empty and a few would hold tens of thousands of events. (Fixed-duration windowing does exist,
for one specific job: `Windower.AroundPivot` takes everything within ±N minutes of a moment of
interest, reproducing the analyst's "what else happened around this time?" pivot.)

Window size turns out to be the single most consequential knob in Part VII, for reasons §7.3
develops.

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

`DtPrev = ln(1 + Δseconds)` is the log-compressed inter-event gap — the single temporal feature
carried on every canonical event. §1.5 covers why the gaps are stored on a log scale and what the
values mean (1 second ≈ 0.69, one hour ≈ 8.19, one day ≈ 11.37).

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

## 3.1 Surprisal: the common currency

Every detector in the toolkit outputs its score in the same unit — **bits of surprisal**. This
section builds that idea from nothing, because every formula in Part III is expressed in it.

### The starting point: a probability

Each detector holds some probability model of the host's normal behaviour, fitted by counting
things in the baseline. When a new event arrives, the model can say how probable that event was.
Concretely, for the simplest detector: if the token `evtx:4624` occurred 40,000 times in a
baseline of 130,948 events, the model's estimate is

```
p(evtx:4624) = 40000 / 130948 = 0.305
```

and for a token seen only 8 times,

```
p(evtx:1102) = 8 / 130948 = 0.000061
```

Low probability means "the model did not expect this," which is what we want to rank by. So we
could simply sort events by ascending `p` and be done.

### Why not just use the probability

Three practical problems, none of them deep:

1. **The numbers are unreadable.** A shortlist entry saying `p = 7.6e-12` next to one saying
   `p = 6.1e-5` is technically ordered but tells an analyst nothing about how much more unusual the
   first one is. These scores are shown to a human and to an LLM; legibility is a requirement, not
   a nicety.
2. **Probabilities multiply, and underflow.** Combining several independent pieces of evidence
   means multiplying their probabilities. Multiply half a dozen small numbers together and you get
   something that is awkward to reason about and, at forensic scale, close to floating-point zero.
3. **Differences are not meaningful on a linear scale.** Is `p = 0.001` twice as interesting as
   `p = 0.002`? The gap between `0.5` and `0.4` is the same *number* as the gap between `0.1001`
   and `0.0001`, but nothing like the same *significance*.

### The fix: take the negative logarithm

Define the **surprisal** (also called information content, or self-information) of an outcome:

```
I(x) = -log₂ p(x)          measured in bits
```

That is the whole of the information theory used in this document. Its properties are exactly the
three fixes:

- **It is monotone.** `-log₂` is a decreasing function, so ranking by surprisal descending gives
  the *identical* order to ranking by probability ascending. The ranking is unchanged; only the
  readability of the number changes.
- **`p = 1` gives 0 bits.** A certain event is not surprising and carries no information. As `p`
  approaches 0, surprisal grows without bound — which is why every detector floors its probability
  estimate rather than allowing a literal zero (see the `ε` in §3.2).
- **Multiplication becomes addition.** This is the important one:

  ```
  -log₂(p₁ · p₂)  =  (-log₂ p₁) + (-log₂ p₂)
  ```

  Independent evidence *adds* instead of multiplying. That is what lets the ensemble in Part IV
  combine five detectors by summing their scores, with no tuned weights and no calibration step.

### What one bit means

A bit is one halving of probability. `n` bits means `p = 2⁻ⁿ`, i.e. "about one in 2ⁿ":

| Bits | Probability | Reads as |
|---|---|---|
| 0 | 1 | certain — no information |
| 1 | 1/2 | a coin flip |
| 3.3 | 1/10 | one in ten |
| **6** | 1/64 | *the toolkit's default reporting threshold* |
| **8** | 1/256 | *the transition detector's threshold* |
| 10 | ~1/1,000 | |
| 14 | ~1/16,000 | |
| 20 | ~1/1,000,000 | one in a million |
| 37 | ~1/10¹¹ | never seen in this baseline |

An equivalent reading, if it helps: `n` bits is the number of yes/no questions you would need to
pin down the outcome among 2ⁿ equally likely alternatives. (This is where the name comes from —
Shannon's result is that an optimal code spends about `-log₂ p` bits encoding a symbol of
probability `p`. Camel never encodes anything; it just borrows the scale.)

### Worked example, on the real validation host

Baseline of `N = 130,948` events, self-baselined (§3.2), using `RareTypeDetector`'s formula:

| Event type | Count `c` | `p = c/N` | `-log₂ p` | Reported? |
|---|---|---|---|---|
| A routine type making up ~30% of the stream | 40,000 | 0.305 | **1.7 bits** | no — below 6 |
| `evtx:1102` "audit log cleared" | 8 | 0.000061 | **14.0 bits** | **yes** |
| A token absent from the baseline entirely | 0 (floored to ε) | 7.6 × 10⁻¹² | **36.9 bits** | **yes** |

Checking the middle row by hand: `130948 / 8 = 16368`, and `2¹⁴ = 16384`, so the surprisal is
`log₂(16368) ≈ 14.0` bits. The log-clear is roughly a one-in-sixteen-thousand event on this host —
and that is the *whole* detection mechanism for the anti-forensics IOC.

### What the thresholds mean

Each detector has a `minBits` below which it stays silent. Because the unit is interpretable, so is
the dial:

- `RareTypeDetector(minBits: 6.0)` — report only what the model rates at `p ≤ 1/64`.
- `RareTransitionDetector(minBits: 8.0)` — report only transitions at `p ≤ 1/256`. Higher, because
  a bigram model over a shuffled multi-process stream is noisier than a unigram one, so it needs
  more evidence before it speaks.

Setting these in probability units (`0.0156`, `0.0039`) would be the same thing, less legibly.

### Adding them up

Because surprisals add, an episode that several detectors independently flag accumulates:

```
rare type (14.0 bits) + suspicious content (12.0 bits) = 26.0 bits total
```

Read literally that says "jointly about a one-in-67-million occurrence." Read practically, it says
"two independent models both found this strange, so it outranks anything only one model flagged" —
which is the behaviour we actually want out of an ensemble, obtained for free from the choice of
unit.

Two honest caveats, both revisited later:

- **Independence is assumed and is false.** A burst of a rare type triggers both `RareType` and
  `TimingBurst` on correlated evidence, and summing double-counts it. See §8.5.
- **A shared unit is not a shared scale.** Two detectors can both report "bits" while having
  wildly different dynamic ranges, which broke the first version of the ensemble outright. This is
  §4.2, and it is the most instructive failure in the whole design.

### The detector contract

With the unit established, the `IEventDetector` contract is uniform:

```csharp
IEnumerable<Finding> Detect(CanonicalEvent[] baseline, CanonicalEvent[] target);
record Finding(int EventIndex, long Ts, string Token, double Bits, string Detector, string Reason);
```

Fit statistics on `baseline`, score `target`. Passing the same array for both is self-baselining.
Every `Finding` carries a human-readable `Reason` — non-negotiable in forensics, where a
conclusion that cannot be explained cannot be used.

## 3.2 RareTypeDetector — surprisal of a single event type

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

## 3.3 RareTransitionDetector — surprisal of a transition

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

Now a genuine time-series model — the Poisson set-up and the worked rate estimate are in §1.5. For
each token, estimate a homogeneous Poisson rate from the baseline:

```
λ̂_τ = c(τ) / T_baseline          μ_τ = λ̂_τ · W ,   W = 60 s
```

Then stream the target maintaining a 60-second sliding window per token (a `Queue<long>` of
timestamps, amortized O(1) per event). With `n` observed in the window against expectation `μ`,
score the upper tail by its **Chernoff / large-deviation exponent**:

```
-log P(X ≥ n)  ≈  n·ln(n/μ) - (n - μ)   nats        bits = nats / ln 2
```

In the vocabulary of §3.1, this is still "how many bits of surprise," just computed for a *count*
rather than for a symbol: it approximates `−log₂ P(seeing at least n events)` when the true rate is
`μ`. It is the standard large-deviation rate function for a Poisson variable, and equals the
Kullback–Leibler divergence between the observed and hypothesized rates — a quantity you can read
here simply as "bits of evidence against the claim that this token's rate is still `μ`." The
approximation is used instead of the exact tail sum `Σ_{k≥n} e^{−μ}μᵏ/k!` because it needs no
factorials or incomplete gamma function, stays numerically stable at n in the thousands, and is
monotone in n — which is all a ranking requires. Zero when n ≤ μ (only the upper tail is of
interest).

A quick sanity check on the scale, using the real burst from §4.2: 2,318 events of a token whose
baseline rate predicts ~0.033 per 60-second window gives
`2318·ln(2318/0.033) − (2318 − 0.033) ≈ 23,550` nats ≈ **34,000 bits**. That is an absurd-looking
number, and it is *correct* — the model genuinely assigns that burst a probability near 2⁻³⁴⁰⁰⁰.
Note how far it is from the 14 bits of the log-clear. §4.2 is about what that gap does to a ranked
shortlist.

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

The robust-statistics choice — median-plus-tolerance-fraction rather than coefficient of variation
— is deliberate, and §1.5 explains why: real beacons jitter on purpose and go quiet when the host
sleeps, and a handful of long gaps destroys a CV-based score while leaving "fraction of intervals
near the median" intact.

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
[  34012.3 bits ×2318 ] 2018-08-06 19:14:02Z evtx:4907 — 2318 'evtx:4907' events in 60s (≈0.03 expected, 34012.3 bits)
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
  for the comparative experiments.

In plain terms, for a ranked list of suspects:

- **Precision@k** — of the top `k` entries, what fraction are genuinely of interest. "How much of
  what I read first was worth reading."
- **Recall@k** — of everything genuinely of interest, what fraction appears in the top `k`. "How
  much did I find."
- **Average Precision (AP)** — walk down the ranked list; each time you hit a genuine positive,
  note the precision at that point; average those numbers. It rewards putting positives *early* and
  needs no threshold, which makes it the right summary for comparing two rankings. A perfect
  ranking scores 1.0; random ranking scores roughly the positive rate, which is why every AP figure
  in Part VII is quoted against its **chance AP** — 23.3% means little until you know chance was
  0.2%.
- **First-hit rank** — how far down the first genuine positive appears. The most human metric there
  is: how long before the analyst sees something real.

Accuracy is never used for anomaly ranking (§1.2 explains why). It is used only in the *balanced*
action-classification proxy of §7.5, where it is appropriate.

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

These describe other people's systems, so the section necessarily uses their vocabulary. The
minimum needed to follow it:

| Term | In one sentence |
|---|---|
| **GRU / BiLSTM** | neural networks that read a sequence one item at a time, keeping a running memory — the standard pre-transformer way to model text |
| **NER** (named-entity recognition) | tagging each word with what it *is* (a username, an IP, a path) — here, used to pull structured fields out of free-text log lines |
| **Sentiment classifier** | a model trained to judge whether text is positive or negative in tone; these papers treat "negative" as "an event of interest" |
| **Zero-shot NLI** | a model asked to judge whether a statement follows from a text, using only its general pre-training — no task-specific training data |
| **Autoencoder** | a network trained to compress its input and rebuild it; anything it rebuilds badly is unlike its training data, so reconstruction error becomes an anomaly score |
| **Isolation Forest / Random Forest** | tree-based methods — the first isolates outliers with random splits, the second is a supervised classifier voting over many decision trees |
| **RAG** (retrieval-augmented generation) | fetch the passages most relevant to a question, then have a language model answer using them |
| **Tomek links** | a resampling trick that discards borderline majority-class examples to help a classifier learn a rare class |
| **F1** | see §5.1 — the balanced combination of precision and recall these papers report |


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

## 7.1 Background: representations, similarity, and k-NN

Part VII involves the one genuinely modern piece of machine learning in this document. This section
covers what is needed; skip it if "embedding" and "k-NN" are familiar.

### Everything has to become numbers

Machine-learning algorithms operate on numbers, not on records. So the first step of any such
method is turning each thing you want to reason about — here, a *window* of timeline events — into
a fixed-length list of numbers, called a **vector**. That list is the thing's **representation**,
and its quality bounds everything downstream. A vector of length 384 is just 384 numbers; treat it
as coordinates of a point in a 384-dimensional space. You cannot picture that, but every operation
below works exactly as it would on a sheet of graph paper.

### Two ways to build one

**Feature hashing** — the cheap, training-free baseline (`HashingEmbedder`). Split the rendered
text into words, and for each word compute a hash that maps it to one of 256 slots; add ±1 there.
The result is a "bag of tokens" — a fingerprint of *which* tokens appeared and how often, with the
order discarded. Two windows containing a similar mix of tokens end up with similar vectors. It
requires no model and no training, and it is deterministic across machines.

**An embedding** — the learned version (`MiniLmEmbedder`, `NomicEmbedder`). A neural network,
pre-trained on an enormous corpus of ordinary text, that maps a sentence to a vector such that
sentences with similar *meaning* land near each other **even when they share no words at all**:
"the machine rebooted" and "the host restarted" should be close, while feature hashing sees two
completely unrelated token bags. `all-MiniLM-L6-v2` produces 384 numbers per sentence; nomic-v1.5
produces 768. Both run locally through ONNX Runtime — nothing is sent anywhere.

That promise — capturing similarity of *meaning* rather than of *spelling* — is the entire reason
to try this, and §7.4 is the story of it not paying off on this data.

### Measuring how similar two vectors are

The standard measure is **cosine similarity**: the cosine of the angle between the two vectors.

- **1.0** — same direction (as similar as possible)
- **0.0** — perpendicular (unrelated)
- **−1.0** — opposite

Angle rather than straight-line distance, because a vector's *length* mostly reflects how much text
there was, while its *direction* reflects what the text was about — and we care about the latter.

**L2 normalization** just means rescaling every vector to length 1. Once every vector has length 1,
the cosine similarity is exactly the dot product (multiply the two lists element-wise and add up),
which is fast. That is the only reason every embedder in Camel returns normalized vectors; it
changes nothing conceptually.

### k-nearest-neighbours

k-NN is the simplest useful algorithm in machine learning, and it has no training step at all: to
judge a new point, find the `k` known points closest to it and let them decide. Camel uses it in
both of its modes.

**As a novelty score** (the anomaly-detection use, `NoveltyScorer`). Embed a set of windows from
benign activity — those are the known points. For a new window, find its `k` most similar benign
windows and average that similarity:

```
novelty = 1 − (mean cosine similarity to the k nearest baseline windows)
```

A window that resembles routine activity has close neighbours, so novelty ≈ 0. A window unlike
anything in the baseline has no close neighbours, so novelty ≈ 1. Rank by novelty and the most
unfamiliar episodes float to the top. This is the "distance / density" family from §1.2, and it is
a completely reasonable unsupervised anomaly detector.

**As a classifier** (the measurement use). Given labelled points, label a new one by majority vote
of its `k` nearest neighbours. Camel uses this not to classify anything in production, but as a
*ruler*: if same-activity windows genuinely land near each other, a k-NN vote will be right often;
if the representation is poor, it will be near chance. That makes classification accuracy a
convenient proxy for **representation quality**, which is what §7.5 measures.

**Leave-one-out** is how that ruler is applied to a small dataset: take each window in turn, hide
its label, classify it using all the others, and count how often the vote was right. Every point
serves as a test case, and nothing is ever classified using its own label.

### The scores those experiments report

- **Accuracy** — fraction classified correctly. Meaningful *here* because this proxy task is
  balanced, unlike the anomaly task (§1.2).
- **Chance baseline** — what random guessing would score: `1/number of classes`. With 15 user
  actions that is 6.7%, and every result must be read against it.
- **F1** — for one class, the harmonic mean of precision (of those I called X, how many were?) and
  recall (of the actual Xs, how many did I find?). It is high only when both are.
- **Macro-F1** — the plain average of the per-class F1 scores, giving a class with 3 examples the
  same weight as one with 300. It therefore *exposes* imbalance that accuracy hides — which turns
  out to matter a great deal in §7.6.

### Why you would expect this to work

The appeal for forensics is real, and worth stating before watching it fail. Two intrusions never
look textually identical — different tool names, paths, accounts, hosts. But if "malicious episode"
has a consistent *shape*, then a representation that captures meaning rather than spelling should
place such episodes near one another and far from routine activity — and would flag an attack
technique nobody had written a rule or signature for. That is the promise, it is the modern default
answer to this problem, and it is exactly what the next four sections test.

## 7.2 The hypothesis

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
  - `NomicEmbedder` — nomic-embed-text-v1.5, 768-d, 4-bit quantized (weights stored at reduced precision to shrink the model), with task-instruction prefixes (`classification:` / `clustering:` / `search_document:`), trained for retrieval and clustering rather than sentence similarity.
- **`NoveltyScorer`** — fit on benign window vectors; score a query by `1 − mean(top-k cosine
  similarity)`. Near 0 = looks like normal; near 1 = unlike anything seen.
- **`TimelineNoveltyBaseline`** — the whole pipeline, embedder injected.
- **Eval harnesses** — `AnomalyDetectionEval` (ranking metrics) and `DatasetEvaluator` +
  `ActionClassificationEval` (leave-one-out k-NN over labelled windows).

This is a reasonable, well-instrumented unsupervised anomaly detection design. It lost anyway.

## 7.3 Experiment 1 — synthetic injection (it works)

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

## 7.4 Experiment 2 — the real host (it fails completely)

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

## 7.5 Experiment 3 — is a better encoder the answer?

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

- **Tokenization is worth more than model capacity here.** A language model does not read whole
  words; a *tokenizer* first chops the text into known fragments (WordPiece, the scheme these
  models use, splits unfamiliar strings into sub-word pieces it has seen before). Simply putting a
  space in `eid: 4624` instead of `eid4624` lifted MiniLM by 1.5 points — a bigger gain than
  upgrading MiniLM to nomic — because the tokenizer cannot sensibly split a glued alphanumeric
  blob, whereas `eid` and `4624` are both familiar. Feature hashing is unaffected, since it just
  splits on whitespace. If you feed engineered tokens to a pretrained language model, its tokenizer
  is part of your model.
- **Render style is embedder-specific, and matters more than the embedder.** On filtered
  `Tiled(5)` data with MiniLM: natural prose **22.1 / 17.3**, terse semantic **15.7 / 11.1**,
  semantic + bracketed structural **16.1 / 16.4**. Expanding compound values ("Shimcache" →
  "application compatibility cache") helps — a WordPiece model has no vocabulary for enum
  spellings. But *dropping* grammatical scaffolding and *bracketing* structural facts
  (`[m...] [hour 0]`) hurts: the model was pretrained on prose and wants facts woven into
  sentences. Structural data does carry signal (macro-F1 16.4 with it vs 11.1 without) — it just
  has to be expressed as language. Meanwhile, for `HashingEmbedder` prose is actively *worse* than
  token salad, because grammatical filler dilutes the discriminative tokens in the bag.

## 7.6 The ceiling is the representation, not the encoder

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

## 7.7 What this means

There is a reading in terms of §3.1's vocabulary that ties Parts II and VII together.

Canonicalization (§2.2) **deliberately destroyed** the fields carrying the most information —
paths and message text, where nearly every value is distinct and therefore individually
surprising — because that information was leaky (it identified *this* intrusion rather than
describing intrusions). What survives is a low-dimensional, discrete substrate: a handful of enums
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

## 7.8 Status of the code

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

**8.2 "Anomalous" is not "malicious."** §1.3(4). The shortlist top on the validation host is
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
per-detector quota limits the damage; a proper treatment would model the dependence — a noisy-OR
combination (which asks "how surprising is it that *at least one* detector fired", rather than
adding up overlapping evidence), or likelihood ratios with an explicit correlation structure.

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

**8.11 The rate model is homogeneous.** §1.5. `TimingBurst` fits one constant `λ` per token over
the whole baseline, so it has no notion of business hours, nightly maintenance windows, or weekly
patch cycles — a benign workload that is merely *concentrated* can exceed a flat expectation. A
time-of-day or day-of-week rate (the ingredients are already on `CanonicalEvent.HourOfDay`) would
be a modest change with a real payoff, and would also let the detector notice a burst that is
unremarkable at 2 p.m. but not at 3 a.m.

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
4. Studiawan, H., Breitinger, F., Scanlon, M. **Towards a standardized methodology and dataset for evaluating LLM-based digital forensic timeline analysis.** arXiv:2505.03100. *Source of the Windows 11 per-action dataset used in §7.5.*
5. Studiawan, H., Sohel, F., Payne, C. **Automatic Event Log Abstraction to Support Forensic Investigation.** ACSW, 2020.
6. Studiawan, H., Sohel, F., Payne, C. **Automatic Log Parser to Support Forensic Analysis** (`nerlogparser`).
7. Loumachi, F.Y., Ghanem, M.C., Ferrag, M.A. **GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval-Augmented Generation and Large Language Models.** arXiv:2409.02572.
8. Felix, A.O. **Enhancing Digital Forensics Investigations Using AI Driven Anomaly Detection and Log Correlation: A Mixed Methods Approach.** *IJFEI*, 2025.

Local copies: `reference/papers/timelineml/`. Dataset: `reference/datasets/scenario-1/`.
Companion document: [MachineLearning.md](MachineLearning.md) (the short version).

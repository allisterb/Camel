# Machine Learning in Camel — the Anomaly Detection Toolkit

> **This is the overview.** For the full treatment — the mathematics of each detector, the design
> failures that forced the ensemble's shape, the evaluation methodology, the Studiawan research
> the toolkit builds on, and the representation-learning experiments that were run and lost — see
> **[MachineLearningExpanded.md](MachineLearningExpanded.md)**.

## What it does

Given a canonical event stream — typically a Plaso super-timeline acquired with the Timeline
toolkit — the toolkit returns a ranked triage shortlist in one call:

> *"Of these N events, here are the K worth a human's attention, and exactly why."*

It is:

- **Label-free and self-baselining.** The host's own event stream defines "normal"; no clean
  reference image or training labels are required. (It can also score a target against a
  separate benign baseline when one exists.)
- **Information-theoretic.** Every detector scores each event in **bits of surprisal**
  (`-log₂ p`), so all detectors share one currency and compose additively — an event flagged by
  several detectors floats to the top.
- **An ensemble of five complementary detectors**, each catching a different shape of evil:

  | Detector | Catches |
  |---|---|
  | **Rare type** | Event types the host has never produced (e.g. EVTX 1102 "audit log cleared") — anti-forensics, first-of-a-kind activity |
  | **Rare transition** | Ordinary events in an order the host never does — scripted attack chains, lateral movement |
  | **Timing burst** | Volume spikes of an otherwise-common type — logon storms, password spray (4625 floods), rapid service installs |
  | **Timing beacon** | Low-jitter periodic cadence — C2 beacons, scheduled tasks; visible in timing alone even when payloads are encrypted |
  | **Content** | Malicious content inside a common event type — DFIR keywords (download cradles, LOLBins) and abnormally long/encoded messages |

The ensemble collapses bursts into single **episodes** (a 2,000-event flood takes one shortlist
slot, not 2,000) and applies a per-detector quota so a high-magnitude detector can't crowd out a
quieter-but-equally-interesting one. Each shortlist entry carries a plain-language reason and the
bit score, so the agent receives **evidence, not raw data**.

### Sample results

On the SANS SRL-2018 intrusion dataset (host `base-rd-01`, Security + System + PowerShell logs),
self-baselined at a review budget of 200:

| | |
|---|---|
| Timeline | 145,756 events |
| Shortlist | **148 entries** (0.10% — a ~985× reduction) |
| Anti-forensics log-clears (`1102`/`104`) recovered | **100%** (8/8) |
| C2 PowerShell (`squirreldirectory` download cradle) recovered | **100%** (24/24) |
| Runtime | ~2 seconds, pure CPU |

Ground truth here is *real*, not synthetic — the malicious events were identified after the fact
for scoring, never constructed. Caveats on what that does and does not prove (one host, two IOC
classes, and why the top of the shortlist is probably benign) are in
[the expanded document, §5.4](MachineLearningExpanded.md#54-honest-caveats).

### Why not learned embeddings?

The obvious alternative — render each window of events to text, embed it with a sentence
transformer, and score novelty as distance to a baseline — was built and evaluated in
`Camel.Training` before these detectors existed. It lost, decisively and for an instructive
reason:

- On **synthetic** injected anomalies it looked strong (AP 23.3% against a 0.2% chance floor).
- On the **real** SRL-2018 host it scored **at chance** (AP 0.3%, the log-clear windows ranked
  338th of 4,000), while a one-line event-ID frequency count ranked every one of them **first**.
- Upgrading the encoder did not help: feature hashing, all-MiniLM, and nomic-v1.5 all plateau at
  23–24% on a balanced action-classification proxy, because ~80% of every window is filesystem
  churn common to all classes. The ceiling is the representation, not the model.

The diagnosis is that averaging a window into one vector attenuates a rare categorical signal by
roughly the window size, while `−log p` on that same feature has unbounded sensitivity to exactly
the rare values that matter. The one idea that survived — content signals — is in the
`ContentDetector`, as two leakage-safe scalars rather than an embedding. Full write-up in
[§7 of the expanded document](MachineLearningExpanded.md#part-vii--the-experiments-that-lost-representation-learning-in-cameltraining);
the experiment code remains in `Camel.Training`, which the shipped toolkit does not reference.

## Why this beats an agent analyzing event logs on its own

Letting an LLM page through event logs directly is the obvious approach, and it is the wrong one
for forensic-scale data. Concretely:

- **It doesn't fit.** A real host produces hundreds of thousands to millions of timeline events.
  That cannot enter a context window. An agent reading logs directly is forced to *sample* — and
  the single 1102 record or the one beaconing process is exactly what gets dropped. The toolkit
  scores **every** event, then surfaces the ~0.1% that matter.

- **Base rates need counting, not intuition.** "Rare" and "bursty" are quantitative claims about
  frequencies across the *whole* stream. Computing `p(token)` over 145k events, or a Poisson
  arrival-rate exceedance, is arithmetic the model cannot do reliably by eyeballing text — but is
  trivial, exact, and instant in code.

- **Some signals are invisible in text.** A C2 beacon's tell is a regular *inter-arrival
  cadence*; a password-spray's tell is *volume per minute*. Reading records one at a time, an LLM
  literally cannot see periodicity or rate — those signals only exist across thousands of events
  viewed together. The timing detectors are built for exactly this.

- **Cost and latency.** Pushing a multi-hundred-megabyte timeline through a model token-by-token
  is enormously expensive and slow. The detectors are pure CPU math (no tool I/O, no model
  calls): effectively free and near-instant. This is the whole point of Camel's *code-mode*
  design — let deterministic code do the heavy reduction so model tokens are spent on judgment,
  not bulk scanning.

- **Determinism and auditability.** Forensic conclusions must be reproducible and defensible.
  The same input always yields the same shortlist with the same bit scores and reasons — no
  stochastic variation, no hallucinated "events" that were never in the data.

The division of labor is the key idea: **ML does the quantitative reduction it is good at;
the agent does the contextual reasoning it is good at** — over a shortlist small enough to fit,
and explained well enough to act on.

## What it does not do

Worth stating plainly, because unsupervised anomaly detection is easy to oversell:

- **Anomalous is not malicious.** The toolkit ranks by statistical surprise. A GPO rollout is
  surprising; a logon with valid stolen credentials is not. It narrows the analyst's search, it
  does not render a verdict.
- **Self-baselining detects *rare* evil, not *prolific* evil.** Because the host's own stream
  defines normal, an adversary who generates a large share of the events becomes part of the
  baseline.
- **Transition modelling is global.** Real lateral movement lives in per-session sub-sequences;
  making the bigram model per-entity is the toolkit's highest-value open item.

The full list, with the reasoning behind each, is in
[§8 of the expanded document](MachineLearningExpanded.md#part-viii--limitations-and-open-work).

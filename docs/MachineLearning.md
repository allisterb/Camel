# Machine Learning in Camel — the Anomaly Detection Toolkit


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

On the SANS SRL-2018 intrusion dataset: **145,756 events → a ~150-event shortlist
(~0.1%)** that recovered **100% of both IOC classes** — the anti-forensics log-clears and the C2
PowerShell.

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

# GAPS — limitations and edge cases in the original

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec at commit `7a73b16`

The final rebuild carries exactly two improvements:

| | Name | Status |
|---|---|---|
| **Improvement 1 — the fix** | Preserve authenticated sessions during an IP ban | Selected. Derived from G-1 (section 2) |
| **Improvement 2 — the Differentiator** | End-user-facing ban explanation | Selected, with a scoped evidence statement and one stated risk (section 3) |

Observation IDs (**O-n**, **U-n**) refer to [OBSERVATIONS.md](OBSERVATIONS.md).

## How to read the gaps

A "gap" here is a limitation or edge case that the evidence supports, judged against our use case: a university portal that must pass the three Killer Tests. Several of them are reasonable design choices for CrowdSec's own goals. None of them is a claim that CrowdSec is broken.

Each gap states its evidence and its limits, meaning what the evidence does *not* show.

## 1. Gaps

### G-1 — A ban on an IP also affects legitimate users behind that IP

- **Evidence.** Buckets are partitioned by the scenario's `groupby` value (O-7). The decision scope defaults to `Ip` (O-20) and the default profile bans by IP (O-12). A decision carries a single value (O-13).
- **Consequence (inference).** When a scenario groups by source IP, everyone sharing that public IP shares one counter and one ban. On a campus this is common: NAT, Wi-Fi, labs, VPN exit nodes.
- **Limits.** This depends on configuration. The real `ssh-bf` scenario is not in the repository (U-1), so we have not seen its `groupby`. CrowdSec supports other scopes (O-20) and an allowlist (O-21), which an operator could use to reduce the effect. How a ban is applied to people who are already signed in is decided by the bouncer, which we did not examine (U-3). We claim only that the default IP-scoped path has no per-user distinction, not that CrowdSec cannot be configured around it.

### G-2 — There is no direct "N failures in T seconds" rule

- **Evidence.** Behavior is defined by `capacity` and `leakspeed` (O-8, O-9). The limiter that implements refill is external (O-3, U-2).
- **Consequence.** A requirement worded as "10 failed logins within one minute" has to be translated into capacity and leakspeed, and the exact outcome at the boundary cannot be read from this repository.
- **Limits.** This is a mismatch with how our Killer Test is worded, not a defect. A leaky bucket is a deliberate and common design.

### G-3 — Repeat overflows can create more than one active decision for the same IP

- **Evidence.** No check for an existing active decision was found in the create path (O-15). A new bucket starts after an overflow (O-19).
- **Consequence (inference).** Continued attack traffic can add further decision rows for an already-banned IP.
- **Limits.** This is an absence in the code we read, not a documented behavior. `blackhole` can suppress repeats when a scenario sets it (O-19), and the stream de-duplicates what it reports to bouncers by default (O-24). The practical impact may be small.

### G-4 — When a ban actually lifts is decided outside the product

- **Evidence.** CrowdSec has no enforcer (O-1). Expiry is passive: a decision stops matching the active filter (O-17). Bouncer polling is unknown (U-3).
- **Consequence.** "The ban is lifted exactly when it expires" is true at the API at query time, but the moment traffic is unblocked depends on a separate program.
- **Limits.** Separating detection from enforcement is an intentional architecture that lets one decision feed many enforcers. We did not observe any bouncer, so we make no claim about how large the delay is.

### G-5 — The exact instant of expiry is treated differently by different endpoints

- **Evidence.** The per-IP query uses `until >= now`; the stream uses `until > now` for active and `until < now` for expired (O-16).
- **Consequence (inference).** At the instant `until == now`, the per-IP query still returns the ban, while the stream lists it as neither active nor expired.
- **Limits.** The window is a single timestamp tick. We did not run the system, so real-world impact is not established (U-6).

### G-6 — A ban built from replayed logs can be created already expired

- **Evidence.** `until` is `StopAt` plus duration (O-14). In TIMEMACHINE mode `StopAt` is the log's time (O-23).
- **Consequence (inference).** Replaying logs older than the ban duration yields decisions whose `until` is in the past.
- **Limits.** This applies only to replay mode, where it is arguably the intended result. It does not affect live operation.

### G-7 — An overflow can be dropped under load

- **Evidence.** A full postoverflow queue drops the overflow (O-22).
- **Consequence.** In that situation an attack that crossed the threshold produces no alert and no ban.
- **Limits.** The code documents this as a deliberate fail-safe, since the alternative risks banning whitelisted sources. The default queue holds 256 entries and we have no evidence of how often it fills.

### G-8 — Detection is not immediate

- **Evidence.** Alerts are batched on a 1-second ticker (O-11), then enforcement waits for the bouncer (U-3).
- **Consequence.** There is a delay between the triggering event and the block.
- **Limits.** One second is small. The bouncer portion is unknown.

## 2. Improvement 1 — the fix: preserve authenticated sessions during an IP ban

**Status: selected. Derived from G-1.**

### What it does

When Sentinel bans an IP, the ban stops **new login attempts** from that IP. It does not cut off people behind that IP who were already signed in.

| Rule | Meaning |
|---|---|
| Existing sessions continue | A user who was authenticated before the ban can keep using their existing session |
| New logins stay blocked | Every new login attempt from the banned IP is refused until the ban ends |
| The ban is untouched | The IP ban stays active with the same expiry. Authenticated activity never removes, shortens or weakens it |
| No bypass | There is no way to obtain a new session from a banned IP |

### Why it is safe

The attack being stopped is password guessing, which happens at the login step. A person who already holds a valid session has finished that step. Letting their session continue gives an attacker nothing: an attacker without a valid password has no session to continue, and cannot get one from the banned IP.

One edge is closed explicitly. A login can be in flight when the ban is created: checked before the ban, verified after it. Sentinel processes all reports for one IP in order, and the portal must not create a session when Sentinel's answer to the report says the IP is banned. So every session that exists was created before the ban took effect.

### What it does not do

It does not help a legitimate user behind the banned IP who is **not yet signed in**, or who signs out. They must wait for the ban to expire. Improvement 1 reduces the collateral damage of G-1; it does not remove it. Removing it fully would need a way to tell users apart before they authenticate, which we could not make secure.

### Relationship to the original

This is a rebuild improvement addressing G-1. We make no claim about how CrowdSec bouncers treat existing sessions (U-3).

### Where it is specified

Requirement FR-13 in [PRD.md](PRD.md); decision D-15 in [ARCHITECTURE.md](ARCHITECTURE.md); the `context` parameter of `GET /v1/check` in [API.md](API.md). Sentinel stores no session data ([DATA_MODEL.md](DATA_MODEL.md)).

### Gaps not chosen as the fix

G-2, G-3, G-4, G-5, G-6 and G-8 are already avoided by the core design in [ARCHITECTURE.md](ARCHITECTURE.md) section 6. They are treated there as design decisions, most of them needed to pass the Killer Tests, and are not counted as the fix. G-7 has no counterpart in Sentinel, which has no queue between detection and ban.

## 3. Improvement 2 — the Differentiator: end-user-facing ban explanation

**Status: selected, on a scoped evidence statement. One risk is recorded below.**

### What it does

When access is blocked, Sentinel gives the portal a ready-made explanation that is safe to show to the blocked person:

- that access is blocked,
- why,
- when the block started,
- when it expires.

### Evidence statement

> Our examined CrowdSec materials document operator-facing alert and decision context, but we did not find a documented end-user portal flow that explains a ban to the blocked user.

What supports each half:

| Claim | Evidence |
|---|---|
| Operator-facing context exists | Alerts record scenario, times, event count and source (O-10). Operators can list decisions and alerts with `cscli` (O-28). |
| What a bouncer is given | For each decision: remaining duration, scenario, scope, value, type and origin. The start time is not included (O-27). |
| No end-user explanation flow found | In the repository at `7a73b16` we found no page or API response that tells a banned end user why, since when and until when (O-29). |

### What this statement does not claim

- It does **not** say CrowdSec has no explanations. Operators get detailed context.
- It does **not** say CrowdSec shows nothing to end users. Its AppSec component has a user-facing status code and a challenge page (O-29).
- It covers **one repository at one commit**. "Examined materials" means that and nothing more.

### Risk to this claim

Bouncers do the blocking (O-1), so the claim was checked against them in a separate verification pass on 2026-10-05.

- **What was checked.** Official CrowdSec bouncer documentation on docs.crowdsec.net (the remediation components index; the Nginx, Apache, HAProxy SPOA, Traefik, WordPress, Magento 2 and PHP library pages; the AppSec configuration page; the remediation component specification) and the default ban templates in the official `lua-cs-bouncer`, `cs-haproxy-spoa-bouncer` and `php-cs-bouncer` repositories.
- **What exists.** Generic end-user block pages exist. The default templates show a fixed "access forbidden" message, or texts set by the operator.
- **What was not found.** The checked official materials did not document a ban explanation flow that exposes the specific reason, start time, expiry time and remaining duration to the blocked user.
- **Result.** The Differentiator survives, with the evidence statement above unchanged.

This is "not found in the examined official sources", not "CrowdSec does not have it". Pages were read through a summarising fetch tool, not every official bouncer was checked, the hosted console was not examined, and an operator can customise any template. If an official end-user explanation of reason, start and expiry is found later, this Differentiator must be replaced.

### Minimum design

- The explanation is derived from the Ban record at the time of the request. Nothing new is stored.
- It contains only the four items above, plus the seconds remaining. It never contains evidence, usernames or anything about other users.
- Its wording refers to the network address, not the person, because many people can share one IP (G-1).

Specified as FR-14 in [PRD.md](PRD.md), D-16 in [ARCHITECTURE.md](ARCHITECTURE.md), the Ban Explanation in [DATA_MODEL.md](DATA_MODEL.md) and the `explanation` object in [API.md](API.md).

### Candidates rejected

| Candidate | Why not |
|---|---|
| Detect one account attacked from many IPs | `groupby` is an expression (O-7), so grouping by username may already be possible by configuration. Absence not shown. |
| Ban duration that grows for repeat offenders | A commented example in the default profile file computes a duration from past decisions (`config/profiles.yaml:8`). Probably already exists. |
| Generic risk scoring | No evidence either way. Absence not shown. |

## 4. Post-specification extension

Added after this file was finalized. It does not change anything above: the rebuild's two required improvements remain Improvement 1 (section 2) and Improvement 2 (section 3).

**Sentinel extension: successful-authentication alert following repeated failures for the same account and source address.** When a successful login follows repeated failed attempts for the same username from the same IP inside the window, Sentinel adds an advisory warning to its answer. Nothing is banned, counted or persisted because of it.

How it relates to this file:

- **It is not derived from any gap G-1 to G-8.** It addresses a limit of our own rule: a threshold only catches an attacker who keeps failing, so a correct guess before the threshold would pass as an ordinary login.
- **It is not the fix and not the Differentiator.**
- **No claim is made about CrowdSec.** We did not examine whether the original, its hub content or its bouncers can detect a success that follows failures, and we do not say it is absent. No observation in [OBSERVATIONS.md](OBSERVATIONS.md) bears on it.

Specified in [API.md](API.md) ("The Warning object"), decision D-17 in [ARCHITECTURE.md](ARCHITECTURE.md) and the Config table in [DATA_MODEL.md](DATA_MODEL.md). Recorded in [AGENT_LOG.md](AGENT_LOG.md), Session 5.

An **optional AI incident brief** for administrators was added later still (endpoint 5 in [API.md](API.md), decision D-18, [AGENT_LOG.md](AGENT_LOG.md) Session 6). The same three statements apply to it: it is not derived from any gap, it is neither the fix nor the Differentiator, and no claim is made about CrowdSec.

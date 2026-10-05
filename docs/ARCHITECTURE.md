# ARCHITECTURE — Sentinel

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec

This is the proposed architecture of **our rebuild**. It is not CrowdSec's architecture. Where the two differ on purpose, section 6 says how and why, citing [OBSERVATIONS.md](OBSERVATIONS.md) (**O-n**, **U-n**) and [GAPS.md](GAPS.md) (**G-n**).

It covers the core and the two improvements defined in [PRD.md](PRD.md). No implementation exists.

## 1. Overview

Sentinel is one service with one client, the portal. The portal makes two kinds of call:

- **Before** handling a request: "may this proceed?"
- **After** verifying a login: "this IP just succeeded / failed."

```
                    +------------------------- Sentinel --------------------------+
                    |                                                             |
 +--------+  check  |  +-----+     +-------------+      +-----------+             |
 |        | ------> |  |     | --> | Ban Manager | <--> | Ban Store |  (durable)  |
 | Portal |         |  | API |     +-------------+      +-----------+             |
 |        | ------> |  |     |            ^                                       |
 +--------+ report  |  |     |            | "threshold reached"                   |
                    |  |     |     +-------------+      +-----------------+       |
 +--------+         |  |     | --> |  Detector   | <--> | Failure Windows |       |
 | Admin  | ------> |  |     |     +-------------+      +-----------------+       |
 +--------+ list /  |  +-----+                               (in memory)          |
            unban   |               Clock and Config are used by all components   |
                    +-------------------------------------------------------------+
```

The portal authenticates with the **portal key**; administrators use the **admin key**.

## 2. Components

| Component | Responsibility | Holds state? |
|---|---|---|
| **API** | Authenticates callers, validates input, normalises IP addresses to canonical form, routes to the components below. Contract in [API.md](API.md). | No |
| **Detector** | Keeps the recent failures of each IP and decides when the threshold is reached. | Failure Windows, in memory |
| **Ban Manager** | Creates bans, answers whether an IP is banned, builds the end-user explanation, lifts bans on request. The only component that decides ban state. | No |
| **Ban Store** | Durable record of every ban ever created. | Yes, on disk |
| **Clock** | The single source of "now" for every decision and every timestamp. Replaceable in tests. | No |
| **Config** | Threshold, window and ban duration, read at start-up. | No |

Sentinel has no session component. Sessions belong to the portal.

The data these components hold is defined in [DATA_MODEL.md](DATA_MODEL.md).

## 3. Control flow

### 3.1 Reporting a login attempt

1. The portal sends the IP, the outcome and optionally the username.
2. The API validates and normalises the IP and reads "now" from the Clock. This is the attempt's time (D-3).
3. From here to the end, the work for this IP is atomic (D-6).
4. The Ban Manager checks whether the IP is banned now. If it is, the report is answered "banned", with the explanation, and nothing is counted. This holds for failures and successes alike.
5. If the outcome is success, the report is answered "not banned" and nothing is counted.
6. If the outcome is failure, the Detector:
   - removes from this IP's Failure Window every failure received more than 60 seconds before "now",
   - adds this failure,
   - counts what remains.
7. If the count has reached the threshold (10), the Ban Manager creates a ban with `triggered_at` = "now" and `expires_at` = "now" + ban duration, attaching the failures as evidence. The Detector then clears this IP's window.
8. The answer says whether the IP is now banned and whether this report triggered the ban. If banned, it carries the explanation.

### 3.2 Checking an IP

1. The portal sends the IP and the context: `login` for a new login attempt, `session` for a request in an existing authenticated session.
2. The Ban Manager reads "now" from the Clock and looks for a ban on this IP that has not been lifted and for which now < `expires_at`.
3. The answer states whether the IP is banned and whether the request is allowed:
   - `login` context: allowed only if the IP is not banned.
   - `session` context: allowed. The answer still states truthfully that the IP is banned (D-15).
4. If the IP is banned, the answer carries the explanation (D-16).

Nothing is written. Expiry is the comparison in step 2 and nothing else (D-4).

### 3.3 Lifting a ban by hand

1. An administrator names a ban.
2. Atomically for that IP (D-6): the Ban Manager records "now" as `revoked_at`, and the Detector clears the IP's Failure Window. The record is kept.
3. From that moment, checks for the IP report not banned.
4. Repeating the request changes nothing (D-13).

### 3.4 How the portal uses Sentinel

For a login request:
1. The portal checks the client IP with the `login` context (3.2).
2. If not allowed, the portal refuses the request without verifying the password and shows the explanation.
3. Otherwise the portal verifies the credentials and reports the outcome (3.1).
4. If the answer to the report says banned, the portal does not create a session.

For a request carrying a valid existing session:
1. The portal checks the client IP with the `session` context. The request is allowed.

If Sentinel does not answer (D-14):
- a login attempt is refused with a temporary error;
- a request in an existing session continues.

The portal must pass the real client IP. If it sits behind a proxy, working out the true address is the portal's job; Sentinel uses what it is given.

## 4. Design decisions

| ID | Decision | Reason |
|---|---|---|
| D-1 | **Events arrive by API call, not from log files.** | The portal already knows the IP and outcome. This removes log parsing as a source of error. |
| D-2 | **Detection is a sliding window: count failures received in the last 60 seconds.** A failure exactly 60 seconds old still counts. | Killer Test 1 is worded as "N within T". A sliding window states that directly, with boundary behavior we fully control. |
| D-3 | **An attempt's time is when Sentinel receives it.** All timestamps are generated by Sentinel. | One clock means no disagreement between machines and no trust in caller-supplied times. |
| D-4 | **Ban state is computed at the moment of asking.** | Makes expiry exact with no timer, job or polling to drift (Killer Test 3). |
| D-5 | **The ban check is part of Sentinel.** | The portal's check is answered from the same data and clock that created the ban, so there is no propagation delay. |
| D-6 | **Per-IP atomicity (implementation invariant).** All state-changing operations for the same canonical IP must be serialized/atomic so concurrent login-attempt reports cannot create duplicate active bans or lose failure-window updates. The exact mechanism (per-IP lock, transactional storage, etc.) is an implementation choice. | Without it, two simultaneous failures could both be counted as "the 10th", or one could be lost. Operations on different IPs need no ordering between them. |
| D-7 | **One active ban per IP; reports from a banned IP are not counted.** They do not extend the ban and cannot trigger another. | Keeps ban state unambiguous and gives a clean start after expiry. |
| D-8 | **Successes neither count nor reset the count.** | An attacker holding one valid account could otherwise reset the counter between guesses. |
| D-9 | **Bans are stored durably; Failure Windows are in memory only.** | A restart must not release banned IPs. Losing at most 60 seconds of counting on restart is acceptable. |
| D-10 | **Ban records are never deleted by normal operation.** | The record is the audit trail. A retention period can be added later. |
| D-11 | **One expiry rule everywhere: a ban that has not been lifted is active iff now < `expires_at` and expired iff now ≥ `expires_at`.** | A single half-open rule removes any ambiguity at the boundary instant. |
| D-12 | **Defaults: threshold 10, window 60 s, ban duration 15 min.** All three configurable. | The first two come from the card. The duration is our choice for a shared-IP campus. |
| D-13 | **Manual unban is idempotent and clears the IP's Failure Window.** | Repeating a request is safe; a lifted IP starts from zero like an expired one. |
| D-14 | **Logins fail closed; existing sessions fail open.** If Sentinel is unreachable the portal refuses new login attempts and lets existing sessions continue. | An outage must not become a way around a ban. Refusing only new logins keeps the cost of an outage low and matches D-15. |
| D-15 | **Improvement 1: a ban governs login attempts, not existing sessions.** A `session`-context check is allowed while the IP is banned. It writes nothing and never changes the ban. | Password guessing happens at login. People already signed in behind a shared IP are not the attacker and are not cut off. No new session can be obtained from a banned IP, so there is no bypass. |
| D-16 | **Improvement 2: every "banned" answer carries an end-user-safe explanation**, derived from the ban record at request time. | The blocked person learns what happened and when it ends, without the portal having to compose it and without exposing evidence. |

## 5. How the design meets the Killer Tests

**KT-1 — 10 failed logins from one IP within one minute → that IP is banned.**
Failures 1 to 9 from IP *A* are added to *A*'s window and answered "not banned". Failure 10 arrives within 60 seconds of failure 1, the count reaches the threshold, and the ban is created before the answer is sent (3.1 steps 6 to 8). The next check says banned.

**KT-2 — A normal user logging in at the same time is not affected.**
A user on IP *B* has a separate window and no ban. Their success is not counted (3.1 step 5). Their checks never see *A*'s ban, because the lookup is by exact IP (3.2). Operations on *A* do not delay operations on *B* (D-6).

**KT-3 — The ban is lifted exactly when it expires.**
The check compares "now" to `expires_at` (D-4, D-11). With the test clock one instant before `expires_at`, the answer is banned. With the clock at `expires_at`, the answer is not banned. No background task is involved.

**Why the improvements cannot break them.**
Improvement 1 changes only the answer to `session`-context checks; the Killer Tests use login attempts and `login`-context checks. Improvement 2 adds a field to answers and changes no decision.

## 6. Intentional differences from CrowdSec

| Topic | CrowdSec, as observed | Sentinel, by design | Related gap |
|---|---|---|---|
| Input | Acquires log lines and parses them through staged nodes (O-4, O-6) | Receives structured reports from the portal (D-1) | — |
| Detection rule | Leaky bucket set by `capacity` and `leakspeed`; no native "N in T" rule; refill behavior external (O-8, O-9, U-2) | Sliding window count of failures (D-2) | G-2 |
| Threshold | Evidence indicates `capacity: N` overflows on event N+1 (O-8) | The Nth failure triggers; the threshold is the number itself (D-12) | G-2 |
| Rule language | Scenarios with expression filters and grouping (O-7) | One fixed rule with three numbers | — |
| Alert-to-ban step | Overflow → alert → batched to LAPI on a 1 s ticker → profile → decision (O-10, O-11, O-12) | Threshold → ban, in one atomic step, before the report is answered (D-6) | G-8 |
| Enforcement | Not included; an external bouncer fetches decisions (O-1) | Built-in check called by the portal (D-5) | G-4 |
| Expiry boundary | `until >= now` on one endpoint, `until > now` / `until < now` on another (O-16) | One half-open rule everywhere (D-11) | G-5 |
| Repeat bans | No active-decision check found in the create path (O-15) | At most one active ban per IP (D-7) | G-3 |
| Time source | Arrival time in LIVE mode, log time in TIMEMACHINE mode (O-9) | Arrival time only; no replay mode (D-3) | G-6 |
| Default duration | 4 h in the default profile (O-12) | 15 min (D-12) | — |
| Scope of a ban | One counter and one IP-scoped decision for everyone behind the address, on the default path (O-7, O-12, O-20). Effect on signed-in users is up to the bouncer (U-3) | A ban blocks new logins; existing sessions continue (D-15) | G-1 |
| What the blocked person is told | Operator-facing context exists (O-10, O-28); no end-user explanation flow found in the examined repository (O-29). Bouncers not examined (U-7) | An end-user-safe explanation with every "banned" answer (D-16) | — |

Two ideas are similar to the original because they are sound, not because they were copied:
- Expiry as a stored time compared at query time (O-17). Sentinel does the same (D-4).
- Manual unban keeps the record and marks it ended (O-17). Sentinel does the same (D-10).

No CrowdSec source code, package or configuration is reused.

## 7. Failure behavior and known limits

| Situation | Behavior |
|---|---|
| Sentinel restarts | Bans are restored from the Ban Store. Failure Windows start empty, so an attacker mid-burst gets a fresh count. |
| Sentinel is unreachable | New login attempts are refused; existing sessions continue (D-14). |
| The system clock is stepped | Expiry times shift with it, because they are stored as wall-clock times. Accepted; noted as a risk. |
| An attack from very many IPs | Each IP has its own small window, discarded when idle. The per-IP rule does not detect an attack spread thinly across addresses. |
| A legitimate user shares the attacker's IP | If already signed in, they keep working (D-15). If not signed in, they are blocked until the ban ends. |
| IPv6 | Each address is tracked separately; an attacker with a large IPv6 allocation can rotate addresses. Not addressed. |

## 8. Not decided

- Implementation language, web framework and storage engine.
- The mechanism that provides per-IP atomicity (D-6).

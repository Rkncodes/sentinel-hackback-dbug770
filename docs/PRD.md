# PRD — Sentinel

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec · **Multiplier:** Brutal ×1.2

Sentinel is our rebuild. Everything in this file is a requirement or decision of ours. Facts about the original are cited by ID (**O-n**, **U-n**, **G-n**) from [OBSERVATIONS.md](OBSERVATIONS.md) and [GAPS.md](GAPS.md).

## 1. Problem

A university portal has a login page. Bots attack it by guessing passwords, often thousands of attempts from a small number of addresses. The portal needs to:

- notice an address that is failing logins at attack speed,
- block that address quickly and automatically,
- leave everyone else alone,
- and let the address back in at a known, exact time.

## 2. Users and context

| Who | What they need |
|---|---|
| **The portal** (a web application; Sentinel's only direct client) | A fast answer: "may this login attempt proceed?" and a place to report login results |
| **Students and staff** | To log in normally while an attack is under way; if blocked, to be told why and until when |
| **Portal administrators / helpdesk** | To see who is banned, why, and until when; to lift a ban by hand |

Context assumptions:
- The portal already knows each request's client IP and whether the login succeeded.
- The portal owns user sessions. Sentinel never creates, stores or validates a session.
- Many legitimate users can share one public IP (campus Wi-Fi, labs, NAT).
- One Sentinel instance serves one portal.

Two credentials exist, used with the same names in every doc:
- the **portal key**, held by the portal, for reporting and checking;
- the **admin key**, held by administrators, for listing bans and unbanning.

## 3. What we are building

A small service the portal calls directly. The portal reports each login attempt; Sentinel counts failures per IP, bans an IP that crosses the threshold, and answers ban checks.

This is a rebuild of the *behavior* on our card, not a copy of CrowdSec. CrowdSec is a general log-analysis pipeline with an external enforcer (O-1, O-4). Sentinel is deliberately narrower: one event type, one rule, and the ban check built in. [ARCHITECTURE.md](ARCHITECTURE.md) lists each intentional difference.

## 4. Scope

### In scope

- Receiving login attempt reports from the portal.
- Detecting 10 failed logins from one IP within one minute.
- Creating a time-limited ban on that IP.
- Answering "is this IP banned?" with exact expiry.
- A ban history that explains each ban.
- Manual unban by an administrator.
- The two improvements in section 8.

### Out of scope

| Excluded | Why |
|---|---|
| Reading or parsing log files | The portal reports events directly. CrowdSec's acquisition and parser stages (O-4, O-6) are not rebuilt |
| A general scenario or rule language | One fixed rule, with configurable numbers |
| Firewall or network-level blocking | The portal enforces the verdict itself |
| Bans on anything other than a single IP | No ranges, countries or usernames |
| Session management | The portal owns sessions |
| Shared threat intelligence between sites | Not needed for the card |
| Running several Sentinel instances together | Single instance only |
| User interface | API only. The portal renders anything shown to people |

## 5. Functional requirements

### Required core behavior

| ID | Requirement |
|---|---|
| FR-1 | Sentinel accepts a report of one login attempt: the client IP, the outcome (success or failure) and, optionally, the username. |
| FR-2 | Sentinel counts failed attempts per IP over a sliding window of 60 seconds. The time of an attempt is the moment Sentinel receives the report. |
| FR-3 | When a failed attempt brings an IP's count in the window to 10, Sentinel bans that IP. The ban is in effect before Sentinel answers that report. |
| FR-4 | Successful attempts never count toward a ban and never reset the failure count. |
| FR-5 | Counting and banning are per IP. Activity from one IP never changes the count or ban state of another. |
| FR-6 | Sentinel answers whether a given IP is banned at the moment of the question. |
| FR-7 | A ban has a fixed expiry time, `expires_at`, set when the ban is created. A ban that has not been lifted by hand is **active if and only if now < `expires_at`** and **expired if and only if now ≥ `expires_at`**. No action is needed to lift it. |
| FR-8 | An IP has at most one active ban. Reports from a banned IP are not counted: they do not extend the ban and cannot trigger another. When a ban ends, the IP starts with a count of zero. |
| FR-9 | Every ban is kept as a record: the IP, when it was triggered, when it expires, the rule values in force, and the failed attempts that caused it. |
| FR-10 | An administrator can lift a ban early. The record is kept and shows when it was lifted. Lifting also clears the IP's failure count. Repeating the request has no further effect. |
| FR-11 | Bans survive a restart of Sentinel. Failure counts do not: they are held in memory and start empty after a restart. |
| FR-12 | The threshold, window and ban duration are configurable. Defaults: 10 failures, 60 seconds, 15 minutes. |

### Improvements

| ID | Requirement |
|---|---|
| FR-13 | **Improvement 1 — preserve authenticated sessions during an IP ban.** A ban blocks new login attempts from the IP. A request that the portal identifies as belonging to an existing authenticated session is allowed even while the IP is banned. Such a request never changes the ban: it does not remove, shorten or weaken it, and it is never counted. No new session can be obtained from a banned IP. |
| FR-14 | **Improvement 2 — end-user-facing ban explanation.** Whenever Sentinel reports that an IP is banned, it also returns an explanation the portal can show to the blocked person: that access is blocked, why, when the block started and when it expires. The explanation contains nothing about other users and no evidence. |

### Boundary rules

So that tests are unambiguous:

- **Window.** A failure counts if it was received no more than 60 seconds before the current one. Ten failures spanning exactly 60 seconds trigger a ban; spanning more than 60 seconds, they do not.
- **Trigger.** The ban is created by the 10th failure, not the 11th.
- **Expiry.** Active iff now < `expires_at`; expired iff now ≥ `expires_at`. At exactly `expires_at` the IP is no longer banned.

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 **Exact expiry** | Ban state is computed from `expires_at` each time it is asked for. It never depends on a background job or a polling interval. |
| NFR-2 **Immediate effect** | Once the report of the 10th failure has been answered, every later check for that IP reports it as banned. |
| NFR-3 **No double bans, no lost counts** | All state-changing operations for the same IP are atomic with respect to each other. Concurrent reports for one IP produce exactly one ban and lose no failure. |
| NFR-4 **Speed** | The ban check is fast enough to sit in front of every login request. Target: under 10 ms at the 99th percentile on a single host. This is a target to verify, not a measured result. |
| NFR-5 **One clock** | Every timestamp is generated by Sentinel from its own clock. Callers never supply a time. |
| NFR-6 **Testable time** | The clock can be controlled in tests, so the Killer Tests run deterministically without waiting in real time. |
| NFR-7 **Access control** | The portal key can report and check. The admin key can list bans and unban. Neither key works for the other's operations. |
| NFR-8 **Data minimisation** | Sentinel never receives or stores passwords or session identifiers. It stores usernames only as evidence attached to a ban, visible only with the admin key. |
| NFR-9 **Bounded memory** | Tracking state for an IP is discarded once its failures are older than the window. |

## 7. Portal integration rules

Sentinel decides; the portal enforces. These rules are part of the contract.

| ID | Rule |
|---|---|
| P-1 | Before verifying credentials, the portal asks Sentinel whether the login attempt may proceed. If the answer is no, the portal refuses the attempt without verifying the password. |
| P-2 | After verifying credentials, the portal reports the outcome. If Sentinel's answer says the IP is banned, the portal does not create a session, even if the credentials were correct. |
| P-3 | **Fail closed for logins.** If Sentinel does not answer a check or a report for a login attempt, the portal refuses that attempt with a temporary "try again shortly" error. An outage must not become a way around a ban. |
| P-4 | **Existing sessions are not interrupted.** For a request that carries a valid existing session, the portal asks Sentinel with the session context (FR-13). If Sentinel does not answer, the portal lets the request continue. |
| P-5 | When access is refused because of a ban, the portal shows the explanation Sentinel returned (FR-14). |

P-3 and P-4 together mean that if Sentinel is down, nobody new can sign in, and everybody already signed in keeps working.

## 8. The three Killer Tests

The rebuild must pass all three.

| # | Test | Passes when | Requirements |
|---|---|---|---|
| KT-1 | 10 failed logins from one IP within one minute → that IP is banned. | After the 10th failure report from IP *A* inside 60 seconds, a check for *A* says banned. After only 9, it says not banned. | FR-2, FR-3, NFR-2 |
| KT-2 | A normal user logging in at the same time is not affected. | While *A* is attacked and banned, a user on IP *B* reports a successful login and checks for *B* say not banned throughout. | FR-4, FR-5 |
| KT-3 | The ban is lifted exactly when it expires. | A check for *A* one instant before `expires_at` says banned; a check at `expires_at` says not banned. | FR-7, NFR-1 |

KT-2 places the normal user on a different IP. A user on the *same* IP as the attacker is covered by Improvement 1 only if they were already signed in.

## 9. Core and the two improvements

The final rebuild is the core plus **exactly two** improvements.

| | What | Source | Requirement |
|---|---|---|---|
| **Core** | Sections 4 to 8 of this file | The card and the Killer Tests | FR-1 to FR-12 |
| **Improvement 1 — the fix** | Preserve authenticated sessions during an IP ban | Gap G-1, [GAPS.md](GAPS.md) section 2 | FR-13 |
| **Improvement 2 — the Differentiator** | End-user-facing ban explanation | [GAPS.md](GAPS.md) section 3 | FR-14 |

Both improvements are additions. Neither changes the result of any Killer Test.

### Acceptance checks for the improvements

| ID | Check |
|---|---|
| A-1 | While IP *A* is banned, a check for *A* in the session context is allowed, and a check for *A* in the login context is refused. |
| A-2 | After any number of session-context checks, *A*'s ban has the same `expires_at` and is still active. |
| A-3 | A successful login report from *A*, received while *A* is banned, is answered "banned". |
| A-4 | Every answer that says *A* is banned carries an explanation with the reason, start time and expiry time, and no evidence. |
| A-5 | An answer for an IP that is not banned carries no explanation. |

### Post-specification extension

Added after this specification was finalized and after the core and both improvements were built and tested. It is recorded here for transparency; see [AGENT_LOG.md](AGENT_LOG.md), Session 5.

**Sentinel extension: successful-authentication alert following repeated failures for the same account and source address.** When a successful login report follows at least 5 failed attempts (configurable, and always lower than the ban threshold) for the same username from the same IP inside the window, Sentinel's answer carries a warning for the portal. The alert is advisory: it bans nothing, counts nothing, stores nothing and resets nothing, and a banned IP is still answered "banned".

- It is **not** a third required improvement. The required improvements remain exactly the two in the table above, unchanged.
- It is **not** the Differentiator, and it is not derived from a gap in [GAPS.md](GAPS.md).
- We make **no claim** about whether CrowdSec has an equivalent. That was not examined.
- It leaves FR-4 intact: a success still never counts toward a ban and never resets the count. The contract is in [API.md](API.md), "The Warning object".

### Not planned

Recorded so they are not mistaken for scope: IP range bans, escalating ban durations, detection keyed on username, risk scoring, multi-instance deployment, a dashboard.

## 10. Open items

1. **Differentiator verification.** The claim behind Improvement 2 rests on one repository. Official bouncers and documentation have not been checked ([GAPS.md](GAPS.md) section 3).
2. **Technology.** Implementation language and storage engine are not chosen. The docs are independent of both.

Decided in this version: the fix is session preservation; logins fail closed when Sentinel is unreachable; the default ban duration is 15 minutes. CrowdSec's default profile uses 4 hours (O-12); we chose shorter because long bans are costly on a shared campus IP.

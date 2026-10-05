# DATA MODEL — Sentinel

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec

These are the data structures **our rebuild** needs, for the core and the two improvements in [PRD.md](PRD.md). Field names here match [API.md](API.md). The model is described independently of any storage engine; none has been chosen.

Nothing here is taken from CrowdSec's schema. For comparison only: CrowdSec stores a decision with fields including `until`, `scenario`, `type`, `scope`, `value`, `origin`, `simulated`, `uuid` and integer IP bounds (O-13 in [OBSERVATIONS.md](OBSERVATIONS.md)). Sentinel needs fewer fields because it has one rule, one scope and one ban type.

## 1. Summary

| Structure | Purpose | Lifetime |
|---|---|---|
| Login Attempt | One report from the portal | Not stored; processed and discarded |
| Failure Window | Attack tracking: recent failures of one IP | In memory only; lost on restart |
| Ban | The ban decision, its expiry and its audit record | Durable, kept permanently; survives restart |
| Ban Explanation | What a blocked person may be told (Improvement 2) | Not stored; derived from a Ban on request |
| Config | The three rule values | Read at start-up |

There is no separate audit log entity. Each Ban carries everything needed to explain it (section 4.3).

There is no session entity. Improvement 1 needs none (section 8).

## 2. Login Attempt

The input message for one login. It is never stored as its own record.

| Field | Type | Required | Notes |
|---|---|---|---|
| `ip` | IP address | Yes | Client address as seen by the portal. Normalised on receipt (section 7). |
| `outcome` | `success` or `failure` | Yes | |
| `username` | Text | No | The account name that was tried. Used only as ban evidence. |
| `received_at` | Timestamp | Set by Sentinel | The moment Sentinel received the report. Never supplied by the caller. |

What happens to it:
- **Success:** nothing is kept. Successes never count and never reset the count. (Extension: the IP's Failure Window is read, not changed, to decide whether the answer carries a success alert; see [API.md](API.md). If the alert fires, its time and failure count are remembered in memory for that IP, without the username, so that the optional incident brief can mention it. This note is not persisted and is dropped once it can no longer matter.)
- **Failure, IP not banned:** `received_at` and `username` are added to the IP's Failure Window.
- **Any report from a banned IP:** nothing is kept. It does not extend the ban or trigger another.

Passwords and session identifiers are never part of this message.

## 3. Failure Window

The attack-tracking state. There is one per IP that has failed recently.

| Field | Type | Notes |
|---|---|---|
| `ip` | IP address | Key. One window per canonical IP. |
| `failures` | Ordered list of `{received_at, username}` | Oldest first. |

Rules:
- An entry is dropped once it was received more than `window_seconds` (60 by default) before the attempt being processed. An entry exactly 60 seconds old is kept.
- When the list reaches `threshold` entries (10 by default), a Ban is created and the window is cleared. The list therefore never holds more than `threshold` entries.
- The window is also cleared when the IP's ban is lifted by hand.
- A window with no entries is removed.
- Windows exist only in memory and are empty after a restart.
- Every change to a window, and the ban creation that may follow, is atomic for that IP (D-6 in [ARCHITECTURE.md](ARCHITECTURE.md)).

## 4. Ban

One record per ban. This is the decision, the expiry and the audit trail in one place.

### 4.1 Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | Unique identifier | Yes | Assigned by Sentinel. |
| `ip` | IP address | Yes | The banned address, in canonical form. |
| `reason` | Text | Yes | Always `failed_login_threshold`. |
| `triggered_at` | Timestamp | Yes | `received_at` of the failure that reached the threshold. |
| `expires_at` | Timestamp | Yes | `triggered_at` + ban duration. Fixed at creation, never changed. |
| `revoked_at` | Timestamp | No | Set once, when an administrator lifts the ban early. Empty otherwise. |
| `rule` | `{threshold, window_seconds, ban_duration_seconds}` | Yes | The Config values in force when the ban was created. |
| `evidence` | List of `{received_at, username}` | Yes | The failures that caused the ban; `threshold` entries. |

### 4.2 Status

Status is **not stored**. It is worked out from the fields and the current time whenever it is needed:

| Status | Condition, with *now* from Sentinel's clock |
|---|---|
| `revoked` | `revoked_at` is set |
| `active` | `revoked_at` is empty and *now* < `expires_at` |
| `expired` | `revoked_at` is empty and *now* ≥ `expires_at` |

An IP **is banned** exactly when it has a Ban whose status is `active`.

This is what makes expiry exact: nothing has to run at `expires_at`. At that instant the condition simply stops being true.

### 4.3 Audit

The Ban record answers the audit questions directly:

| Question | Answered by |
|---|---|
| Who was banned? | `ip` |
| Why? | `reason`, `rule`, `evidence` |
| When did it start? | `triggered_at` |
| When did or will it end? | `expires_at`, or `revoked_at` if lifted early |
| Was it lifted by hand? | `revoked_at` is set |

The record does not say *which* administrator lifted a ban, because there is a single admin key ([API.md](API.md)).

### 4.4 Constraints

- At most one Ban per IP has status `active` at any time.
- `expires_at` is later than `triggered_at`.
- `revoked_at`, when set, is not earlier than `triggered_at`, and is never changed again.
- Ban records are not deleted and, apart from setting `revoked_at` once, not modified. In particular, nothing extends or shortens `expires_at`.

### 4.5 Lookups the store must support

| Lookup | Used by |
|---|---|
| The active Ban for a given IP | Every check and every report |
| One Ban by `id` | Manual unban |
| Bans filtered by IP and by status, newest first, up to a limit | Administrator listing |

## 5. Ban Explanation

Improvement 2. What the portal may show to a blocked person. It is derived from an active Ban each time it is needed and is never stored.

| Field | Type | Derived from | Notes |
|---|---|---|---|
| `blocked` | Boolean | — | Always `true`; an explanation exists only for an active ban. |
| `reason_code` | Text | Ban `reason` | `failed_login_threshold`. |
| `message` | Text | Ban `reason` | A fixed, plain sentence for the reason. It refers to the network address, not the person. |
| `started_at` | Timestamp | Ban `triggered_at` | |
| `expires_at` | Timestamp | Ban `expires_at` | |
| `retry_after_seconds` | Whole number | `expires_at` − *now* | Rounded up, so it is at least 1 while the ban is active. |

Rules:
- It never contains `evidence`, usernames, the rule values or anything about other users.
- It exists only while the ban is `active`. An expired or revoked ban has no explanation.

## 6. Config

| Setting | Default | Meaning |
|---|---|---|
| `threshold` | 10 | Failures in the window that trigger a ban |
| `window_seconds` | 60 | Length of the sliding window |
| `ban_duration_seconds` | 900 | How long a ban lasts (15 minutes) |
| `success_alert_threshold` | 5 | Extension. Failures in the window for the same IP and username at or above which a following success is answered with a warning. Not part of a ban's `rule`. Must be lower than `threshold`; a value at or above it is rejected at start-up, because a window never holds that many failures without a ban. When not set it is 5, or one below `threshold` if that is lower |

Two further settings belong to the optional AI incident brief and affect nothing else: `groq_api_key` (empty by default, which means the deterministic summary is always used) and `groq_model`. The key is never stored in a Ban, returned by the API or written to a log.

A change of Config applies to bans created afterwards. Existing bans keep their own `expires_at` and their own `rule` snapshot.

## 7. Shared conventions

- **Timestamps** are UTC with millisecond precision, written in RFC 3339 form at the API (for example `2026-10-05T10:00:00.000Z`). Every one is generated by Sentinel from its single clock; callers never supply one. In tests the clock is replaced by a controllable one.
- **IP addresses** are stored in one canonical text form so that the same address always matches itself. An IPv4 address written in IPv6-mapped form is treated as the IPv4 address. Anything that is not a valid single IP address is rejected.

## 8. Not in the model, and why

| Left out | Reason |
|---|---|
| A stored history of all login attempts | Not needed to detect, ban or explain a ban. Keeping it would store more personal data than the job requires. |
| Sessions, users, successful logins | Improvement 1 is a rule about which requests a ban applies to. The portal tells Sentinel whether a request belongs to an existing session; Sentinel stores nothing about it. |
| IP ranges, scopes, ban types | Sentinel bans single IPs with one kind of ban. |
| A stored explanation | The explanation is computed from the Ban, so it can never disagree with it. |

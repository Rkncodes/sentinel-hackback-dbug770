# Sentinel

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec · **Multiplier:** Brutal ×1.2

Sentinel is a small HTTP service that protects a login page from password guessing. A web portal reports each login attempt to it; Sentinel counts failed logins per IP address, bans an address that fails 10 times within 60 seconds, and answers "may this request proceed?" with an exact expiry time.

It is a clean-room rebuild of the *behavior* on our hackathon card, not a copy of CrowdSec.

## The problem

Bots attack a university portal's login page by guessing passwords, often thousands of attempts from a few addresses. The portal needs to:

- notice an address that is failing logins at attack speed,
- block that address quickly and automatically,
- leave everyone else alone,
- and let the address back in at a known, exact time.

## The three Killer Tests

| # | Test | How Sentinel passes it |
|---|---|---|
| KT-1 | 10 failed logins from one IP within one minute → that IP is banned | Failures are counted per IP in a 60-second sliding window. The 10th failure creates the ban before that report is answered; 9 failures do not ban. |
| KT-2 | A normal user logging in at the same time is not affected | Counting and bans are keyed by exact IP. A successful login is never counted. |
| KT-3 | The ban is lifted exactly when it expires | A ban is active if and only if `now < expires_at`, computed on every request. There is no timer or background job that lifts it. |

All three are automated in [tests/test_killer.py](tests/test_killer.py) and run through the HTTP API.

## The two improvements

**Improvement 1 — existing sessions survive an IP ban.** Many legitimate users can share one public IP (campus Wi-Fi, labs, NAT). A ban blocks *new login attempts* from the IP, but a request the portal identifies as belonging to an already-authenticated session is still allowed:

| `GET /v1/check` | IP not banned | IP banned |
|---|---|---|
| `context=login` (default) | `allow: true` | `allow: false` |
| `context=session` | `allow: true` | `allow: true`, and `banned: true` is still reported |

A session check never changes the ban, and no new session can be obtained from a banned IP: a login report from a banned IP is answered `banned: true` even when the password was correct. Sentinel stores no session data; sessions belong to the portal.

**Improvement 2 — end-user ban explanation (the Differentiator).** Every answer that says an IP is banned carries an `explanation` the portal can show to the blocked person:

```json
{
  "blocked": true,
  "reason_code": "failed_login_threshold",
  "message": "Sign-in from your network address is temporarily blocked because of too many failed sign-in attempts.",
  "started_at": "2026-10-05T10:00:41.250Z",
  "expires_at": "2026-10-05T10:15:41.250Z",
  "retry_after_seconds": 852
}
```

It is derived from the ban at request time and never stored. It contains no usernames, evidence or rule values, and it is `null` whenever the IP is not banned. `retry_after_seconds` is rounded up, so it is at least 1 while the ban is active.

## Extension: the success alert

*Stop the attacker. Spare the bystander. Catch the lucky guess.*

A threshold only catches an attacker who keeps failing. If the right password is guessed on the sixth try, no ban fires. So when a successful login follows repeated failures **for the same account from the same address**, Sentinel adds a `warning` to its answer:

```json
{
  "code": "success_after_failed_attempts",
  "message": "Successful login followed repeated failed attempts from this address.",
  "failed_attempts": 5
}
```

The alert fires at 5 such failures inside the 60-second window (configurable; it must be lower than the ban threshold, and a setting that could never fire is rejected at start-up). It is advisory: nothing is banned, counted, persisted or reset, and what to do with it is the portal's decision. Failures for other accounts or from other addresses do not contribute, a report without a username never produces it, and a banned IP still gets the normal "banned" answer. The warning contains no username and no failure history.

This is an extension added on top of the two improvements. It is not the Differentiator, and we make no claim about whether CrowdSec offers something similar; that was not examined.

## Optional: AI incident brief

An optional AI-powered incident briefing layer that converts Sentinel's structured security facts into a concise administrator-readable summary.

`POST /v1/incident-brief` (admin key) takes an IP and returns a two-to-four-sentence brief with the facts it was written from. Sentinel gathers the facts from its own state: ban status and expiry, failed attempts, the rule values, and whether a flagged success occurred. No usernames, evidence or secrets are included.

- **With `GROQ_API_KEY` set**, Sentinel sends those facts to Groq and returns the validated text (`"source": "groq"`).
- **Without a key, or if Groq fails or times out**, the same endpoint returns a deterministic summary of the same facts (`"source": "fallback"`). Sentinel works fully without Groq.
- **The AI never decides anything.** Detection, bans and expiry are Sentinel's deterministic rules alone; the brief only describes what they did, and nothing reads it back.
- **The key stays on the server.** It is never returned by the API, logged, or sent to the demo portal or the browser.

The Groq call uses the standard library, so there is still nothing to install. It is an optional layer: not a required improvement, not the Differentiator, and we make no claim about whether CrowdSec offers something similar.

## Architecture

```
 Portal ──check / report──▶ ┌─────┐ ──▶ Ban Manager ◀──▶ Ban Store        (SQLite file, durable)
                            │ API │          ▲
 Admin ──list / unban─────▶ └─────┘ ──▶ Detector    ◀──▶ Failure Windows  (in memory)
                              Clock and Config are used by every component
```

| Endpoint | Key | Purpose |
|---|---|---|
| `POST /v1/login-attempts` | portal | Report the outcome of one login attempt |
| `GET /v1/check` | portal | Ask whether a request from an IP may proceed |
| `GET /v1/bans` | admin | List bans with their evidence |
| `DELETE /v1/bans/{id}` | admin | Lift a ban early (idempotent) |
| `POST /v1/incident-brief` | admin | Optional: administrator summary of one IP's current state |

Major design decisions (full list in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

- **Events arrive by API call**, not from log files. The portal already knows the IP and the outcome.
- **Sliding window.** A failure counts if it was received no more than 60 seconds before the current one. Successes neither count nor reset the count.
- **One clock.** Every timestamp is generated by Sentinel; a timestamp sent by a caller is ignored.
- **Ban state is computed when asked**, from `expires_at`. Status is never stored.
- **Per-IP atomicity.** Every state-changing operation for one IP runs under that IP's lock, so concurrent reports create exactly one ban and lose no failure.
- **One active ban per IP.** Reports from a banned IP are not counted and do not extend the ban.
- **Bans are durable; failure counts are not.** Bans survive a restart; counting starts empty.
- **Two keys.** The portal key can report and check; the admin key can list and unban. Neither works for the other's endpoints.

The contract is in [docs/API.md](docs/API.md) and the data model in [docs/DATA_MODEL.md](docs/DATA_MODEL.md).

## Technology

- **Python, standard library only.** No third-party packages and nothing to install. Written for Python 3.10 or newer; developed and tested on Python 3.12.
- **HTTP:** `http.server.ThreadingHTTPServer`.
- **Storage:** one SQLite file (`sqlite3`) holding the bans. Failure windows are a dictionary in memory.
- **Tests:** `unittest`, with an injected fake clock so time-dependent behavior is checked exactly without waiting.

## Run the API

From the repository root, in PowerShell:

```powershell
$env:SENTINEL_PORTAL_KEY = "choose-a-portal-key"
$env:SENTINEL_ADMIN_KEY  = "choose-a-different-admin-key"
python -m sentinel
```

Sentinel listens on `http://127.0.0.1:8080`. Both keys are required and must differ. All settings are listed in [.env.example](.env.example); Sentinel reads them from the process environment and does not load a `.env` file itself.

```powershell
curl.exe -H "Authorization: Bearer choose-a-portal-key" "http://127.0.0.1:8080/v1/check?ip=203.0.113.7"
```

## Run the demo

The demo is a mock portal in [demo/](demo/), a separate client of the Sentinel API. Sentinel itself has no user interface.

Window 1, Sentinel with a short ban so expiry can be watched:

```powershell
$env:SENTINEL_PORTAL_KEY = "demo-portal-key"
$env:SENTINEL_ADMIN_KEY  = "demo-admin-key"
$env:SENTINEL_BAN_DURATION_SECONDS = "30"
python -m sentinel
```

Window 2, the demo portal:

```powershell
$env:SENTINEL_PORTAL_KEY = "demo-portal-key"
$env:SENTINEL_ADMIN_KEY  = "demo-admin-key"
python demo/portal.py
```

Open `http://127.0.0.1:8081/` and click in this order:

1. **EXISTING SESSION** → "1 · Sign in (before the attack)".
2. **ATTACK SIMULATOR** → "+5 failed logins", then "Sign in with the correct password". The state card turns amber: signed in, but flagged. No ban fired.
3. **ATTACK SIMULATOR** → "+5 failed logins" again. The success reset nothing, so the 10th failure triggers the ban; the state card turns red with a countdown.
4. **LEGITIMATE USER** → "Sign in" and "Check address" on the other IP. Unaffected.
5. **EXISTING SESSION** → "2 · Use the session". Allowed while banned.
6. **NEW LOGIN** → "Try a new sign-in". Blocked, even with the correct password, with the explanation shown.
7. **ADMIN** → "✦ Generate incident brief" for a short summary of the incident (Groq if `GROQ_API_KEY` is set for Sentinel, the deterministic summary otherwise).
8. Wait for the countdown. The page re-checks just before and at `expires_at`, and the state card returns to green.
9. **ADMIN** → ban the IP again, then "Unban".

Do steps 2 and 3 within 60 seconds of each other, or the first failures leave the window. Before starting, make sure no older Sentinel is still running on port 8080.

The client IPs are simulated: the page sends whatever is typed in the two IP fields. The demo portal has no authentication of its own, has one hardcoded account, and binds to `127.0.0.1` only. It is for demonstration, not deployment.

## Run the tests

```powershell
python -m unittest discover -s tests -t . -v
```

137 tests. `python -m unittest` runs the same suite. No test calls the real Groq API; that call is mocked.

| File | Tests | Covers |
|---|---|---|
| [tests/test_killer.py](tests/test_killer.py) | 3 | KT-1, KT-2, KT-3 through the API |
| [tests/test_core.py](tests/test_core.py) | 29 | Window boundaries, ban lifecycle, restart persistence, manual unban, concurrency, IP forms, config |
| [tests/test_api.py](tests/test_api.py) | 21 | Keys (401/403), validation and error codes, response shapes, evidence visibility |
| [tests/test_improvement1.py](tests/test_improvement1.py) | 8 | Session checks allowed, new logins blocked, no bypass, ban unchanged |
| [tests/test_improvement2.py](tests/test_improvement2.py) | 10 | Explanation contents, rounding, exact disappearance at expiry, nothing leaked |
| [tests/test_success_alert.py](tests/test_success_alert.py) | 27 | Extension: alert at the threshold, per account and per address, window boundary, nothing changed or leaked |
| [tests/test_incident_brief.py](tests/test_incident_brief.py) | 33 | Optional AI brief: facts, fallback, mocked Groq success and failure, key never exposed, security state unchanged |
| [tests/test_demo.py](tests/test_demo.py) | 6 | The demo portal against a real Sentinel with the real clock and a 3-second ban |

## Repository structure

```
docs/        The finalized specification (seven files). Frozen.
sentinel/    The service. API only.
  api.py       HTTP routing, authentication, validation
  service.py   Ban Manager: report, check, list, unban, explanation
  detector.py  Failure Windows (in memory)
  store.py     Ban Store (SQLite)
  clock.py     The single clock and timestamp format
  config.py    Environment configuration
  ips.py       Canonical IP form
  brief.py     Optional AI incident brief: Groq client and deterministic fallback
demo/        Mock portal and its one-page UI. A client of the API.
tests/       The automated suite.
deck.pdf     Five-slide summary.
```

## Clean-room methodology

The work was done in two separated phases:

1. **Study.** CrowdSec was read, not run, at one commit, and only behavior was recorded: [docs/OBSERVATIONS.md](docs/OBSERVATIONS.md) and [docs/GAPS.md](docs/GAPS.md). From that, our own requirements, architecture, data model and API were written ([docs/PRD.md](docs/PRD.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DATA_MODEL.md](docs/DATA_MODEL.md), [docs/API.md](docs/API.md)). The process is recorded in [docs/AGENT_LOG.md](docs/AGENT_LOG.md).
2. **Build.** The implementation was written from those seven documents only, without opening the CrowdSec checkout. No CrowdSec source code, configuration, package or template is used, and Sentinel does not depend on CrowdSec.

Statements about CrowdSec in this repository are limited to what the docs record, with their stated limits: one repository, one commit, static reading.

## Limits

- Single instance, single portal. No IP ranges, no escalating durations, no detection across many IPs.
- Each IPv6 address is tracked separately.
- A legitimate user who shares the attacker's IP and is *not* already signed in is blocked until the ban ends.
- Expiry times are wall-clock times; stepping the system clock shifts them.
- `GET /v1/bans` returns at most 200 bans and has no pagination.

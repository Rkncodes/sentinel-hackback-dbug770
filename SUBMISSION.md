# HACKBACK submission — Sentinel

## Team

| | |
|---|---|
| Team | Hack Matrix |
| Team ID | DBUG 770 |
| Members | Rajvinder Kaur, Ann Mary Jo, Esai Kavya Bhuvaneswari Muthuvel |
| Repository | https://github.com/Rkncodes/sentinel-hackback-dbug770 |

## Card

| | |
|---|---|
| Card | SENTINEL — Intrusion Detection & Auto-ban |
| Original / reference product | CrowdSec |
| Multiplier | Brutal ×1.2 |
| Reference studied | CrowdSec source at commit `7a73b16`, by static reading only. It was not built, installed or run. |

## What we built

Sentinel is an HTTP service for one web portal. The portal reports every login attempt; Sentinel counts failed logins per IP, bans an IP that fails 10 times within 60 seconds, and answers ban checks with an exact expiry time. Defaults are 10 failures, 60 seconds and a 15-minute ban; all three are configurable.

It rebuilds the behavior on the card, not CrowdSec's design. CrowdSec, as we observed it, is a general log-analysis pipeline whose blocking is done by a separate component. Sentinel is deliberately narrower: one event type, one rule, and the ban check built in. The intentional differences are tabulated in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), section 6.

## The three Killer Tests

All three are automated in [tests/test_killer.py](tests/test_killer.py), run through the HTTP API, and pass.

| # | Test | What the automated test asserts |
|---|---|---|
| KT-1 | 10 failed logins from one IP within one minute → that IP is banned | Reports 1 to 9 are answered `banned: false` and a check after 9 says not banned. Report 10, 54 seconds after the first, is answered `banned: true, ban_triggered: true`. The next check says `banned: true, allow: false`. |
| KT-2 | A normal user logging in at the same time is not affected | While IP A is attacked and banned, IP B reports a successful login and is checked before, during and after: always `banned: false, allow: true, ban: null`. |
| KT-3 | The ban is lifted exactly when it expires | With the test clock one millisecond before `expires_at`, the check says banned. With the clock at `expires_at`, it says not banned. No timer or job is involved; the state is computed from `expires_at` on each request. |

Supporting tests cover the boundaries: ten failures spanning exactly 60.000 s ban and spanning 60.001 s do not; successes never count or reset the count; reports from a banned IP do not extend or retrigger the ban; bans survive a restart while failure counts do not; manual unban is idempotent; 40 simultaneous failures for one IP create exactly one ban.

## Improvement 1 — the fix: existing sessions survive an IP ban

**Gap addressed:** G-1 in [docs/GAPS.md](docs/GAPS.md). On the default IP-scoped path we observed, everyone behind a banned address shares one ban. On a campus, many legitimate users share one public IP.

**What Sentinel does:** a ban blocks new login attempts, not existing sessions. `GET /v1/check` takes a `context`:

- `context=login` (the default): `allow: false` while the IP is banned.
- `context=session`: `allow: true` while the IP is banned, with `banned: true` still reported.

A session check writes nothing and never changes the ban. There is no bypass: a login report from a banned IP is answered `banned: true` even when the password was correct, and the portal must then not create a session. Sentinel stores no session data; the portal asserts that it has validated the session.

**What it does not do:** it does not help a legitimate user behind the banned IP who is not yet signed in. They wait for the ban to expire.

**Verified by:** [tests/test_improvement1.py](tests/test_improvement1.py), 8 tests.

## Improvement 2 — the Differentiator: end-user ban explanation

**What Sentinel does:** every answer that says an IP is banned carries an `explanation` object for the blocked person: `blocked`, `reason_code`, a fixed `message`, `started_at`, `expires_at` and `retry_after_seconds`. It is derived from the ban at request time and never stored. It contains no usernames, evidence or rule values, and its wording refers to the network address, not the person. It is `null` whenever the IP is not banned, including at the exact instant of expiry.

**Evidence statement, as scoped in [docs/GAPS.md](docs/GAPS.md), section 3:** our examined CrowdSec materials document operator-facing alert and decision context, but we did not find a documented end-user portal flow that explains a ban to the blocked user. This is "not found in the examined sources", not a claim that CrowdSec does not have it. The examined sources and their limits are listed in that section.

**Verified by:** [tests/test_improvement2.py](tests/test_improvement2.py), 10 tests.

## Extension — the success alert

Added on top of the two improvements; it is neither the fix nor the Differentiator.

**Sentinel extension: successful-authentication alert following repeated failures for the same account and source address.** A threshold ban only catches an attacker who keeps failing. When a `success` report follows at least 5 failures (configurable) for the same username from the same IP inside the 60-second window, Sentinel's answer carries a `warning` with a code, a fixed message and the number of failures. It is advisory: nothing is banned, counted, persisted or reset, and a banned IP still gets the normal "banned" answer. The warning contains no username and no failure history.

**No claim about the original.** We did not examine whether CrowdSec, its hub content or its bouncers can do this, and we do not say it is absent. It was added after the specification was finalized and is recorded as such in [docs/AGENT_LOG.md](docs/AGENT_LOG.md), Session 5.

**Verified by:** [tests/test_success_alert.py](tests/test_success_alert.py), 27 tests, plus one demo test.

## Optional layer — AI incident brief

Not a required improvement, not the Differentiator and not the extension above. Those are unchanged.

An optional AI-powered incident briefing layer that converts Sentinel's structured security facts into a concise administrator-readable summary. An administrator calls `POST /v1/incident-brief` for an IP (the demo has a button in its ADMIN panel). Sentinel gathers the facts from its own state and, if `GROQ_API_KEY` is configured, asks Groq to summarize them; otherwise, or if Groq fails or times out, it returns a deterministic summary of the same facts. The answer says which one was used.

- **The AI makes no security decision.** Sentinel's deterministic rules remain the sole authority; the brief is written after the fact and nothing reads it back.
- **Sentinel works fully without it.** No key is needed to run, test or demonstrate anything else.
- **The key stays on the server**, and the facts sent contain no usernames, evidence or secrets.
- **No claim about the original.** We did not examine whether CrowdSec or its ecosystem offers AI summaries.

**Verified by:** [tests/test_incident_brief.py](tests/test_incident_brief.py), 33 tests, with the Groq call mocked. Separately, the `openai/gpt-oss-20b` model was verified directly against the real Groq API during final integration testing, and Sentinel's request settings were set from what that test showed. A complete incident brief generated through the running application with a live key has not yet been confirmed end to end. Groq remains optional: without a key, or whenever Groq is unavailable, the application uses the deterministic fallback.

## Technologies and libraries

| | |
|---|---|
| Language | Python (written for 3.10 or newer; developed and tested on 3.12) |
| Third-party packages | None. Standard library only |
| HTTP server | `http.server` (`ThreadingHTTPServer`) |
| Storage | SQLite through the standard `sqlite3` module, one file, bans only |
| In-memory state | Failure windows, in a dictionary guarded by locks (`threading`) |
| Optional AI brief | Groq's OpenAI-compatible HTTP API, called with the standard `urllib`. No SDK or package |
| Tests | `unittest` |
| Demo | A standard-library mock portal and one HTML page with plain JavaScript |

No CrowdSec code, package, configuration or template is used, and Sentinel does not depend on CrowdSec.

## Verification

Command:

```
python -m unittest discover -s tests -t . -v
```

Result: **137 tests, all passing** (Python 3.12 on Windows 11).

| File | Tests |
|---|---|
| tests/test_killer.py | 3 |
| tests/test_core.py | 29 |
| tests/test_api.py | 21 |
| tests/test_improvement1.py | 8 |
| tests/test_improvement2.py | 10 |
| tests/test_success_alert.py | 27 |
| tests/test_incident_brief.py | 33 |
| tests/test_demo.py | 6 |

Time-dependent tests use a fake clock injected by the test harness; Sentinel has no public endpoint for controlling time. The demo tests use the real clock with a 3-second ban. The demo page itself was verified by driving the portal endpoints its buttons call; there is no automated browser test.

## Demo

A mock portal under [demo/](demo/), separate from the service, shows the attack, the automatic ban, the unaffected user on another IP, the existing session that keeps working, the blocked new login with its explanation, the countdown to exact expiry, an admin unban, and the success alert when the attacker guesses correctly before the threshold. Start-up commands are in [README.md](README.md).

## Clean-room constraint

The original was studied first and only its behavior was recorded, in [docs/OBSERVATIONS.md](docs/OBSERVATIONS.md) and [docs/GAPS.md](docs/GAPS.md). The specification of the rebuild was then written in [docs/PRD.md](docs/PRD.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DATA_MODEL.md](docs/DATA_MODEL.md) and [docs/API.md](docs/API.md). The implementation was written from those seven documents alone, without opening the CrowdSec checkout. [docs/AGENT_LOG.md](docs/AGENT_LOG.md) records the study and specification sessions (1 to 3), the build (4) and the extension (5).

## Deliverables in this repository

| File | Purpose |
|---|---|
| [README.md](README.md) | Overview and how to run |
| [SUBMISSION.md](SUBMISSION.md) | This file |
| [.env.example](.env.example) | Every supported environment variable, with placeholders |
| [deck.pdf](deck.pdf) | Five-slide deck |
| [docs/](docs/) | The seven specification documents |

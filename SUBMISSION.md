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

## Technologies and libraries

| | |
|---|---|
| Language | Python (written for 3.10 or newer; developed and tested on 3.12) |
| Third-party packages | None. Standard library only |
| HTTP server | `http.server` (`ThreadingHTTPServer`) |
| Storage | SQLite through the standard `sqlite3` module, one file, bans only |
| In-memory state | Failure windows, in a dictionary guarded by locks (`threading`) |
| Tests | `unittest` |
| Demo | A standard-library mock portal and one HTML page with plain JavaScript |

No CrowdSec code, package, configuration or template is used, and Sentinel does not depend on CrowdSec.

## Verification

Command:

```
python -m unittest discover -s tests -t . -v
```

Result: **76 tests, all passing** (Python 3.12 on Windows 11).

| File | Tests |
|---|---|
| tests/test_killer.py | 3 |
| tests/test_core.py | 29 |
| tests/test_api.py | 21 |
| tests/test_improvement1.py | 8 |
| tests/test_improvement2.py | 10 |
| tests/test_demo.py | 5 |

Time-dependent tests use a fake clock injected by the test harness; Sentinel has no public endpoint for controlling time. The demo tests use the real clock with a 3-second ban. The demo page itself was verified by driving the portal endpoints its buttons call; there is no automated browser test.

## Demo

A mock portal under [demo/](demo/), separate from the service, shows the attack, the automatic ban, the unaffected user on another IP, the existing session that keeps working, the blocked new login with its explanation, the countdown to exact expiry, and an admin unban. Start-up commands are in [README.md](README.md).

## Clean-room constraint

The original was studied first and only its behavior was recorded, in [docs/OBSERVATIONS.md](docs/OBSERVATIONS.md) and [docs/GAPS.md](docs/GAPS.md). The specification of the rebuild was then written in [docs/PRD.md](docs/PRD.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DATA_MODEL.md](docs/DATA_MODEL.md) and [docs/API.md](docs/API.md). The implementation was written from those seven documents alone, without opening the CrowdSec checkout. [docs/AGENT_LOG.md](docs/AGENT_LOG.md) records the study and specification sessions; it was frozen before implementation began and so does not describe the build.

## Deliverables in this repository

| File | Purpose |
|---|---|
| [README.md](README.md) | Overview and how to run |
| [SUBMISSION.md](SUBMISSION.md) | This file |
| [.env.example](.env.example) | Every supported environment variable, with placeholders |
| [deck.pdf](deck.pdf) | Five-slide deck |
| [docs/](docs/) | The seven specification documents |

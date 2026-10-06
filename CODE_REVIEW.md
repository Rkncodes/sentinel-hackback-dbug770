# HACKBACK code review · DBG-770 · Intrusion Detection & Auto-ban

- Reviewed at: 2026-10-06T08:41:00Z (2026-10-06T14:11:00 IST)
- Judged commit: a9ef5cd318d0f95f3856dc34feb376b7f5dc72cb (2026-10-06T11:17:20+05:30) · the last commit before the code freeze
- Reviewer: AI agent run by a HACKBACK judge

### DBG-770 · Intrusion Detection & Auto-ban
Commit: a9ef5cd318d0f95f3856dc34feb376b7f5dc72cb · 2026-10-06T11:17:20+05:30 · Clean-room: OK

| Section | Score | Why (path:line) |
|---|---|---|
| A. Core flow | 28/30 | Full sliding-window counting (sentinel/detector.py:12-22), ban decisions with expiry (sentinel/service.py:92-106), durable SQLite storage (sentinel/store.py:70-94), ban check on every request (sentinel/store.py:54-57), and GET /v1/check as the enforcer (sentinel/api.py:94-96, 185). Log-file tailing is explicitly out of scope (docs/PRD.md:56). No network-level firewall blocker exists (also explicitly excluded, docs/PRD.md:57); the check endpoint is the blocker the portal must call before every login. 2 points off because enforcement is the portal's responsibility via an HTTP call; there is no generic proxy middleware that enforces bans at the network layer. |
| B. Killer Tests | 30/30 | All three killer tests pass: tests/test_killer.py:7-65, proved by running py -m unittest discover: 137 tests, 0 failures in 57.954s. |
| C. Two improvements | 20/20 | Improvement 1 (preserve authenticated sessions): sentinel/api.py:185, tests/test_improvement1.py 8 tests all pass. Improvement 2 (ban explanation): sentinel/service.py:34-49, sentinel/api.py:166, tests/test_improvement2.py 10 tests all pass. |
| D. Built from their docs | 10/10 | Every PRD FR matched: FR-1 to FR-12 (core) all implemented; FR-13 (session preservation) at sentinel/api.py:185; FR-14 (explanation) at sentinel/service.py:34-49. All 5 API.md routes present (sentinel/api.py:91-108). DATA_MODEL.md entities: Ban (sentinel/store.py:44-57), Failure Window (sentinel/detector.py:6-51), Ban Explanation (sentinel/service.py:34-49). DB constraints: expires_at > triggered_at CHECK (sentinel/store.py:24), one active ban per IP (sentinel/service.py:86-88), status never stored (sentinel/store.py:35-40). |
| E. Engineering | 9/10 | Auth on every route via constant-time hmac.compare_digest (sentinel/api.py:117); role separation portal/admin 401/403 (sentinel/api.py:110-122); input validation (sentinel/api.py:133-169); IP validation rejects non-strings, CIDRs, zone IDs (sentinel/ips.py:16-21); JSON parse errors caught (sentinel/api.py:143); no committed secrets (.env.example has placeholders only, .env is gitignored); README run steps work. -1: client IP comes entirely from the request body field "ip" supplied by the portal (sentinel/api.py:158); there is no technical enforcement that the portal sends the real remote address. |
| **Total** | **97/100** | |

Killer Tests:
1. READY / 10/10 / sentinel/detector.py:12-22 implements a true sliding window (now - received_at <= window_ms). 9 failures do not ban; the 10th does (sentinel/service.py:92-106). Threshold and window are configurable (sentinel/config.py:14-15). Proved: tests/test_killer.py:7-25 (test_kt1_ten_failed_logins_within_a_minute_ban_the_ip) passes; tests/test_core.py:28-33 confirms spanning > window does not ban.
2. READY / 10/10 / Counting is per-IP keyed on canonical_ip() (sentinel/detector.py:9). Successes never count (sentinel/service.py:89-90). No global counter. Proved: tests/test_killer.py:27-48 (test_kt2_normal_user_on_another_ip_is_not_affected) passes; tests/test_core.py:35-40 confirms successes never count or reset.
3. READY / 10/10 / Each ban stores expires_at; Ban.status() computes "active" iff now < expires_at (sentinel/store.py:54-57); active_for_ip() queries the DB on every request with the live clock (sentinel/store.py:96-103). No background job lifts the ban. Proved: tests/test_killer.py:50-65 (test_kt3_ban_is_lifted_exactly_when_it_expires) passes; tests/test_core.py:97-104 (test_expiry_is_half_open) also confirms.

Improvements:
1. Preserve authenticated sessions during an IP ban / 10/10 / Implemented via context query parameter of GET /v1/check: allow = context == "session" or not verdict.banned (sentinel/api.py:185). Session checks never change the ban; POST /v1/login-attempts from a banned IP always returns banned:true even for success outcome (sentinel/service.py:86-88). Proved: 8 tests in tests/test_improvement1.py all pass.
2. End-user-facing ban explanation / 10/10 / explanation() in sentinel/service.py:34-49 derives six fields from the live ban (blocked, reason_code, message, started_at, expires_at, retry_after_seconds rounded up). Present whenever banned:true, null otherwise, never stored. No usernames, evidence, or rule values exposed. Proved: 10 tests in tests/test_improvement2.py all pass.

Flags: none

3 questions for the judges to ask this team in their Defence, aimed at the weakest spots found:

1. Blocker trust boundary - The ban check is only as good as the portal's compliance. If Sentinel's HTTP server is reachable directly (e.g. port 8080 not firewalled), an attacker can bypass it entirely. How does your deployment prevent a client from reaching the login endpoint without going through the Sentinel check, and why didn't you bind Sentinel to a UNIX socket or loopback-only path by default?

2. IP supplied by the caller - The "ip" field in POST /v1/login-attempts comes from the request body written by the portal. Nothing in Sentinel validates it against the TCP connection's source address. If a compromised or misconfigured portal sends the wrong IP, what stops it from getting an innocent IP banned, or an attacker from evading the ban by asking the portal to report their traffic under a different IP?

3. In-memory failure windows lost on restart - PRD FR-11 says failure counts are intentionally lost on restart. During a live bot attack, restarting Sentinel (crash or redeploy) resets all in-progress windows. An attacker could exploit this: attack to 9 failures, trigger a crash, attack again from zero. Was this residual risk explicitly accepted, and is P-3 (portal must fail-closed if Sentinel is unreachable) sufficient mitigation, or would a write-ahead log of partial windows help?

SCORE core=28 kt=30 imp=20 docs=10 eng=9 total=97

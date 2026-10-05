# AGENT LOG — Sentinel

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec · **Multiplier:** Brutal ×1.2

A record of the work done so far with an AI coding agent (Claude Code), in order. Three sessions on 2026-10-05: reconnaissance, documentation, then a final audit and correction pass.

**State at the end of Session 3: documentation only; no implementation code had been written.** The build is recorded in Sessions 4 and 5 at the end of this file. The sections "Unresolved" and "Not done" describe the state at the end of Session 3.

## Ground rules followed in every session

| Rule | How it was kept |
|---|---|
| Original studied | CrowdSec, local checkout in `crowdsec/`, commit `7a73b16` |
| Read-only | No file in `crowdsec/` was created, changed or deleted. `git status` on the checkout was clean after the documentation session |
| Not executed | CrowdSec was not built, installed or run. No packages were installed. (Go is not installed on the machine.) |
| No copying | No CrowdSec source code, package or configuration was copied into our work |
| Evidence | Every statement about the original cites a file and line range, or is marked unknown |
| Writes | Only the seven files in `docs/` were written. In Session 3 two throwaway text-replacement scripts were kept in the operating system's temporary folder, outside the project |

## Session 1 — Reconnaissance

### Goal

Trace how the original handles the flow behind our three Killer Tests:

log input → parsing → detection → decision → ban → expiry

### What was investigated

| Area | Files read |
|---|---|
| Process wiring and channels | `cmd/crowdsec/main.go`, `crowdsec.go`, `parse.go`, `pour.go`, `output.go` |
| Event types | `pkg/pipeline/event.go`, `queue.go`, `line.go`, `constants.go` |
| Log acquisition | `pkg/acquisition/acquisition.go`, `pkg/acquisition/modules/file/run.go` |
| Parsing | `pkg/parser/runtime.go`, `node.go`, `stage.go`, `unix_parser.go`, `enrich.go`, `enrich_date.go` |
| Detection | `pkg/leakybucket/` — `bucket.go`, `manager_run.go`, `manager_load.go`, `bucketstore.go`, `buckettype.go`, `overflows.go`, `timemachine.go`, `blackhole.go`, `processor.go`, `trigger.go`, `scopetype.go`, `overflow_filter.go`, `README.md`, and three fixture directories under `testdata/` |
| Alert to decision | `pkg/apiserver/controllers/controller.go`, `controllers/v1/alerts.go`, `pkg/csprofiles/csprofiles.go`, `config/profiles.yaml` |
| Serving and expiring bans | `pkg/apiserver/controllers/v1/decisions.go`, `pkg/database/decisions.go`, `decisionfilter.go`, `alerts.go`, `flush.go`, `pkg/database/ent/schema/decision.go` |
| Configuration | `config/config.yaml`, `config/acquis.yaml`, `config/simulation.yaml`, `pkg/csconfig/crowdsec_service.go`, `profiles.go`, `simulation.go` |
| Tests, read as documentation | `test/bats/40_cold-logs.bats`, `test/bats/99_lapi-stream-mode.bats` |
| Dependencies | `go.mod` |

Searches were also run for firewall mechanisms (to find an enforcer) and for the SSH scenario by name.

### Important findings

1. **No enforcer in the repository.** CrowdSec stores decisions and serves them over HTTP; a separate bouncer blocks.
2. **The SSH parser and `ssh-bf` scenario are hub content**, not in the repository.
3. **The rate limiter is an external fork** whose source is not present.
4. **The flow is a channel pipeline:** acquisition → parsing → leaky buckets → overflow → alert → LAPI → profile → decision.
5. **Detection is a leaky bucket** set by capacity and leakspeed. Evidence indicates capacity N overflows on event N+1. There is no native "N in 60 seconds" rule.
6. **Per-IP isolation comes from `groupby`** partitioning.
7. **A decision's `until` is the alert's stop time plus the duration**, not the insert time.
8. **Expiry is passive.** Nothing lifts a ban; the decision stops matching a time comparison. Two endpoints compare differently at the exact boundary.
9. **No check for an existing active decision** was found when creating one.

Full detail with line references is in [OBSERVATIONS.md](OBSERVATIONS.md).

### Unknowns left by the reconnaissance

- Parameters and patterns of the real SSH parser and `ssh-bf` scenario.
- Token-refill behavior of the external limiter.
- Bouncer polling and enforcement behavior.
- Formats accepted by the external duration parser.
- Whether bucket garbage collection is ever enabled.
- Any runtime behavior, since nothing was executed.

### Corrections made during the session

- Two source files were first read joined together, which shifted their line numbers. The references to `cmd/crowdsec/parse.go` and `pour.go` were recalculated per file, and one was confirmed against an independent search result.
- The fixture directory under `pkg/leakybucket/testdata/` was first taken as test proof, then downgraded because no Go test running it was found. **That second step was itself wrong and was corrected in Session 3:** a test does run the fixtures.

## Session 2 — Documentation

### Goal

Write the seven required files in `docs/`, keeping observed facts, unknowns and our own design decisions visibly separate.

### Starting point

All seven files existed as empty placeholders. Nothing was overwritten.

### Order of work

1. `OBSERVATIONS.md` first, so every other file can cite it.
2. `GAPS.md` from the observations.
3. `PRD.md`, then `ARCHITECTURE.md`, `DATA_MODEL.md` and `API.md` for the rebuild.
4. Consistency checks.
5. This log.

### Documentation decisions

| Decision | Reason |
|---|---|
| Give every fact, unknown, gap, design decision and requirement an ID (`O-`, `U-`, `G-`, `D-`, `FR-`, `NFR-`, `KT-`) | A claim in one file can be traced to its source in another |
| Write source paths in full | `alerts.go` and `decisions.go` each exist in two packages; short names are ambiguous |
| Mark conclusions as "(inference)" | Separates what the code says from what we concluded |
| List findings beyond the summary in their own section (O-18 to O-26) | They come from the same reconnaissance but can be checked independently |
| Give each gap a "Limits" paragraph | Prevents overstating; several gaps are reasonable choices for CrowdSec's own goals |
| Describe the rebuild independently of language and storage engine | Neither is chosen yet |
| Keep the two improvements out of the architecture, data model and API | They were not designed at this point. Superseded in Session 3, which specifies both |
| No Differentiator named | The reconnaissance could not prove any candidate absent from CrowdSec. Superseded in Session 3 |

### Design decisions for the rebuild

Recorded in full in [ARCHITECTURE.md](ARCHITECTURE.md) section 4. The main ones:

- The portal reports login attempts by API; no log parsing.
- Sliding window count of failures, 10 in 60 seconds, timed by arrival at Sentinel.
- The ban check is built in and computed from the expiry time when asked. No timer and no polling.
- One active ban per IP. Expiry is half-open: banned before the expiry time, not banned at it.
- Bans are durable and double as the audit record. Tracking state is in memory.

These are ours. They differ from the original on purpose, and the differences are tabulated in [ARCHITECTURE.md](ARCHITECTURE.md) section 6.

### Checks run before finishing

| Check | Result |
|---|---|
| Every `O-`, `U-`, `G-`, `D-`, `FR-`, `NFR-` ID that is referenced is also defined | Pass |
| Every CrowdSec file path cited in `OBSERVATIONS.md` and `GAPS.md` exists in the checkout | Pass |
| `git status` in `crowdsec/` | Clean |
| Workspace contains only `crowdsec/` and `docs/` | Pass |
| No implementation code in `docs/` | Pass. `API.md` contains JSON examples of message shapes only |

The line ranges themselves were taken from the Session 1 reading and were not re-verified one by one in Session 2.

### State at the end of Session 2

The fix was proposed (G-1) without a mechanism, no Differentiator was named, and the portal's behavior when Sentinel is unreachable was undecided. All three were settled in Session 3.

## Session 3 — Final audit and correction

### Goal

Audit the seven existing docs rather than rewrite them: verify every citation, tighten the design where it was vague, decide the open questions, and check the set for contradictions.

### Citation audit

Every line range cited for O-1 to O-26 and U-1 to U-6 was printed from the checkout at `7a73b16` and compared with its statement. The observations cited by G-1 to G-8 were then checked against each gap's wording.

| Entry | Finding | Action |
|---|---|---|
| O-8 | **Wrong statement.** We had written that no Go test runs the bucket fixtures. `TestBucket` does (`pkg/leakybucket/bucketstore_test.go:32-78`) | Corrected. The fixture is now described as an expectation asserted by the project's test suite, which we did not run |
| O-8 | The functional test with 6 SSH lines was listed as evidence for the N+1 reading. It is not, because that scenario's capacity is unknown | Kept as an observation, removed as evidence for N+1 |
| O-1 | "Found only help-text examples" was too narrow: the search also hit an unrelated variable name and test data | Reworded; added the README line that points to external remediation components |
| O-2 | Stated as fact that the SSH content is hub content | The "installed at runtime" part is now marked as inference |
| O-6 | The node order omitted the stash step | Added |
| O-9 | The link between each mode and its timing function was not cited | Citations added |
| O-10 | The source-IP rule applies to the `Ip` and `Range` scopes | Scoped; range widened to `106-121` |
| O-13 | "Has these fields" implied a complete list | Now "includes"; remaining fields named |
| O-14 | Did not mention the fallback when the stop time cannot be parsed | Added, with citation |
| O-17 | "No timer or job lifts a ban" was stated as fact | Now "we found no"; supporting code comment cited; range corrected to `244-261` |
| O-18 | Range `227-232` missed the start of the branch | Corrected to `220-232`; wording made precise |
| O-24 | Applies by default and to both stream lists | Reworded; citations added |
| O-26 | Implied rows are removed soon after expiry | Reworded: the flush removes alerts by age or count, and decisions go with them |
| U-4, U-5 | Lacked citations | Added |
| All others | Range and statement agree | None |

No citation in GAPS.md needed correcting. G-1 gained one limit (how bouncers treat signed-in users is unknown) and G-2 one cross-reference.

### New observations

A narrow search was made for one purpose: to test whether the Differentiator's absence claim could be supported. It produced O-27 (what a bouncer receives per decision), O-28 (operator command-line tools), O-29 (end-user-facing responses in the AppSec component, and no ban explanation found) and U-7 (what bouncers and documentation show an end user is unknown).

### Decisions made

| Topic | Decision |
|---|---|
| Per-IP atomicity (D-6) | Stated as an implementation invariant, with the mechanism left open |
| Improvement 1 | **Preserve authenticated sessions during an IP ban.** A ban blocks new logins; requests in existing sessions are allowed; the ban is never changed by them. Replaces the earlier, vaguer "shared-IP" fix |
| Improvement 1, no bypass | A login in flight when the ban lands is answered "banned", and the portal must not create a session |
| Improvement 2 | **End-user-facing ban explanation**, selected on a scoped evidence statement |
| Sentinel unreachable | New logins are refused; existing sessions continue |
| `GET /v1/bans` | Documented as a bounded audit view; no pagination |
| Manual unban | Idempotent; also clears the IP's failure count |
| Expiry wording | One sentence used in every doc: active iff now < `expires_at`, expired iff now ≥ `expires_at` |
| Credentials | Called "portal key" and "admin key" in every doc |
| Default ban duration | Confirmed at 15 minutes |

### Checks run before finishing

| Check | Result |
|---|---|
| Every `O-`, `U-`, `G-`, `D-`, `FR-`, `NFR-`, `KT-`, `P-`, `A-` ID that is referenced is defined, and the reverse | Pass |
| Every CrowdSec path cited in `OBSERVATIONS.md` and `GAPS.md` exists in the checkout | Pass |
| The three Killer Tests are worded identically in PRD, ARCHITECTURE and API | Pass |
| 10 failures / 60 seconds / 15 minutes, and the expiry rule, agree across PRD, ARCHITECTURE, DATA_MODEL and API | Pass |
| No leftover "not selected", "proposed" or "undecided" wording outside this log | Pass |
| `git status` in `crowdsec/` | Clean |
| Workspace contains only `crowdsec/` and `docs/` | Pass |
| No implementation code in `docs/` | Pass. `API.md` contains JSON examples of message shapes only |

## Unresolved

1. **Differentiator verification — performed, residual limit only.** In a separate pass on 2026-10-05, official CrowdSec bouncer documentation and default ban templates were checked (sources listed in [GAPS.md](GAPS.md) section 3, "Risk to this claim"). Generic end-user block pages exist. The checked official materials did not document a ban explanation flow exposing the specific reason, start time, expiry time and remaining duration. The Differentiator therefore survives, with its existing careful wording. This remains "not found in the examined official sources", not "CrowdSec does not have it": not every official bouncer was checked, and the hosted console was not examined.
2. **Technology.** Language, framework, storage engine and the mechanism for per-IP atomicity are not chosen. This is left to implementation by design.

## Not done

- No implementation code.
- No tests.
- No execution of the original.
- No verification of anything outside the one repository and commit.
- Nothing committed or pushed.

## Session 4 — Implementation (clean-room build)

Added to this log after the fact, in Session 5, so that the build is on record. Sessions 1 to 3 were not altered apart from the state line at the top of this file.

### Ground rules

| Rule | How it was kept |
|---|---|
| Specification | The seven files in `docs/` were the only product specification used |
| Original | The CrowdSec checkout was not opened, searched or referenced during the build |
| Dependencies | Python standard library only. Nothing was installed. CrowdSec is not a dependency |
| Docs | The seven files were not modified during this session |

### Decisions taken before coding

The plan was reviewed against the docs first. Six points the docs left open were raised and approved by the team before any code was written:

| Point | Decision |
|---|---|
| When the clock is read | Inside the per-IP critical section, so timestamps for one IP are processed in order |
| User interface | The service stays API-only. The demo is a separate mock portal under `demo/` |
| Showing expiry in the demo | Real clock with a short configured ban duration. No clock endpoint |
| Idle failure windows | A periodic in-memory sweep that cannot change any decision |
| `limit` out of range on `GET /v1/bans` | `400 invalid_request` |
| Location | The implementation lives in its own repository, separate from the CrowdSec checkout |

Technology chosen: Python standard library (`http.server`, `sqlite3`, `threading`, `unittest`), one SQLite file for bans, per-IP atomicity through a fixed set of locks keyed by IP.

### Order of work

1. Core (FR-1 to FR-12): the four endpoints, detection, ban lifecycle, persistence, manual unban. 53 tests, including the three Killer Tests.
2. Improvement 1 (FR-13): `context=session` on `GET /v1/check`. 8 tests.
3. Improvement 2 (FR-14): the `explanation` object. 10 tests.
4. Demo: mock portal and one page under `demo/`. 5 tests, using the real clock.
5. Submission artifacts: `README.md`, `SUBMISSION.md`, `.env.example`, `deck.pdf`.

State at the end of Session 4: 76 automated tests passing.

### Known deviations from the docs

- An unknown route is answered `404 not_found`, and an unexpected server fault `500` with code `internal_error`. Neither is in the error table of [API.md](API.md).
- NFR-4 (check latency) was measured only informally on the development machine, not under load.
- The demo page was verified through the portal endpoints its buttons call, not by an automated browser test.

## Session 5 — Extension: success alert

### What and why

A competitive review of the finished build concluded that it read as a careful, narrow rebuild. One extension was added on top of it:

> Sentinel extension: successful-authentication alert following repeated failures for the same account and source address.

A threshold ban only catches an attacker who keeps failing. If the correct password is guessed before the tenth failure, no ban fires and the login looks ordinary. Sentinel now answers such a success with a `warning`.

### What this is not

- **It is not the Differentiator and not one of the two required improvements.** Those remain Improvement 1 and Improvement 2 as specified in Session 3.
- **No claim is made about CrowdSec.** Whether the original, its hub content or its bouncers can detect a success after failures was not examined. We do not say it is absent.
- It was not derived from the original. It comes from a blind spot in our own rule FR-4 (successes never count).

### Behavior

- On a `success` report with a `username`, from an IP that is not banned, Sentinel counts the failures in the window for the same IP and username. At `success_alert_threshold` (default 5, `SENTINEL_SUCCESS_ALERT_THRESHOLD`) or above, the answer carries `warning` with a code, a fixed message and the count.
- The alert threshold must be lower than the ban threshold. A setting at or above it could never fire and is rejected at start-up; when unset, the default is 5 or one below the ban threshold, whichever is lower.
- It is advisory. Nothing is banned, counted, stored or reset. A banned IP still gets the normal "banned" answer with no warning.
- The warning contains no username, timestamps or evidence.

### Changes

| Area | Change |
|---|---|
| Code | `sentinel/config.py`, `sentinel/detector.py` (one read-only count), `sentinel/service.py`, `sentinel/api.py`, `sentinel/__main__.py` (start-up message) |
| Tests | `tests/test_success_alert.py` (27 tests); one test added to `tests/test_demo.py`. No existing test was changed |
| Demo | `demo/portal.py` passes the warning through; `demo/index.html` gains an account field, a "Send 5 failed logins" button and a "Guess the correct password" button with an amber alert |
| Docs | `API.md` (Warning object, endpoint 1), `DATA_MODEL.md` (Config, Login Attempt), `ARCHITECTURE.md` (3.1 step 5, D-17), a "Post-specification extension" note in `PRD.md` (section 9) and `GAPS.md` (section 4), this log |
| Artifacts | `README.md`, `SUBMISSION.md`, `.env.example` updated; `deck.pdf` re-created with the extension shown separately from the two improvements |

State at the end of Session 5: 104 automated tests passing (the 76 from Session 4, unchanged, plus 28).

### Left open for the team

- [PRD.md](PRD.md) section 9 and [GAPS.md](GAPS.md) still say the rebuild carries "exactly two improvements". That wording was kept on purpose: it describes the two required improvements, and each file now carries a separate note for the extension.
- When checking the demo, an older Sentinel process was found still listening on port 8080. On Windows a second instance can bind the same port without an error, so requests may reach the older process. Stop old instances before a demonstration.

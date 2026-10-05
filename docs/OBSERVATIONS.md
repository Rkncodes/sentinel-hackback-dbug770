# OBSERVATIONS — what we saw in CrowdSec

**Card:** SENTINEL — Intrusion Detection & Auto-ban · **Original:** CrowdSec · **Multiplier:** Brutal ×1.2

This file records only what was observed in the original. It contains no design for our rebuild; that starts in [PRD.md](PRD.md).

## How to read this file

| Item | Value |
|---|---|
| Repository studied | CrowdSec, local checkout in `crowdsec/` |
| Commit | `7a73b16` |
| Method | Static reading of source, config, fixtures and tests |
| Executed? | No. Nothing was built, installed or run |
| Citations | Every cited line range was re-opened and checked against its statement in a final audit pass (see [AGENT_LOG.md](AGENT_LOG.md), Session 3) |

Each entry has an ID so the other docs can cite it:

- **O-n** — an observed fact, with the file and line range it was read from.
- **U-n** — something we could not establish from this repository.

File paths are relative to `crowdsec/`. Two file names occur in more than one package, so paths are always written in full:

- `alerts.go` exists in `pkg/apiserver/controllers/v1/` (HTTP handler) and `pkg/database/` (storage).
- `decisions.go` exists in the same two packages.

Where an entry is a conclusion we drew from several facts rather than something written in the code, it is marked **(inference)**.

## 1. System shape

**O-1 — CrowdSec does not contain the component that blocks traffic.**
It stores ban decisions and serves them over HTTP (O-4, O-16). Its README says remediation happens "thanks to the Remediation Components" and links to external bouncer documentation (`README.md:32`). A search of the Go code for firewall mechanisms (iptables, nftables, ipset) found no blocking code: the hits were help-text examples naming a hub collection (`cmd/crowdsec-cli/cliitem/hubcollection.go`), an unrelated variable name, and test data.

**O-2 — The SSH parser and the `crowdsecurity/ssh-bf` scenario are not in this repository.**
A search of the repository found no SSH parser or `ssh-bf` scenario file. The functional test installs a hub collection with `cscli collections install crowdsecurity/sshd` (`test/bats/40_cold-logs.bats:16-18`) and afterwards expects an alert from `crowdsecurity/ssh-bf` (`:51`).
**(inference)** The scenario and parser therefore arrive as "hub" content installed at runtime.

**O-3 — The rate limiter is an external fork.**
`golang.org/x/time` is replaced by `github.com/crowdsecurity/time` (`go.mod:285`). The fork's source is not in the repository.

**O-4 — The flow is a pipeline of stages connected by channels.**

| Stage | What happens | Evidence |
|---|---|---|
| Log acquisition | Data sources write raw lines to a channel | `cmd/crowdsec/crowdsec.go:177`, `:197` |
| Parsing | Lines are parsed into events | `cmd/crowdsec/parse.go:59-73` |
| Detection | Events are poured into leaky buckets | `cmd/crowdsec/pour.go:38-71` |
| Overflow | A full bucket emits an overflow event | `pkg/leakybucket/bucket.go:295` |
| Alert push | Overflows are sent to the Local API (LAPI) as alerts | `cmd/crowdsec/output.go:85-94` |
| Decision | LAPI receives `POST /v1/alerts` and applies profiles | `pkg/apiserver/controllers/controller.go:125`, `pkg/apiserver/controllers/v1/alerts.go:226-269` |
| Serving bans | Bouncers call `GET /v1/decisions` and `/v1/decisions/stream` | `pkg/apiserver/controllers/controller.go:146-149` |
| Expiry | Decisions are filtered by their `until` time when queried | `pkg/database/decisions.go:132` |

## 2. Events and parsing

**O-5 — An event is a `pipeline.Event`.**
It holds `Line` (the raw log line and its source), `Parsed`, `Enriched` and `Meta` string maps, plus `Type`, `ExpectMode`, `Time` and `MarshaledTime`. A code comment states that `Meta` is the only part that reaches the API (`pkg/pipeline/event.go:20-47`).

**O-6 — Parsing is a staged tree of nodes.**
- Nodes are grouped in stages. An event that does not succeed in a stage is dropped (`pkg/parser/runtime.go:233-343`).
- Each node runs: filter → whitelist → grok pattern → stash → child nodes → statics (`pkg/parser/node.go:294-397`).
- Events that fail to parse, or that are whitelisted, never reach the buckets (`cmd/crowdsec/parse.go:45-54`).

## 3. Detection

**O-7 — A scenario is a `BucketSpec` loaded from YAML.**
Its fields include `type`, `name`, `filter`, `groupby`, `capacity`, `leakspeed`, `blackhole`, `labels` and `scope` (`pkg/leakybucket/manager_load.go:29-55`).

Routing of one event (`pkg/leakybucket/manager_run.go:212-298`):
1. The scenario `filter` is evaluated; the event is skipped if it returns false.
2. `groupby` is evaluated to produce a partition value.
3. The bucket key is a hash of filter + groupby value + scenario name (`pkg/leakybucket/manager_load.go:391-400`).
4. The bucket for that key is loaded, or created if absent.

**O-8 — A bucket overflows when an event arrives after capacity has been reached.**
- The limiter is created from the scenario's `leakspeed` and `capacity` (`pkg/leakybucket/bucket.go:85`). The pour code asks the limiter whether the event is allowed; if not, the bucket overflows on that event (`pkg/leakybucket/bucket.go:253-271`).
- Two pieces of evidence indicate that `capacity: N` overflows on event N+1:
  - The package README says: "When the capacity is reached and a new event is poured, the bucket overflows" (`pkg/leakybucket/README.md:24-26`).
  - A fixture with `capacity: 1` and two events 5 seconds apart expects one alert with `events_count: 2` (`pkg/leakybucket/testdata/simple-leaky-overflow/bucket.yaml`, `test.json`). A Go test, `TestBucket`, loads every fixture directory and compares the results (`pkg/leakybucket/bucketstore_test.go:32-78`, `:80-130`). It feeds the events in TIMEMACHINE mode (`:194`).
- We did not run that test (U-6). The fixture is therefore an expectation asserted by the project's own test suite, not a result we observed.
- A functional test feeds 6 SSH failure lines and expects an `ssh-bf` alert reporting 6 events (`test/bats/40_cold-logs.bats:6`, `:51`). This shows a real scenario overflowing, but it does not confirm the N+1 reading by itself, because that scenario's capacity is unknown (U-1).

**O-9 — Bucket timing depends on the event's mode.**
- A LIVE bucket uses the `Pour` function (`pkg/leakybucket/bucket.go:97-98`), which reads the wall clock at the moment the event is poured (`pkg/leakybucket/bucket.go:258-263`).
- A TIMEMACHINE bucket uses `TimeMachinePour` (`pkg/leakybucket/timemachine.go:50-56`), which uses the time parsed from the log line (`pkg/leakybucket/timemachine.go:25-39`).
- There is no built-in "N events in 60 seconds" rule. Behavior comes from `capacity` and `leakspeed` together.

**O-10 — An overflow produces an alert.**
The alert carries `StartAt`, `StopAt`, scenario name, capacity, leakspeed, event count and source (`pkg/leakybucket/overflows.go:298-403`).
- For the `Ip` and `Range` scopes, the source IP is read from `Meta["source_ip"]` and must be a valid IP address (`pkg/leakybucket/overflows.go:106-121`).
- `Remediation` is true only if the scenario has the label `remediation: true` (`pkg/leakybucket/overflows.go:383-385`).

**O-11 — Alerts reach LAPI in batches.**
- Pending alerts are flushed on a 1-second ticker; a failed send is requeued (`cmd/crowdsec/output.go:221`, `:261-277`).
- Before that, overflows pass through postoverflow parsers, which can whitelist them (`cmd/crowdsec/output.go:136-139`).

## 4. Decisions

**O-12 — Profiles turn alerts into decisions.**
The default profile matches `Alert.Remediation == true` with scope `Ip` and creates a decision of `type: ban`, `duration: 4h` (`config/profiles.yaml:1-14`; generation in `pkg/csprofiles/csprofiles.go:97-164`).

**O-13 — A stored decision includes these fields.**
`until`, `scenario`, `type`, `scope`, `value`, `origin`, `simulated`, `uuid`, and integer `start_ip` / `end_ip`. The schema also has `created_at`, `updated_at`, `start_suffix`, `end_suffix`, `ip_size` and a link to the owning alert (`pkg/database/ent/schema/decision.go:17-42`).

**O-14 — `until` is the alert's `StopAt` plus the duration.**
It is not insert time plus duration (`pkg/database/alerts.go:390`, `:644`, `:656`). The stop time is parsed from the alert, and falls back to the current time only if it cannot be parsed (`pkg/database/alerts.go:419-437`). For an alert built from a bucket, `StopAt` is the bucket's overflow time (`pkg/leakybucket/overflows.go:310`).

**O-15 — No check for an existing active decision was found in the create path.**
Each overflow can add a new decision row (`pkg/apiserver/controllers/v1/alerts.go:226-269`, `pkg/database/alerts.go:369-417`). This is an absence we observed in the code we read, not a documented guarantee.

## 5. Serving bans and expiry

**O-16 — "Active" is defined by comparing `until` to the current time, and the comparison differs by endpoint.**

| Endpoint | Condition | Evidence |
|---|---|---|
| `GET /v1/decisions?ip=…` | `until >= now` | `pkg/database/decisions.go:131-132` |
| `GET /v1/decisions/stream`, `new` list | `until > now` | `pkg/database/decisions.go:32-34` |
| `GET /v1/decisions/stream`, `deleted` list | `until < now` | `pkg/database/decisions.go:78-80`, `:195-197` |

**O-17 — Expiry is passive.**
- We found no timer or job that lifts a ban; the decision stops matching the active condition (O-16). A code comment says the same: "a decision expires when the clock passes it, with no write to order against" (`pkg/apiserver/controllers/v1/decisions.go:246-247`).
- Expired decisions are reported to bouncers through the stream's `deleted` list (`pkg/apiserver/controllers/v1/decisions.go:244-261`).
- A manual unban sets `until` to the current time instead of deleting the row (`pkg/database/decisions.go:295-302`).

## 6. Further observations from the full reconnaissance

These come from the same read-only work at the same commit. They go beyond the summary findings above and are listed separately so they can be checked independently. O-27 to O-29 were added in the final audit pass, from a narrow search made to test the Differentiator claim in [GAPS.md](GAPS.md).

**O-18 — A leaky bucket's lifetime is `(capacity + 1) × leakspeed`, restarted on each event; when it runs out the bucket is destroyed without an alert** (`pkg/leakybucket/bucket.go:101-103`, `:197-204`, `:220-232`).

**O-19 — After an overflow the bucket ends; the next matching event starts a new one** (`pkg/leakybucket/bucket.go:245-248`, `pkg/leakybucket/manager_run.go:98-107`). An optional `blackhole` duration suppresses repeat overflows for the same key (`pkg/leakybucket/blackhole.go:33-66`).

**O-20 — The decision scope defaults to `Ip`** when a scenario does not set one (`pkg/leakybucket/scopetype.go:19-21`). Other scopes exist in the code (`pkg/types/event.go:9-16`).

**O-21 — An allowlist check can skip an alert entirely** for IP or range sources (`pkg/apiserver/controllers/v1/alerts.go:128-147`, `:181-184`).

**O-22 — If the postoverflow queue is full, the overflow is dropped.** The default queue size is 256. A code comment calls dropping "the fail-safe direction" because postoverflow runs the whitelists (`cmd/crowdsec/output.go:313-320`, `pkg/csconfig/crowdsec_service.go:58`).

**O-23 — In TIMEMACHINE mode the overflow time is the log's time** (`pkg/leakybucket/timemachine.go:43`).
**(inference)** Combined with O-14, a decision created from old replayed logs can have an `until` that is already in the past.

**O-24 — By default, the stream leaves out a decision if a longer one exists for the same value, type and scope.** This applies to both the `new` and `deleted` lists unless the caller asks for `dedup=false` (`pkg/database/decisions.go:35-38`, `:81-84`, `:158-190`).

**O-25 — Simulated decisions are excluded from bouncer queries unless requested** (`pkg/database/decisionfilter.go:26-32`).

**O-26 — Decision rows are not removed at expiry.** A flush job runs every minute (`pkg/database/flush.go:60-62`). It deletes alerts that exceed a configured age or count, never one that still has an active decision; a comment notes that deleting an alert removes its decisions with it (`pkg/database/flush.go:391-396`).

**O-27 — A bouncer receives these fields for each decision:** `id`, `duration` (time remaining, rounded to the second), `scenario`, `scope`, `value`, `type`, `origin` and `uuid` (`pkg/apiserver/controllers/v1/decisions.go:19-38`). The start time of the decision is not among them.

**O-28 — Operators can inspect decisions and alerts with the `cscli` command-line tool.** The repository has `decisions` and `alerts` command packages (`cmd/crowdsec-cli/clidecision/decisions.go:134-135`, `:233-234`; `cmd/crowdsec-cli/clialert/`), and the functional tests use `cscli decisions list` (`test/bats/40_cold-logs.bats:59`).

**O-29 — The repository contains some end-user-facing responses, in its application-security (AppSec) component.** Its configuration has an HTTP status code "returned to the user" when a request is blocked (`pkg/appsec/appsec.go:601`), and there is a challenge page template titled "CrowdSec Challenge" (`pkg/appsec/challenge/challenge.html.tmpl:4`). We did not find, in this repository, a page or API response that tells a banned end user why they were banned, since when and until when.

## 7. What this implies for the three Killer Tests

These are inferences from the entries above, about the original only.

| Killer Test | What the original's design implies | Based on |
|---|---|---|
| 1. 10 failed logins from one IP in a minute → ban | A threshold of 10 corresponds to `capacity: 9` under the N+1 reading. "Within a minute" is not a native rule; it would emerge from capacity and leakspeed. A ban also needs `remediation: true`, a valid `source_ip` and a matching profile. | O-8, O-9, O-10, O-12 |
| 2. A normal user at the same time is unaffected | `groupby` gives each IP its own bucket, and a decision carries one value. A legitimate user who shares the attacker's public IP is in the same partition and can be affected. | O-7, O-13, O-20 |
| 3. The ban lifts exactly at expiry | At LAPI, expiry is exact relative to `until` at query time. When traffic is actually unblocked depends on the external bouncer. | O-1, O-16, O-17 |

## 8. Unknowns

**U-1 — SSH parser patterns and `ssh-bf` parameters.** The grok patterns, `capacity`, `leakspeed`, `groupby` and labels of the real scenario are hub content (O-2) and are not in this repository.

**U-2 — Token-refill behavior of the rate limiter.** The limiter is an external fork (O-3). We can state when the code overflows (O-8) but not the exact refill mathematics, so we make no claim about how many events over what interval trigger a given scenario.

**U-3 — Bouncer behavior.** How often a bouncer polls, how it blocks, and how quickly it applies the `deleted` list are outside this repository (O-1).

**U-4 — Duration parsing.** Profile and decision durations are parsed by `cstime.ParseDurationWithDays` from the external library `go-cs-lib` (`pkg/csprofiles/csprofiles.go:85`, `pkg/database/alerts.go:375`; `go.mod:31`). The accepted formats are not established here.

**U-5 — Bucket garbage collection.** A flag `BucketsGCEnabled` is declared with no YAML key (`pkg/csconfig/crowdsec_service.go:30`) and read in `cmd/crowdsec/pour.go:23`. A search of the Go code, tests included, found no place that sets it. Whether and when that collection runs is not established.

**U-6 — Runtime behavior in general.** Nothing was executed. Every entry above is what the code says, not what a running system was seen to do.

**U-7 — What a blocked end user is shown.** Bouncers, CrowdSec's hosted console and its online documentation were not examined. Whether any of them tells a banned end user the reason, start and expiry of a ban is unknown. O-29 covers this repository only.

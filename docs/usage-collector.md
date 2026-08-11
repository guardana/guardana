---
title: "The collector"
nav_order: 300
summary: "the optional collector: what a run verified and where, organizations and projects, persistence, migrations, health and readiness"
status: beta
---

# The collector — tenants, persistence, migrations, and what a database does not fix

The collector (`guardana-server`) aggregates findings from many agents. It is
**optional in every direction**: the engine never imports it, no feature needs it,
and nothing is sent anywhere unless a run is given `--reporter`.

> **Maturity: beta.** It keeps what it is given, **requires an API key** for every
> route that carries a finding, isolates one **project** from another, and records
> what each run verified and where — with an optional **environment pin** that
> makes a credential reach exactly one environment in both directions. Findings carry a **lifecycle** and waivers
> that expire, every state change is **audited**, and **retention** is a policy an
> operator applies. Still ahead of it: RBAC and human identities.

## Standing one up: three commands

```bash
export GUARDANA_DATABASE_URL=postgresql://guardana:secret@db:5432/guardana
guardana-collector migrate
guardana-collector bootstrap --org acme --project web   # prints the key, once
guardana-collector serve                                # http://127.0.0.1:8000
```

`bootstrap` creates the organization, the project and the first key together,
because a security boundary that adds four commands to the first run is a boundary
that makes a tool nobody starts. The granular commands below exist for the second
team, not for the first one.

`serve` binds **loopback** unless told otherwise: `--host 0.0.0.0` is a decision,
so it is one you type. It needs an ASGI server, which is an extra
(`pip install "guardana-server[serve]"`) rather than a dependency — a deployment
already running gunicorn or hypercorn should not be made to carry a second one,
and any of them can run the app directly:

```bash
gunicorn -k uvicorn.workers.UvicornWorker 'guardana.server:create_app()'
uvicorn 'guardana.server:create_app' --factory        # what serve does for you
```

Or as a container, where the same three commands are three `docker run`s:

```bash
docker run --rm -e GUARDANA_DATABASE_URL="$GUARDANA_DATABASE_URL" \
  ghcr.io/guardana/guardana-collector:0.19 migrate
docker run --rm -e GUARDANA_DATABASE_URL="$GUARDANA_DATABASE_URL" \
  ghcr.io/guardana/guardana-collector:0.19 bootstrap --org acme --project web
docker run -d -p 8000:8000 -e GUARDANA_DATABASE_URL="$GUARDANA_DATABASE_URL" \
  ghcr.io/guardana/guardana-collector:0.19
```

The image's default command is `serve --host 0.0.0.0 --port 8000`, and it does
**not** migrate on start — see
[`deploy/docker/README.md`](../deploy/docker/README.md) for why, and for the
health and readiness endpoints an orchestrator should use.

Then point a run at it:

```bash
export GUARDANA_COLLECTOR_TOKEN=gdn_…
guardana scan . --reporter server://https://collector.example.com
```

## What a run says it verified

```bash
guardana scan . --ai-system support-agent --environment production
guardana probe … --ai-system support-agent --environment staging --deployment-id 2026-08-05.3
```

or, for a pipeline that would otherwise repeat itself on every step:

```bash
export GUARDANA_AI_SYSTEM=support-agent
export GUARDANA_ENVIRONMENT=production      # a flag still wins over the variable
```

Without this a project's history is one undifferentiated stream, and "did
production get worse since Tuesday" has no answer in it.

**The commit is read from whatever CI this is** — `GITHUB_SHA`, `CI_COMMIT_SHA`,
`GIT_COMMIT`, `BUILD_SOURCEVERSION` — because the answer that matters is the one
nobody had to remember to pass. **The environment and the AI system are never
guessed.** A branch is not an environment and a repository is not an AI system: a
monorepo has several systems, and one repository deployed twice is one system in
two environments. A guessed value is one a team would build a dashboard on.

Nothing is created in advance. The collector records the names a run used, and

```bash
guardana-collector system list [--project acme/web]
guardana-collector environment list [--project acme/web]
guardana-collector deployment list [--ai-system support-agent]
```

read them back. Requiring an administrator to register a system first would put a
human step between a pipeline and its first report, and a pipeline that fails on a
missing prerequisite gets commented out rather than fixed. The cost is that a typo
creates a second system — and the listing is what makes that mistake visible
rather than silent. Correct it by running the pipeline with the right name; the
wrong one stays as the empty system it is.

`Production`, `production ` and `production` are one environment: names are folded
and stripped at the door, so grouping does not depend on who typed what.

## Pinning a key to one environment

```bash
guardana-collector key create --project acme/web --name prod-ci --environment production
```

A pinned key **writes and reads only that environment**. A run declaring a
different one is refused with `403` — never "prefer the more specific one", never a
silent relabel. A run declaring *nothing* is stored under the pin, because the
credential asserted the environment and the run did not contradict it; storing it
unlabelled would let a pinned key write evidence into a place it cannot itself
read.

Read *and* write, not write alone: a pin that bounded writes while letting the same
key read every environment would be a half-boundary that reads as a whole one.

It is **optional**, and that is the trade. One pipeline legitimately deploys to
dev, staging and production, and sourcing the environment from the key would mean
three credentials per project for every team — while the blast radius is already
bounded, because the key names the project. Pin the credential that must not be
able to write production evidence; leave the rest unpinned.

An unpinned key sees the whole project, labelled runs and unlabelled ones alike. A
*pinned* key does not see unlabelled runs: they belong to the project and to no
environment, and folding them into every one would let a laptop run appear as
production evidence.

## Reading back what the collector holds

```bash
guardana-collector run list [--project acme/web] [--environment production]
guardana-collector finding list [--project acme/web] [--environment production]
```

`run list` is the time axis: when a run arrived, which system and environment it
was about, its **gate**, and where it came from. The gate is the fact a collector
without it cannot supply — findings alone cannot tell a failing run from one whose
findings a baseline waived. A run whose agent did not say prints `unknown`, never
blank and never `pass`.

`finding list` groups every sighting by the identity the engine computes — the rule
and where it was found, never the evaluator's rationale, which moves on every
re-run — and shows how many runs saw it, first and last. That is the "has this been
there since Tuesday, or is it new" question.

**Runs, not sightings.** One run's rule can report the same identity several times
— `malicious_dependency` names three bad packages in a single `requirements.txt`,
and the identity is the rule plus the path — so counting rows would answer "how
often was this printed" while the column claims to answer the other question. A
finding a single scan reported three times reads `1 runs`.

**A retried job is stored once.** The same run id in the same project is accepted
with `200` and `"duplicate": true` instead of being stored again: a retry is not a
failure and must not turn a pipeline red, and counting it twice would make a
regression answer from a duplicate. An agent older than 0.9 sends no run id,
identifies nothing, and is stored every time — which is honest, not clever.

## Triage: what somebody decided about a finding

A finding is an entity, not just a pile of sightings. It carries a status, an
owner, and — when a team accepts the risk — a waiver with a name, a reason and a
date it lapses.

```bash
guardana-collector finding list --project acme/web [--status open]
guardana-collector finding status 1854bc20 --project acme/web --status acknowledged --owner konrad
guardana-collector finding waive  1854bc20 --project acme/web \
  --approver konrad --reason "vendor fix due in September" --expires 2026-09-30
```

Identities are `sha256:…`, so every command takes a **unique prefix**, like git.
An ambiguous one is refused with the candidates listed and nothing is changed:
acting on the wrong finding is worse than being asked to type four more
characters.

| Status | Means |
|---|---|
| `open` | seen; nobody has said anything, or a waiver lapsed |
| `acknowledged` | a human has read it |
| `in_progress` | somebody is fixing it |
| `resolved` | believed fixed |
| `false_positive` | the rule is wrong here |
| `accepted_risk` | waived, with an approver, a reason and a date |

**A `resolved` finding reopens when it is seen again.** This is the transition
the whole model exists for: a fix that did not hold must not stay green because
somebody once ticked a box. A `false_positive` stays one — the identity *is* the
rule plus the location, so it really is the same judgement — and an
`accepted_risk` stays accepted until its date.

**A waiver expires, and the expiry is applied when you read it.** The collector
runs no scheduler, so nothing has to happen for a lapsed waiver to stop waiving:
the finding lists as `open` again and says which waiver ran out. Backdating is
allowed and announced, because recording a decision that has already run out is a
legitimate thing to do and a surprise is not.

### This is not `guardana baseline`, and does not replace it

|  | `guardana baseline` | collector waiver |
|---|---|---|
| Changes the build's exit code | **yes** | **no** |
| Lives | next to the code, in git | in the collector, shared by the team |
| Answers | "should this pipeline fail today" | "did anybody decide anything about this" |

The collector never tells an agent what to do. A gate that asked a server whether
to fail would be a gate that fails open when the network does — so if you want a
build to stop failing, that is still `guardana baseline`
([usage-baseline.md](usage-baseline.md)). Exporting a project's collector waivers
*as* a baseline file is a natural next step and is deliberately not here yet.

## The audit log

```bash
guardana-collector audit list [--project acme/web] [--limit 50]
```

State changes only: keys created and revoked, tenants created and renamed,
findings triaged, schema migrated and rolled back, anything deleted. Reads are not
recorded — a log that grows with every dashboard refresh is a log nobody reads.

**Every row says what kind of actor it was, and the difference matters:**

| Kind | Example | Worth |
|---|---|---|
| `key` | `key:prod-ci (id 4)` | **verified** — the credential was presented and matched |
| `cli` | `cli:konrad@ops-1` | **asserted** — an operator with database access said so |

A CLI actor is the operating-system user, taken from the environment rather than
typed, and `--actor` overrides it for a shared operations account. It is not
authentication: anybody who can reach the database can write any name. It is
recorded anyway, because "what happened, roughly when, by which route" is the
question a log usually answers — and labelling an assertion as proof would be the
same false green this tool refuses in a verdict. Real identities arrive with users
and RBAC.

`api_keys.created_by` is filled by the same actor, and a stored submission now
records **which key wrote it**.

One event can never be recorded: rolling back the migration that created the log
removes the log. The command says so on stderr rather than failing after the fact.

## Retention: keeping less, on purpose

```bash
guardana-collector retention set   --project acme/web --keep-days 90
guardana-collector retention show  --project acme/web
guardana-collector retention apply --project acme/web --dry-run
guardana-collector retention apply --project acme/web
```

Per **project**, because the tenant is the project everywhere else here and a
policy at a different granularity is one that eventually deletes somebody else's
evidence. A project nobody has told keeps everything, and `apply` **refuses**
without a policy rather than falling back to a default — deleting on a default is
a collector that removes evidence because nobody said not to.

**Applying is a command, never a background job.** There is no scheduler in the
collector, so "what deleted my evidence" is answerable from the audit log rather
than from source. Run it yourself, or from a cron you wrote.

Two things retention deliberately does not touch:

- **The audit log.** A log pruned by the policy it describes cannot answer
  questions about the pruning.
- **Triage.** A tracked finding outlives its occurrences: its status and waiver
  stay, and the sighting count falls to zero. Otherwise a finding that reappears
  after a prune arrives as new and somebody re-decides what they already decided.

## Deleting a project, an organization, or a typo

```bash
guardana-collector project delete --project acme/web --yes
guardana-collector org delete --slug acme --yes
guardana-collector system merge --project acme/web --from suport-agent --into support-agent
```

`--yes` is required on both deletions, and deleting an organization **refuses
while it still holds projects**: cascading two levels of tenancy from one word is
exactly the command somebody runs at three in the morning in a shell they thought
was pointed elsewhere. Delete the projects first, one at a time.

The record of a deletion is filed under the *organization*, because audit events
cascade from a project — an event about a deleted project, filed under that
project, would be deleted by the deletion it describes.

`system merge` is the one operation here that edits the past rather than removing
it. It exists because the alternative is a permanent second AI system created by
one keystroke, which is what makes people stop trusting an inventory.

## Organizations and projects

**The tenant is the project.** An organization is what a project belongs to and
what gets named; isolation runs along the project, because that is the line a team
draws for itself — `web` and `api` are not the same body of evidence even when one
department pays for both.

```bash
guardana-collector org create --slug acme --name "Acme Inc"
guardana-collector org list                             # marks the adopted one
guardana-collector org rename --slug adopted --to acme
guardana-collector project create --org acme --slug web --name "Web app"
guardana-collector project list [--org acme]
guardana-collector project rename --project acme/web --to api
```

**The project comes from the key, never from the envelope.** If the envelope named
it, the runner would declare where it writes — and a credential that does not bound
the write is not a boundary at all. It is also why the envelope stays at v5 and why
nothing in the engine changed: an agent and a collector upgrade independently, and
no fleet has to move in step with a collector. The cost is real and accepted: a
team with ten projects needs ten keys in CI.

**There is no command that deletes an organization or a project**, and the foreign
keys are `on delete restrict`. Removing tenant data is retention, and it deserves
to be designed there rather than smuggled in here.

**Renaming is safe.** A key hangs off a project's identity, not its name, so
`project rename` does not invalidate anything.

### What migration `0003` did to a collector that already had data

It **adopted** it rather than refusing to run. Refusing is the most faithful to "a
decision, never a default", but it stops an upgrade half-way, and that is exactly
the pressure that produces workarounds.

Every pre-tenancy submission and every pre-tenancy key landed in one organization
called `adopted` — named for what happened, because a thing called `default` is a
thing nobody chose. Three conditions make that honest rather than convenient:

- it is created **only when there is something to adopt**, so a fresh install gets
  no tenant it never asked for;
- **old keys keep working**, because adoption must not be a silent invalidation of
  a fleet of credentials;
- **it can be renamed**, because a name a migration invented must not be permanent.

`org list` marks it and says where it came from, so an administrator who upgraded
without reading a changelog still finds out where their history went.

**Rolling `0003` back refuses when two tenants would be merged.** Dropping the
tenant column on a database serving two teams folds their evidence into one
undifferentiated pile, so the down migration counts the tenants across the
submissions *and* the keys first and raises rather than doing it.

## Limits: how much one caller may send, and how often

| Variable | Default | What it bounds |
|---|---|---|
| `GUARDANA_MAX_BODY_BYTES` | `8388608` (8 MiB) | one request body; over it answers `413` |
| `GUARDANA_RATE_LIMIT_PER_MINUTE` | `120` | requests per caller per rolling minute; over it answers `429` with `Retry-After` |

`0` turns a limit off and is something somebody types. A value that is not a
number is refused **at start-up** rather than treated as "no limit": a typo must
not silently remove a control.

The size check counts bytes off the wire rather than trusting `Content-Length` — a
header is a claim, and a chunked request need not make one. Liveness and readiness
are never rate limited: a readiness probe answered `429` is a rolling deploy that
stalls, which is a self-inflicted outage caused by a control meant to prevent one.

**The rate limiter lives in the process.** A deployment running four workers has
four times the limit, and there is no shared counter. That is stated rather than
implied, because a limit somebody believes is global and is not is worse than one
they know to put a reverse proxy in front of. For a real global limit, rate-limit
at the proxy that already terminates your TLS.

An unauthenticated caller is charged by peer address, an authenticated one by its
credential — so one noisy agent cannot spend a whole fleet's allowance.

## Choosing where submissions go

There is no default, on purpose. A store nobody chose is a store somebody
deploys, and the ephemeral one loses everything on restart.

```bash
# Durable. What a team should run.
export GUARDANA_DATABASE_URL=postgresql://guardana:secret@db:5432/guardana

# Ephemeral, and you had to say so. For evaluating Guardana on a laptop.
export GUARDANA_STORAGE=memory
```

With neither set, the collector refuses to start and says which to set. This is
the same rule as "no default credentials", one layer down: the unsafe
configuration must not be the one you get by not deciding.

## API keys

Every route that carries a finding needs one. Keys live in the database, so a
collector with no database cannot authenticate anybody — and refuses to be built
rather than serving openly.

```bash
guardana-collector key create --project acme/web --name github-actions   # ingest only
guardana-collector key create --project acme/web --name dashboard --scope read
guardana-collector key create --project acme/web --name ci --expires-in-days 90
guardana-collector key list [--project acme/web]              # prefixes, never secrets
guardana-collector key revoke <prefix>
```

**`--project` is required, and this command does not guess** even when exactly one
project exists. Issuing a credential against a tenant nobody named has the same
shape as a default credential, and `bootstrap` already covers the case where there
is only one.

```bash
export GUARDANA_COLLECTOR_TOKEN=gdn_…                                # never a flag: see below
guardana scan . --reporter server://https://collector.example.com
curl -H "Authorization: Bearer gdn_…" https://collector.example.com/findings
```

**Two scopes, not one.** `ingest` writes runs; `read` browses them. A CI job needs
to write and never to browse, and a single scope covering both would make every
pipeline credential a full read of every finding the organisation has recorded.
`key create` therefore defaults to `ingest` alone.

**The agent reads its key from `GUARDANA_COLLECTOR_TOKEN`**, not from a flag. A
credential on a command line lands in shell history, in `ps`, and in the echoed
command of most CI logs — the same reason `probe` takes `--api-key-env` rather
than `--api-key`. A collector that rejects a submission says so as a warning
naming the status, because a whole fleet quietly failing to report while a
dashboard shows stale data as current is the failure that matters.

**`--reporter` takes the collector's URL, not a route.** The reporter appends the
ingest path itself, so `server://https://collector.example.com` is the whole thing
a pipeline needs to know. A URL that already carries a path is left alone, for a
deployment behind a reverse proxy that maps one.

**The URL keeps its own scheme**, `http://` or `https://` — `server://` says
"send this to a collector" and does not decide how. A bare `host:port` is
refused before the run starts, with a `3` and a message naming both forms,
because guessing would mean either sending evidence over plaintext to a remote
host or breaking every local evaluation, and neither is a guess worth making on
somebody's behalf.

**Shown once.** There is no command and no endpoint that returns a key after it is
created — a credential a system can re-read is a credential that leaks through
every path that reads it. Only a digest is stored: a stolen backup of a collector
database must not also be a set of working credentials for the thing that produced
its contents.

**Absence is refusal.** A fresh collector has no keys and accepts nothing. That is
the behaviour, not an oversight: a system reading "no credentials configured" as
"no credentials required" is the shape of every default-admin incident there has
ever been. `key list` says so plainly on an empty collector.

Every failure — unknown key, malformed key, revoked, expired — answers with the
same `401` and the same sentence. Saying which one would turn the endpoint into a
way to enumerate valid prefixes. A key that *is* valid and lacks the scope gets
`403` instead, because that is a different fact and a pipeline retrying its
credentials forever is not the right outcome.

### The dashboard signs in with a read key

`GUARDANA_DASHBOARD=1` mounts a read-only page. It used to refuse to mount on a
collector that requires keys — correctly, because a browser has nowhere to put a
bearer token and every panel would have loaded empty. Now the browser signs in:

```bash
guardana-collector key create --project acme/web --name panel --scope read
# then open the collector and paste the key once
```

The key goes into an `HttpOnly`, `SameSite=Strict` cookie the page itself cannot
read; `key revoke` ends the session, and an expiring key ends it on its own. There
are no user accounts — those arrive with RBAC and replace this.

**The cookie authenticates reads and nothing else.** Ingest takes a bearer header
only, so a page on another origin cannot make a signed-in browser submit findings.
That is enforced in the guard rather than left to `SameSite`, because a control
that rests on one browser flag fails the day somebody adds an exception for a
proxy ([design](design/panel-sessions.md)).

A signed-in browser sees exactly what the key sees: one project, and one
environment when the key is pinned to one. It cannot reach further than a `curl`
with the same key.

### A database outage is not a rejected key

If the collector cannot reach its database while checking a key, it answers `503`,
not `401`. A fleet told its credentials were rejected goes and rotates credentials
that were fine — and the agent-side warning talks about matching schema versions,
which is advice about the wrong thing entirely. Nothing is leaked by the
distinction: `/readyz` already tells any caller whether the database is reachable.

### Running without any of it

`GUARDANA_ALLOW_UNAUTHENTICATED=1` (or `allow_unauthenticated=True` when building
the app in code) accepts a collector anyone who can reach the port can read and
write. It exists for evaluating Guardana on a laptop, and it has to be typed:
combined with choosing the ephemeral store, that is two explicit switches for the
toy configuration and none for the real one.

## Migrations

```bash
guardana-collector status      # what is applied, what is pending
guardana-collector migrate     # apply everything pending
guardana-collector rollback    # undo the most recent (--steps N for more)
```

Exit codes match [the table the rest of the tool uses](exit-codes.md): `0` did
what was asked, `1` the database said no, `3` the command was pointed at nothing.

**Every migration ships a rollback**, checked when the migration set is loaded
rather than when it is needed. A schema change that cannot be undone is an upgrade
nobody will risk, and "we will write the rollback if we need it" is a decision
made under exactly the pressure that produces bad rollbacks.

**Each migration runs in one transaction**, together with the row that records it.
One that fails half-way leaves the database as it found it, rather than in a state
no version describes.

**A Postgres advisory lock covers the whole run**, so two replicas starting
together cannot both apply the same version.

### Three things the runner refuses

| Refused | Why |
|---|---|
| a migration edited after it was applied | two databases now disagree about what version four *is*, and nothing else would ever notice. The checksum is recorded when it is applied and checked every time after. Add a new migration instead |
| a migration numbered below the highest applied one | a rebase accident. Applying only what comes after would skip it on that database forever, while every other database has it |
| a database holding a migration this build does not ship | it was written by a newer Guardana, and an older collector would write rows the newer schema does not describe |
| rolling back `0003` on a database holding two tenants | dropping the tenant column would merge two teams' evidence into one undifferentiated pile. The only refusal tied to a single migration, because only this one can destroy an isolation boundary |

Rolling back `0004` needs no refusal: it drops labels, which loses information and
merges no tenants, and the submissions themselves stay.

## Health and readiness are two questions

```bash
curl -s localhost:8000/healthz   # the process is running. Touches no database
curl -s localhost:8000/readyz    # the schema this build expects is the one present
```

`/readyz` returns `503` while a migration is pending, so a rolling deploy does not
send traffic at a schema that is not there yet — and returns `503` again after a
rollback, which is the direction that matters during an incident.

Under `GUARDANA_STORAGE=memory` it reports `"storage": "memory"` rather than a
plain "ready". A fleet view that cannot tell durable from ephemeral will read one
as the other, and the ephemeral one is the one that forgets.

## Applying migrations

`guardana-collector migrate` is the supported path. `GUARDANA_MIGRATE_ON_START=1`
makes the server migrate before serving, which is what a single-node Docker
Compose wants and what a rolling deploy should not have: migrating on boot means
two versions of the code briefly run against one schema.

## Running one locally

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
export GUARDANA_DATABASE_URL=postgresql://guardana:guardana@127.0.0.1:55439/guardana_test
uv run guardana-collector migrate
uv run guardana-collector bootstrap --org acme --project web    # prints the key once
uv run --with uvicorn guardana-collector serve
```

(`--with uvicorn` because the ASGI server is an extra and this repository does not
carry it as a development dependency.)

Then point a run at it:

```bash
export GUARDANA_COLLECTOR_TOKEN=gdn_…
guardana scan . --reporter server://http://127.0.0.1:8000
```

To look at nothing but the dashboard, skip all of it — `GUARDANA_STORAGE=memory`
with `GUARDANA_ALLOW_UNAUTHENTICATED=1` still starts a collector with a working
page, no database, no organization and no key.

A collector that is unreachable never changes a gate's exit code — the scan
already ran and its verdict stands on its own. A collector that *rejects* a
submission is different and says so, because a whole fleet silently failing to
report while a dashboard shows stale data as current is the failure that matters.

## Contributing to the collector

Its tests need a real PostgreSQL. Without one they **skip**, so changing a rule
does not require running a database. Setting `GUARDANA_REQUIRE_POSTGRES=1` turns
that skip into a failure, and CI sets it — because "the isolation test did not
run" reading as a green build is the same fail-open this project refuses
everywhere else, relocated into the test suite.

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
uv run pytest packages/guardana-server
```

Every assertion about storage runs against **both** the in-memory store and
PostgreSQL, from one parametrised contract test. Two implementations tested apart
become two implementations that behave differently, and the one nobody runs
locally is the one that behaves differently in production. The cross-tenant tests
run against both for the same reason, and a further test walks the `Store`
protocol and fails on any method that does not take a tenant scope first.

## See also

- [`design/collector-domain-model.md`](design/collector-domain-model.md) — the model the next items build
- [`design/collector-persistence.md`](design/collector-persistence.md) — why persistence is shaped the way it is
- [`design/collector-tenancy.md`](design/collector-tenancy.md) — the organization/project boundary that is being built next
- [`architecture.md`](architecture.md#the-coreserver-boundary) — why the engine never imports this
- [`privacy.md`](privacy.md) — evidence is redacted by the agent before it is sent

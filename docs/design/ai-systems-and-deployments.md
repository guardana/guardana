# Design: AI systems, environments and deployments

**Status:** implemented in 0.9.0 · **Written:** 2026-08-05 · **Phase C, item 22**

## The problem

A collector now knows *which project* a run belongs to. It does not know **what was
verified, where it runs, or which version of it** — so a project's history is one
undifferentiated stream in which last night's production check and a developer's
laptop experiment sit side by side.

That is the gap between "we keep the evidence" and "we can answer a question with
it". Every question a team actually asks needs this axis:

- did production get worse since Tuesday?
- is the staging deployment of the support agent verified at all?
- this finding — which commit introduced it?

The engine has had the vocabulary since 0.7: `DeploymentRef` on the run manifest
carries `ai_system`, `environment`, `deployment_id`, `commit_sha`, `image_digest`,
`model_digest`, `model_name`, `model_revision`. **Nothing has ever filled it in,
and the envelope has never carried it.** Both are recorded debt
([`ROADMAP.md`](../../ROADMAP.md)): "deployment identifiers populated from CI" and
"the collector envelope carrying the manifest — belongs with the collector work,
not ahead of it". This is that work.

It is also what the company-ready checklist entry "project/**environment**
isolation" is still waiting on, and what keeps the collector's maturity at
`experimental` after [tenancy](collector-tenancy.md).

## What must not get harder

Stated first, for the same reason it is stated first in the tenancy document: a
boundary that lengthens the first run is a boundary fewer people ever get behind.

- **A local scan is untouched.** No collector, no system, no environment, no flag.
- **Reporting into a collector gains no required argument.** A run that declares
  nothing is stored against the project and against no system — recorded as
  unknown, never folded into a system somebody did not name.
- **Standing a collector up stays three commands.** `bootstrap` is unchanged; AI
  systems, environments and deployments are *inferred from what a run declares*,
  not created by an administrator beforehand.
- **The evaluation path stays two variables.** `GUARDANA_STORAGE=memory` with
  `GUARDANA_ALLOW_UNAUTHENTICATED=1`.

## Six decisions

### 1. The project comes from the key; the system and environment come from the run

Tenancy settled that the project may only come from the credential, because a
credential that does not bound the write is not a boundary. The obvious move is to
apply the same rule one level down — and it is the wrong one.

A single pipeline legitimately deploys to `dev`, `staging` and `production`.
Sourcing the environment from the key would mean three credentials per project for
every team, and the blast radius that buys is already bounded: the key names the
project, and everything it can reach is inside it.

So the run declares its system and environment, and the collector records them
inside the project the key names. **This is a labelling axis by default, not an
authorization boundary** — and the next decision is what makes that statement
survivable.

### 2. A key may pin an environment, and then it is a boundary in both directions

`key create --project acme/web --environment production` produces a credential that
**writes only production runs and reads only production evidence**. Unpinned keys
behave as they do today: the whole project.

Optional rather than mandatory, because the pin is a *narrowing*, and narrowing is
the direction a credential should err in without being the direction everybody is
forced into. The team that needs "the dev pipeline must not be able to write
production evidence" gets it with one flag; the team with one pipeline and three
environments is not made to manage three secrets to get started.

Read *and* write, not write alone. A pin that bounded writes but let the same key
read every environment would be the kind of half-boundary that reads as a whole one
— and asymmetry is exactly what makes a security claim wrong in a way nobody
notices until it matters.

**A mismatch is a refusal.** A pinned key that submits a run declaring a different
environment gets `403`, never "prefer the more specific one" and never a silent
rewrite. This is the rule the tenancy document already wrote for the day the
envelope carries a tenant identifier; this is that day, one level down.

**Silence is not a mismatch.** A pinned key submitting a run that declares no
environment labels it with the pin. The credential asserted the environment; the
run did not contradict it. The alternative — storing it unlabelled — would let a
pinned key write evidence into a place it cannot itself read, which is a blind spot
manufactured by a security feature. It also means a pipeline behind a pinned key
does not have to repeat `--environment` on every command.

### 3. Systems, environments and deployments are inferred, and a mistake is visible

The alternative is requiring an administrator to create an AI system before a
pipeline can report against it. That puts a human step between a pipeline and its
first report, and pipelines that fail on a missing prerequisite get commented out,
not fixed.

So the collector creates what a run names. The cost is real: one typo
(`--ai-system suport-agent`) creates a second system, and a dashboard showing two
systems where there is one is a dashboard that lies quietly.

The answer is not to refuse; it is to make the mistake **visible**.
`guardana-collector system list` on a typo shows two entries and one of them is
obviously wrong, which is the difference between a mistake somebody finds and one
nobody does.

An earlier draft of this document gave every inferred row an `unclaimed` flag,
"until a human or an API call adopts it" — which is what the domain model leans
towards. It is dropped, because **this item ships no command that could ever clear
it**. Every row would be `unclaimed` forever, so the marking would distinguish
nothing while looking like it distinguished something; and a column nothing can
fill is the same defect as the `created_by` that tenancy removed from `store_key`.
The flag arrives with the command that clears it.

Adopting one — and the *merge* that a typo actually needs — is deliberately not in
this item. Merging two systems moves evidence between identities, which is the same
class of operation as deletion, and it belongs with retention (item 26) where that
class is designed once. Until then a typo is corrected the way it is made: by
running the pipeline with the right name, and reading the wrong one as the empty
system it is.

**Systems and environments are always resolved inside the key's project.** Two
projects may each have a `production` and a `support-agent`, and they are four
rows. A lookup that matched on the name alone would be a cross-tenant read
reintroduced one level down, by a query that looks innocent.

### 4. The environment vocabulary is open, and normalized

Closing it to `dev | staging | production` would be wrong within a week: teams run
`preview`, `canary`, `eu-prod`, `pr-1423`. Guardana's engine "knows no regulation
and no vendor", and it should not know somebody's deployment topology either.

Open, therefore — but held to the same slug rules as an organization or a project,
so `Production`, `production ` and `production` are one environment rather than
three. Normalization at the door, because the alternative is a dashboard whose
grouping depends on who typed what.

This is deliberately *not* the reasoning that keeps `Capability` closed. A typo'd
capability makes a rule silently skip forever, which is a fail-open; a typo'd
environment makes a visible extra row.

### 5. The envelope goes to v6, and carries only the deployment block

Not the whole run manifest. The manifest is the *engine's* reproducibility record
and it is versioned independently; folding it into the wire format would tie two
schemas that were separated on purpose, and would send a collector rule digests and
budget ceilings it has no question to ask of.

v6 adds one optional object. A v5 agent keeps working against a v6 collector and
reports less, which is honest: it could not observe more. The collector accepts
2–6, as it accepts 2–5 today.

`HttpReporter` takes the deployment at construction rather than on `submit`,
because `Reporter.submit` is a documented extension point and a third-party
reporter should not stop satisfying the protocol over this. One reporter is built
per run by the CLI, and `monitor` reuses one across repeated runs of the *same*
target — so the constructor is the honest home for it either way.

### 6. Detect what CI states; never invent what only a human knows

`commit_sha`, `image_digest` and the run URL are facts a pipeline already holds, and
reading them from the environment beats asking a user to remember a flag —
`detect_source()` already does exactly this for the source kind.

`ai_system` and `environment` are **not** detectable. A branch name is not an
environment, and a repository name is not an AI system: a monorepo has several, and
a repository deployed twice has one system in two environments. Guessing would
produce a value a team would then build a dashboard on, which is the same mistake as
an invented `estimated_cost` — and this project already refuses that one.

So: declared by flag or `guardana.yaml`, detected never.

## Design

### Schema, migration 0004 — labels on a submission, not three new tables

```sql
alter table submissions
    add column ai_system       text,
    add column environment     text,
    add column deployment_ref  text,
    add column commit_sha      text,
    add column image_digest    text,
    add column model_digest    text,
    add column model_name      text,
    add column model_revision  text;

alter table api_keys add column environment text;

create index submissions_project_environment_idx
    on submissions (project_id, environment, received_at desc);
```

The existing `(project_id, received_at desc)` index **stays**. A composite index led
by `project_id, environment` cannot order by `received_at` for a query that
constrains only the project, so an unpinned read — still the common one — would lose
its ordering. Two indexes, each for a shape of read that actually happens.

**Every added column is nullable, and null means "the run did not say"** — never
"applies to everything". A scoped read filters on the environment only when the
scope names one, so an unlabelled run stays visible to an unpinned key and invisible
to a pinned one. That asymmetry is the point: a pinned key must not see evidence
that never claimed to be about its environment. Nothing needs adopting, because
every existing submission *is* a run that did not say.

#### Why no `ai_systems`, `environments` or `deployments` tables

The first draft of this document created all three. Reviewing it against the two
defects this repository has already removed — `store_key`'s `created_by` and this
document's own `unclaimed` flag — killed them, for the same reason both times: **a
row whose only columns are the name it was created from is a table pretending to be
an entity.**

Today a run declares a *slug* and nothing else. An `ai_systems` row would hold that
slug and a `name` column nothing sets; an `environments` row would hold a slug and
nothing at all. Neither has an owner, a policy, a lifecycle or a retention rule —
those are items 24 and 26, and that is when each becomes a thing rather than a
label.

So an environment is a **normalized name**, an AI system is a **normalized name**,
and both are answered by an aggregate query over the submissions that used them.
The pin on a key is text for the same reason and one more: it is an *assertion by a
credential*, true whether or not any run has yet used that environment, so making it
a foreign key would mean creating a row to hold a name nobody has reported against.

`deployment_ref` is the run's `deployment_id` when it gave one, otherwise its
`commit_sha`. A run with neither identifies no deployment, and inventing a surrogate
would produce one "deployment" per run.

When item 24 gives an AI system an owner and a lifecycle, the migration that
promotes these labels to rows has **real data to build them from** — which is a
better position than inventing empty rows now and backfilling meaning later.

### The scope grows a second, optional axis

```python
@dataclass(frozen=True, slots=True)
class TenantScope:
    project_id: int | None = None
    environment: str | None = None
```

`Store`'s shape is untouched: the scope is already the first argument of every
method, which is the property this change collects on. `PostgresStore` adds
`and (%s::text is null or environment = %s)` to each read, and the in-memory store
compares the label it was given. One axis added, no signature moved.

`Authenticated.scope` carries the key's environment pin; `TenantScope.unauthenticated()`
is unchanged.

### Commands

```bash
guardana scan . --ai-system support-agent --environment production
guardana probe … --ai-system support-agent --environment staging --deployment-id 2026-08-05.3
guardana-collector key create --project acme/web --name prod-ci --environment production
guardana-collector system list [--project acme/web]        # marks the unclaimed ones
guardana-collector environment list [--project acme/web]
guardana-collector deployment list --system acme/web/support-agent
```

There is **no `guardana.yaml` block**, and this is a change from the first draft.
An environment varies per invocation — the dev job and the prod job are different
runs of the same repository — so a repository-level constant would be wrong for the
field that matters most. Environment *variables* cover what a config file would
have: a pipeline exports `GUARDANA_AI_SYSTEM` once and one job still passes
`--environment production`. `monitor` takes the flags too: a scheduled check of
production is exactly the run whose environment matters most.

`key list` shows the pin, because a credential whose reach is narrower than its
neighbours' is a fact an operator has to be able to see without reading a database.

## Testing

Every isolation test takes the `database_url` fixture, so CI cannot record one that
did not run as a pass.

- a pinned key writing another environment: `403`, and nothing stored
- a pinned key reading: sees its environment, and **not** the project's unlabelled runs
- an unpinned key: sees everything in its project, labelled or not
- two environments of one project, per entity, on both stores
- an environment pin cannot reach across a *project* either (the two scopes compose)
- a run declaring nothing still ingests, and is stored with three nulls
- a v5 agent against a v6 collector still ingests
- a v6 envelope against the *engine's* serializer — the real bytes, not a hand-written dict
- the same system name in two projects is two systems, and a lookup for one never
  finds the other
- a pinned key submitting a run that declares no environment stores it under the pin
- `system list` and `environment list` show what runs created
- `Production`, `production ` and `production` are one environment
- migration 0004 up and down on a database with submissions, with the rows intact
- a deployment with neither `deployment_id` nor `commit_sha` records no deployment

## Acceptance criteria

- A pinned key reads and writes exactly one environment, proven per entity on both
  stores and over HTTP.
- An unlabelled run is stored as unlabelled and never as a default system.
- The envelope is v6, the collector accepts 2–6, and a v5 agent still reports.
- `Reporter.submit`'s signature is unchanged.
- First run of a real collector is still three commands; reporting still requires no
  new flag.

## What this item deliberately does not deliver

- **`ai_systems` and `environments` as tables**, because today they would be rows
  whose only column is the name they were created from — see above. They arrive with
  the owner and the lifecycle that make them entities (item 24).
- **Adopting or merging an inferred system**, because moving evidence between
  identities is the same class of operation as deleting it (item 26).
- **Read-side roles** — who may see which environment beyond what their key pins
  (item 24).
- **Deployment regression views** in the collector: comparing two deployments is
  `guardana diff`'s question, and the collector does not run rules or comparisons.
- **Populating `configuration.*_digest`** — still the application-awareness work.

## Open questions

1. **Should an unpinned read key see a pinned key's writes?** It does, and that is
   the meaning of "the pin narrows". If a team wants an environment nobody can read
   without pinning, that is a role, and it is item 24.
2. **`last_seen_at` on a deployment is a write on every ingest.** One row, indexed
   by primary key, and it is what makes "which deployments are still reporting"
   answerable. Revisit if ingest volume ever makes it measurable.
3. **A run that declares an environment but no AI system.** Recorded as such. It is
   a real state — a shared endpoint checked per environment — and refusing it would
   force a fake system name into every such pipeline.

# Design: collector domain model and persistence

**Status:** proposed · **Target:** v0.7 · **Current maturity:** experimental

## The problem

`guardana-server` ingests findings, keeps them in memory, and renders a dashboard.
It has no persistence, no authentication and no tenancy, which means it is a
demonstration rather than a product — and the README should not have implied
otherwise. A team that runs it today loses everything on restart and exposes every
finding to anyone who can reach the port.

It is also the single largest gap between "an individual can use Guardana" and "a
company can adopt Guardana", because everything a team wants — history, ownership,
regression across deployments, an audit trail — needs a place to live.

## Design

### Domain model

```
Organization
 └─ Project
     └─ AISystem
         ├─ Environment          (dev / staging / production)
         ├─ Deployment           (a specific version of the system in an environment)
         ├─ Run                  (one Guardana execution, carrying its Run Manifest)
         ├─ Finding              (a problem, identified stably across runs)
         │   └─ FindingOccurrence (this finding, in this run)
         ├─ Waiver               (accepted risk, with an expiry)
         └─ Policy
```

Plus `User`, `ServiceAccount`, `ApiKey`, `AuditEvent`, `Integration`.

**Why `Finding` and `FindingOccurrence` are separate.** A finding has a lifecycle
that outlives any single run: first seen, owner, status, remediation, resolution.
An occurrence is one run's sighting of it. Collapsing them means either losing the
history on every run or re-litigating triage every time — the mistake that makes
scanners produce alert fatigue.

**The identity that links occurrences is the one `diff` already uses**: rule plus
location relative to what the run examined, never the evaluator's rationale. That
decision was made in 0.6 for comparison and the collector inherits it rather than
inventing a second identity — two notions of "the same finding" in one system
guarantees they diverge.

### Persistence

PostgreSQL, with migrations from the first release. Not SQLite: multi-writer
ingest from concurrent CI jobs is the normal case, and a team that outgrows SQLite
mid-adoption has to migrate under pressure.

Every migration ships with a tested rollback or a documented restore procedure. A
migration that cannot be undone is an upgrade nobody will risk.

### Authentication and tenancy

- **API keys for runners.** A CI job needs to *write*, not to browse. Scoped to a
  project, revocable, hashed at rest, shown once.
- **Users for humans**, local auth first with an OIDC-shaped interface so SSO
  slots in later without reworking the model.
- **RBAC:** owner, admin, member, viewer, runner. Five roles cover the real
  distinctions and stop short of a permission system nobody can reason about.
- **Tenancy is enforced at the query boundary, not in the handler.** Every
  repository method takes the tenant scope; there is no unscoped query. A test
  asserts that reading another organization's data returns nothing regardless of
  the identifier presented — cross-tenant reads are the failure that ends trust in
  a security product.
- **No default credentials, ever.** First-run bootstrap generates one and prints
  it once; public registration is disabled by default.

### Finding lifecycle

```
open → acknowledged → in_progress → resolved
  ↓                                    ↑
accepted_risk (waiver, expires) ───────┘
  ↓
expired_waiver → reopened
false_positive
```

**A waiver expires.** Accepted risk that never comes back is not accepted risk, it
is a permanently disabled check. When a waiver expires the finding reopens and the
gate sees it again.

### Ingest is redacted before it arrives

The collector never sees evidence the sending agent's privacy policy excluded, and
it enforces its own policy on top. Two independent applications of the same rule,
because the collector cannot trust that every agent in a fleet was configured
correctly.

### API

Stable and versioned, with OpenAPI generated from the implementation rather than
maintained beside it. Pagination and filtering on every list. Health and readiness
endpoints separate: readiness fails while migrations are pending, so a rolling
deploy does not send traffic at a schema that is not there yet.

### UI scope

Deliberately small for v0.7: sign-in, project switcher, AI systems, runs, finding
list, finding detail with evidence, deployment regression, policies, API keys,
audit log. No charts nobody asked for. **Evidence rendering is escaped and
sanitized** — evidence is attacker-influenced text by definition, and a dashboard
that renders it raw is a stored-XSS vector delivered by the tool that was supposed
to find them.

## Acceptance criteria

- Migration up, migration down (or documented restore), on a database with data.
- Cross-tenant read and write attempts fail, per entity, as tests.
- An authorization matrix test: every role against every endpoint.
- Redaction enforced on ingest, tested independently of the agent's redaction.
- Backup and restore documented **and exercised** — an untested backup is a
  belief, not a procedure.
- No default credential; first-run bootstrap tested.
- Rate limits and request-size limits on ingest.

## Open questions

1. **Does a `Deployment` need to be created explicitly, or inferred from a run's
   manifest?** Inferring is friendlier and risks silently creating a deployment per
   typo'd identifier. Leaning: inferred, but listed as "unclaimed" until a human or
   an API call adopts it.
2. **Retention granularity.** Per-organization is simplest; per-project is what
   people will ask for. Starting per-organization and stating so.
3. **Does the collector need to run rules?** No — and stating it here so it does
   not creep in. The collector aggregates verdicts; the engine produces them. A
   collector that runs rules would need the target's credentials, which is exactly
   what a team self-hosts to avoid.

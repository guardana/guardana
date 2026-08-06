# Design: the audit log, retention, and deleting things on purpose

**Status:** accepted · **Implemented in:** 0.11.0 · **Component:** collector

## The problem

Two gaps that look separate and are not.

**Nothing records who did what.** A collector holds a team's security evidence and
its credentials, and it cannot answer "who created this key", "who waived that
finding", or "who rolled the schema back at 3am". `api_keys.created_by` has
existed since 0.8 with nothing filling it — a column nobody writes is a promise
the code does not keep.

**Nothing can be deleted.** Every foreign key is `on delete restrict` and there is
no command to remove an organization, a project, or an old submission. That is
deliberate — deletion before an audit log is deletion nobody can account for — but
it means the disk grows forever and a project created by a typo is permanent.

They belong together because deletion is the operation an audit log exists for.

## The audit log

One table, append-only by convention and by the absence of any command that writes
to it other than by recording an action.

```
audit_events(occurred_at, organization_id, project_id, actor, actor_kind, action, subject, detail)
```

**What is recorded: state changes, never reads.** Creating and revoking a key,
creating and renaming a tenant, triaging a finding, applying and rolling back a
migration, deleting anything. Listing findings is not recorded — a read log on a
dashboard refresh is volume without an answer, and volume is how a log stops being
read.

### The actor, and what it is worth

Two kinds, and the difference is stated in every row rather than implied:

| `actor_kind` | Example | Worth |
|---|---|---|
| `key` | `key:prod-ci (id 4)` | **verified** — the credential was presented and matched |
| `cli` | `cli:konrad@ops-1` | **asserted** — the operator ran a command on a machine with database access |

A CLI actor is the operating-system user, taken from the environment rather than
typed, and overridable with `--actor`. It is not proof of anything: anyone who can
reach the database can write any name. Recording it anyway is right, because the
question an audit log usually answers is "what happened, and roughly when, and by
which route" — but calling it authentication would be the same false green this
project refuses everywhere else, so the column says which kind it is and the
documentation says what that means.

Real identity for humans arrives with users and RBAC, in the team-platform
milestone. Until then this is a log of actions, honestly labelled.

### Which key wrote this submission

`submissions.api_key_id` answers the open question from the tenancy design. It is
nullable: a submission that arrived on an unauthenticated evaluation collector has
no key, and inventing one would be worse than the null.

## Retention

Per **project**, not per organization. The tenant is the project everywhere else in
this collector, and a retention policy at a different granularity than the tenant
is one that eventually deletes somebody else's evidence.

```bash
guardana-collector retention set   --project acme/web --keep-days 90
guardana-collector retention apply --project acme/web [--dry-run]
```

**Applying is a command, never a background job.** The collector has no scheduler,
and adding one to delete data would make "what removed my evidence" answerable
only by reading source. An operator runs it, or a cron they wrote runs it, and
either way the audit log has a row for it.

`--dry-run` prints what would go and deletes nothing. A destructive command whose
first run is the real one is a command people run once and regret.

**Retention never deletes audit events.** A log that is pruned by the same policy
as the data it describes cannot answer questions about the pruning. They are kept
until an organization is deleted, and then they go with it.

**A tracked finding outlives its occurrences.** Retention removes submissions and
their findings; the entity, its status and its waiver stay, with the sighting count
falling to zero. Deleting the triage along with the evidence would mean a finding
that reappears after a retention run arrives as new, and somebody re-decides
something they already decided.

## Deleting a project or an organization

```bash
guardana-collector project delete acme/web --yes
guardana-collector org delete acme --yes
```

Both refuse without `--yes`, and both print what will go before doing it. An
organization refuses while it still has projects — cascading through two levels of
tenancy from one word is exactly the operation somebody performs at 3am with a
shell they thought was pointed elsewhere.

`on delete restrict` stays everywhere. Deletion is done by these commands, in a
transaction, in an order that leaves nothing orphaned, and the constraint is what
guarantees a future code path cannot delete a tenant by forgetting one of its
tables.

## Merging two systems after a typo

Deferred in the AI-systems design, and it belongs here because it is the same
class of operation: moving evidence between identities.

```bash
guardana-collector system merge --project acme/web --from suport-agent --into support-agent
```

Relabels the submissions and records the move. It is the only "edit the past"
operation in the collector, and it exists because the alternative — a permanent
second system created by one keystroke — is what makes people stop trusting the
inventory.

## What this deliberately does not include

- **No log shipping, no syslog, no SIEM format.** `audit list` and the table are
  the interface; a team that wants events elsewhere reads them out. Inventing a
  format nobody asked for is how integrations rot.
- **No per-row signatures or hash chaining.** They protect against an attacker who
  already has database write access, and at that point the collector has bigger
  problems. Stated so nobody reads "audit log" as "tamper-evident audit log".
- **No retention of *runs* separately from submissions.** A run is a submission
  here; when they become separate entities, this policy grows a second knob.

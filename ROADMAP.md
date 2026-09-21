# Guardana roadmap

This file is the ordered plan. It intentionally does not repeat the feature
catalog, framework coverage, release history, or design debates:

- [FEATURES.md](FEATURES.md) says what ships;
- [the generated rule summary](docs/generated/rule-summary.md) and
  [rule catalog](docs/generated/rule-catalog.md) are the coverage source of truth;
- [CHANGELOG.md](CHANGELOG.md) records history;
- [docs/design/](docs/design/) records accepted and rejected design choices.

Items are ordered by dependency, not promised dates. Work moves up when user
evidence changes the order.

## Product constraints

Every roadmap item must preserve these properties:

1. A check that did not run or could not decide is never reported as a pass.
2. Offline scanning stays offline; active checks run only when requested.
3. Guardana remains outside the production request path.
4. Cost and side effects are bounded before a run starts.
5. Application-specific risk remains expressible without forking the engine.
6. Public schemas are versioned and migratable.

## What ships today (0.26.1)

The current release is beta. It provides artifact scanning, controlled endpoint
and MCP probing, recorded-trace analysis, regression comparison, policy and
baseline gates, extension APIs with scaffolding for a new pack, and an optional
authenticated PostgreSQL-backed collector. See [FEATURES.md](FEATURES.md) for the concise overview and
[Product status](docs/product-status.md) for limitations.

## Now: repeatable application assurance

Target locators are complete since 0.24.0 and declarative fixtures since 0.25.0,
and one command now writes an installable pack whose rules already grade their own
finding, clean, and inconclusive samples. The remaining milestone turns a
repeatable extension into measurement a team can compare and operate. The order below reflects the
[0.23 repository and market audit](docs/design/audit-0.23-market.md): author
workflow and honest measurement come before additional output destinations. The
[0.25 audit](docs/design/audit-0.25-market.md) re-read the standards and the
comparable projects a month later and moved no row.

| Order | Deliverable | Done when |
|---:|---|---|
| 1 | Suites, versioned datasets, and assessors | a run records the sample, assessor, denominator, and uncertainty rather than only findings |
| 2 | Paired statistical diff | comparison refuses unequal or undersized samples and gates only on a declared minimum effect |
| 3 | Renderer and reporter plugins | outputs are discoverable entry points and every output remains behind the common redaction boundary |
| 4 | Provider conformance matrix | documented endpoint support is backed by repeatable capability tests |
| 5 | Assessments in the collector | trends are keyed by system, deployment, dataset, and assessor version; findings and quality measurements stay separate |

Design inputs exist for everything shipped so far and for rows 1, 2 and 3:

- [target locators](docs/design/target-locators.md)
- [declarative fixtures](docs/design/declarative-fixtures.md)
- [pack scaffolding](docs/design/pack-scaffolding.md)
- [output plugins](docs/design/output-plugins.md)
- [extension author tooling](docs/design/extension-author-tooling.md)
- [quality suites](docs/design/quality-suites.md)
- [paired regression statistics](docs/design/paired-regression-statistics.md)

The full OTLP intake remains in the next milestone because the OpenTelemetry
GenAI agent conventions are still changing. A compatibility spike may proceed
after items 1 and 2, in parallel with items 4 and 5, but it must normalize an
explicit supported subset behind an adapter rather than make a development
convention a persisted Guardana schema.

### Milestone exit criteria

- A third-party target, rule, evaluator, renderer, and reporter are usable without
  modifying Guardana; target locators satisfy the target part from 0.24.0, and
  `guardana new-pack` scaffolds the rest.
- A suite records passes as well as failures and names its dataset version.
- `guardana diff` can say better, worse, unchanged, or incomparable with an
  auditable statistical reason.
- The collector can plot measurements without turning missing samples into zero.

## Next: continuous assurance

Consume a bounded sample of real interactions without becoming an APM or an
inline control.

1. OTLP intake with redaction before persistence or queuing.
2. A bounded queue, backpressure, sampling, and stateless workers.
3. Continuous rules over synthetic runs and recorded traffic.
4. Prometheus and webhook outputs through the reporter seam.
5. Retention, deletion, and audit behavior proven under the new data volume.

This lane starts as soon as suite and statistical shapes are stable; it does not
wait for every provider-matrix entry. That ordering responds to the market need
for continuous inventory and post-deployment evidence without freezing a moving
external telemetry convention into Guardana's own documents.

Exit criteria: overload fails closed without affecting the application; raw
sensitive payloads are not retained by default; every trend identifies its sample
and deployment revision.

## Then: self-hosted platform fit

- Helm deployment with tested upgrade, rollback, backup, and restore.
- OIDC/SSO and role-based access for human users.
- Live RAG targets with safe fixtures and explicit data boundaries.
- Central policy distribution with signed, versioned policy artifacts.
- Integrations through output plugins rather than product-specific engine code.

## 1.0: compatibility, not a feature count

Guardana reaches 1.0 when external authors can rely on it:

- the extension API and package manifest are frozen with a deprecation policy;
- schemas have published compatibility guarantees and migration tests;
- a standalone conformance kit covers targets, rules, evaluators, and outputs;
- two release candidates ship without an unplanned public API change;
- security and recovery runbooks are exercised, not merely documented.

## Parallel contributor lane

New artifact formats, deterministic rules, framework adapters, and taxonomy
updates may proceed in parallel when they do not delay the ordered milestone.
Prefer extension packs when a feature adds a large dependency, a niche corpus, or
an experimental evaluator.

One taxonomy update is open now: the MITRE ATLAS catalogue records a data-format
version rather than the content release its entries were transcribed from, and
three content releases have landed since.

## Researched after the foundations

- multi-agent protocols and delegated identity;
- multimodal attack carriers;
- adaptive attack generation inside a strict sandbox;
- broader multilingual and domain-specific corpora.

These need measured evaluation quality and bounded execution first. They are not
shortcuts around the current milestone.

## Non-goals

Guardana is not planned to become:

- an inline firewall, WAF, or guardrail proxy;
- a general SAST, CVE, secret, or network-discovery scanner;
- a second trace store competing with observability platforms;
- a compliance certification or legal-advice engine;
- a marketplace of unverified prompts;
- an autonomous production attacker.

## Release gate for roadmap work

Every increment needs tests, user documentation, explicit exit behavior, redacted
evidence, and a changelog entry. The full repository gate in
[CONTRIBUTING.md](CONTRIBUTING.md) must pass. A feature that cannot distinguish
"safe" from "not measured" is incomplete.

## Changing the order

Open an issue or design document with the user problem, evidence, affected exit
criterion, dependencies, and what moves down. New work is not prioritized by
adding more prose to this file.

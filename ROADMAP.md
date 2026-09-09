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

## What ships today (0.23.0)

The current release is beta. It provides artifact scanning, controlled endpoint
and MCP probing, recorded-trace analysis, regression comparison, policy and
baseline gates, extension APIs, and an optional authenticated PostgreSQL-backed
collector. See [FEATURES.md](FEATURES.md) for the concise overview and
[Product status](docs/product-status.md) for limitations.

## Now: application awareness and honest regression

The next milestone makes custom targets usable from the CLI and turns individual
assessments into comparable suites. Complete the following in order.

| Order | Deliverable | Done when |
|---:|---|---|
| 1 | Target locators and `TargetFactory` | an installed target can be selected from the CLI without user Python; malformed and conflicting schemes fail closed |
| 2 | Renderer and reporter plugins | outputs are discoverable entry points and every output remains behind the common redaction boundary |
| 3 | YAML fixtures for scenario and trajectory rules | declarative rules can ship positive, negative, and inconclusive samples just like Python rules |
| 4 | `guardana new-pack` | one command creates an installable pack with manifest, entry points, fixtures, and tests |
| 5 | Suites, versioned datasets, and assessors | a run records the sample, assessor, denominator, and uncertainty rather than only findings |
| 6 | Paired statistical diff | comparison refuses unequal or undersized samples and gates only on a declared minimum effect |
| 7 | Assessments in the collector | trends are keyed by system, deployment, dataset, and assessor version; findings and quality measurements stay separate |
| 8 | Provider conformance matrix | documented endpoint support is backed by repeatable capability tests |

Design inputs already exist for the first six items:

- [target locators](docs/design/target-locators.md)
- [output plugins](docs/design/output-plugins.md)
- [extension author tooling](docs/design/extension-author-tooling.md)
- [quality suites](docs/design/quality-suites.md)
- [paired regression statistics](docs/design/paired-regression-statistics.md)

### Milestone exit criteria

- A third-party target, rule, evaluator, renderer, and reporter are usable without
  modifying Guardana.
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

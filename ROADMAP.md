# Guardana roadmap

Guardana should give an individual developer a useful result on the first run,
then let a team turn the same evidence into its own tests, gates, reports and
tools without forking the engine. It is an offline-first verification framework
with a usable CLI and optional collection, outside the production request path.

[GitHub Issues](https://github.com/guardana/guardana/issues) are the live work queue.
[Milestones](https://github.com/guardana/guardana/milestones) group release scope.
The `next` milestone collects work for the next release. A milestone is a
scope, not a date.
Ideas without a reproducible problem or acceptance test start in
[Discussions Ideas](https://github.com/guardana/guardana/discussions/categories/ideas).

## What ships today (1.0.0rc5)

The current release carries the stable compatibility promise for its supported surface; [Product status](docs/product-status.md) lists maturity by component.
It scans model and code artifacts offline, probes live endpoints, MCP servers and A2A agents, grades recordings, compares runs and gates CI.
Historical documents from 0.2.0 through 1.0.0rc5 are read by current tests.
See [FEATURES.md](FEATURES.md) for shipped behaviour, [Product status](docs/product-status.md) for limits, and the [generated rule summary](docs/generated/rule-summary.md) and [rule catalog](docs/generated/rule-catalog.md) for coverage.

## The 1.0 promise

1.0 promises that incompatible changes to the supported surface require a major
release. [Compatibility](docs/compatibility.md) defines that surface and the
deprecation rules. Every 1.x release reads earlier persisted documents and
supports extension API 2 and output API 1.

The [versioning policy](docs/compatibility.md#versioning) chooses releases by
change impact. Fixes merge whenever ready. The maintainer reviews package
changes each Monday; urgent fixes use the same gates outside that schedule
([release cadence](CONTRIBUTING.md#release-cadence)). The criteria the first
stable release had to meet are in
[product status](docs/product-status.md#stable-release-criteria).

Adoption measures — five consented first runs, two independent application teams, a team's live retrieval pilot and independent third-party customization and its reproduction — are published separately, not release criteria. The generated [first-run](docs/generated/first-run.md) and [application](docs/generated/application-measures.md) measures read "not measured": 0 of 5 sessions and 0 of 2 teams. Invitations remain open.

Six maintainer-run proofs are published as notes. The [clean-install offline first run](https://guardana.dev/notes/clean-install-offline-first-run) and [customization through published extension points](https://guardana.dev/notes/customization-through-published-extension-points) passed against 1.0.0rc5 from PyPI ([run](https://github.com/guardana/guardana/actions/runs/39424046832)). Linux and macOS first-run cells passed; all Windows cells passed and are required, with the displayed path `model\weights.pkl` recorded as a known difference ([#167](https://github.com/guardana/guardana/issues/167)). The reference pack 0.1.3, installed from PyPI outside the repository, passed the conformance kit; its wheel and sdist are also attached to each GitHub Release. The [retrieval pilot](https://guardana.dev/notes/retrieval-pilot-poisoned-document-and-tenant-filter), [regression loop](https://guardana.dev/notes/regression-loop-with-a-redacted-regression) and [collector recovery runbooks](https://guardana.dev/notes/collector-recovery-runbooks) passed against 1.0.0rc5 in a later [workflow run](https://github.com/guardana/guardana/actions/runs/40005613709), covering the pilot's broken modes, redacted regression promotion, database migration and Compose restores. The maintainer recorded the [security runbook drill](https://guardana.dev/notes/security-runbook-drill), covering a made-up report, TestPyPI release and withdrawal, disclosure on paper, and lessons; no real Guardana release was touched.

## Product constraints

1. An unavailable check, ungraded case, partial run or invalid comparison never becomes a pass.
2. Offline scanning stays offline; target and judge traffic is explicit and bounded.
3. Engine capabilities and built-in checks remain open source, without an account.
4. Application-specific checks and output destinations work without an engine fork.
5. Public data formats are versioned, with tested readers and migrations.
6. Findings, quality measurements, errors and missing evidence remain separate.
7. Results explain their source, coverage, execution cost and comparability.
8. The collector is optional; local files and Python deliver independent value.

## After 1.0

The order is conditional: a row without its start evidence does not displace an application pilot or a reproducible defect.

| ID | Work | Start when | Done when |
|---|---|---|---|
| I1 | Evidence-preserving imports | Two independent teams bring saved observations from an existing tool or agent recorder and cannot retain the evidence they need through the current supported subset. | One requested source has a documented field and trust mapping, positive, negative and incomplete fixtures, bounded parsing and redaction, explicit judge and sampling identity, and a versioned compatibility policy. Imported claims never become a local pass by omission. Promotion to a local regression requires reviewed reproduction. Add another source only after the first has an independent consumer. |
| A1 | A real application's tool effects | An application pilot supplies a controlled injected input, a complete action trace and a harmless oracle for the application's actual tools. | The team's own agent runs an allowed task and an injected task against doubles. The oracle proves a forbidden effect. Missing or truncated action evidence remains indeterminate. Cover one requested workflow, including the allowed control case. Do not present a model harness as the application or build an inline enforcement layer. Review target, fixture and trace compatibility first. |
| M1 | Paired statistical diff | Two independent pilot teams each use local `diff` on comparable saved before/after application runs for a documented ship decision, and one requests uncertainty because descriptive counts are insufficient. | Compatible cases and grading identities are paired. Repeated trials are handled at case level. Insufficient coverage or power is refused. Effect size and uncertainty are reported. Declared effects can gate, and multiple gated suites are controlled. Version the comparison and grading-identity contract. Label existing descriptive diff accurately. |
| M3 | Collector measurements | Two independent teams submit and read their own locked application runs in the optional collector, and each asks the same cross-run question that local files cannot answer. | Versioned envelope and storage queries answer that recorded question by the necessary system, deployment, dataset and assessor dimensions. They enforce tenancy and report sample counts, uncertainty, coverage gaps, missingness and unknowns beside trends. Keep the envelope versioned independently from the run schema. |

Compatible additions can extend versioned contracts in 1.x.

## Later

This is an unordered, unversioned set of possibilities, not a plan for 2.0.
Promotion to active work requires pilot pain, a reproducible failing case,
an acceptance criterion and a versioned contract review.
2.0 requires evidence that a needed public-contract break cannot be a compatible 1.x addition.

- Synthetic scheduled verification with anytime-valid monitoring, rather than repeated fixed-level tests presented as reliable alerts.
- A Prometheus reporter over the common output contract, once a team names the measurements and unknowns it needs.
- Live RAG and application targets beyond the retrieval pilot, with safe fixtures and explicit data boundaries, ordered by pilot needs.
- Model-artifact inventory and parser completeness, starting with unlisted formats; malformed, unreadable and partially scanned inputs must not look clean under the versioned scan and coverage contract.
- Central distribution of signed, versioned profiles and policies, after local locks and recipes prove useful.
- Profiles distributed in packs as a compatible 1.x addition; `guardana.yaml`, presets and the versioned profile schema remain the 1.0 contract.
- Optional A2A agent-card signature verification, keeping the JOSE dependency outside `guardana-core`.
- Agent supply-chain provenance beyond a manifest hash: approved tool schema, package or image identity, resolved server origin, and skill and configuration identity.
- OIDC/SSO, human roles and Helm when collector users need them, with exercised upgrade, rollback, backup, restore and deletion.

An exported recording remains an explicit supported subset behind an adapter.
OpenTelemetry conventions are input formats, not Guardana's storage contract.
Live production intake and supervision belong to Guardana Control.

## Contributing

New checks, adapters and formats follow demonstrated application needs and the
issue process.
Heavy dependencies, niche corpora and experimental graders belong in extension packages.
Built-in security rules retain public-framework mappings. Application quality
checks use the team's own criteria; see [CONTRIBUTING.md](CONTRIBUTING.md#principles).

Contributor priorities include ATLAS provenance with separate monthly-content and data-format pins, positive and negative fixtures for new techniques, fixture expressiveness, and non-executing declarative packs.
A public extension-ID service is excluded: namespaces, local validation and locks cover the author workflow.

Further multi-agent protocols beyond the A2A fixture, multimodal carriers beyond one document or image carrier a pilot uses, adaptive attackers, reusable techniques and broad multilingual or domain corpora follow the foundations.
Their priority depends on measured usefulness, evaluation quality and bounded execution.
Import or buy coverage rather than grow prompt counts; attack volume is not the adoption metric.

## Non-goals

An inline firewall or guardrail proxy; production agent supervision; a general
SAST, CVE, secret or network scanner; a second production trace store; compliance
certification; a marketplace of unverified prompts; autonomous production attacks.

## Changing priorities

Open an issue or discussion with the user problem, observed evidence, affected
item ID, dependencies and the work that moves down.
The owner decides changes to release criteria.

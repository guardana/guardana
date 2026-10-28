---
title: "1.0.0 release gate evidence for engineering criteria (#144)"
date: 2026-10-27
summary: "The engineering tests passed on fb9ab309 for 1.0.0; items without their own tests are tracked in #215."
---

This note records evidence from the final release gate on the `1.0.0` commit for the [engineering criteria in product status](https://guardana.dev/docs/product-status#stable-release-criteria). The first stable release, `1.0.0`, was published on 2026-10-27 from commit `fb9ab309`, which carried the signed tag `v1.0.0`. Tests ran on the maintainer's machine and in [CI](https://github.com/guardana/guardana/actions/runs/40515502114); the local CI mirror ran on the starting tree described below. [Release pull request #235](https://github.com/guardana/guardana/pull/235) was squash-merged as that commit.

## Where the tests ran

- Maintainer's machine, 2026-10-27 12:17–14:12 UTC: `scripts/release.py 1.0.0` ran `ruff`, `ruff format`, `mypy --strict`, the import contract, `pytest -q`, the dogfood scan and the clean-install check before the release commit. After the version bump, it ran `pytest -q` and the dogfood scan again. All passed; both dogfood scans returned 0 findings. Both pytest runs included the collector tests against local PostgreSQL. The only skips were a recipe-source test needing `setuptools` and, before the bump only, a final-version check; that check ran and passed after the bump.
- [CI on `fb9ab309`](https://github.com/guardana/guardana/actions/runs/40515502114), tagged `v1.0.0`: all jobs were green. Each `test` job on Python `3.11`, `3.12` and `3.13` used a PostgreSQL service and reported 14169 passed and 1 skipped; the skipped recipe-source test needed `setuptools`, which was absent. Coverage met the floor in all 25 critical areas, the dependency audit found no known vulnerabilities in 95 packages, and dogfood returned 0 findings. `example-plugin` ran each example's own suite in an isolated environment: custom rule, Hermes integrator, shell-hook integrator, retrieval pilot (5 passed), output pack (125 passed) and reference pack (45 passed). Template-scaffolded packs with 3 rules and 1 rule installed, validated and graded. `clean-install` answered every documented command as documented and produced 5 SBOMs for `1.0.0`; `images` checked that both images behaved as documented. The [pull-request run](https://github.com/guardana/guardana/actions/runs/40512141357) used the same tree.
- Local CI mirror, `scripts/ci_local.sh --quiet`, 2026-10-27 06:14–06:58 UTC: 27 of 27 jobs were green, with 14168 pytest tests passed and 2 skipped. It ran on the tree that main held after #207 (`993b11b4`), where the release started. The release commit added only the version bump, regenerated pages, the lock file and the changelog roll, with no test or package logic changes. The second skip was the final-version check that ran and passed in CI on the release commit. Coverage floors held in all 25 critical areas, dogfood returned 0 findings, and the six example suites and new-pack check were green.

## Before the release

Historical samples written by the published `1.0.0rc3` packages, using run schema `18`, were added to [`packages/guardana-core/tests/historical/`](https://github.com/guardana/guardana/blob/v1.0.0/packages/guardana-core/tests/historical/) in [#206](https://github.com/guardana/guardana/pull/206). The pre-1.0 statement and rules in [the compatibility policy](https://guardana.dev/docs/compatibility) were rewritten in [#207](https://github.com/guardana/guardana/pull/207); before the gate, `scripts/release.py` checked that the policy no longer stated pre-1.0 rules. The refusal and rewritten-policy paths were guarded by `scripts/tests/test_release_script.py::test_a_final_1x_release_is_refused_while_the_policy_says_pre_1_0` and `scripts/tests/test_release_script.py::test_a_final_1x_release_continues_once_the_policy_is_rewritten`.

## The engineering criteria

### Typed Python outcomes

*"Python consumers receive failed, incomplete and stopped outcomes as typed data."*

- `test_python_facade_parity.py`: `test_a_failed_run_is_returned_as_data_never_raised`, `test_a_scan_writes_the_same_run_from_python_and_from_the_cli` (fail, unverified, indeterminate, unread), `test_a_probe_writes_the_same_run_from_python_and_from_the_cli` (budget stop).
- `a2a/test_a2a_rules.py`: `test_a_stopped_run_keeps_the_same_findings_whatever_the_concurrency`.
- `test_sample_verifications.py`: `test_the_samples_are_a_passed_a_failed_an_empty_a_stopped_and_an_unverified_run`.
- `test_verify_surface.py`: `test_a_verification_holds_the_documented_fields`.

Published: [Python API](https://guardana.dev/docs/python-api), [`docs/generated/api-surface.json`](https://github.com/guardana/guardana/blob/v1.0.0/docs/generated/api-surface.json).

Not guarded by its own test: `Verification.exit_code` `4` (target stop) and `7` (interrupted) through the Python facade ([#215](https://github.com/guardana/guardana/issues/215)); `7` was covered only by `test_gate_outcome.py::test_an_interrupted_run_is_indeterminate`.

### Outcomes through saved evidence

*"Case outcomes and missing evidence survive serialization, redaction and export."*

- `test_saved_run_round_trip.py`: `test_every_channel_of_a_saved_run_survives_being_written_and_read_back`, `test_no_key_of_a_saved_run_can_be_deleted_without_the_reader_noticing`, `test_the_fixture_occupies_every_channel_a_result_has`.
- `test_saved_run_channels.py`: `test_the_reader_requires_exactly_what_the_published_schema_does` (run schema `18`).
- `test_redaction_every_text_field.py`: `test_an_assessment_rationale_loses_the_secret`.
- `report/test_redaction_seam.py`: `test_a_shortfall_is_never_left_without_a_reason_under_metadata_only`, `test_the_shortfall_channel_goes_through_the_redactor_like_every_other`.
- `report/test_redaction_every_text_field_rendered.py`: `test_no_string_field_carries_a_key_through_a_renderer`.
- `examples/output_pack/tests/test_table.py`: `test_every_field_is_exported_or_excluded_by_name`, `test_a_case_row_says_how_the_case_ended`, `test_every_exported_case_field_changes_the_table`.
- `test_output_load_verification.py`: `test_the_gate_is_read_as_recorded_never_re_derived`.
- `cli/test_suite_accounts_for_every_case.py`: `test_a_suite_stopped_by_the_budget_is_an_error_testcase_in_junit`.

The collector keeps a reduced envelope by design, rather than the whole saved run. The saved run is the evidence.

Published: [What the collector keeps](https://guardana.dev/docs/reading-results#what-the-collector-keeps).

Not guarded by its own test: redacting a result that carries case outcomes and reading it back ([#215](https://github.com/guardana/guardana/issues/215)).

### Built-in rule fixtures

*"Every built-in rule that can decline has finding, clean and inconclusive fixtures."*

- `test_builtin_fixture_coverage.py`: `test_every_built_in_rule_not_exempt_carries_all_three_samples`, `test_every_fully_sampled_rule_actually_classifies_its_own_samples`, `test_every_exemption_names_a_shipped_unsampled_rule_and_a_reason`.

All 58 built-in rules classified their own finding, clean and inconclusive samples. The exemption list was empty.

Published: [Rule summary](https://guardana.dev/docs/generated/rule-summary), [detection limits](https://guardana.dev/docs/generated/detection-limits).

### Provider and adapter conformance

*"Provider and adapter conformance covers system messages, tools, failure paths, budgets, usage and adapter limits."*

- `target/test_provider_conformance.py`: `test_the_system_message_arrives_as_the_table_says` (each provider), `test_offered_tools_reach_the_model_and_its_calls_come_back`, `test_a_refusal_status_fails_without_a_retry`, `test_a_retry_is_refused_by_the_request_ceiling`, `test_token_counts_are_read_when_sent_and_unknown_when_not`, `test_a_token_ceiling_is_refused_where_counts_are_not_carried`, `test_the_providers_page_prints_the_table_this_suite_enforces`.
- `test_conformance_of_built_in_endpoints.py`: `test_every_built_in_provider_conforms`, `test_an_adapter_transport_conforms`.
- `target/test_adapter_declines.py`: `test_the_adapter_reports_metadata_and_never_claims_token_counts`.

Published: [Providers](https://guardana.dev/docs/providers), whose table was the one the suite enforced.

### Collector envelope versions

*"The collector envelope is versioned independently from the run schema; clients and storage migrate together."*

- `server/test_envelope_schema.py`: `test_the_schema_describes_the_version_both_halves_speak`, `test_every_property_the_collector_accepts_is_published_and_nothing_else`.
- `server/test_historical_envelopes.py`: `test_an_envelope_a_release_wrote_is_stored_as_it_was_sent`, `test_an_agent_newer_than_its_collector_is_refused_with_the_versions_it_speaks`.
- `server/test_upgrade_from_previous_release.py`: `test_a_collector_upgraded_from_the_oldest_release_keeps_its_data_and_takes_every_envelope`.

These tests needed PostgreSQL. They ran in the release script, the CI `test` job and the local mirror.

Published: [`schemas/`](https://github.com/guardana/guardana/blob/v1.0.0/schemas/) (collector envelope `8`, run schema `18`), [compatibility matrix](https://guardana.dev/docs/generated/compatibility-matrix).

Not guarded by its own test: the independence of collector envelope `8` and run schema `18`, which holds by construction; no test states it ([#215](https://github.com/guardana/guardana/issues/215)).

### Historical documents and extensions

*"Older persisted documents and extension conformance pass the release gate, with migrations exercised on older run, dataset, profile, pack and collector documents."*

- `test_historical_documents.py`: `test_every_stored_run_loads_migrates_and_yields_its_recorded_verdict`, `test_every_stored_dataset_loads_in_the_format_it_declares`, `test_every_stored_profile_loads`, `test_every_stored_pack_manifest_loads`, `test_every_stored_lock_loads`, `test_every_version_a_reader_accepts_has_a_stored_document_or_a_reason`.
- `server/test_migrations.py`: `test_rows_written_before_a_migration_survive_it`.
- `examples/custom_rule/tests/test_every_rule_is_sampled.py`: `test_every_acme_rule_proves_all_three_outcomes`.
- `test_output_conformance_kit.py`: `test_a_conforming_reporter_passes_with_its_requests_counted`.
- `test_target_protocols.py`: `test_the_conformance_kit_catches_a_target_that_under_declares`.

Current tests read historical documents from `0.2.0` through `1.0.0rc5`. Four versions a reader accepts had no stored document, each named in the test with its reason: collector envelope `6` (no published release wrote it); pack manifest `1` (no release that wrote it could lock a pack; a hand-written manifest of that version is tested separately); pack manifest `3` and pack lock `3` (written only for a pack that declares or pins an output, which no captured pack does). Extension conformance also ran the reference pack's and custom-rule example's own suites and checked a new pack scaffolded from the template in the `example-plugin` job.

### Published supported surface

*"The supported surface, compatibility matrix, deprecation policy and conformance kit are published."*

- `scripts/tests/test_api_surface.py`: `test_the_committed_snapshot_is_what_the_source_says_today`, `test_the_snapshot_holds_every_surface_and_leaves_the_runner_out`.
- `scripts/tests/test_compatibility_matrix.py`: `test_a_candidate_stands_for_its_minor_until_the_final_release_is_recorded`.
- `test_docs_consistency.py`: `test_generated_truth_is_current`.
- `scripts/tests/test_release_script.py`: `test_a_final_whose_surface_moved_since_its_candidate_is_refused_whatever_the_changelog_says`.
- `test_testing_kit_is_documented.py`: `test_every_testing_export_is_named_in_the_extension_guide`.

Before its gate, `scripts/release.py` checked that the final release's supported surface equalled its last candidate's surface, comparing `docs/generated/api-surface.json` against `v1.0.0rc5`. The check passed for `1.0.0`.

Published: [`docs/generated/api-surface.json`](https://github.com/guardana/guardana/blob/v1.0.0/docs/generated/api-surface.json), [compatibility matrix](https://guardana.dev/docs/generated/compatibility-matrix), [versioning and deprecation policy](https://guardana.dev/docs/compatibility), [conformance kit](https://guardana.dev/docs/conformance-kit).

Not guarded by its own test: the deprecation policy text and the conformance-kit table ([#215](https://github.com/guardana/guardana/issues/215)).

## Follow-up

[#215](https://github.com/guardana/guardana/issues/215), in milestone `1.0.1`, adds a test for each item above that no single test guards today, with no production code change.

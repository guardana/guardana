---
paths:
  - "packages/guardana-cli/**"
  - "packages/guardana-report/**"
---
# The CLI and the renderers

Contract: `docs/exit-codes.md`.

- **Exit codes are a contract.** A new outcome gets its own code and a row in
  `docs/exit-codes.md` and the design table; a code is never reused for a different meaning.
- **No false green from any direction**: an unsupported capability, an exhausted budget, a
  redaction failure, missing coverage, a comparison that could not be made — each is its own
  outcome and exit code, never a pass. `diff` says better, worse, unchanged or incomparable.
- **Every output stays behind the common redaction boundary.** A renderer never learns a
  threat and never re-derives a verdict; it renders the `Finding`s it is given.
- **The layer contract**: CLI over packages over core. A renderer importing a rule, or a rule
  reaching for a CLI helper, breaks `uv run lint-imports`.
- **A target is selected by locator** (`--target scheme://locator`); malformed, unknown,
  reserved or mismatched schemes are refused before a rule runs, and the command owns the kind.
- **Plugin trust**: discovery always runs; `--plugins disabled` refuses and records every
  refusal (`SECURITY.md`). `import-observations` runs with plugins disabled and no flag.
  An installed format or reporter is never discovered: it is selected by `--format` or
  `--reporter`, refused with exit `3` before anything is sent, and a failure of its code is
  exit `8`, never `5`; a failure of Guardana's own redaction before it is `5`
  (`BoundaryError`, `core/output.py`, `cli/_outputs.py`).
- **A file beside `--output` is removed only when it is an earlier run's**: the saved run there
  records its digest, read before that run is replaced and checked again before the removal
  or overwrite (`exchanges_recorded_by` in `core/verify.py`); a sidecar nobody recorded is kept,
  whatever its name. Inputs go to `refuse_writing_over_an_input` before anything is read, and
  a failed write removes nothing (`cli/_sidecar.py`, `cli/_outputs.py`, `Verification.save`).
- **Styled output is normalised in tests** — assert on the normalised text, never on escape
  sequences or column widths that differ between a laptop and a CI runner.
- A new command or flag: `docs/usage-<command>.md`, `docs/index.md`, `FEATURES.md`,
  `CHANGELOG.md`, and `scripts/clean_install_check.py` runs the documented invocation in an empty
  environment — the only gate that sees an undeclared import.
- **A `.tmpl` under `cli/pack_templates/` is code nothing lints.** Ruff and mypy do not look
  inside it and the unit tests only read the tree it produces, so a template edit is proven
  only by `scripts/new_pack_check.py`, which installs the generated pack and runs its suite.
  Run it after touching one.
- `probe`, `monitor`, `target inspect` and `calibrate` contact whatever endpoint the user names;
  `plan probe` never does. A budget bounds requests before the first one is sent, and sending
  more than `--max-requests` is a defect that has shipped once.
- **What makes a run not clean is decided once**, by `core.gate.open_questions` and the
  recorded gate (`report/_refusal.py`). A renderer, `plan` or a new output reads those; a
  condition list written in a renderer drifts from the gate. Pass `gate=` when there is no
  manifest (`monitor`).

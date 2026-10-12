---
title: "guardana case"
nav_order: 89
summary: "`guardana case add|list`: promote one reviewed failure from a recording into a regression case of a suite, proven on both sides before it is written"
status: beta
---

# `guardana case` — turn a reviewed failure into a regression case

A recipe run that failed, or stopped, keeps its exchanges when the profile and the recipe ask
for them (`run.exchanges.jsonl` in the artifact). `guardana case add` turns one of those
exchanges into a case of a quality suite's dataset, labelled, versioned and proven on both
sides. Once the case is in the dataset, `guardana rule test` and every `guardana recipe`
command regrade it, and CI runs it against your application.

```bash
guardana case list guardana-artifact/run.exchanges.jsonl
guardana case add rules/support.yaml --from guardana-artifact/run.exchanges.jsonl \
  --line 4 --expect '{"contains_any": ["reset link"]}' \
  --accepted-file accepted.txt --version 2026.10 --label "no reset link"
guardana case add ... --write        # the same command, now writing the dataset
```

Nothing is written without `--write`. The person who runs it with `--write` promotes the
case; Guardana never promotes one by itself.

## `case list`

`guardana case list RECORDING` prints every kept exchange: its line, its rule, its key and
whether its reply is altered (redacted, marked `altered`, or from a recording that is not
verbatim), or `declined` for a request the application declined. The input and the reply,
shortened and with control characters escaped, are printed only to a terminal or with
`--show`; a declined line's reply is shown as `[declined: <name> (HTTP <status>)]`.

## `case add`

`RULE` is the YAML file of one suite — a rule with `dataset:` — in your own source tree. The
case is appended to that suite's dataset:

| Part of the case | Where it comes from |
|---|---|
| `input` | The kept exchange's input, or `--input-file` (tagged `input:rewritten`). |
| `observed` | The kept exchange's reply: the failure. An altered reply needs `--observed-file`, a stand-in you write that reproduces the failure without the removed data (tagged `observed:synthetic`). |
| `accepted` | `--accepted-file`: a correct reply you write. |
| `expect` | `--expect`: what a correct reply must satisfy, a JSON object of the suite evaluator's fields, overlaid on the suite's own `expect:` as a hand-written case's is. |
| `tags` | `regression`, `label:<text>` with `--label`, and `origin:<run id>` when the recording names the run it was kept from. |

The dataset's header gets `--version`, which must differ from its current version. Every
other line is kept byte for byte, and a format-1 dataset is rewritten as format 2.

**How the file is written.** With `--write`, `case add` creates a lock file beside the
dataset (`.<dataset>.lock`), reads the suite and the dataset again, and refuses, writing
nothing, when either differs from the text the case was proven against. It then writes the
new dataset to a temporary file in the same directory and renames it over the dataset, so a
reader sees the old file or the new one, never part of either, and removes the lock file
whatever happened. A second `case add` that finds the lock file refuses (exit `3`) rather
than wait, so two promotions into one dataset never both write over the same version. The
lock excludes only other `case add` runs: an editor that saves the dataset between that
last read and the rename is not detected. A lock file left by a process that was killed is
not removed for you; delete it once no `case add` is running.

A file you write for `--input-file`, `--observed-file` or `--accepted-file` is read as UTF-8
text; one line ending at its end is dropped, and an empty file, or one holding a redaction
placeholder, is refused.

### The proof

Before anything is written, the suite's evaluator grades `observed` and `accepted` against
the case's effective expectation. **The case holds only when `observed` grades `fail` and
`accepted` grades `pass`**: an expectation that does not tell the two apart gates nothing.
Only an evaluator that declares itself deterministic and declares that a verdict asks no
judge can prove a case without sending anything, such as `contains`, `regex`, `exact_match`,
`json_valid` or `length`. A judge, or an
evaluator that declares neither, is refused, never skipped. The proof uses the built-in
plugin trust, so an evaluator from an installed pack is not available to it.

A synthetic `observed` proves the expectation against your reconstruction, not against what
the application said; its tag says so. The proof shows that the expectation separates two
replies. It does not show that the input reproduces the failure against the build CI runs: a
case from another subject, or with a rewritten input, passes from its first run if it never
reproduced. Run the recipe once against the unfixed build to see the case fail.

### What is printed

Off a terminal, the output names the suite, the dataset and its versions, the recording line
and key, and the length and digest of the input, `observed` and `accepted`, the names of the
`expect` fields, the tags and what each side of the proof graded. The text of the case, and
the evaluator's reasons, which may quote a reply, are printed only to a terminal or with
`--show`, so a dry run scripted in CI does not copy into its log what a redactor missed.

### What is refused

| Situation | Exit |
|---|---|
| the case was written, or shown without `--write` | `0` |
| a side graded the wrong way: `observed` passed or `accepted` failed | `1`, nothing written |
| no side graded the wrong way and a side declined | `2`, nothing written |
| an evaluator raised on a side | `3`, nothing written |
| `--key` and `--line` both or neither; a key on several lines (pick one with `--line`); a line with no key, which only `--line` names; a line or key the recording does not hold | `3` |
| an input that was altered — it holds a redaction placeholder, it no longer matches the key taken before redaction, or the line has no key and the recording is not verbatim — without `--input-file` | `3` |
| an altered reply without `--observed-file` | `3` |
| a line the application declined: it holds no reply to pair with a correct one, whatever `--observed-file` says | `3` |
| a file for `--input-file`, `--observed-file` or `--accepted-file` that holds a redaction placeholder | `3` |
| with `--write`: the dataset's lock file exists, or the suite or the dataset changed while the case was being proven | `3`, nothing written |
| a `RULE` that is not one YAML suite, that does not load, that lies in an installed distribution, or whose dataset or its directory is not writable | `3` |
| an evaluator that cannot prove the case without sending | `3` |
| `--expect` that is not a JSON object, or a field the evaluator does not read | `3` |
| `--version` equal to the current one; a case line over the dataset's line limit; a case the dataset already holds; a suite that would not load with the case | `3` |
| a recording that cannot be read | `3` |

## The suite stays a regression gate

A dataset that holds any `observed`/`accepted` pair refuses, whenever the suite is loaded, a
suite that declares `sample:` or whose `gate.min_pass_rate` is below 1: a regression case that
may not run, or that other cases can outvote, prevents nothing. Set `gate.min_sample` to at
most the number of cases, since its default of 30 refuses a small suite at load. The
`regression` tag is a label: a case that carries it without a pair changes no gate. See
[quality suites](usage-suites.md).

## Regrading

A live run sends the case's input and grades the target's reply. It never sends `observed` or
`accepted` or grades either as the target's reply. It only regrades the pair offline as the
list below describes. Neither is part of the case's identity.

- `guardana rule test` regrades every pair of every selected suite with the rule as it is now,
  sending nothing, and names each case whose pair no longer holds: exit `1` when a side graded
  the wrong way, `2` when a side declined or the evaluator raised, and `3` when the suite's
  evaluator cannot regrade without sending ([testing rules](usage-rule-test.md)).
- `guardana recipe lock`, `recipe lock --check` and `recipe run` regrade the pairs of every
  selected suite before they compare anything. Any of those four states is a refusal there,
  with one code: `lock` writes nothing and exits `1`, `lock --check` exits `1`, and `run`
  sends nothing and exits `3` ([recipes](usage-recipe.md)).
- `guardana probe`, `grade`, `monitor` and `plan`, and a `Verifier` run from Python, regrade
  the pairs of every suite they select before the first rule, sending nothing. A pair that no
  longer holds, or cannot be regraded without sending, is an error for that suite (stage
  `regression`), so the run cannot pass while `fail_on_error` is on (exit `2`).

The suite's digest covers its dataset, so after `case add --write` the recipe's lock no
longer holds: `recipe run` sends nothing until you run `guardana recipe lock` and commit the
dataset and the lock together. In CI the suite then runs every case against your application
and fails on any one.

The format of a dataset is [`dataset-v2.schema.json`](https://guardana.dev/schemas/dataset/v2.schema.json);
format 1 ([`dataset-v1.schema.json`](https://guardana.dev/schemas/dataset/v1.schema.json)) is still read.

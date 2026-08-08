# `guardana taxonomy` — which framework entry a rule actually means

Every Guardana rule maps to a public framework, because a finding nobody can look
up is a finding nobody can answer for. This command shows what those mappings can
name: which catalogues are installed, what each entry is called, and what an entry
recorded years ago corresponds to today.

## Why an edition is part of a reference

OWASP published the 2026 edition of the LLM Top 10 on 3 August 2026, and it did not
renumber into empty space:

| Short id | 2025 edition | 2026 edition |
|---|---|---|
| `LLM05` | Improper Output Handling | Data and Model Poisoning |
| `LLM06` | Excessive Agency | Unbounded Consumption |
| `LLM07` | System Prompt Leakage | Misinformation |
| `LLM08` | Vector and Embedding Weaknesses | Hidden Context Exposure |
| `LLM09` | Misinformation | Vector and Embedding Weaknesses |
| `LLM10` | Unbounded Consumption | Improper Output Handling |

So a reference names its edition. In a rule that is `LLM07:2025`, and a bare `LLM07`
is a **load-time error** listing the editions that define it — never a guess,
because guessing would silently decide what your rule claims to an auditor:

```
$ guardana taxonomy LLM01
error: taxonomy id 'LLM01' does not say which edition it means; write one of: LLM01:2025, LLM01:2026
```

A framework that publishes no editions keeps its bare ids. `AML.T0051` and
`supply-chain` are written exactly as before, and so is a reference your own
catalogue registers.

## List what is installed

```bash
guardana taxonomy
```

```
OWASP-LLM-2026 — OWASP Top 10 for Large Language Model Applications
  10 entries · digest sha256:7a30d74e1feb0…
  https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
    LLM01:2026       Prompt Injection
    LLM02:2026       Sensitive Information Disclosure
    …
```

The digest is the one every run pins in its manifest (`run.coverage.taxonomies`).
That is what makes a report readable in three years: it says which edition was
installed, and exactly which revision of it, without anybody having to remember.

## Explain one reference

```bash
guardana taxonomy LLM07:2025
```

```
LLM07:2025  System Prompt Leakage
  framework: OWASP-LLM-2025
  rank:      7
  corresponds to:
    LLM08:2026 Hidden Context Exposure (broader) — renamed and widened past the
    system prompt to tool schemas, retrieved content and credentials embedded in context
```

Note what it does *not* say. `LLM07:2025` does not correspond to `LLM07:2026`, which
is Misinformation. The crosswalk is data with an explicit relation on every pair —
`exact`, `broader`, `narrower` or `related` — because the 2026 edition redrew its
categories as well as re-ranking them, so most pairs are not equivalences.

`--format json` prints the same thing for a script, with `scheme`, `edition` and
`framework` as separate fields.

## What this never does

**It never rewrites stored evidence.** A saved run, a baseline and a collector row
keep the reference they were written with, forever: a `LLM07` recorded under
`OWASP-LLM-2025` is read as System Prompt Leakage by every later build, whatever
that short id means in an edition installed today. A correspondence is computed in
memory when you ask for one, and that is the only place it exists.

**It never remaps a rule.** Where the semantics genuinely overlap a rule carries
both editions — the canary system-prompt check is `LLM07:2025` *and* `LLM08:2026` —
and `guardana rules` prints both.

## Registering your own framework

A company mapping rules to its own control catalogue registers references through
the `guardana.taxonomies` entry point and then writes `taxonomy: [ACME-14]` in YAML
like any built-in. Registration happens through an installed package rather than a
string in a rule file, which is what keeps an unknown reference a load-time error
instead of a rule that maps to nothing. See
[`extending.md`](extending.md) and
[`design/taxonomy-editions.md`](design/taxonomy-editions.md).

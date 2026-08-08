# Taxonomy editions: a short id is not an identity

**Status:** accepted, implemented — ships in the next release · **Written:** 2026-08-08

## The problem, stated precisely

Every Guardana rule maps to a public framework, because a finding nobody can look
up is a finding nobody can answer for. Until now a mapping was stored as a short
id plus a framework name — `LLM07`, `OWASP-LLM-2025` — and the registry that
resolves those ids was keyed on **the short id alone**, with redefinition refused:

```python
_registry: dict[str, TaxonomyRef] = {ref.id: ref for ref in ...}
```

That was correct while one edition of each framework existed. It stopped being
correct on **3 August 2026**, when OWASP published the 2026 edition of the LLM Top
10. The new edition did not renumber into empty space:

| Short id | 2025 edition | 2026 edition |
|---|---|---|
| `LLM05` | Improper Output Handling | Data and Model Poisoning |
| `LLM06` | Excessive Agency | Unbounded Consumption |
| `LLM07` | System Prompt Leakage | Misinformation |
| `LLM08` | Vector and Embedding Weaknesses | Hidden Context Exposure |
| `LLM09` | Misinformation | Vector and Embedding Weaknesses |
| `LLM10` | Unbounded Consumption | Improper Output Handling |

Nothing Guardana has published is a lie: the `framework` field on every reference
says `OWASP-LLM-2025`, and a reader who looks at it gets the right answer. But the
short id is what a report renders, what a dashboard chip shows, and what a person
types into a search box — and `LLM07` now means Misinformation to an auditor and
System Prompt Leakage to this build. That gap widens with every run somebody
saves, which is why this is a defect with a clock on it rather than a backlog item.

## The decision

**Identity is scheme + edition + local id.** `OWASP-LLM/2025/LLM07` and
`OWASP-LLM/2026/LLM07` are two different controls that happen to share a string.
Titles and ranks are display data hanging off that identity; they are never part
of it.

Seven consequences, each of which is a section below.

1. `TaxonomyRef` splits `framework` into `scheme` + `edition`, and keeps
   `framework` as the composed string the wire already carries.
2. Catalogs become immutable data files with a digest, and the digest is pinned
   in the run manifest.
3. A reference in a rule names its edition: `LLM07:2025`. A bare local id is the
   canonical reference only of an entry whose scheme publishes no editions.
4. A rule carries both editions where the semantics overlap, and never a silent
   remap.
5. The crosswalk is data with explicit relations, held by the *newer* catalog.
6. Saved runs, baselines and collector rows are never rewritten, and the recorded
   title travels with the reference.
7. Every run carries a coverage fingerprint, so `diff` can say *coverage changed*
   instead of folding it into *security changed*.

## 1. `TaxonomyRef` — scheme, edition, local id

```python
@dataclass(frozen=True, slots=True)
class TaxonomyRef:
    scheme: str            # "OWASP-LLM"
    id: str                # "LLM07"
    title: str             # "System Prompt Leakage"  — display data
    edition: str | None = None   # "2025"
    rank: int | None = None      # display data: where it sits in its edition
```

`framework` survives as a **property**, composed as `f"{scheme}-{edition}"` when
there is an edition and `scheme` when there is not. Every framework string in
every document Guardana has ever written is reproduced exactly:
`OWASP-LLM-2025`, `OWASP-ASI-2026`, `MITRE-ATLAS`, `NIST-AI-100-2`. That is the
whole reason for keeping it: the wire format and the collector's stored rows are a
contract, and this change must not touch a single stored byte's meaning.

The first field keeps position 1, so a third party's
`TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")` still
constructs, still has `framework == "ACME-CONTROLS-1"`, and still needs no
edition. **An absent edition is a statement, not a default:** it says this scheme
publishes one catalogue whose local ids do not change meaning between revisions.

### Why MITRE ATLAS and NIST get no edition

ATLAS technique ids are stable across ATLAS releases — `AML.T0051` has meant LLM
Prompt Injection since it was minted — so the version of ATLAS a catalogue was
transcribed from is *provenance*, not identity. It is recorded as a catalogue-level
`version` field, which lands in the digest, and it does not enter the framework
string. Giving ATLAS an edition would rewrite `MITRE-ATLAS` to
`MITRE-ATLAS-5.6.0` in every future document for no gain in truth, and would split
one control into two for every reader comparing an old run against a new one.

If ATLAS ever *does* renumber, its catalogue gains an `edition` and the bare ids
stop resolving — loudly, at load time, which is the failure direction this whole
document argues for.

### Rejected: a `TaxonomyRef` that parses its own framework string

`"OWASP-LLM-2025".rsplit("-", 1)` would have produced scheme and edition without a
schema change. Rejected on product principle 1: that heuristic *is* knowledge of
how OWASP names things, living in the engine, and it gets `NIST-AI-100-2` wrong on
the first try. The split belongs in the data file, where a curator writes it down.

## 2. Catalogs are immutable data files with a digest

The refs move out of Python and into
`packages/guardana-core/src/guardana/core/taxonomy/catalog/*.yaml`, one file per
scheme-and-edition:

```yaml
scheme: OWASP-LLM
edition: "2026"
title: OWASP Top 10 for LLM Applications
source: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
published: "2026-08-03"
entries:
  - id: LLM08
    rank: 8
    title: Hidden Context Exposure
    supersedes:
      - ref: LLM07:2025
        relation: broader
        note: renamed and widened past the system prompt to tool schemas and retrieved content
```

The Python constants stay — they are the public API twenty rules and
`examples/custom_rule` are written against — but they become lookups into the
loaded catalogue rather than literals. A missing or malformed catalogue file is a
loud `TaxonomyError` at import, not an empty registry: an engine that starts with
no taxonomy would fail *every* rule's mapping, and it must say so in one sentence
rather than twenty.

**Immutable** is the operative word. A catalogue file is never edited once
published, because its digest is pinned in saved runs; a correction is a new
edition. This is also why the crosswalk lives in the newer file (§5): a 2025
catalogue cannot describe its relationship to an edition that did not exist when
it was written without being rewritten.

`digest` is taken over the catalogue's *parsed content*, canonically dumped —
never over the file's bytes. Reformatting a file or adding a comment is not a
changed catalogue, while a reworded entry is; hashing bytes would also make the
digest depend on which line endings a checkout happened to produce. It is recorded
per catalogue in the run manifest's coverage block, so a report read in three years
says which editions were installed and exactly which revision of each, without
asking anybody to remember.

### Rejected: shipping the catalogues in `guardana-rules`

It is where a purist would put framework data, and it is wrong here for a
mechanical reason: `guardana.core.taxonomy` resolves a rule's `taxonomy:` while
the rule is being parsed, and `guardana-core` must not import `guardana-rules`.
Moving the data there would make every mapping depend on discovery order. Data
files inside core satisfy the principle that matters — the engine holds no
framework *logic*; a curator edits YAML, not Python.

## 3. Naming a reference: `LLM07:2025`

`resolve()` looks up the **canonical reference**, which is `LOCAL_ID:EDITION` for an
entry whose scheme publishes editions and a bare `LOCAL_ID` for one whose scheme
does not. So `LLM07:2025` and `ASI06:2026` resolve, and so do `AML.T0051`,
`supply-chain` and a third party's `ACME-14`.

A bare id that is only held by editions raises `TaxonomyError`, and
`_parse_taxonomy` turns that into a `RuleLoadError` naming every candidate. So
`taxonomy: [LLM01]` is now a load-time failure that says:

> taxonomy id 'LLM01' does not say which edition it means; write one of:
> `LLM01:2025`, `LLM01:2026`

Note what this is *not*: "resolves while exactly one edition happens to be
installed". That reading would make a rule file load on one machine and fail on
another, and would silently change a rule's meaning the day a second catalogue
arrives. Whether a bare id is legal depends on the scheme, not on the install.

This is a **breaking change for third-party YAML rule packs** that name OWASP LLM
ids, and it is deliberately breaking rather than defaulted. Any default — newest
edition, oldest edition, a configured one — silently changes what a rule claims to
an auditor when a catalogue is added, which is precisely the failure this document
exists to end. A load error costs a pack author one line per reference and cannot
be misread. The typo gate is untouched: an id nobody registered is still a load
error, with the same message it had before.

`register()` keeps refusing a redefinition, on a slightly narrower rule than
before: **a local id may be shared across editions of one scheme, never across
schemes.** A pack registering `LLM01` under `ACME-CONTROLS-1` is still refused —
otherwise an installed package could quietly change what `LLM01` means in a report
— and the refusal message is unchanged.

## 4. A rule carries both editions

Where the semantics genuinely overlap, a rule names both:

```yaml
taxonomy: [LLM07:2025, LLM08:2026, AML.T0056]
```

```python
taxonomy=(OWASP_LLM03_2025, OWASP_LLM04_2026, NIST_SUPPLY_CHAIN)
```

The Python constants gain an edition suffix for every scheme that has editions,
which is the point: `OWASP_LLM03_2025` could not tell a reader which edition it meant,
and after August 2026 that ambiguity is the bug. `ATLAS_T0051` and
`NIST_POISONING` keep their names, because their schemes have no edition to state.

What must never happen is a **silent remap**: rewriting `LLM07:2025` to
`LLM07:2026` would move a system-prompt-leak finding into Misinformation. Only the
crosswalk decides which 2026 control a 2025 one corresponds to, and it says
`LLM07:2025 → LLM08:2026`.

## 5. The crosswalk is data with relations

Not a global alias table. Most of these pairs are not equivalences, because the
categories changed meaning as well as position. Four relations, each read as *this
entry, relative to the one it names*:

| Relation | Meaning | Example |
|---|---|---|
| `exact` | same control, the rank moved | `LLM09:2025 Misinformation` → `LLM07:2026` |
| `broader` | this one covers more | `LLM07:2025 System Prompt Leakage` → `LLM08:2026 Hidden Context Exposure` |
| `narrower` | this one covers less | (none in this crosswalk; the inverse of `broader`) |
| `related` | they overlap, neither contains the other | `LLM10:2025 Unbounded Consumption` → `LLM06:2026`, reframed as cost asymmetry |

The inverse direction is derived (`broader` ⇄ `narrower`, `exact` and `related`
symmetric), so one statement is written once and read from both sides.

A crosswalk is **never applied to stored data**. It answers a question a reader
asks — "what does this 2025 reference correspond to today" — in memory, at the
moment of asking.

## 6. Saved runs are never rewritten, and the title travels

A saved run records `{"framework": "...", "id": "..."}` per reference. Two changes:

- **The recorded title travels with the reference.** Without it, a run produced
  with somebody's rule pack installed and read on a machine without it renders a
  bare `ACME-14`, and an offline evidence pack is unintelligible. This is a
  document schema change: saved-run schema **v2 → v3**, `SCHEMA_URL` moves to
  `run/v3.schema.json`, and `migrate_v2` fills the title from the registry where
  the `(framework, id)` pair is known and leaves it empty where it is not —
  inventing nothing, exactly as `migrate_v1` invents no usage and no verdict.
- **A recorded reference is read as the edition it names.** `load.py` already
  takes a registry ref only when the recorded `framework` matches, and keeps the
  document's own framework otherwise. That behaviour is kept and tested: a 2025
  reference in a 0.12 run stays a 2025 reference in this build, forever.

The collector envelope moves **v7 → v8** for the same field, optional, and
`SUPPORTED_SCHEMA_VERSIONS` grows to `{2..8}`. An older agent simply sends no
title, which is honest — it could not observe one. No database migration is
needed: the taxonomy column is JSON.

`finding_identity` in `guardana.core.diff` is `(rule_id, location)` and taxonomy
does not enter it. That is load-bearing and gets a test of its own: remapping must
not invalidate a baseline waiver or a triage decision in the collector.

## 7. A coverage fingerprint on every run

`Rule.digest()` covers `meta`, and `meta` includes the taxonomy — so every rule
digest changes in this release, correctly, and `diff` would emit *"19 rule(s)
changed definition … a different result there may be the sharper test rather than
a worse system"* on every 0.12→0.13 comparison. True but useless: nothing about
what those rules *do* changed.

So `RuleRecord` gains a second digest over everything except the mapping, and
`diff` distinguishes the two cases:

- behaviour digest equal, full digest different → *"N rule(s) changed only their
  framework mapping"*
- behaviour digest different → the existing *"changed definition"* note

And the manifest gains a `coverage` block: catalogue digests, negotiated protocol
versions (a new optional `Target.protocols()` hook — the MCP client negotiates
`2025-06-18` today and discards the server's answer), the declared trial count per
rule, and one digest over all of it plus the rule/evaluator digests and the
target's capabilities. `diff` reports a differing coverage fingerprint as its own
statement, because a run with fewer applicable checks must never read as an
improvement.

## What this does not do

- **No `if edition == "2026"` anywhere in the engine.** The edition is a string in
  a data file. If a future change needs the engine to know one edition from
  another, that change is wrong.
- **No re-ranking of severities.** A rule's severity is Guardana's judgement about
  the finding, not OWASP's about the category. The 2026 ranks are recorded as
  display data and gate nothing.
- **No new coverage claimed from a remap.** Mapping a supply-chain rule to
  `LLM04:2026` does not make it cover more; `ROADMAP.md`'s coverage table already
  reads in 2026 categories and says where the gaps are.
- **`finish_reason` and latency on `Exchange` stay deferred.** The 2026 edition's
  cost-asymmetry framing is measurable without them — a short prompt against a
  large reply is a ratio anybody can compute from the exchange — and carrying a
  provider's finish reason honestly means adding it to the transport protocol that
  third-party transports implement. That is a contract change worth doing on its
  own, not as a passenger on a taxonomy release.

## Related

- [`run-manifest-v2.md`](run-manifest-v2.md) — the document this extends to v3.
- [`../writing-rules.md`](../writing-rules.md) — where a rule author reads the
  reference syntax.
- `ROADMAP.md`, *Step one — the mapping is true again*.

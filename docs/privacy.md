---
title: "Evidence and redaction"
nav_order: 310
summary: "evidence redaction, modes, and what Guardana keeps"
status: stable
---

# Evidence, redaction and what Guardana keeps

Guardana's evidence is by construction the most sensitive text in a deployment:
the prompt that worked, the reply that leaked, the tool argument that carried a
key. Since 0.7 that text passes through **one redactor at one seam**, and every
way a finding leaves the process goes through it.

## Defaults

Every command defaults to `redacted`; artifact scans send nothing, and Guardana sends no
telemetry and needs no account. Probes contact the named target and send graded exchanges
to judges or guards under `evaluators:`; when an MCP target requires authorization, they
also read its advertised protected-resource metadata and the metadata of the authorization
server it names, possibly on other hosts. Guardana itself contacts nothing else; a package admitted with `--plugins` runs with your privileges and can open its own connections ([threat model, T3](threat-model.md#t3--a-malicious-plugin-or-rule-pack)). The collector, or a reporter
an installed package adds, receives results only when `--reporter` names it, and a reporter never
receives kept exchanges ([installed outputs](outputs.md#what-an-output-receives)). The collector also [redacts](usage-collector.md#what-the-collector-refuses-and-redacts-on-ingest) recognisable secrets in a submission's evidence text using the engine's patterns before storing it, so those secrets do not enter the database even when a third-party sender or an older agent does not redact them.

```yaml
privacy:
  evidence_mode: redacted     # metadata_only | redacted | full
  redact_secrets: true        # the only value; `false` is refused, see below
  redact_emails: true
  redact_ip_addresses: false  # an IP address is frequently the finding itself
  hash_identifiers: true
  custom_patterns: []
  max_evidence_bytes: 16384
  keep_exchanges: false       # true: probe keeps every chat exchange beside the run
```

| Mode | What is kept |
|---|---|
| `metadata_only` | which rule fired, where, what verdict. No text from the target. |
| `redacted` *(default)* | evidence with secrets, credentials and configured patterns removed, bounded in size. |
| `full` | the model's words — **still without credentials**. |

**`full` does not mean "store a live key".** Secrets are removed at every mode,
including this one. There is no useful reading of "keep the credential": the
finding is that a secret appeared, not what it was.

`redact_secrets: false` is **refused at load time**, with a message saying why.
Until 0.7.1 the switch existed and took effect only at `full` — so its single
reachable outcome was writing a working credential into a report, while this page
said the opposite. The key is still accepted so that a profile stating the default
keeps working, and so that anyone who set it gets told rather than ignored.

## Every channel, not just the findings

The policy covers every channel of a result: `findings`, `unverified`, `waived`,
`assessments`, `observations`, `coverage_shortfall`, `suites` — and **`errors`**,
where a check that could not run records why. That last one carries an exception message, and an exception message is
written by whoever raised it: a third-party rule, a provider, a parser handed the
model's own reply. An unparseable response puts 120 bytes of it in there, and a
gateway refusing a request routinely quotes the credential it refused.

Until 0.12.0 the reason was bounded in *length* and never passed through the
policy, so it reached the JSON report, the SARIF file and the collector envelope
untouched. Under `metadata_only` the reason is replaced by a note rather than
emptied, because an error with a blank reason reads as a check that failed for no
reason instead of one whose reason this run declined to keep.

The same holds for every string inside a result, not only evidence: a finding's
title, its location and its verdict's rationale, every assessment, every
observation's name, ref and attributes, coverage shortfalls and suite summaries. A
judge's reply becomes a rationale, and an imported claim supplies a title and a
ref, so each is the same untrusted text the evidence is. The redactor walks the
result's fields rather than a list of them, so a field added later is covered
without anyone naming it. Two kinds of string are treated differently:

- **Narrative text** — evidence, an error's reason, a shortfall's detail, a
  rationale — gets the whole policy: bounded in size, and under `metadata_only`
  replaced by a note. An evidence summary's note carries a 12-character digest of
  the summary as `redacted` would show it, because a baseline waiver matches on the
  summary; without it, waiving one finding waived every finding of that rule in that
  file.
- **Names and locations** — a title, a `target_ref`, an observation's ref — lose
  only the matched spans and are never emptied or truncated, so a reader can still
  find the file: `configs/[redacted:openai-key:…]/settings.py:12`.

An error message about a `--target` locator prints it without userinfo, without a
fragment and with its query replaced by a placeholder, whatever the scheme.

A run also withholds the values its target sends to authenticate, which no pattern may
recognise: the API key, an adapter's values read from `${VAR}`, the value of each
adapter header named for a credential (`Authorization`, `Proxy-Authorization`, `Cookie`,
`*-Key`, `*-Token`, `*-Secret`, `*ApiKey`, compared case-insensitively with `_` read as `-`) with the token after a scheme word such as `Bearer`, the
MCP bearer token from `--mcp-token-env`, what an installed target declares with [`sent_secrets()`](extending.md#adding-a-target), and
what the command resolved or the Python API's `secrets` name. Each value of four
characters or more is shown as `[redacted:credential]` in findings, rationales, every
other text the redactor walks, recorded failures and kept exchanges, in every evidence
mode and before the policy's own patterns run. A literal header such as `Content-Type: application/json` is not withheld.

When an endpoint answers with an error status, the message quotes the start of its
body under the run's own policy, with those values withheld. Under `metadata_only` it
gives the status and the body's size only, and so does a target whose declaration of
what it sends fails. A reply Guardana cannot use, an unreachable endpoint and a judge's
failure are quoted the same way; under `metadata_only` the message names the failure and
gives its size only.

## Redaction is never silent

A finding whose evidence was changed says so, in the text a reader sees:

```text
▲ [HIGH] guardana.supply_chain.hardcoded_secret
    AWS key in config.py: [redacted:aws-key:3f9a1c2b7e04]
```

Truncation announces itself the same way. A report that quietly dropped the half
of the evidence that mattered would look complete and would not be — the same
dishonesty the `unverified` channel exists to prevent.

## Why placeholders are hashed

`hash_identifiers` replaces a redacted value with a short digest of that value, so
two occurrences of the same secret stay comparable across runs without the value
being stored. That matters more than it looks: a finding's **fingerprint** is
computed from its evidence summary, and a baseline waiver matches on that
fingerprint. A placeholder that changed between runs would silently expire every
waiver you had.

**A digest can confirm a guess.** Placeholder digests and `case_id` are unsalted SHA-256 truncated to 12 hex characters (48 bits). They stay the same across runs and machines so waivers and diff pairing work. Anyone holding a report can check a guess at a low-entropy redacted value, such as an email address or short identifier, or at a private dataset prompt. `hash_identifiers: false` writes a bare label instead of a digest.

The **label** is the other half, and it is what tells you which key to rotate:

```text
[redacted:github-token:1a2b3c4d5e6f]
```

Patterns are ordered most specific first so that a GitHub token is labelled as
one. Until 0.7.1 they were applied one at a time, each reading the previous one's
output, so the generic "token = value" pattern matched the *label* of the
placeholder that had just replaced the secret and produced
`[redacted:github-[redacted:credential-assignment:…]]`. Matches are now collected
against the original text and spliced in once.

**A placeholder is recognised narrowly, and that narrowness is load-bearing.** A
second pass skips spans this redactor already wrote — that is what makes redacting
twice idempotent — and the redactor's input is the model's reply, which is
attacker-influenced by definition. Recognising `[redacted:` *anything* `]` would
mean that anything able to make a model emit `[redacted:` around a credential
carried it through untouched: the output format turned into a smuggling envelope.
Only a lower-case label with an optional twelve-hex digest is skipped, and nothing
that fits that shape is a secret, an address or an IP.

## One seam, and why that is the whole design

```
rules → findings → [EvidenceRedactor] → renderers / reporter / baseline
```

The redactor is applied by the renderer *factory*, not by each renderer. A format
added next year is covered without its author knowing this document exists, and
there is no way to obtain a renderer that skips it. A policy applied in thirty
places has thirty exceptions, and the one that matters is the one somebody forgot.

`scan`, `probe` and `monitor` also redact once, early — before a baseline is
written or matched — because a fingerprint is computed from the evidence summary.
Redaction is idempotent: a placeholder claims its own span before any pattern is
offered the text, so a second pass cannot read the first pass's label as content.

**`monitor` was the exception until 0.7.1**, and it was the worst one to have: it
printed through a renderer built with no policy — so the library default, `full` —
and forwarded alerts to the collector without redacting at all. It is the mode
that runs unattended and ships evidence off the machine continuously. It now
builds its handler from the profile, and two tests assert both exits separately,
because only one of them is visible to whoever is watching the terminal.

A test enumerates every registered renderer from the registry and asserts that a
crafted, obviously-fake credential cannot pass through any of them, plus the
collector envelope and a baseline file. Per path, not once: asserted centrally, it
would pass while one path quietly bypassed the seam — which is exactly what
happened, one layer above the renderers, where nothing was enumerating anything.

## The manifest records what was applied

```json
"privacy": {
  "evidence_mode": "redacted",
  "redaction_policy_digest": "sha256:…"
}
```

So a reader knows what was applied to the evidence in front of them, rather than
assuming the defaults of whichever build they happen to run.

## What a run declares about itself is not evidence, and is not redacted

Since 0.9 a run may say **what it verified and where**: the AI system, the
environment, a deployment identifier, and the commit, image, model name and model
digests behind it. All of it travels to a collector as declared, and none of it
passes through the redactor.

That is deliberate, and stating it is the point. Redaction exists for **evidence** —
model output, retrieved documents, prompts — which is attacker-influenced text and
the most sensitive thing Guardana handles. These eight fields are the opposite: an
operator typed them or a pipeline stated them, and redacting a commit or an
environment name would destroy exactly the identity that makes a collector's
history answerable while protecting nothing.

If any of those names is itself sensitive in your organisation, do not pass it.
Every field is optional and absent means "not known" — a run that declares nothing
still reports its findings.

## Kept exchanges

`keep_exchanges: true`, or `probe --keep-exchanges`, writes every chat exchange of a
probe's plain pass beside the saved run (`run.json` → `run.exchanges.jsonl`), so
[`guardana grade`](usage-grade.md) can grade the same replies again. It is off by default
because that file holds every reply, passes included, and widens what a leaked run
exposes; whether to keep them is the operator's decision for their data.

- Every input and reply passes this policy's redactor before it is written: matched
  spans are replaced, with no size bound, because a truncated reply would be graded
  wrongly later. Secrets are removed at every mode, `full` included, and so is every
  value the target sends to authenticate, from replies and metadata alike; a metadata
  value that held one is left out.
- A reply the redactor changed is marked `altered`, and `grade` never grades it: a reply
  that leaked a secret cannot be regraded into a pass.
- `keep_exchanges: true` with `evidence_mode: metadata_only` is refused at load time:
  the two settings contradict each other.
- The system prompt, canary passes and tool offers are never kept. The collector never
  receives the file, and the saved run records only its digest, its line count and how
  many replies were altered.

## What is not solved yet

The redactor is not an extension point, and that is deliberate: a pluggable
redactor is also a pluggable *un*-redactor, and a third-party implementation that
returned its input unchanged would silently disable the whole policy. Patterns are
configurable data; the redactor itself is not. Local and collector policies are
still one setting — separating them lands with the collector work.

## See also

- [`threat-model.md`](threat-model.md) — what Guardana protects and what it does not
- [`safe-testing.md`](safe-testing.md) — what an active run actually does

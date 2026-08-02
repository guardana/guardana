# Evidence, redaction and what Guardana keeps

Guardana's evidence is by construction the most sensitive text in a deployment:
the prompt that worked, the reply that leaked, the tool argument that carried a
key. Since 0.7 that text passes through **one redactor at one seam**, and every
way a finding leaves the process goes through it.

## Defaults

Every command defaults to `redacted`. Nothing is sent anywhere: there is no
telemetry, no account, and the collector is opt-in in both directions.

```yaml
privacy:
  evidence_mode: redacted     # metadata_only | redacted | full
  redact_secrets: true
  redact_emails: true
  redact_ip_addresses: false  # an IP address is frequently the finding itself
  hash_identifiers: true
  custom_patterns: []
  max_evidence_bytes: 16384
```

| Mode | What is kept |
|---|---|
| `metadata_only` | which rule fired, where, what verdict. No text from the target. |
| `redacted` *(default)* | evidence with secrets, credentials and configured patterns removed, bounded in size. |
| `full` | the model's words — **still without credentials**. |

**`full` does not mean "store a live key".** Secrets are removed at every mode,
including this one. There is no useful reading of "keep the credential", and no
flag offers one: the finding is that a secret appeared, not what it was.

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

## One seam, and why that is the whole design

```
rules → findings → [EvidenceRedactor] → renderers / reporter / baseline
```

The redactor is applied by the renderer *factory*, not by each renderer. A format
added next year is covered without its author knowing this document exists, and
there is no way to obtain a renderer that skips it. A policy applied in thirty
places has thirty exceptions, and the one that matters is the one somebody forgot.

Commands also redact once, early — before a baseline is written or matched —
because a fingerprint is computed from the evidence summary. Redaction is
idempotent, so applying it twice changes nothing.

A test enumerates every registered renderer from the registry and asserts that a
crafted, obviously-fake credential cannot pass through any of them, plus the
collector envelope and a baseline file. Per path, not once: asserted centrally, it
would pass while one path quietly bypassed the seam.

## The manifest records what was applied

```json
"privacy": {
  "evidence_mode": "redacted",
  "redaction_policy_digest": "sha256:…"
}
```

So a reader knows what was applied to the evidence in front of them, rather than
assuming the defaults of whichever build they happen to run.

## What is not solved yet

The redactor is not an extension point, and that is deliberate: a pluggable
redactor is also a pluggable *un*-redactor, and a third-party implementation that
returned its input unchanged would silently disable the whole policy. Patterns are
configurable data; the redactor itself is not. Local and collector policies are
still one setting — separating them lands with the collector work.

## See also

- [`threat-model.md`](threat-model.md) — what Guardana protects and what it does not
- [`safe-testing.md`](safe-testing.md) — what an active run actually does

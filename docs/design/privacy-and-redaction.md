# Design: privacy, redaction and safe evidence

**Status:** implemented in 0.7 · user-facing description in [`docs/privacy.md`](../privacy.md)

## The problem

Guardana's evidence is, by construction, the most sensitive text in a deployment:
the prompt that worked, the reply that leaked, the tool argument that carried a
secret. Today that evidence is redacted **by convention** — rules are careful, and
`Evidence` documents that it never carries the secret itself — but nothing
enforces it centrally. A third-party rule can put anything in `Evidence.detail`,
and it flows unmodified into the JSON report, the SARIF file, and the collector
envelope.

Convention held while every rule was ours. It does not survive an extension API.

## Design

### One redactor, at one seam

A single `EvidenceRedactor` applied **after** rules produce findings and **before**
anything serializes or dispatches them. Not inside each rule: a policy applied in
thirty places is a policy with thirty exceptions, and the one that matters is the
one someone forgot.

```
rules → findings → [EvidenceRedactor] → renderers / reporter / collector
                                      ↑
                        the only path evidence takes out
```

The seam is enforced by a test that walks every serialization entry point and
asserts it sits downstream of the redactor.

### Modes

| Mode | What is kept |
|---|---|
| `metadata_only` | Which rule fired, where, what verdict. No text from the target at all. |
| `redacted` *(default)* | Evidence with secrets, credentials and configured patterns removed, bounded in size. |
| `full` | Everything, with a warning printed at run time and recorded in the manifest. |

**`redacted` is the default, and `full` is loud.** A tool that quietly stored
model output would be a liability the first time someone ran it against a
production support agent.

### What is redacted by default

Secrets and credentials always. Emails by default. IP addresses not by default —
they are frequently the finding. Custom patterns configurable. Identifiers hashed
rather than dropped, so two occurrences of the same value stay comparable across
runs without the value being stored.

Prompts, responses and tool arguments are **not stored** by default, at any mode
below `full`. The finding says what happened; the reproduction is the rule, which
is public.

### Bounded size

`max_evidence_bytes` (default 16 KiB) applied at the same seam. Unbounded evidence
is a denial-of-service against the collector and a memory risk locally — and a
64 MiB model reply in a report helps nobody.

### The report says what it removed

A finding whose evidence was redacted or truncated says so, in a field. Silent
redaction produces a second class of dishonest report: one that looks complete and
is not. This is the same principle as `unverified` — the report must never imply
it saw more than it did.

### Local and collector policies are separate

A team may keep full evidence locally and send only metadata to a central
collector. One knob for both would force the strictest setting everywhere and get
turned off entirely.

### Logging

No API key, authorization header or raw target response at any log level by
default. Debug logging that dumps responses is how evidence escapes a policy that
was correctly applied everywhere else.

## Acceptance criteria

- A test proving a finding constructed with a live-looking credential in
  `Evidence.detail` cannot reach any renderer, the reporter, or the collector
  envelope with the credential intact — asserted per output path, not once.
- A test that `full` mode warns, and that the manifest records the mode used.
- A test that truncation is reported rather than silent.
- A test that no log record at any level contains an API key.
- Fixtures use crafted, obviously-fake secrets built in code
  (`guardana.core.testing`), never a real-looking key pasted into a file.

## Open questions

1. **Does redaction belong in `guardana-core` or `guardana-report`?** Answered:
   core. The collector reporter lives there too, and evidence must be redacted
   before *any* dispatch. What was not anticipated: the seam had to be the
   renderer **factory** rather than each renderer, because only the factory can
   guarantee that a format added later is covered.

   Also unanticipated: redaction changes a finding's fingerprint, which a baseline
   waiver matches on. Commands therefore redact once, early, before a baseline is
   written or applied — and the redactor is idempotent so the output seam can
   apply it again safely.
2. **Should the redactor be pluggable?** Answered: no. An enterprise will want its own patterns.
   A pluggable redactor is also a pluggable *un*-redactor — a third-party
   implementation that returns its input unchanged silently disables the whole
   policy. Leaning: patterns are configurable data, the redactor itself is not an
   entry point. Same reasoning that keeps `Capability` a closed vocabulary.
3. **Hashing identifiers needs a per-run or per-project salt.** Per-run makes
   values incomparable across runs, defeating the purpose; per-project needs
   somewhere to keep the salt. Decided with the collector schema.

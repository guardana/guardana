---
name: false-green-audit
description: Hunt for the failure this project exists to prevent — code that compiles, types, tests green, and quietly reports "all clear" about something it never examined. Use when reviewing a release, auditing a subsystem, or before tagging.
---

# Hunting a false green

Every audit of this repository has found real defects **on top of a fully green
gate**. That is not a comment on the gates; it is what this class of bug is. The
code is correct in every way a linter, a type checker or a unit test can see, and
wrong in the one way that matters: it says "nothing found" about something it did
not look at.

Treat a green gate as the start of an audit, never its conclusion.

## The seven shapes, with the release each was found in

**1. Silence spelled `pass`.** A check that cannot actually run returns clean
instead of `inconclusive`. Grep for `except ... : pass`, for `return ()` in a
branch that means "I could not tell", and for any evaluator path that yields a
verdict without having seen text. *An empty reply graded `pass@0.95` (0.12).*

**2. A channel rebuilt field by field.** A function that constructs a dataclass by
listing its fields silently drops the next field somebody adds. Look for
`return SomeResult(a=..., b=..., c=...)` where the input was already a
`SomeResult`; it should be `replace(...)`. *`compare_reports` dropped the whole
measurement channel (0.22); `ScanResult.merged` exists because `errors` went
missing the same way (0.9).*

**3. A whitelist where a scan belongs.** A gate that iterates a hand-written list
of files covers the files somebody remembered. Every new file is invisible.
*Image pins sat on `:0.9` for twelve releases because the four files carrying them
were created after the list (0.22).*

**4. A promise that rots.** A statement that was true when written and became
false with no diff to blame: "coming in v0.7", "the collector has no audit log",
a pin to a container tag. *Five future-tense claims about features shipped
fourteen releases earlier (0.22).*

**5. A seam nothing exercises.** A documented extension point with no registrant
anywhere is a seam nobody has run. *`guardana.targets` was in the contract from
0.1 with no example, so `Registry.targets()` returned `[]` and a false red
shipped in `pack validate` (0.18); `guardana.taxonomies` was in the same state
until 0.19.*

**6. A test that measures an echo.** An assertion on a document, a log line or a
mock's call count measures what the code *said*, not what it *did*. Move the
assertion to the seam where the value has to arrive. *A capability check that
asserted on the manifest instead of on what ran.*

**7. A test that cannot fail.** Invert the **behaviour**, not the branch: change
the production code so the thing under test is genuinely wrong, and confirm the
test goes red. A test built on `getattr(x, "thing", ())` where nothing has
`thing` is vacuous and looks thorough.

## The method that has found the most

**Run the documented command and read the artifact.** Not the test suite — the
command a user would type, against a real (or realistically faked) target, and
then open the JSON it wrote. Three separate releases had their worst defect found
this way and by nothing else:

- `probe --max-requests 5` sent ten (0.12);
- a 66 KB `model.pt` hid `posix.system` behind 65 MB of deflated padding and
  produced zero findings (0.12);
- `diff` reported "no regression" over an `indeterminate` run (0.17);
- `compare_reports` dropped the measurement channel — every unit test passed
  because each tested the half it owned (0.22).

A fake endpoint is three lines of `http.server`; there is no excuse for skipping
this step.

## Where to look first

The seam between what the project **claims** and what it **does**: documentation
against behaviour, a schema against its reader, a capability against its surface,
a manifest field against whatever is supposed to populate it. Both of the two
worst findings in the 0.21 audit were there, and neither was in the engine.

Then: anything that reads a file somebody else wrote, anything with a `version`
or `schema_version`, anything that decides `pass` vs `indeterminate`, and any
field of a persisted document that no fixture populates.

## When you find one

Fix it **and** add the gate that makes it impossible — a whitelist becomes a scan,
a promise becomes a test, a hand-written list becomes a measurement. The repo's
own rule: a finding is closed when it has a gate that will not let it back, not
when it has been corrected once.

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.20.0] - 2026-08-12 — the pack author's last mile, and every persisted document read back

### Added

**`guardana pack lock` — a pin over what a check *is*, not over what its package is
called.** The last open item of the extension-author tooling, and the reason it
waited: a lock over distribution versions is not a lock for this project.
`Rule.digest()` has existed since 0.6 precisely so that "the same rule" means more
than "the same package version" — a pack can sharpen a corpus, widen a prompt set or
swap an evaluator inside one patch release, and every one of those changes what a
run tests while the version string says nothing moved.

So three things are pinned three ways, and the file says which is which: rules by
their hashed declaration, evaluators and targets by id (Python has no declaration to
hash, and inventing a digest from a class name would claim a detection it does not
have), catalogues by a digest over the references a pack registers. The distribution
version sits beside all of it as the coarse pin covering what none of the others can.
`guardana pack lock --check` is the CI half, and it never writes: a check that
created the file it was asked to compare against would pass on every first run.

Drift is reported in both directions. A rule that vanished is coverage a team still
believes they have; one that appeared is a check nobody reviewed running against
production. Extensions from a package that declares no manifest are recorded as
`unlocked` and said out loud, because a lock silent about them would read as a fully
pinned repository that is not one.

**Pack manifest schema 2: `provides.taxonomies`.** `guardana.taxonomies` has been
one of the four extension groups since 0.1 and got its first registrant in 0.19.0 —
but a pack could register a control catalogue and its manifest had **nowhere to say
so**, which left `pack validate` blind to a whole category. A pack shipping *only* a
catalogue could not write a valid manifest at all: `provides:` had to list something,
and none of the three things it could list were what that pack shipped. It was also
never discovered, because the group was missing from the list discovery walks.

A schema 1 manifest still loads, migrated forward **in memory** and never by
rewriting the author's file, and `pack validate` now prints that it happened. A
schema 1 manifest that names `taxonomies:` is refused: a key invented after the
version that names it is a manifest whose own `schema_version` no longer describes
it.

### Fixed

**A pinned MCP manifest recorded which server it was approved for, and the reader
threw that field away.** Pointing `--mcp-pin` at another server's file — a
copy-paste, a wrong path in CI, a repository holding pins for several servers —
produced a full comparison against a manifest nobody had approved for that server.
Where the tool names lined up it produced a **clean pass**: a rug-pull check
reporting "nothing changed" about a server nobody ever approved, which is the exact
false green that check exists to make impossible. A pin whose server does not match
the target, or which names no server at all, is now `inconclusive` — never a finding,
because the server may be perfectly intact, and never a pass.

**A re-read run said the target metered nothing.** `load_report` rebuilt seven of
`ScanResult`'s nine channels and silently defaulted `usage` and `protocols`, so a run
that made 42 requests and negotiated MCP `2026-07-28` came back claiming no target
counted and no protocol was spoken. Both are recorded in the manifest and are now
read back from it.

**A dead property and two unexercised branches in the documentation-site
generator.** `Page.depth` was used by nothing; `render.split_heading`'s
link-in-a-heading branch and `build._tables`' substitution had no test between them.
The first is gone, the other two are covered — including the fact that wrapping
tables by substituting on `<table>` is safe *only* because the parser escapes raw
HTML, which nothing had written down.

### Changed

**Every versioned document now has a round-trip gate, and the list is read off the
source.** Nine persisted schemas shipped and exactly one was gated that way. The
other eight were covered the way the failing one had been — the writer's tests
asserting what it wrote, the reader's asserting what it read, both correct about
their own half and neither able to see a field that fell between them. That is how
`calibration` was lost in 0.18 and `deployment` in 0.19, and how `usage` above was
lost in this one.

Each gate writes a document, reads it back, compares every field walked off the
dataclass, and then **deletes each key in turn and requires the reader to notice** —
a key whose removal changes nothing is a key nothing reads. A meta-gate parses the
source for `*_SCHEMA_VERSION` constants, so a new persisted document arrives failing
until its gate exists. The collector envelope is walked across the package boundary
it lives on, engine to collector and into both stores.

## [0.19.1] - 2026-08-11 — the gate lied about itself

**`v0.19.0` was tagged and never published.** Its CI was red on an import-ordering
lint, so the release run was cancelled before it could reach PyPI rather than
publishing from a commit that failed its own gate. `0.19.1` is that release plus
this fix; nothing else moved. The tag stays where it is — a pushed tag is not
rewritten here, and a version number is cheaper than a rewritten history.

### Fixed

**A stale `.ruff_cache` entry made the local gate green while CI was red.** The
lint gate answered from a cached result for a file whose imports had since been
rewritten — so `uv run ruff check .` reported success on exactly the code CI
refused. Same family as the `__pycache__` trap: a cache that keys on something
coarser than what changed will eventually tell you what you want to hear.

The ordering itself was ambiguous, which is why it could differ at all: whether
`sitegen` is a first-party module decides which block its import belongs in, and
nothing had said. `[tool.ruff] src` now declares it, so the answer is a decision
rather than an inference that can vary by machine.

## [0.19.0] - 2026-08-11 — documentation that is generated, and two documents read back wrong

### Added

**Documentation on guardana.dev, generated from the prose and the registry.**
`scripts/build_site.py` renders `docs/**.md` plus `docs/generated/rules.json` into
`site/docs/` — 190 pages, no build step in Cloudflare, nothing hand-edited. The
header's **Docs** link finally points at documentation instead of at the GitHub
README, which is the open item `site/README.md` has carried since the domain was
parked. Reasoning and the alternatives that lost:
[`docs/design/documentation-site.md`](docs/design/documentation-site.md).

The page worth building is the **rule explorer**. Every rule has a page — severity,
surface, impact, declared request budget, required capabilities, the goal its own
expectation states, and its framework mapping with the edition spelled out — and
every filter is a *pre-rendered page*: by family, surface, severity, impact, cost,
framework, and each of the 52 framework entries. It is the one page a competitor
cannot copy without also having the rules, and because it is generated it cannot go
stale the way this project's landing page once did.

**Filtering is navigation because `script-src 'none'` is a product claim.** The site
tells visitors a security vendor's own pages run nothing and reach nothing, and that
is checkable in devtools rather than asserted in prose — so the filter space is
rendered ahead of time instead of being scripted. A test reads the built pages and
refuses a script tag, an inline handler or a `javascript:` URL anywhere; a second
pins `connect-src 'none'`. Free-text search over the prose is the one thing this
cannot do, and the design document says it is the only reason worth revisiting the
policy for.

- **Frontmatter on every documentation page** (`title`, `nav_order`, `summary`,
  `status`) and **a build that refuses a page without it**. Inferring a title from a
  filename or a first heading is free and silently reorders the navigation the day
  somebody retitles a page.
- **`docs/generated/rules.json`**, emitted by `generate_docs.py` from the same
  registry walk that writes `rule-catalog.md` — one walk, two renderings, and a test
  comparing them, so the explorer cannot drift from the catalogue.
- **Every internal link checked after rendering, anchors included.**
  `test_docs_consistency.py` checks `.md` targets in markdown; what ships is HTML,
  where the target has been rewritten and every anchor regenerated. That check found
  four links in the shipped documentation pointing at an anchor that did not exist.

### Fixed

**A saved run's `deployment` block was written on every run and read back on none.**
`manifest_to_dict` serialized all eight fields — which AI system, which environment,
which deployment, commit, image digest, model digest, model name, model revision —
and `manifest_from_dict` never rebuilt them. `guardana run inspect --format json`
therefore re-rendered a run against production as a run against nothing, and any
consumer holding a loaded manifest lost what the evidence was about.

Same shape as the `calibration` defect 0.18.1 fixed, and it survived for the same
reason: the serializer's tests assert what it writes, the loader's tests assert what
it reads, and both were right about their own half. **No gate went through both
doors in one trip, so now one does** — `test_manifest_round_trip.py` enumerates the
fields off the dataclass, writes, reads, and compares each one; then deletes every
key the document carries in turn and requires the reader to notice.

**`guardana taxonomy` listed the built-in catalogues and called it what is
installed.** The command runs discovery first, and its own comment says a listing
showing only the built-ins "would tell them their pack is not installed when it is"
— and then it printed only the built-ins. A company that registered its own control
catalogue ran the one command that confirms what is installed and was told, in
effect, that it is not. Package-registered references now appear in their own
section, and in `--format json` with `"digest": null`, because a package registers
references rather than a catalogue file and inventing a digest would claim a
provenance nobody has.

It survived because **nothing had ever registered through `guardana.taxonomies`**.
The group has been documented in `README.md`, `FEATURES.md` and
`docs/usage-taxonomy.md` while `entry_points(group="guardana.taxonomies")` returned
an empty list — precisely the state `guardana.targets` was in when 0.18.0 shipped
`pack validate` accusing every pack with a target. `examples/custom_rule` now
registers a control catalogue and maps a YAML rule to `ACME-14`, so the reference
resolves only because discovery registered the taxonomy first. All four entry-point
groups now have a real registrant; there is no fifth.

## [0.18.1] - 2026-08-11 — six things the audit of 0.18.0 found

Audited by running the release rather than reading it. Three of the six could only
have been found that way: the suite was green, the types checked, and the documents
were being written correctly and read wrongly.

### Fixed

**`pack validate` accused every pack that ships a `Target` — a false red.** The
manifest accepts `provides.targets`, and the command built its "what is registered"
set from rules and evaluators only. Any pack declaring a target was told it declares
something it does not register. This project treats a false red exactly as seriously
as a false green: a validator that accuses a pack of a fault it does not have is a
validator somebody turns off, and then it protects nothing.

It survived because **nothing in this repository had ever registered a target**.
`guardana.targets` has been in the entry-point contract table since 0.1 with no
example, so `Registry.targets()` came back empty in every install and the path a
third party would use was never exercised. `examples/custom_rule` now ships one, and
its suite asserts both halves.

**A run pointed at an unreadable calibrations file exited `1` with a stack trace.**
Exit `1` means *policy failed*, so a pipeline reading exit codes would have reported
a security regression when the only thing wrong was a broken JSON file — a wrong
verdict, which is worse than a crash. It now refuses with `3` and a sentence, like a
profile or a contract that will not load.

**A recorded calibration was written to the run document and never read back.** The
serializer wrote it; the loader dropped it. So `guardana run inspect` said
"confidence not measured" over a document that plainly contained the measurement,
and `diff` could not have seen a judge whose calibration changed. A field written and
never read is not a half-feature — it is a document whose two halves disagree about
what the run recorded.

**`guardana run inspect` never showed the calibration at all.** Even once the loader
kept it, the human path was blind: the whole point of the feature is that a reader
opening a run sees how honest the judge's confidence was, and it arrived only for
whoever parsed the JSON themselves. An evaluator nobody measured now says so rather
than being left out, so a reader cannot assume the ones listed are all of them.

**Two installed packs claiming one manifest name silently lost one of them.**
Discovery keyed manifests by declared name, so the second vanished — a pack that
stops being validated without saying so. The contract compiler refuses exactly this
shape for two contracts producing one rule id; `pack validate` now validates both and
reports the collision.

**`guardana rule test` graded fixtures with default configuration** while the runner
grades with the profile's `rule_config`. A rule configured in `guardana.yaml` was
verified in a shape the pipeline never executes, so a green fixture said nothing
about the rule that actually runs.

### Changed

**The roadmap carries the documentation site**, with the decision the design settles:
prose stays markdown with YAML frontmatter, facts stay generated from the registry as
JSON, and the interactivity worth building is a generated rule explorer rather than a
docs theme. See [`docs/design/documentation-site.md`](docs/design/documentation-site.md).

## [0.18.0] - 2026-08-11 — what a third party needs before the API freezes

### Added

**`guardana rule test` — a rule's own samples, run as a command, including the one
nobody writes.** "Every rule ships a positive *and* a negative fixture" has been
project law since 0.1 and a `pytest` convention in practice — which meant the engine
could not see those fixtures, and nothing could repeat the proof for a pack this
repository never shipped. That is precisely the third party's problem. `Rule.fixtures()`
makes them data: declared in a YAML rule's `fixtures:` block, or returned from a
Python plugin using the doubles `guardana.core.testing` already ships.

**The third outcome is the whole point.** A rule that cannot fire is caught by a
positive sample and a rule that fires on everything by a negative one; **a rule that
cannot say "I could not tell" is caught by nothing**, and it is the one that will
eventually report clean about something it never examined. So a rule declaring no
`inconclusive` fixture exits `2`, and so does a rule declaring none at all — a
command built to disprove false greens cannot print "ok" over an empty set of cases
in its own output. `--write-corpus` turns a fixture set into the labelled corpus
`calibrate` measures a judge against, dropping `inconclusive` samples and saying how
many, because a sample with no known outcome cannot measure accuracy against
anything.

**51 rules ship and 5 are fully sampled.** A gate pins that number so it can only
rise, and `guardana rule test 'guardana.*'` reports the rest as `indeterminate`,
truthfully. Writing 46 more sets in an afternoon would mean writing them to move a
counter, and a fixture written for that reason is a test that cannot fail.

**`guardana pack validate`, and a versioned pack manifest.** 1.0 entry criterion 8
asks in these words that a third party be able to run it against a release
candidate. `guardana-pack.yaml` ships *inside* the package — `pack validate` runs
against an installed distribution, and `pyproject.toml` is not in a wheel — and
declares two things: which extension API the pack needs, and what it provides.

**`extension_api` is versioned separately from the product, and refuses in both
directions.** In 0.x the product's minor breaks API by design, so a pack pinned to
`guardana>=0.17,<0.18` would need re-releasing on every minor even when nothing it
touches moved; this integer moves only when `Rule`, `Evaluator`, `Target` or
`Finding` change shape. Too old and too new get different messages and one outcome:
refuse to load. A "close enough" acceptance is worse than no declaration, because it
is the point at which an author stops checking. `provides:` is compared against what
the entry points really register, and the missing direction is the one that matters —
a pack promising a check it does not register leaves a team believing something runs
that does not. Guardana's own pack ships a manifest and goes through the same door;
its `provides:` block is generated from the registry, because 56 hand-maintained ids
is how every stale count here began.

**`guardana calibrate --record`, and the field that was never filled.**
`CalibrationRecord` has been in the run manifest since the manifest existed, has
always been serialized, and until now nothing outside a test ever constructed one:
every saved run said `"calibration": null` for every evaluator. A field in a
persisted schema no production path fills is a promise the document makes and never
keeps — and here it is the promise a judge-graded verdict most needs. `--record`
writes the measurement, a profile's `calibrations:` block picks it up, and a run now
carries the Brier score, the ECE, **the date it was measured and a digest of the
corpus** — because a judge model gets replaced under the same name, and a score with
no date describes an evaluator that may not exist any more. An unreliable
measurement is refused rather than recorded: the manifest carries the number, not
the caveat.

**`docs/usage-calibrate.md` exists.** `calibrate` shipped in 0.5 and was documented
by one sentence in `product-status.md` — so for `Evaluator`, one of the four
extension points 1.0 freezes, there was nothing to write an extension *from*, which
is 1.0 entry criterion 6 failing quietly. Two of the three things the roadmap asked
for here already worked: `--evaluator` has always taken any registered id including a
third party's, and `--corpus` has always taken anyone's labelled set.

### Changed

**Adding fixtures to a rule does not change its digest.** `taxonomy:` was excluded
from `declaration_digest` in 0.12 after leaving it in made every rule announce
"changed definition" the release an OWASP edition landed. `fixtures:` is excluded
for the same reason and before paying the same cost twice: sampling a rule that was
never sampled is not a different test, and leaving it in would have made this release
report all 51 rules as changed against every saved run from before it.

**The README is shorter, and every count in it is now pinned to the registry.**
`test_readme_rule_table.py` covered the family table and the headline beside it and
stopped there — so the first line under the badges offered "47 security checks to
start" through the releases that took the number to 51, three screens above a table
that said 51 correctly. A count is not covered because it is *near* a covered one.
The lede, the extension-point sentence and the quickstart transcript are pinned now
too, and `docs/writing-rules.md` no longer says "of the 32 built-in rules" — that was
the *runtime* count promoted to a total, two true numbers rearranged into a false
sentence.

The reference material that duplicated `docs/` — the twelve-command table, the
extensibility walkthrough, the collector's full feature list — is now a sentence and
a link. The rule-family table stayed: it is machine-pinned, and trading a checkable
claim for prose is the wrong direction for this repository.

### Added

**`llms.txt` on guardana.dev, generated from the documentation map.** A model asked
what this project is could previously only read the landing page's markup;
[`/llms.txt`](https://guardana.dev/llms.txt) hands it the documentation instead —
the summary, the honest-verdict property, and every page with the sentence that
describes it, as raw markdown URLs rather than rendered HTML.

It is **generated from `docs/index.md`**, which is the part worth stating: that file
is already the curated map, already describes every page, and every link in it is
already checked against the filesystem. So a page added to the docs appears here for
free, one removed disappears, and the hand-written second list — the shape of every
stale claim this repository has had to fix — never exists.
`scripts/generate_llms_txt.py --check` joins `sync_site.py` and `generate_docs.py` in
the freshness test and in `release.py`.

**A share card, and the Open Graph tags to point at it.** Links to guardana.dev
rendered as bare URLs in Slack, X and LinkedIn: `og:image`, `og:url` and
`twitter:card` were absent, and a crawler resolves nothing against the page it
fetched. `site/og.png` is rendered from `scripts/og_card.html`, which is committed
beside it so the card can be re-rendered rather than reverse-engineered.

**The card states no rule count on purpose.** A number rendered into a PNG is a claim
no gate here can read, and this repository has now had that number go stale on the
landing page, in the README and in the GitHub repository description. So the image
carries the four verbs and the licence, and the test refuses a count in the card's
*source* rather than waiting to find one in the pixels. It also reads the PNG's own
header, so a card re-rendered at a different size cannot sit beside meta tags
claiming the old dimensions, and it refuses a `.assetsignore` that would exclude
either file from the deploy — the opposite of the mistake that once published
`site/README.md`.

**A design document for a documentation site on guardana.dev**
([`docs/design/documentation-site.md`](docs/design/documentation-site.md)), closing
the open item at the end of `site/README.md`. It argues that the interactivity worth
building is a *generated rule explorer* rather than a docs theme, that prose stays
markdown while facts stay generated from the registry — the answer to "should docs
live in YAML" is no for the first and already-yes for the second — and it states the
constraint that decides the shape: `site/_headers` sets `script-src 'none'` as a
product claim, so free-text search costs that claim on the docs subtree and
pre-rendered filtering does not. Proposed, not agreed.

## [0.17.1] - 2026-08-10 — three things 0.17.0 said that were not true

An audit of the release, done by running it rather than by reading it. Every item
below was found by pointing a command at a real file and reading the artifact; two
of them are wrong *sentences* rather than wrong verdicts, which is the class a green
test suite is structurally unable to see.

### Fixed

**A contract's coverage demand survived the policy that switched the assertion off —
a false red.** `rules.exclude:` matching a compiled assertion dropped its rule from
the run and left its requirement standing, so the run went `indeterminate` for
missing evidence that no surviving check would have read. Measured on one trace: exit
`0` with the assertion deleted from the contract, exit `2` with the assertion present
and its rule excluded, with the same six rules run and seven skipped either way.
Identical work, opposite verdict.

This project treats a false red as seriously as a false green, and for the same
reason: a tool that accuses a run of missing coverage nobody asked for gets its
coverage demands turned off, and then it protects nothing. The implied demand now
lives and dies with the assertion — `wire_contracts` requires only the dimensions of
assertions the run will actually check, through a shared `refused_by_this_run`
predicate that a test holds against the plan the runner really builds. **`trace.require:`
is deliberately unchanged**: it is a demand the operator stated outright rather than
one implied by a check, so it stands whether or not a rule wants the dimension.

An excluded assertion is now also **printed** as excluded. Subtracting the demand
silently would have left `contracts: 1 assertion(s) apply to this execution` standing
over a green report about a rule nothing ran.

**`guardana trace inspect` counted rules a dimension is *needed by* and labelled the
column as what it *unlocks*.** Those are different numbers wherever a rule wants two
dimensions: `guardana.trace.unapproved_side_effect` needs approvals *and* side
effects, so against a producer recording neither it was counted under both while
instrumenting either alone unlocked nothing. A team budgeting instrumentation read
`approval: 1 rule(s)` and would have gained no check for the work. The table now
carries both counts — `needed by` and `unlocks` — and the JSON gains an additive
`unlocks` key beside `licenses`, which keeps its meaning.

**`guardana.trace.cross_tenant_retrieval` said no document carried a tenant when the
documents were the labelled half.** One sentence covered two different gaps: a query
with no tenant, and a query with one where no returned document has any. A real
LlamaIndex run is the first case — `source_nodes` each carry a tenant and the
`Response` carries none — so the decline sent a team to instrument the side that was
already done. The verdict was right and the instruction was wrong; the two cases are
now counted and reported apart.

### Changed

**The measured reach of security contracts is now written down where it is decided.**
Against a real run from every shipped adapter — pydantic-ai 2.27.0, llama-index-core
0.14.23, crewai 1.15.14 — four of the five assertion kinds decline, because no
framework records approvals, delegations or side effects on its own. The declines are
the honest verdict working, and they also mean contracts today serve a team that
instruments its own agent. `docs/usage-contracts.md`, `ROADMAP.md`, the design
document and the landing page say so rather than leaving a reader to discover it in
a pipeline.

*Checked and deliberately left alone:* a contract directory picking up a stray
`.yaml` (fail-closed, and the message names the file and the reason); an explicitly
empty selector list reading as "all" (it widens, never narrows, and the loader
already refuses empty wherever empty would silence a check); `tenant_boundary`
reporting one finding per tenant beyond the first (one per site of the crossing, each
with its own span, which is the pattern the built-in retrieval rule already uses).

## [0.17.0] - 2026-08-10 — the evidence matrix, and the application's own threat model

### Added

**`guardana trace inspect` — what a recorded execution can answer at all.** The
trace design's central mechanism, that a producer which does not record a dimension
stops the rules needing it from running, has existed since 0.14 and was visible only
as a skip note on a run that had already happened. An operator could not gate on
it, because they could not see what was missing until a rule was missed. The new
command prints the matrix ahead of time: per dimension, whether the producer
**declares** it, how many **records** this execution carries, whether the profile
**requires** it, and how many installed rules it **licenses** — counted from the
registry, so a rule pack a team installed is included and the number cannot rot.

`declared` and `records` are separate columns because they are separate failures.
`declared: yes, records: 0` is an execution with nothing to approve and is gradable;
`declared: no` is an instrumentation gap where silence proves nothing. Collapsing
them would make the two indistinguishable, which is the one inference the trace
model exists to refuse. **There is no coverage percentage and there will not be
one** — a single number is compatible with having no identity evidence whatsoever,
and a team gating on a number rather than on a name ships the day the missing part
is the part that mattered. The command opens one file, writes no run document, and
reaches no network. See [`docs/usage-trace-inspect.md`](docs/usage-trace-inspect.md).

**`trace.require:` in `guardana.yaml` — evidence a run demands.** A producer that
does not record a required dimension makes the run `indeterminate`, never a pass,
and **no `fail_on_*` setting governs it**. Every other branch of the gate is behind
a switch, correctly: they cover checks nobody specifically asked for. This one was
asked for by name, and `fail_on_skipped` defaulting to off is exactly what would
otherwise have turned "the coverage I gate on was not there" into exit `0`. It
governs traces only — demanding that a file scan record approvals is a category
error, and reading it as one would make a shared config a `guardana scan` that can
never pass.

**Security contracts — the application's threat model, executable.** Rules are
tests, evaluators are judgement, targets are the system. The missing layer was what
an application is *allowed to do*: which principals exist, whose data is whose,
which actions need a human, which boundary may never receive a credential. No public
framework knows any of that, and "you can write a custom rule" stopped being a
differentiator once policy libraries became a mainstream red-team feature.

A contract is a versioned YAML file a team keeps in its own repository, loaded with
`--contract` (repeatable, directories accepted) or `contracts:` in `guardana.yaml`.
Five deterministic assertion kinds — `tenant_boundary`, `approval_required`,
`allowed_scopes`, `credential_boundary`, `forbidden_sink` — each compiled into an
ordinary `Rule`, so redaction, baselines, `diff`, the collector and the exit-code
contract all apply with no new path through the engine. Generated attacks aimed at
*breaking* an invariant are deliberately not part of this: the order is state the
invariant, prove it, then generate traffic. See
[`docs/usage-contracts.md`](docs/usage-contracts.md) and the design document,
[`docs/design/security-contracts.md`](docs/design/security-contracts.md), which
records what was rejected — a contract as a profile, a contract as a YAML rule, and
an evaluator seam that would have let a tenant boundary be graded by a language
model.

**The `coverage_shortfall` channel, and why it has no switch.** A contract assertion
whose dimension the producer does not record is skipped by the runner for a missing
capability — and a skip reaches the gate only through `fail_on_skipped`, which
defaults to `false`. So the default path for *"the contract you wrote could not be
checked at all"* was a clean report and exit `0`. That is now its own channel on the
result, it makes the run `indeterminate` unconditionally, and it is recorded in the
saved run under `run.coverage.shortfall` — because a run whose verdict is not
explained in its own evidence leaves `diff` and the collector holding a conclusion
with no cause. It is deliberately neither a `CheckError` (a framework that emits no
approval spans has malfunctioned in no way, and `fail_on_error` is a toggle) nor a
second copy of the skip.

**A contract can say "not mine" without that being a pass.** `applies_to.ai_system`
is matched against `--ai-system`, which the trace commands already take and never
guess. A contract about another system has its assertions recorded as **not
applicable** — the first `SkipReason` whose `is_coverage_gap` is `false`, because
nothing is missing — printed rather than dropped, and counted as coverage by
nothing. A contract that names a system when no `--ai-system` was given is
**refused** (exit `3`): "I cannot tell whether this applies" has two wrong answers
and no right one. And a run where contracts were loaded and *none* of them applied
is `indeterminate`, which is the wrong-file case and the only way the
not-applicable state could have become a silent green.

### Changed

- **Run schema v5.** `run.coverage.shortfall` records the coverage a run's operator
  demanded and did not get, and `rules_skipped[].reason` gains `not_applicable`. The
  second is why this is a version rather than an addition: the reason is read
  against a closed list, so a v4 reader handed a v5 document refuses it outright —
  which is correct, and exactly why the enum is not widened in place. A v4 run
  migrates forward in memory and through `guardana run migrate`; the shortfall
  arrives empty, which is what a v4 run knew, because nothing could demand coverage
  yet. Published as [`schemas/run-v5.schema.json`](schemas/run-v5.schema.json).
- The human report no longer prints `✓ No findings.` over a run with unmet coverage,
  and the JUnit report counts one as an `<error>` rather than leaving `errors="0"`.
  The tick is what people scroll for and what a CI dashboard reads.
- Evidence redaction covers the shortfall channel. Its detail is Guardana's own
  prose *about the user's material* — a target ref they chose, the AI system they
  named, the contract names they wrote — which is the same borrowed text
  `errors[].reason` carries, and leaving one channel out is precisely how the
  redactor covered three of four for four releases.

### Fixed

Two false verdicts found by auditing the new assertions rather than by a gate, both
in `approval_required`:

- **A false red on same-step approvals.** Approvals were only counted from *earlier*
  spans, so a producer recording the approval and the effect it authorised on one
  step — the common shape, since they are one decision — was accused of acting
  unapproved. A span has no internal order, so the rule was reading its own
  iteration order back as evidence. Approvals recorded on the step itself now count;
  an approval in a *later* span still does not, which is the audit trail written to
  look compliant.
- **`guardana diff` reported "no regression" over a run that could not answer.**
  Found by running the documented commands on two real files, not by a test: a run
  whose contract could not be checked produces exactly the finding list of one where
  the contract held, so subtracting them yields no change and the comparison exited
  `0` over a run that was `indeterminate` on its own. A pipeline gating on the
  comparison alone would have gone green. Unmet coverage now makes the comparison
  **incomplete**, which fails before any threshold is consulted — the same treatment,
  and the same reasoning, as a run stopped by an exhausted budget.
- **A false red on a mixed approver record.** With `approvers:` set, a step carrying
  one approval by the wrong approver and one by nobody recorded was reported as a
  finding. The unnamed one may have been the right approver, so that step is one
  this build cannot grade: it is now `inconclusive`, and a finding only when every
  matching approval names an approver and none of them matches.


## [0.16.0] - 2026-08-10 — MCP, as the specification now is

### Added

**Guardana speaks both revisions of MCP, and records which one it spoke.** The
specification revised on 2026-07-28 removed the `initialize` handshake and
protocol-level sessions, and made every request carry its own protocol version and
client capabilities in `_meta`. Guardana pinned `2025-11-25` and opened every
conversation with `initialize`, so against a server built to the current
specification it did not connect at all. It now settles which era a server is in
before asking it anything, and the negotiated revision lands in `coverage.protocols`
— so [`guardana diff`](docs/usage-diff.md) reports a server that moved between
revisions as *the reach changed* rather than as the system behaving differently.

The probe is one `server/discover` call, which is the method the newer revision
requires and the older one has never heard of. The cheaper route the HTTP binding
permits — send an ordinary request, read the body of a `400` — is **deliberately not
taken**: the specification warns that some older servers answer an era-ambiguous
method without a handshake, so a client that opened with `tools/list` would take
their manifest and write `2026-07-28` into a run manifest as a coverage claim no
server ever agreed to. Reasoning in
[`docs/design/mcp-protocol-eras.md`](docs/design/mcp-protocol-eras.md).

**Guardana declares no client capabilities, which is a safety property.** Under the
new Multi Round-Trip Requests pattern a server asks for sampling, elicitation or a
root listing by returning them in a result — and it **MUST NOT** ask for a capability
the client did not declare. A client declaring none cannot be asked to run a model
completion or to prompt a human on the server's behalf. An interim `input_required`
result is refused rather than read, because it carries no `tools`: a reader that
shrugged would have recorded a server asking a question as a server offering nothing
to poison.

**`guardana.mcp.issuer_identification` (medium).** An authorization server whose
metadata does not advertise `authorization_response_iss_parameter_supported` gives a
client no way to tell that an authorization response came back from the issuer it
started the flow with. Validating a present `iss` is now a client `MUST` (RFC 9207),
and mix-up is the attack it exists to catch — a `MUST` a client cannot perform where
nothing is advertised.

**`guardana.mcp.cache_scope` (medium).** A server that refuses its tool manifest to
an unauthenticated caller and returns it to an authorized one declaring
`cacheScope: "public"` has made two declarations about one document that cannot both
be intended: any shared gateway on the path is invited to serve those tool
declarations to a caller the server would have refused. It grades **what the server
declares** and never goes looking for a cache, which would be reporting somebody
else's infrastructure.

**Dynamic Client Registration is not reported as a defect**, and there is a test that
says so. `2026-07-28` deprecates it in favour of Client ID Metadata Documents and
keeps it legal for at least twelve months; it remains the only registration route
some authorization servers offer, and reporting a supported feature as a defect is a
false red.

### Changed

**`guardana.mcp.session_binding` is silent against a server with no sessions.** A
conforming `2026-07-28` server mints none, so there is nothing to guess and nothing
to authenticate with: the invariant holds, and silence is what this codebase says
when it does. It previously reported `inconclusive — the server issues no session
id`, which under a policy that fails on indeterminate checks broke the build of the
team that had upgraded correctly.

A server that offers an older revision **alongside** the new one is still graded over
that older one. It answers `server/discover`, so the conversation settles as modern
and carries no session — while the same server keeps handing a predictable one to
every legacy client it serves, which is a live defect the modern half cannot show.

**A version mismatch is an outcome, never a pass.** Where client and server share no
revision, the authorization checks report `inconclusive` naming both version lists,
the manifest checks are skipped with the same sentence, and `protocols()` claims
nothing — so `fail_on_skipped` turns it into an indeterminate run.

**A `200` nobody could read is no longer read as a refusal.** A reply carrying
neither a result nor an error was folded into "the server declined", which is a pass
on a question that was never answered.

**Every MCP rule declares one more request** — the single `server/discover` that
settles the revision, bought once per run and shared by every rule that reads the
same observation.


## [0.15.0] - 2026-08-10 — the translators, and the field they proved was missing

### Added

**Tool calling through the LangChain adapter, which six rules were waiting for.** A
team probing a LangChain chat model got six skips and a coverage note, because the
adapter could send prose and nothing else. It now offers tools the way every provider
reads them, and replays a whole tool conversation — the assistant turn carrying the
calls, and each result paired to the call it answers. The `(role, content)` tuple form
this used before could express neither; LangChain raises `KeyError: 'tool_call_id'` on
the attempt, so an agentic rule replaying its own history died on the second turn.

Whether a given model *can* be offered tools is **measured, not assumed**:
`bind_tools` exists on every LangChain chat model and raises on the ones without a
function-calling API, so Guardana binds a throwaway tool once at construction — no
request, no token — and advertises `CALL_TOOLS` only if that worked. A model that
refuses keeps every text rule and skips the agentic ones with a reason, which
`fail_on_skipped` can turn into an indeterminate result.

**Three framework adapters as translators into `Trace`** —
`guardana.adapters.pydantic_ai`, `.llama_index`, `.crewai` — each turning a run its
framework already performed into the model the trace rules grade. None of the three
libraries is imported, and `guardana-core` gains no dependency; the shapes were read
by running the real libraries and are recorded, with versions, in
[`docs/design/framework-adapters.md`](docs/design/framework-adapters.md).

They drive three *different* halves of the model, which is the point: PydanticAI
supplies messages with typed parts and a tool loop, LlamaIndex supplies retrieval with
a tenant and a score on every document, CrewAI supplies multi-agent invocations and
handoffs. **Each declares only the dimensions its framework really records.** A
PydanticAI trace does not claim to carry approvals, so the rule that grades unapproved
effects is skipped rather than reporting that it found none — and a run where nothing
could be checked says `0 rules ran — nothing was checked (this is not an all-clear)`
and exits `2`.

**Two rules over a recorded execution.** `guardana.trace.cross_tenant_retrieval` —
a retrieval performed for one tenant returned another tenant's document, which is the
deterministic half of the RAG work and the reason `Retrieval` carries a tenant on the
query *and* on each document. `guardana.trace.handoff_authority_expansion` — an agent
exercised a scope wider than the handoff carried to it. Both decline by name rather
than passing when the comparison cannot be made: an unlabelled corpus cannot be proven
not to have leaked, and a handoff that never recorded its scopes did not record that
none crossed. 47 built-in rules → 49.

### Changed

**Trace schema v1 → v2: `Span.agent`, because a multi-agent execution records who
acted and the model had nowhere to put it.** CrewAI names an agent on every task
output; the OpenTelemetry conventions have carried `gen_ai.agent.name` and
`gen_ai.agent.id` since they settled, and the trace design document listed them among
what Guardana reads — while nothing read them, because there was no field to read them
into. A crew of three agents over twenty steps has two handoffs and eighteen spans
whose actor the producer recorded and this dropped.

It is a named field rather than an `attributes` bag, and it is not folded into
`Identity`: an agent name is not a credential, and a crew whose agents are named must
not thereby satisfy the identity dimension and stop `session_as_identity` declining.
[`schemas/trace-v2.schema.json`](schemas/trace-v2.schema.json) is published;
`trace-v1` stays published, and a v1 file still reads — the migration says the field
is absent, which is what it was.

**The trace migration seam now hands its result to the reader.** It took the
already-parsed header's version and threw its own return value away, so a migration
that needed to change a field could not have. A seam nothing consumes is a seam nobody
would notice was broken, and the first real migration is where that surfaced.

**`Capability.READ_RETRIEVAL` and `READ_HANDOFFS`**, so the retrieval and handoff
dimensions gate their rules through the same table every other dimension uses.

### Documentation

**`--write-trace` writes a faithful copy, not a redacted one, and now says so.**
Redaction covers evidence — what leaves in a report, a SARIF file or a collector
envelope — and a trace being converted is input. Redacting it would change what the
rules then grade while the file still looked authoritative. An export holding customer
prompts or a key in a tool argument produces a converted file holding them too, in a
form that is easier to read than the original.

## [0.14.0] - 2026-08-09 — the domain model, and grading a run Guardana did not start

### Added

**A common `Trace` model, and two commands that read one.** Guardana has only ever
verified runs it started itself. The interesting failures happen in the runs it did
not: the documents your retriever returned were whatever the index held at 09:41, the
memory already contained a note from Tuesday, and the credential that reached the
third MCP server came from a delegation chain no prompt can recreate. A trace is the
only place those are visible.

`guardana.core.trace` is the domain model for one: model calls, messages with **typed
content parts** (so a multimodal carrier does not force a breaking change later), tool
offers, calls and results, retrieval queries and retrieved documents, identity and
scopes, delegation, consent, policy decisions, approvals, memory reads and writes,
external side effects, and agent handoffs. Design and rejected options:
[`docs/design/trace-domain-model.md`](docs/design/trace-domain-model.md).

**`guardana analyze-trace` reads a trace and grades it.** OpenTelemetry GenAI
semantic conventions are the interoperability base rather than a Guardana protocol —
a format nobody emits is a format nobody uses — read from OTLP/JSON, from an SDK file
exporter, and from all three generations of the message convention. It opens one file
and no socket.

**Seven rules over a recorded execution**, six of them existing because the model
carries a distinction that would otherwise be unrepresentable: a credential in a tool
argument, one credential crossing two trust boundaries (the token passthrough the MCP
work had to defer as invisible from outside a server), a token presented outside its
audience, a session standing in for an identity, a scope no consent granted, a policy
decision the run went ahead against, and a consequential effect nobody approved.

**`guardana import-observations` carries somebody else's results in as claims.**
garak, promptfoo, or a documented shape for an internal harness — read with their
provenance intact and landing in `unverified`, because Guardana did not send those
prompts and cannot grade what it did not observe. Their outcome stays in their terms:
promptfoo's `success: false` means *this assertion did not hold*, which is not the
same sentence as "the attack worked", and nothing here upgrades it into one. The
command **never exits `0`** — no rule ran, so "the policy passed" is a sentence that
run is not entitled to.

**The mechanism that makes all of it honest, stated once.** A trace records what an
application *chose* to record. When no approval appears before a payment, three worlds
fit the file: none was sought, the framework does not emit approval spans, or the
trace was cut short. Reading the absence as the first fires on every well-governed
system; reading it as the second passes on the one that skipped it. So a dimension the
producer does not record becomes an undeclared **capability**, the runner skips the
rules needing it with a reason, and `fail_on_skipped` turns the coverage hole into an
indeterminate result. What must not happen is six rules finding nothing in a file that
could not have contained it.

That mechanism also decided the layering twice. Reading the OpenTelemetry registry
produced the finding this design turns on — **the conventions carry the model-call
half of the domain and have no field for the other half**: no presented credential, no
token audience, no delegation boundary, no consent, no approval, no policy decision,
no side effect. `mcp.session.id` is the closest thing to an identity in the whole
registry, and a session id is precisely not one — so a session in a trace does *not*
make identity count as instrumented, or the session-as-authentication rule would
accuse a properly authenticated deployment of the thing its instrumentation never
mentioned.

Also in this work:

- **`schemas/trace-v1.schema.json`**, published and versioned like every other
  document a user keeps. A version this build cannot read is **refused**, not read as
  v1 — reading it anyway would drop the fields we do not know and grade what was left.
  A file with no version key is refused too: guessing is how an unversioned format
  acquires a version in name only. Unknown keys on a span are refused, because a
  misspelled `aprovals:` would leave the approval dimension declared and empty and the
  rule would then report a system that approved everything properly.
- **Credentials are named, never carried.** `CredentialRef` has no field for a value.
  A trace that records a raw token gets it hashed at the reader and the value
  discarded, so a producer's carelessness stops there rather than travelling into a
  report, a SARIF file and a collector envelope. Binary content is described — media
  type, size, URI, digest — never copied.
- **`scopes: []` and no `scopes` key are different facts**, throughout: one says the
  client was granted nothing, the other that nobody recorded what was granted. The
  first is checkable; the second makes a rule decline by name.
- **`--write-trace` converts any export into the native dialect**, which is how an
  operator adds the dimensions their framework does not emit.
- **`guardana.core.trace.bridge.as_trajectory`** reads a recorded run as the object
  the existing agentic evaluators already grade, carrying the truncation across so a
  trace that was cut short cannot be graded as a complete one.
- **`TargetKind.TRACE`** — a trace is neither an artifact nor an endpoint, and folding
  it into either would have offered the wrong rules a target they cannot read.
- **Saved run schema v4.** The new target kind is one more value in an enum version 3
  closed, and widening v3 in place would have changed a contract under a name that
  promised it had not. `run-v2` and `run-v3` stay published, the 3→4 migration is in
  the same chain as 1→2→3, and a run over a trace records
  `source.kind: imported_trace` — a field the manifest has had since v2 with nothing
  ever setting it.

**A cycle a green gate could not see.** `guardana.core.trace` must import nothing from
the target, report or evaluator layers: `TraceTarget` lives in the target package, and
importing any trace submodule runs the trace package's `__init__`, so a dependency
back closes `target → trace → evaluator → exchange → target` and every command dies at
import time. It happened during this work under a green `ruff` and a green
`mypy --strict` — neither analyses imports by performing them — and it is now pinned
by a test that reads what the package's `__init__` imports *and* imports every entry
point in a cold interpreter.

### Fixed

**A redirect carried the operator's MCP credential to whatever origin the server
named.** `--mcp-token-env` exists so a real bearer token reaches a real server, and
`urllib` copies every header onto a redirected request — it strips only
`Content-Length` and `Content-Type`. The address guard added in 0.13.0 re-checked
each hop and then let a permitted one leave with the token, so any MCP server under
test could answer `302` and be handed the credential of whoever was scanning it.
That is the same confused deputy the guard exists to refuse, pointed at the
credential instead of the address. A hop to another origin now arrives with no
`Authorization` and no `Mcp-Session-Id`; a hop within one origin is untouched,
because a server redirecting to its own path is ordinary. "Same origin" is one
definition in the engine now, shared with the rule that decides whether a metadata
document identifies the server it was served for — two copies of it would drift,
and the one that drifted would be reporting a conforming deployment as a finding.

**Two MCP rules stayed silent about something they never looked at.** Silence from
a rule means *the invariant holds*, which is why these rules have an `inconclusive`
channel at all:

- `guardana.mcp.scope_breadth` reported nothing when neither metadata document
  could be read — so a server whose scopes were never seen was indistinguishable
  from one whose scopes are narrow. `guardana.mcp.authorization_discovery` does
  report the missing document, but that is a different rule id, and a profile that
  excluded it turned the silence into the only answer.
- `guardana.mcp.authorization_discovery` said nothing about PKCE when the issuer
  named in a perfectly good resource document could not be fetched — every
  discovery address for it refused as unsafe to follow. A server aiming its client
  at the cloud metadata endpoint therefore came back clean on the requirement a
  conforming client **must refuse to proceed** without.

**`guardana plan probe` under-priced the run it was pricing.** `probe` plants a
fresh canary system prompt for every rule that needs one, with or without
`--system-prompt-file` — that is how the leak check works at all — while the plan
built its target without one. Every canary rule was therefore listed as skipped and
left out of the ceiling: `guardana.prompt.system_prompt_leak.canary` and
`guardana.scenario.indirect_injection` among them. A budget sized from that plan
stops the real run early, and a run that stops early reports no verdict. The plan
now assumes what `probe` will actually send. An upper bound that is too high refuses
a budget that would have fitted; this was the other direction.

**A probe's manifest recorded neither what it reached nor how it ran.**

- `probe` built its run document without a `TargetIdentity`, so every endpoint and
  MCP run saved a null fingerprint and an empty capability list — and the coverage
  fingerprint, whose stated job includes noticing "a target that lost a
  capability", could not see one. `scan` had been recording both since 0.12.0.
- `probe --concurrency N --mcp …` wrote `N` into the manifest and ran the rules one
  at a time. The setting is now passed to the runner, which the shared observation's
  lock already made safe.

**`McpServerTarget(command=[], allow_exec=True)` raised `IndexError`** from
formatting the reference before the transport could refuse an empty command. No
caller catches that, so a target that should decline with a sentence crashed with a
traceback.

### Changed

- **Four MCP references a rule did the work for but never declared.**
  `guardana.taxonomy` could not answer `MCP04`, `MCP06` or `MCP10` while the roadmap
  called them covered and named the rules that covered them. `agent.mcp_server_manifest`
  now carries `MCP04:2025` (drift from an approved pin is dependency tampering) and
  `MCP10:2025`; `prompt.mcp_tool_poisoning` carries `MCP03:2025` and `MCP10:2025`;
  `agent.tool_result_injection` carries `MCP06:2025`. A mapping is what makes a
  finding answerable in somebody else's audit, so a claim of coverage the registry
  cannot show is not a claim worth making.

### Documentation

- **The landing page's `plan probe` transcript had drifted** to `13 rule(s) would
  run, 0 skipped` — numbers no build has printed for several releases. It is now
  pinned by a test that runs the command and compares, which is the mechanism the
  rule *counts* on the same page have had since 0.11 and this transcript did not.
- **Three claims on the page and in `README.md` were wider than the code.**
  "grades every finding with a confidence" — a deterministic finding carries none,
  because there is nothing to be unsure about; "every finding maps to OWASP LLM Top
  10, MITRE ATLAS, and NIST" — the six MCP authorization rules map to OWASP MCP and
  OWASP Agentic; and `README.md` said the only network traffic is to the target,
  without the qualifier its own collector needs.
- **`ROADMAP.md` still listed as "next" two steps that shipped in 0.13.0**, and said
  all six MCP rules test a specification `MUST` when one grades a deployment fact the
  specification leaves `OPTIONAL` and one reads a `SHOULD`. The shipped steps are
  deleted per this project's own rule; every deferral they carried is kept, plus the
  two 0.13 left open without writing down — `monitor --mcp` and a saved MCP run in the
  compatibility corpus.
- **`FEATURES.md` pointed at `run-v2` while the writer emits `run-v3`**, and carried a
  `monitor` blockquote spliced into the middle of a paragraph about `diff`.
- **`README.md` explained the Evaluator twice**, in two adjacent paragraphs saying
  the same thing, and its roadmap table jumped from 0.13 to 1.0 without the domain
  model that gates it.
- **`site/README.md` promised a `workers.dev` hostname its own config turns off**,
  named `v0.6.0` as the header marker, and said the page shows six checks out of
  thirty-two. The page says forty.

## [0.13.0] - 2026-08-09 — MCP in depth, and what a client may not conclude

### Added

**MCP, in depth: what a client can prove about a server it does not run.** Guardana
has spoken to a live MCP server since 0.5, and what it said was "list your tools".
Everything a deployed MCP server actually gets wrong sits a layer below that — a
token minted for a different service, a session id that is a counter, scopes that
cannot be reduced — and none of it is visible in a tool description. The controls
are settled rather than speculative (OAuth 2.1, PKCE, audience-bound tokens, no
token passthrough), so this is depth on a target Guardana already has. See
[`docs/design/mcp-authorization-depth.md`](docs/design/mcp-authorization-depth.md).

- **Six new rules over a live server's authorization surface**, each testing an
  invariant the specification states as a `MUST`: a server that answers without a
  credential, an authorization surface no conforming client can use (no RFC 9728
  metadata, no authorization server named, a `resource` on another origin, no PKCE
  advertised), a bearer token the server could not have issued being accepted, a
  session id that is guessable or that authenticates a request on its own, scopes
  that cannot express least privilege, and a discovery address a client must not
  follow.
- **What each check refuses to conclude is part of the check.** A server that
  requires no credential cannot demonstrate audience validation, so the audience
  probe reports `inconclusive` there rather than putting a critical finding on every
  development server. A server that rejected the forged token has rejected *that
  token*, and the rule is titled for that narrow claim rather than for the one it
  cannot support. An stdio server does not declare the capability at all — the
  specification says stdio takes credentials from the environment instead of
  following the authorization spec — so those rules are **skipped with a reason**,
  which `fail_on_skipped` can make fatal, rather than reporting nothing about a
  server they never examined.
- **`guardana plan probe --mcp` prices an MCP run without contacting the server.**
  Reading a manifest cost two requests; the authorization checks send around a
  dozen, which is the number somebody wants *before* pointing this at production.
  The ceiling it reports is deliberately higher than any run spends — each rule
  declares what it would cost alone, because a plan cannot know which one runs
  first and buys the observation the rest then share. An **stdio server is priced
  by refusing**: working out what it would cost means starting it, and starting the
  thing under examination is the one thing this command must not do.
- **`--url` and `--model` are no longer required when `--mcp` is.** The documented
  incantation had become `--url unused --model unused`, and a placeholder a user is
  told to type is a field nobody reads. Naming neither is refused by name.
- **The threat model records what changed underneath it.** `T2` covered a target
  that *answers*; since MCP discovery a target also **chooses an address Guardana
  fetches**, which is a different actor. It now separates the two — an address the
  target picks is refused and reported, an address the operator types is followed
  deliberately, because scanning an internal endpoint is this tool's normal case —
  and replaces a residual-risk note that had promised a metadata-endpoint denylist
  as "v0.7 work" for five releases.
- **A server nobody could reach is not a secure server, and all six say so.** Every
  one of them declines with the invariant it would have established named, because
  silence from a rule means the invariant *holds* — and a report where three checks
  said "not established" while three said nothing at all invites reading the second
  three as clean.
- **`--mcp-token-env`**, so Guardana can probe an MCP server that requires
  authentication at all — which it previously could not. Read from the environment
  rather than an argument, and the value never reaches a report at any privacy
  level. The two checks that need it say so and name it when it is absent.
- **Guardana never calls a tool on an MCP server.** Every observation is made with
  `initialize`, `tools/list` and unauthenticated `GET`s of the discovery documents.
- **The SSRF guard and the check are the same code path.** Discovery is the one
  place in MCP where the server picks a URL and the client fetches it. Guardana
  refuses an address that resolves to the cloud metadata endpoint, into the network
  running the scan, or uses a scheme a client must reject — and the refusal *is* the
  finding, because a scanner that followed the URL to prove it was dangerous would
  have performed the attack in order to report it.
- **The OWASP MCP Top 10 is installed as a seventh catalogue** (`MCP01:2025` …
  `MCP10:2025`), pinned to `version 0.1` because it is a beta document whose next
  revision is expected in October 2026 — one of its entries is already rendered two
  ways in two places OWASP publishes. `guardana taxonomy` shows it.
- **The approved MCP manifest now covers the whole tool declaration.** A server
  could widen an input schema, add a parameter or rewrite a property description
  while every word of the prose stayed the same, and the pin stayed green. Pin
  schema **1 → 2**; a version 1 pin still loads and still compares descriptions, and
  every run that uses one carries a note saying which drift it cannot see, because
  reading it silently would claim coverage the document cannot support.

### Fixed

- **The MCP meter counted half of what a run spent.** One session is two JSON-RPC
  calls, `initialize` and `tools/list`, and the meter recorded one — while the rule
  declared "one request", so the test comparing the two agreed with both and stayed
  green. Metering moved into the transport seam: every call reserves before it is
  sent and records after it returns.
- **`--max-requests` now bounds an MCP probe instead of refusing to run it.**
  `McpServerTarget` never implemented `apply_budgets`, so it inherited the base
  class's refusal of any ceiling — fail-closed and fine while a run cost two calls
  nobody would budget, and useless now that an authorization probe costs a dozen.
- **A run that stopped early no longer prints the tick people scroll for.** The exit
  code said `6` and the saved run said `stopped_by: budget_exhausted` with an
  `indeterminate` gate, while the terminal said `✓ No findings.` over a run that
  ended after two rules. `StopReason` exists because "a report that does not say it
  was cut short reads as a complete pass"; the human renderer was the one output
  that did not say it. Found by running `probe --mcp --max-requests 3` against a
  live server and reading the output rather than the exit code.
- **An stdio MCP server left its pipes open.** `close()` terminated the process and
  released neither descriptor, so a long `monitor` run accumulated a pair per cycle.

And **eight defects an adversarial review found in this release's own code**, before
any of it shipped. Six were the same shape — a confident answer the code had not
earned:

- **A tool listing delivered over SSE read as a refusal.** A streamable-HTTP MCP
  server routinely answers a POST with `text/event-stream`, and this client asks for
  it by name in every `Accept` header — but the authorization observations parsed
  the body with a plain `json.loads` while the JSON-RPC reader unwrapped the frame.
  One wire format, two readers, and the one that drifted silenced the
  unauthenticated-access, audience and session checks at once *and* made the
  discovery check report a HIGH about missing metadata on an open server. There is
  one reader now.
- **A reply nobody could parse counted as a refusal.** `False` meant "the server
  declined"; an unreadable `200` was folded into it, which is a pass on a question
  that was never answered. It is a third answer now, and it reads `inconclusive`.
- **A redirect walked straight past the discovery guard.** The guard checked the
  advertised address once and `urlopen` then followed up to ten hops unchecked, so a
  server that answered its own well-known path with `302 Location:
  http://169.254.169.254/…` was followed there. Every hop is checked now, the
  refusal is reported by `guardana.mcp.discovery_target`, and the response is closed
  rather than leaked on the way out.
- **The session verdict depended on which rules were selected.** The sample reused
  ids recorded by other sections, so on a server issuing one session per credential
  `session_binding` alone reported a critical finding while the same server with
  `token_audience` also selected reported nothing. A profile exclusion must not
  change what is true about the target; the sample is its own handshakes now.
- **An injected transport left the authorization probe on the real network.**
  Replacing the JSON-RPC half does not replace the HTTP half, and the target claimed
  the capability anyway — so tests that believed they had no network made outbound
  requests, saved only by an NXDOMAIN.
- **A conforming deployment was reported for naming a different origin** when the
  operator wrote `:443` out: RFC 9728 documents omit the default port, and the
  comparison was made on the netloc verbatim.
- **`--mcp-token-env` naming an unset or empty variable was not refused.** The run
  then told the operator to pass the flag they had passed — or, for an empty
  variable, treated a credential as present while sending no `Authorization` header
  and blamed the server for issuing no session id.
- **A test that could not fail.** `test_the_maintainer_readme_is_not_published`
  matched the whole of `site/.assetsignore`, whose comment quotes the URL of the
  incident — so deleting the actual ignore entry kept it green.

**The mapping is true again.** OWASP published the 2026 edition of the LLM Top 10
on 3 August 2026 and re-ranked seven entries without renumbering into empty space:
`LLM07` used to be System Prompt Leakage and is now Misinformation, `LLM05` used to
be Improper Output Handling and is now Data and Model Poisoning. Nothing Guardana
published was a lie — the `framework` field on every reference has always said
`OWASP-LLM-2025` — but the short id a report renders meant one thing to this build
and another to an auditor who looked it up, and every saved run widened the gap. See
[`docs/design/taxonomy-editions.md`](docs/design/taxonomy-editions.md).

- **A framework reference is now scheme + edition + local id.** `OWASP-LLM/2025/LLM07`
  and `OWASP-LLM/2026/LLM07` are different controls that share a string, and both are
  installed. Titles and ranks became display data. Every `framework` string Guardana
  has ever written is reproduced byte for byte, so no stored document changes meaning.
- **Framework catalogues are immutable data files with a digest** — six of them, under
  `guardana/core/taxonomy/catalog/` — and every run pins those digests. A report is
  readable in three years without asking which edition was installed.
- **A rule carries both editions where the semantics genuinely overlap.** The canary
  system-prompt check is `LLM07:2025` *and* `LLM08:2026`. What never happens is a
  silent remap onto the matching number, which would file it under Misinformation.
- **The crosswalk is data with explicit relations** — `exact`, `broader`, `narrower`,
  `related` — because the 2026 edition redrew its categories as well as re-ranking
  them, so most pairs are not equivalences. It is read, never applied: a stored
  reference is upgraded only in memory, when somebody asks.
- **`guardana taxonomy`** lists the installed catalogues with their digests, or
  explains one reference and what it corresponds to in another edition. Without it,
  learning that a rule must say `LLM01:2025` meant reading the engine's source.
  See [`docs/usage-taxonomy.md`](docs/usage-taxonomy.md).
- **A coverage fingerprint on every run** (`run.coverage`): one digest over the rules
  and their declared trial counts, the evaluators, the target's capabilities, the
  catalogue digests and any protocol version the target negotiated. This is the
  missing half of the promise `rules_run` started — a run with fewer applicable
  checks must never read as an improvement, and `diff` now says *the reach changed*
  instead of folding it into what was found. A run that recorded no fingerprint is
  reported as **unknown reach**, never as equal reach.
- **`guardana.agent.hidden_context.tool_schema`** — the check the 2026 edition's
  `LLM08 Hidden Context Exposure` asks for directly. A marker planted fresh per run
  inside a *tool description* — hidden context the model reads as trusted
  instruction, carrying internal service names in a real deployment. A robust model
  paraphrases what a tool does; reciting the marker is proof.
- **`guardana.prompt.cost_asymmetry`** and the **`amplification`** evaluator —
  `LLM06:2026`, up four places and reframed as cost asymmetry. Not how long a reply
  is but what it cost relative to the request: a twelve-character prompt answered
  with hundreds of times its own length is an operator paying for an attacker's
  request. Measured on characters, so it works against a provider that reports no
  token counts at all.

### Fixed

Five defects an adversarial review of released 0.12 code found under a green gate.
Two of them were found by *running* the tool rather than by reading it, which is
now the third sieve this project uses on purpose.

- **A pickle padded past the per-member read cap was scanned clean, and reported
  nothing at all.** `pickle_opcode` reads at most 64 MB of each ZIP member — a
  bound that exists so a crafted checkpoint cannot exhaust memory — and threw away
  the fact that it had hit it. Deflate makes that cheap to exploit: **a 66 KB
  `model.pt` hid `posix.system` behind 65 MB of padding and produced zero
  findings**, no CRITICAL and not even the LOW "unscanned" the rule emits
  everywhere else it cannot see. The rule's own docstring already promised
  otherwise: "anything it cannot fully parse becomes a visible finding, never a
  silent clean."
- **The same silence covered an unresolvable `STACK_GLOBAL` inside a ZIP member.**
  A crafted stream whose operands this scanner cannot model — but an unpickler may
  well resolve — reports LOW "unscanned" as a raw `.pkl`, and reported nothing at
  all as a member. `torch.save` writes a ZIP, so the quiet half was the half a real
  checkpoint takes. Both are now decided by one question — was this still parsing as
  a pickle where the rule stopped? — and only then reported, so a real checkpoint's
  tensor storages (larger than the cap, and not pickles) and its one-byte
  `archive/version` stay quiet. That last one is not hypothetical: the first version
  of this fix put a finding on every honest checkpoint, and the existing
  benign-archive test is what caught it.
- **`probe` enforced its request budget once per pass instead of once per run.**
  A canary rule runs in a pass of its own, against a target whose system prompt
  carries that rule's marker, and the target owns the meter that holds the ceiling
  — so each pass started from zero. `--max-requests 5` sent **10** requests against
  the shipped catalog, and the overshoot grew with every canary rule installed,
  while `guardana plan` went on quoting the ceiling as the whole run. Every pass now
  shares one meter, and the manifest reports that meter rather than the sum of the
  passes' overlapping snapshots.
- **`guardana-collector finding list` counted sightings and printed them as runs.**
  A rule that names three bad packages in one `requirements.txt` shares one identity
  across all three, so a *single* scan listed "3 runs" — and the question the column
  exists to answer, printed in its own help text and in
  [`docs/usage-collector.md`](docs/usage-collector.md), is "has this been there
  since Tuesday, or is it new". It now counts distinct runs.
- **An empty model reply was graded as a clean pass.** `content: null` was already
  refused at the transport, because `str(None)` would be graded as the word "None";
  `content: ""` is the same absence in a shape that types fine — an Azure content
  filter returns it, and so does an assistant turn that carried only tool calls.
  It reached the evaluators as a string, where `canary` found no marker in it and
  answered **pass at 0.95 confidence** on a reply carrying no evidence in either
  direction. `Exchange.reply_text` is the seam where that decision belongs, and it
  now reports a blank final turn as no reply, so every evaluator inherits one answer.

Two more, uncovered while building the tool-schema check above — both the same
shape as the five, and both found by asking what would happen if the marker were
never planted rather than by reading code that looked right:

- **A canary planted in a tool *schema* was never actually planted.**
  `TrajectoryRule.with_canary` substituted the fresh per-run marker into tool
  results only, so a rule carrying its marker in a tool description would have hunted
  for a token nobody handed the model — the evaluator finds nothing, and the rule
  reports a confident pass for a model that disclosed everything. Found while writing
  the rule that needs it, which is why that rule ships with a fixture asserting the
  fresh marker reaches the description.
- **A declared canary that nothing plants is now a load-time error.** The gate
  covered rules graded by the `canary` evaluator and demanded
  `requires: [plant_system_prompt]`; it said nothing about `tool_call`, which grades
  a marker leaving through a tool argument, and nothing about an agent rule that
  carries its own marker. It is now keyed on the declared `expect.canary` and
  satisfied by any of the three routes a marker can actually reach a model by.
- **The example third-party rule pack named a bare `LLM06`.** Its YAML is the
  one file in this repository that stands in for everybody else's rule pack, and
  every local gate passed over it: `examples/custom_rule` is isolated from the main
  test environment on purpose, so `uv run pytest` never loads it. CI caught it. The
  command is now in the gate list in `CLAUDE.md`, where the six that miss it are.

### Changed

- **Saved runs move to schema 3, the collector envelope to 8.** Both carry the
  *title* of each framework reference beside its framework and id: a short id is not
  self-explanatory once a framework has two editions, and the collector holds no
  catalogue to look one up in — by design, since it never depends on the engine.
  Older documents migrate forward in memory one step at a time, and the title is
  recovered from the installed catalogue for the exact `(framework, id)` pair the
  document already carries. Nothing is guessed and no reference is remapped.
- **`Rule.digest()` no longer covers the framework mapping.** A rule remapped to a
  renamed standard sends the same prompts and grades them the same way, so it is not
  a different test. Leaving the mapping in would have made `diff` announce that every
  rule "changed definition" in this release — true of the declaration, useless to a
  reader, and it would bury the one rule whose corpus really moved. Across a version
  boundary `diff` now says a digest moved without asserting why, because there a
  digest moves when a rule changes *and* when what a digest covers changes.
- **A framework reference in a rule names its edition.** `taxonomy: [LLM01]` is now a
  load-time error listing the editions that define it. This is **breaking for a
  third-party YAML rule pack** that names OWASP ids, and it is deliberately breaking
  rather than defaulted: any default would silently change what a rule claims to an
  auditor the day a catalogue is added. A framework that publishes no editions keeps
  its bare ids — `AML.T0051` and `supply-chain` are unchanged. The Python constants
  gained the same suffix (`OWASP_LLM03_2025`, `OWASP_ASI01_2026`).
- `TrackedFinding.occurrences` is now `TrackedFinding.runs`, because that is what
  it counts and what every caller already claimed it counted.

### Documentation

- **`docs/` pages state counts as fact, and now a test pins them to the registry**
  like `FEATURES.md` and `site/index.html` already were. Both had drifted:
  `how-it-works.md` described eight runtime rules through the five agentic checks
  that took the number to thirteen, and `usage-scan.md` showed a dogfood transcript
  claiming seventeen rules ran when nineteen do.
- **Every design document opens with a status, and a test says so.**
  `collector-domain-model.md` still read `proposed · Target: v0.7 · Current
  maturity: experimental` four releases after persistence, authentication and
  tenancy shipped; it is now `superseded by` the five documents that replaced it,
  with the body kept as the record. `enterprise-readiness-plan.md` had no status
  line at all and now carries one. The existing staleness test deliberately exempts
  `docs/design/` — a design document is allowed to state the problem it solved —
  which is exactly why the status line needed its own check.
- `ROADMAP.md` said five evaluators ship; the generated catalog lists six.
- **The plugin-trust snippet in `SECURITY.md` named an API that does not exist**, so
  the one page telling somebody how to bound an untrusted rule pack could not be
  followed.
- **The landing page's deployment is written down rather than clicked.** `wrangler.jsonc`
  at the repository root pins one public hostname (`workers_dev` and `preview_urls`
  off), and `site/.assetsignore` keeps the maintainer README out of the published
  site — it had been served at `/README.md`.

## [0.12.0] - 2026-08-07 — verification where the developers already are

### Added

- **`guardana.testing.assert_secure` — Guardana as an ordinary `pytest`
  assertion.** A security check that needs its own command, its own pipeline stage
  and its own report is a check somebody runs on Tuesdays; a team already runs
  `pytest`. `assert_secure(target, preset="ci")` takes a path or any `Target`,
  runs the same rules through the same `Runner`, applies the same redactor and
  asks the same three-state gate as `scan` and `probe`, and raises
  `SecurityAssertionError` (an `AssertionError`) with a readable report. On a pass
  it returns the `ScanResult`, so a test can go on to assert something narrower.
  Deliberately **not** a second engine: a check that passes here and fails in CI is
  a fact about the target, never a disagreement between two implementations of
  "secure". [`docs/usage-testing.md`](docs/usage-testing.md).
  - **A run that could not reach a verdict raises too**, and says which it was.
    An empty registry, an over-narrow profile, an endpoint that was down, a check
    that could not grade — every one of those is indistinguishable from a clean
    result until somebody makes it not be, and a test suite is where that goes
    quiet. `.outcome` carries `FAIL` or `INDETERMINATE`; `.result` carries the
    channels.
  - **The failure message is redacted** by the profile's privacy policy before it
    is raised. The message goes into a CI log, which is a file on somebody's build
    server, and a security tool that writes the credential it just found into one
    has made a second incident out of the first.
  - **A path that does not exist refuses**, rather than scanning nothing and
    passing — the same refusal `guardana scan` makes, for the same reason.
- **`guardana.adapters.langchain` — verify the model your application actually
  calls.** `langchain_target(chat_model)` wraps any LangChain chat model as a
  Guardana target, so a probe goes through the client, credentials and
  configuration that object carries instead of an endpoint underneath it that
  nobody deployed. `langchain` is **never imported**: the adapter is duck-typed
  against `invoke`, so `guardana-core` gains no dependency and no release of the
  framework can break the tool that checks it. An object that is not a chat model
  is refused when the target is built, not on the first prompt of a paid probe; a
  reply with no text is an error rather than an empty string, because an empty
  reply grades exactly like a well-behaved model. Reported token usage is counted,
  and an absent count is recorded as unknown rather than zero. Tool calling is
  deliberately not wired up — the agentic rules skip and say so.

### Fixed

- **Evidence redaction covered two channels out of three: `errors` went out
  untouched.** A `CheckError.reason` is an exception message, and an exception
  message is written by whoever raised it — a third-party rule, a provider, a
  parser handed the model's own reply. `post_json` puts 120 bytes of an
  unparseable response into one, and a gateway refusing a request routinely quotes
  the credential it refused. That text reached the JSON report, the SARIF file and
  the collector envelope through the one seam that exists to stop it, on the very
  path whose comment says it "must not depend on whoever wired the reporter up".
  Its *length* had been bounded from the start, which is the half that does not
  keep a secret out of a report. `redact_result` now redacts all four channels, and
  the renderer-seam test carries an error whose reason contains a fake credential,
  so every renderer is held to it.
- **`--preset ci` silently turned redaction off.** A preset "tunes only the
  failure bar" by its own docstring, and inherited `Profile`'s library default of
  `full` evidence — so the most CI-shaped way to run this tool was also the only
  one that stopped redacting what the target said. Secrets were still removed at
  every mode; email addresses were not. Every preset now carries the same privacy
  policy `default_profile()` does.
- **`key revoke` was recorded in the audit log under no tenant.** `key.create` was
  filed against a project and `key.revoke` against nothing, so `audit list
  --project acme/web` showed every credential a team was given and none that were
  taken away — the half somebody investigating actually came for. `revoke_key` now
  writes its own audit row, in the same transaction and under the project the key
  reached, exactly as `store_key` does.
- **A tracked finding's dates came from a second clock.** `received_at` came from
  the store's injectable clock and the sighting from a wall-clock read, so a
  finding's `first_seen` could disagree with the run that first saw it — and
  migration `0006` built those dates from `received_at`, which would make
  backfilled rows and new rows mean different things.
- **Dead code in the collector, with a docstring contradicting what ships.**
  `_refuse_a_dashboard_that_cannot_load` explained at length why the panel is
  refused on an authenticated collector, which 0.11 deliberately stopped doing when
  the panel gained sessions. Removed.
- **A comment in `delete_organization` described a cascade that does not happen.**
  The `org.delete` event is filed under no tenant on purpose, so it outlives the
  organization it describes; the comment claimed the opposite, and a comment that
  misdescribes its own code is the same defect as documentation that does.

### Documentation

- **The maintainer runbook now says to make the container packages public.** A
  package created by a workflow is private whatever the repository's visibility
  is, so the first release pushed two images that the very command the
  documentation tells users to run could not pull. Found by pulling one with no
  credentials, which is the only way to find it: logged in, it works.

## [0.11.0] - 2026-08-06 — life after a finding arrives

### Added

- **A finding is an entity, with a lifecycle and waivers that expire.** The
  collector recorded every sighting and nothing anybody decided, so triage lived
  in a spreadsheet while the one place with the history knew nothing about it.
  `finding status` records `acknowledged` / `in_progress` / `resolved` /
  `false_positive` with an owner; `finding waive` accepts a risk with an
  approver, a reason and a date it lapses — all three required, because a waiver
  that never comes back is a permanently disabled check with better manners.
  Migration `0006` builds the entity from what is already stored, so a collector
  that has been running for months arrives with its history rather than an empty
  list.
  - **A `resolved` finding reopens when it is seen again.** The transition the
    model exists for: a fix that did not hold must not stay green because
    somebody once ticked a box. `false_positive` stays — the identity *is* the
    rule plus the location — and `accepted_risk` is undone by its date, not by a
    sighting.
  - **Expiry is applied when you read.** The collector runs no scheduler, so a
    status that only became correct when a job ran would be quietly wrong in
    between; a lapsed waiver lists as `open` and says which waiver ran out.
  - **It is not a second definition of accepted risk.** A collector waiver never
    changes a build's exit code — that is `guardana baseline`, next to the code —
    and both docs say so, with the same three fields and the same expiry rule.
  - Identities are addressed by unique prefix, like git; an ambiguous one is
    refused with the candidates and nothing is changed.

- **An audit log, and the column it fills.** Every state change — keys created and
  revoked, tenants created, renamed and deleted, findings triaged, schema migrated
  and rolled back — is recorded with its actor, and **every row says what kind of
  actor it was**: a `key` was presented and matched, a `cli` name was asserted by
  somebody who can already reach the database. Calling the second one
  authentication would be the same false green this project refuses in a verdict.
  `api_keys.created_by`, which has existed since 0.8 with nothing filling it, is
  now filled by the same actor, and a stored submission records **which key wrote
  it** — the open question the tenancy design left. Reads are not logged: a log
  that grows with every dashboard refresh is a log nobody reads.
- **Retention, and deleting things on purpose.** `retention set|show|apply` per
  project, with `--dry-run` first and a **refusal when no policy is set** —
  deleting on a default is a collector that removes evidence because nobody said
  not to. Applying is a command, never a background job, so "what deleted my
  evidence" is answerable from the audit log rather than from source. Retention
  never prunes the audit log, and a tracked finding **outlives its occurrences**,
  so a finding that reappears after a prune is not re-triaged from scratch.
  `project delete` and `org delete` both demand `--yes`, and deleting an
  organization refuses while it still holds projects. `system merge` moves a
  typo's runs onto the real system — the one operation here that edits the past,
  and the reason an inventory stays trustworthy.

- **The panel works on a collector that requires keys.** It used to refuse to
  mount there, correctly — a browser has nowhere to put a bearer token, so every
  panel would have loaded empty. Now the browser **signs in with a read-scoped
  key**, kept in an `HttpOnly`, `SameSite=Strict` cookie the page cannot read;
  `key revoke` ends the session and there are no user accounts to invent. The rule
  the design rests on is enforced in the guard, not left to a browser flag: **the
  cookie authenticates reads and nothing else**, so a page on another origin
  cannot make a signed-in operator's browser submit findings.
- **Limits on ingest.** A request-body ceiling (`GUARDANA_MAX_BODY_BYTES`, 8 MiB,
  `413`) counted in **bytes off the wire** rather than from `Content-Length` — a
  header is a claim, and a chunked request need not make one — and a per-caller
  rate limit (`GUARDANA_RATE_LIMIT_PER_MINUTE`, 120, `429` with `Retry-After`).
  A value that is not a number is refused at start-up instead of quietly becoming
  "no limit"; `0` turns a limit off and is something somebody typed. Liveness and
  readiness are never limited, because a readiness probe answered `429` is a
  rolling deploy that stalls. The limiter is per worker process and says so.

### Fixed

- **`finding list --status` returned a short page.** The filter ran after the
  limit, so asking for five open findings could return three while more existed —
  a listing that understates how much there is, which for findings is the wrong
  direction to be wrong in. It now filters in SQL, expiry included, so a lapsed
  waiver is found by asking for `open` and never by asking for `accepted_risk`.
- **The body-size check buffered the whole request before refusing it.** It now
  turns away a declared oversize before reading a byte, and cuts off a chunked
  request as it arrives rather than measuring it afterwards.
- **The rate limiter kept one entry per caller forever.** An unauthenticated
  collector keys on the peer address, so a long-running process facing the
  internet grew a dictionary that nothing emptied.
- **A usage error from the collector CLI reported itself as a database outage.**
  An ambiguous identity prefix came back as "could not reach the database", which
  sends an operator to look at PostgreSQL while PostgreSQL is fine — the same
  mistake as reading a database outage as a rejected credential. Found by running
  the command, and now exits `3` with the candidates listed.

## [0.10.0] - 2026-08-06 — company-ready

### Fixed

- **A mistyped `--reporter` URL ended a run with a traceback and an exit code
  outside the documented table.** It is a usage error, so it now exits `3` — and
  it is checked *before* the run starts rather than at submission time, because
  the submission is the last thing a run does: a probe that spends its whole
  budget and only then finds out the URL was a typo has verified something and
  told nobody.
- **The message told people their hostname was an unsupported scheme.**
  `server://collector.example.com:8000` reaches `urlsplit` as a bare `host:port`,
  which parses as a *scheme* of `collector.example.com` — so the tool reported
  exactly that, and sent the reader after entirely the wrong thing. It now names
  the URL it was given and both forms that work. The scheme stays required: a
  guessed `http://` would ship evidence in plaintext to a remote host, and a
  guessed `https://` would break every local evaluation.

### Added

- **The development Compose file now creates the database it documents.** Its own
  instructions told you to point a collector at `guardana`, and it only ever
  created `guardana_test` — so following them produced `database "guardana" does
  not exist`. Found by running the documented command, not by reading it. On a
  volume that already exists, recreate it or create the database by hand; the
  init script says how.
- **A clean install is now a gate, not a ritual.**
  `scripts/clean_install_check.py` builds an empty virtualenv, installs the five
  distributions into it and runs the commands the documentation tells people to
  type — asserting the **exit code** of each, not just that nothing crashed. A
  scanner whose rule catalog failed to load prints "no findings" and exits `0`,
  so the check scans a deliberately malicious fixture and requires a `1` as well
  as scanning clean input and requiring a `0`. It runs in CI on every push, in
  `release.py`'s gate, and inside the release workflow *before* the upload step.
  This is the defect class that got `0.9.0` tagged and cancelled; it was found by
  hand, and finding it by hand is not a control.
- **Backup and restore, exercised rather than described.** The documented
  `pg_dump`/`pg_restore` procedure is run by the test suite: it restores into a
  database that never held the data — restoring over the live one passes even
  when the dump is half-written — reads the result back through the same
  tenant-scoped store the server uses, checks the restored database reports the
  same applied migrations, and then writes to it, because a restore you cannot
  write to afterwards is half a restore. Running it for the first time found a
  real trap, now documented and refused by the test: **`pg_dump` 17 produces a
  dump that cannot be restored into PostgreSQL 16**, so a backup can look fine
  every day and fail on the one day it matters. Take the dump inside the database
  container, where client and server cannot drift apart.
- **A production deployment guide, and the Compose file it describes.**
  [`docs/deployment.md`](docs/deployment.md) covers standing a collector up,
  putting TLS in front of it, upgrading it in the right order, what to watch, and
  what this deployment still does not give you. Every credential in
  `deploy/docker-compose.yml` is `${VAR:?}` — Compose refuses to start rather
  than fall back to something guessable — the database publishes no port, the
  collector publishes on loopback so terminating TLS is a deliberate act, and
  migrating is a one-shot command rather than something a restart does to you.
  Written by running it: `migrate`, `up`, `bootstrap`, a scan reporting into it,
  and `run list` reading the run back.
- **CI beyond GitHub.** Copyable templates for **GitLab** (includable from a
  remote URL), **Jenkins** and **Azure DevOps**, plus a one-line generic
  container pipeline for anything else — all running the published image, so the
  version of Guardana in a pipeline is a tag somebody pinned. Three properties
  are held by tests rather than by review, because they are the three a copied
  pipeline gets wrong: the exit code reaches the platform (no `allow_failure`, no
  `continueOnError`, no `|| true`), the report is published on the run that
  *failed* rather than only on the green ones, and the entrypoint is overridden
  where the platform wraps commands in its own shell. The generic recipe
  redirects on the host rather than writing inside the container, so the
  workspace can be mounted read-only and no file arrives owned by a uid the CI
  does not have.
- **An SBOM and provenance on every release.** One CycloneDX document per
  distribution — `guardana-cli`'s bill of materials is not `guardana-server`'s,
  and a merged one would tell a collector operator they had installed Typer —
  attached to the GitHub Release, plus Sigstore build provenance over the built
  distributions and PyPI's own PEP 740 attestation, plus an SBOM and provenance
  beside each container image. Generated by `uv export` from the same `uv.lock`
  the tests resolve against, so there is no second resolver to disagree with the
  first, and each written file is read back and checked against that package's
  own metadata before the release keeps it. CI does the same on every push, so a
  tag is never the first time a release artifact is produced. `SECURITY.md` has
  the commands to verify it all.
- **Official container images for both halves.**
  `ghcr.io/guardana/guardana` (the CLI) and `ghcr.io/guardana/guardana-collector`,
  published on every release for `linux/amd64` and `linux/arm64`, with an SBOM and
  a signed provenance attestation pushed alongside each. Two-stage builds, so no
  build tooling ships; a fixed non-root uid, so a deployment can pin `runAsUser`
  and a mounted volume's permissions are predictable. Tags are the exact version,
  the moving minor, and `latest` — and a prerelease moves neither of the last two.
  Both are **built and run** in CI on every push (`scripts/image_smoke.py`), not
  first at the tag: among the checks is a scan of the deliberately malicious
  fixture that has to exit `1` from inside the image, because an image whose rule
  catalog failed to ship reports "no findings" and exits `0` forever. CI caught
  what a Mac could not: a workspace only its owner can read is unreadable to the
  image's non-root user, so a scan of it **refuses** rather than reporting an
  empty directory — `--user "$(id -u):$(id -g)"` is the documented answer, and
  the smoke test now proves that answer works.
- **`guardana-collector serve`** — the collector starts with a command instead of
  an ASGI factory string. It binds **loopback** unless `--host 0.0.0.0` is typed,
  builds the app before the server starts (so a storage backend nobody chose and a
  collector that could authenticate nobody are refused in words, with an exit code
  from the table, rather than as a traceback out of a worker), and is the one
  command dispatched without opening a database connection of its own — a
  collector must be able to start while its database is still coming up and then
  say so on `/readyz`. The ASGI server is a new **extra**,
  `pip install "guardana-server[serve]"`, deliberately not a dependency.
- **The declared-dependency check now covers all five packages, and the
  namespace.** It was written for `guardana-cli` and only ever asked about that
  one. It now asks about every distribution, and asks a second question the
  first cannot: `packages_distributions()` maps top-level module names, so all
  five packages answer to `guardana` and a package importing a sibling it never
  declared is invisible to it.

## [0.9.1] - 2026-08-05

### Fixed — a clean install did not start

- **`guardana` crashed on every command in a fresh environment**, with
  `ModuleNotFoundError: No module named 'click'`. `guardana.cli.main` imported
  `click` to make usage errors exit `3`; Typer used to bring it, and **Typer 0.26
  vendored Click and dropped the dependency**. Nothing in the gate could see it —
  the gate runs where click is installed for other reasons — and it was found by
  installing the released packages into an empty virtualenv and running them.
  Whichever Click a given Typer raises from is now patched, neither is required,
  and finding *none* of them raises rather than silently letting a usage error
  exit `2` against a documented table a pipeline gates on.
- **`guardana-cli` imported `yaml` without declaring `pyyaml`.** It worked because
  `guardana-core` brings it, and a dependency that is only there transitively is
  one a dependant can drop without anybody noticing until a clean install fails.
  Found by the test written for the defect above, on its first run.
- Two tests now hold that line: one resolves every declared distribution to the
  modules it actually provides (`pyyaml` provides `yaml`, and guessing from the
  name would have passed while the hole stayed open) and fails on any third-party
  import nothing declares; the other simulates the clean-install condition and
  asserts a usage error still exits `3`.

## [0.9.0] - 2026-08-05

### Added

- **The collector knows whether a run passed.** A submission said which rules ran
  and what they found, and nothing about the run itself — so "is production
  failing" had no answer in it, because findings without a verdict cannot
  distinguish a failing run from one whose findings a baseline waived. Envelope v7
  carries the run's **gate**, its id, when it actually ran, which build produced
  it, what redaction was applied and what it cost. **An absent gate is recorded as
  unknown and never as a pass**: a fleet with one old agent must not read as green
  because the old agent could not speak.
- **A finding is followed across runs.** Each finding carries the identity
  `guardana.core.diff.finding_identity` has computed since 0.6 — the rule and where
  it was found, never the evaluator's rationale. Computed by the engine and only
  there: the collector does not depend on `guardana-core`, so recomputing it would
  put a second definition of "the same finding" in a package that cannot import the
  first. `guardana-collector finding list` groups by it and says how many runs saw
  each and when, which is the "has this been there since Tuesday" question.
- **A retried pipeline job is stored once.** The same run id in the same project is
  accepted with `200` and `"duplicate": true` rather than stored again — a retry is
  not a failure and must not turn a pipeline red, and storing it twice would make
  "production got worse" answer from a duplicate. A pre-v7 agent sends no run id,
  identifies nothing, and is still stored every time.
- **`guardana-collector run list`** — the time axis, with the gate, the system and
  the environment. A run that did not say prints `unknown`, never blank.
- **A collector knows what a run verified, where it runs, and which version of
  it.** `guardana scan|probe|monitor --ai-system support-agent --environment
  production --deployment-id 2026-08-05.3`, or the same three as
  `GUARDANA_AI_SYSTEM` / `GUARDANA_ENVIRONMENT` / `GUARDANA_DEPLOYMENT_ID` so a
  pipeline sets the repository default once and one job still says it is
  production. Until now a project's history was one undifferentiated stream in
  which last night's production check sat beside a laptop experiment, and no
  question about either could be answered. The engine has carried the vocabulary
  since 0.7 and nothing had ever filled it in — that debt is closed.
- **A key may be pinned to one environment**, and then it writes and reads only
  that one: `guardana-collector key create --project acme/web --name prod-ci
  --environment production`. A run declaring a different environment is **refused**
  with `403`, never relabelled — "prefer the more specific one" would re-open
  exactly the hole the tenant rule closes. A run declaring *nothing* is labelled
  with the pin, because the credential asserted it and the run did not contradict
  it; storing it unlabelled would let a pinned key write evidence into a place it
  cannot itself read. The pin is optional on purpose: one pipeline that deploys to
  three environments needs one credential, not three.
- **`system list`, `environment list` and `deployment list`** on
  `guardana-collector`, each narrowable to a project. Systems and environments are
  *inferred from what a run names* rather than created in advance — requiring an
  administrator first would put a human step between a pipeline and its first
  report, and pipelines that fail on a missing prerequisite get commented out
  rather than fixed. The cost is a typo creating a second system, and the listing
  is what makes that mistake visible rather than silent.
- **Envelope v6** carries the deployment block; the collector accepts 2–6, so a v5
  agent keeps reporting and simply says less. Only the deployment block travels,
  never the whole run manifest: the manifest is the engine's reproducibility record
  and is versioned independently on purpose.
- **The commit is read from whatever CI this is** (`GITHUB_SHA`, `CI_COMMIT_SHA`,
  `GIT_COMMIT`, `BUILD_SOURCEVERSION`). The environment and the AI system are
  **never** guessed: a branch is not an environment and a repository is not an AI
  system, and a guessed value is one a team would build a dashboard on.
- **One collector can serve two teams.** The tenant is a **project**, a project
  belongs to an **organization**, and every API key names exactly one project.
  Until now every key a collector issued could read every finding it held, so one
  instance served one team — which is why its maturity label said `experimental`
  and why "project/environment isolation" is still unticked on the company-ready
  checklist. A cross-tenant read now returns nothing: at the store, over HTTP, per
  entity, between two organizations and between two projects of one organization,
  on **both** the in-memory and the PostgreSQL store. Those tests were written
  with the feature rather than after it, and they take the database fixture — so
  "the isolation test did not run" cannot be a green build.
- **`guardana-collector bootstrap --org acme --project web`** creates the
  organization, the project and the first key in one command, and prints the key
  once. It exists because tenancy would otherwise have taken the first run of a
  real collector from two commands to five: a security boundary added carelessly
  is how a tool anybody could run becomes a tool only its authors run. It refuses
  when that project already exists, naming `key create` instead — a command that
  quietly succeeds the second time is one somebody runs twice in a script and
  never notices issued two credentials. The granular `org create`,
  `project create`, `org rename`, `project rename` and the `--project` filter on
  `key list` are for the second team, not for the first run.
- **Migration `0003` adopts a database that already has data** rather than
  refusing to run. Pre-tenancy submissions and keys land in one organization
  called `adopted` — named for what happened, not `default`, which is a name
  nobody chose — created **only when there is something to adopt**, so a fresh
  install gets no tenant it never asked for. `org list` marks it and says it came
  from migration 0003, so an administrator who upgraded without reading a
  changelog still finds out where their history went, and `org rename` exists
  because a name a migration invented must not be permanent. Pre-existing keys
  keep working: adoption must not be a silent invalidation of a fleet of
  credentials.
- **`0003`'s rollback refuses when it would merge two tenants.** Dropping the
  tenant column on a database serving two teams would fold their evidence into
  one undifferentiated pile. It is the fourth thing the migration runner refuses
  and the only one tied to a single migration, because only this one can destroy
  an isolation boundary. The check counts the union of the submissions and the
  keys: one project in one table and another in the other is still two tenants,
  and a per-table count would see "one and one" and let the merge through. The
  down file also restores the two indexes the forward migration dropped.
- A test fails the build on any **local documentation link pointing at a file
  that does not exist**. It found one on the first run: `docs/usage-plan.md`
  pointed at a `configuration.md` that has never existed, through the whole of
  0.7 and 0.8. A reader who follows a link to nothing concludes the project is
  unmaintained, which is a cheap thing to be wrong about and an expensive
  impression to correct — and nothing else in the gate could see it.

### Fixed — found by reviewing this release's own code

- **`guardana scan` on a path that does not exist printed "✓ No findings" and
  exited `0`.** A typo'd path in a pipeline gated a build on nothing at all —
  the worst shape of false green this project has, reached with one keystroke.
  It is now a usage error (`3`), the same code `plan`, `target inspect` and
  `baseline` already used for it. An *empty* directory is still a clean pass:
  nothing to find is not nothing to look at.
- **`finding list` reported the alphabetically-largest severity, not the worst.**
  `MEDIUM` sorts above `HIGH` and `CRITICAL`, so a finding seen at both would have
  been shown as the lower one — a security tool understating its own severity,
  which is the direction that matters because nobody re-checks a finding the tool
  already called minor.
- **The environment pin is enforced by the store, not by the endpoint.** It lived
  in `POST /findings`, so any other caller of `Store.add` could have written a row
  labelled with an environment its credential may not reach — and the next caller
  is item 23's run persistence, not a person reading the file. Both stores now
  reconcile the scope's pin themselves, which is the same move as `PostgresStore`
  refusing an unscoped query: a boundary nobody can route around beats one
  everybody has to remember.
- **A saved run and the collector disagreed about which environment a run was.**
  The collector folds `Production` and `production` into one name; the agent kept
  the raw spelling, so the same run was filed under two names in two places — and
  `guardana diff` compares saved runs, so it would have surfaced as a change nobody
  made. Found by reading the artifact the command actually wrote, not the object in
  memory.
- **A well-formed key this collector never issued had no test.** Every other
  refusal did — malformed, wrong secret, revoked, expired — while the path a
  fabricated or deleted credential actually takes was only ever reached by
  accident. It now has one, verified by making an unknown key succeed. The same for
  a key whose scopes this build cannot read.
- The inventory query interpolates a column name, which was safe because of *who
  called it* — a property the next caller silently removes. It is now checked
  against the three columns it owns.
- [`docs/privacy.md`](docs/privacy.md) now states that what a run declares about
  itself — system, environment, deployment, commit and model digests — travels
  **unredacted**, and why: redaction is for attacker-influenced evidence, and
  redacting a commit would destroy the identity that makes a history answerable
  while protecting nothing. A new category of data leaving the machine has to be
  written down where a reader looks for that.

### Fixed

- **A refused submission repeats the collector's own reason** instead of always
  advising a schema-version check. A key pinned to another environment answers
  `403` and says so; telling that operator to check a schema version sends them
  after the wrong thing entirely — the same mistake as reporting a database outage
  as a rejected credential, which 0.8 fixed one layer down.
- **The documented way to report into a collector had never worked.**
  `--reporter server://https://collector.example.com` POSTed to `/`, which no
  collector serves, so every submission came back `404`, the CLI printed a
  warning, and the scan still exited `0` — a whole fleet could report nothing
  while a dashboard showed stale data as current, which is precisely the failure
  this project says matters most. The reporter now appends the collector's ingest
  route to a bare URL and leaves a URL that already names a path alone. The gate
  could not see this: the one test pairing the two captured the reporter's bytes
  with a fake transport and then posted them to `/findings` by hand, proving the
  two agreed on the *body* and nothing at all about the *path*. There is now a
  test that drives the real reporter into the real app.

### Changed

- **`Store`'s four methods take a `TenantScope` first** (`add`, `submissions`,
  `trend`, `records`). The scope lives in the signature rather than in a
  per-request repository handed out by `store.for_project(id)`: that shape makes
  it impossible to add a method without a scope, and equally possible to park an
  object holding a tenant in a module global where the next request reuses it. The
  property the shape would have bought is bought with a test instead —
  `test_no_store_method_is_unscoped` walks the protocol and fails on a fifth
  method without one. `PostgresStore` raises `UnscopedQueryError` on
  `TenantScope.unauthenticated()`, on read and on write alike, so a scope that
  belongs to nobody cannot reach durable evidence.
- **The project comes from the key, never from the envelope.** If the envelope
  named it, the runner would declare where it writes, and a credential that does
  not bound the write is not a boundary. The envelope therefore **stays at v5**
  and `guardana-core` is unchanged by the tenancy work: an agent and a collector
  still upgrade independently, and no fleet has to move in step with a collector.
  The cost is accepted and real: a team with ten projects needs ten keys in CI.
  If the envelope ever carries a project identifier, a mismatch with the key must
  be a refusal and never "prefer the more specific one".
- `guardana-collector key create` **requires `--project`** and does not guess even
  when exactly one project exists: issuing a credential against a tenant nobody
  named has the same shape as a default credential. `POST /findings` echoes the
  project it wrote into alongside the credential that wrote it.
- `guardana-collector` **honours the product's exit-code table on bad flags.**
  Argparse exits `2`; the table the rest of the tool uses says `3` for a usage
  error, and a table the tool itself does not honour is a contract a pipeline
  cannot gate on. `--help` still exits `0`.
- `store_key()` takes a `TenantScope` rather than a `project_id`: the reach of a
  key *is* a tenant scope, so the project and the optional environment pin travel
  together as one value that cannot disagree with itself.
- Environment and AI-system names are **normalized at the door** — folded to lower
  case and stripped — so `Production`, `production ` and `production` are one
  environment. Normalized rather than rejected on ingest: a collector that refused
  a submission because a label was untidy would trade a team's evidence for its
  own tidiness. The strict check lives in the CLI, where a human typed it.
- `store_key()` no longer takes `created_by`. The column exists, nothing has ever
  been able to fill it, and there are no human identities yet to fill it with — a
  parameter every caller passes `None` to is a promise the code does not keep. It
  is written by the audit log, where "which identity issued this credential" is
  the question being asked.
- The collector command is a package (`guardana.server.cli`) rather than one
  module. Migrations, tenants and keys are three responsibilities, and a file that
  grows a fourth stops being readable in review. The console entry point is
  unchanged.
- **Design documents are named for their topic, not for their date.**
  `2026-08-03-collector-persistence-design.md` is now
  [`collector-persistence.md`](docs/design/collector-persistence.md), and the
  enterprise-readiness plan and the new tenancy design moved the same way. Four
  of the seven documents already used topic names, so this is a return to the
  convention rather than a new one. A filename that leads with a date tells a
  reader the age of a document instead of its subject, and an accepted decision
  does not expire on a schedule; the date now lives in the header beside the
  status. [`docs/design/README.md`](docs/design/README.md) writes the convention
  down, including what each status means and why an accepted decision is
  superseded rather than rewritten.
- The enterprise-readiness plan now opens by saying it is a **historical input
  document** from 2026-08-02, largely delivered and partly reconsidered — so it
  is not mistaken for the roadmap by anyone who finds it first.
- Dependency upgrades. Development tools take a **floor** bump, because their
  version decides what the gate says: ruff `0.16.1`, mypy `2.3.0`, pre-commit
  `4.6.1`, types-pyyaml. The pre-commit ruff hook moves with it, so a local commit
  and CI lint with the same ruff.
- **Production floors are deliberately left where they are.** Dependabot proposed
  raising `fastapi>=0.115` to `>=0.141.1`, `typer>=0.12` to `>=0.27.0` and
  `psycopg[binary]>=3.2` to `>=3.3.4`. A floor should be the oldest version whose
  API is actually used; raising it to whatever resolved today narrows what every
  user may install and buys nothing. The lockfile takes the newest of all three —
  we test against them, users are not forced onto them.
- Actions: `actions/checkout` and `astral-sh/setup-uv` to v7 in CI *and* in the
  shipped composite action, and `github/codeql-action/upload-sarif` to v4 — the
  last one runs in **users'** pipelines, and v3 is on its way out.
- `ruff format` no longer touches Markdown. Ruff 0.16 began formatting Python
  blocks inside prose; its proposals here exploded a compact illustrative import
  into thirteen lines and inserted blank lines into three-line snippets. The
  formatter owns `.py`; documentation is written for a reader. A version bump must
  not silently change what the gate means, which is the same reason the lint rule
  list is curated rather than `ALL`.
- Ruff 0.16's new `PLR0917` (too many *positional* arguments) is suppressed on the
  six typer commands that already carry `PLR0913`, for the reason already written
  there: every parameter is a CLI flag typer derives from its name, and none of
  them is ever passed positionally.

## [0.8.0] - 2026-08-03

### Security — found by reviewing this release's own code

The same adversarial pass applied to the collector work and the 0.7 fixes below,
before either was pushed. Reviewing a design and reviewing the code that came out
of it find different things; so does reviewing code written an hour ago.

- **The redactor's output format was a smuggling envelope.** A second pass skips
  spans the redactor already wrote — that is what makes redacting twice idempotent
  — and it recognised `[redacted:` *anything* `]`. Evidence is the model's reply,
  so anything able to make a model emit `[redacted:` around a credential carried
  it through the redactor untouched. Only this redactor's own shape is skipped now:
  a lower-case label and an optional twelve-hex digest, into which no secret,
  address or IP fits.
- **A durable store made an unbounded read possible.** `GET /findings` fetched
  every submission and sliced in Python. The in-memory store was safe from that
  only because it forgets; PostgreSQL has no upper size, so one request became
  "load the entire finding history into memory". The bound is applied in SQL now,
  and the `Store` protocol carries it.
- **A database outage was reported as a rejected credential.** Checking a key
  against an unreachable database answered `401`, which sends a fleet off to
  rotate credentials that were fine while the agent-side warning talks about
  schema versions. It answers `503` now; `/readyz` already tells any caller
  whether the database is reachable, so the distinction leaks nothing.
- **The dashboard now refuses to mount on an authenticated collector.** It is a
  browser page that fetches its own data, and a browser cannot present a bearer
  token — so every panel would have loaded empty and an absent capability would
  have looked like a broken one.
- `has_any_key` was removed: its docstring described a use that did not exist, and
  an unused function in a security module is surface with no consumer.

### Added — a collector nobody can talk to anonymously

Second item of the collector work. Every route that carries a finding now needs an
API key. Tenancy is still absent, so every key sees everything in one collector
and pointing two teams at one instance is not yet safe — that is the next item,
and the maturity label stays **experimental** until it lands.

- **API keys for runners**, hashed at rest and shown once. A collector database is
  a list of every security finding an organisation has; a stolen backup must not
  also be a set of working credentials for the thing that produced them. There is
  no command and no endpoint that returns a key after `key create` prints it.
- **Two scopes, not one.** `ingest` writes runs, `read` browses them, and
  `key create` defaults to `ingest` alone — a CI job needs to write and never to
  browse, and one scope covering both would make every pipeline credential a full
  read of the finding history. A valid key without the scope gets `403`, not
  `401`, because a pipeline retrying its credentials forever is the wrong outcome.
- **Absence is refusal.** A collector with no keys accepts nothing, and one with no
  database — which is where keys live — refuses to start at all. Reading "no
  credentials configured" as "no credentials required" is the shape of every
  default-admin incident there has ever been. `GUARDANA_ALLOW_UNAUTHENTICATED=1`
  (or `allow_unauthenticated=True` in code) accepts an open collector, and has to
  be typed: passing a store object in code must not become the way around the
  check.
- **One message for every rejected key** — unknown, malformed, revoked, expired.
  Saying which would turn the endpoint into a way to enumerate valid prefixes.
- **`guardana-collector key create | list | revoke`**, with optional expiry.
  `last_used_at` is recorded on every accepted request, because "this key has not
  been used in four months" is the question that gets an unused credential revoked.
- **The agent carries its key** from `GUARDANA_COLLECTOR_TOKEN` — an environment
  variable and deliberately not a flag, since a credential on a command line lands
  in shell history, in `ps`, and in most CI logs. Without this the whole scheme
  would have been a collector no runner could reach.
- The guard is a per-route dependency, not path-matching middleware, and a test
  enumerates the app's own route table rather than listing paths — so a route
  added later is covered without anybody remembering the test exists.

### Added — the collector keeps what it is given

First item of the collector work. The engine still never imports it, nothing is
sent anywhere without `--reporter`, and the maturity label stays **experimental**:
there is still no authentication and no tenancy, so it must not be exposed. A
database does not make a service safe, and saying otherwise is how the label would
stop meaning anything.

- **PostgreSQL persistence** behind the same `Store` protocol the in-memory store
  implements. One parametrised contract test runs every assertion against both,
  because two implementations tested apart become two implementations that behave
  differently — and the one nobody runs locally is the one that differs in
  production. New dependency on `guardana-server` only: `psycopg[binary]`.
- **Reversible migrations, from the first row.** Numbered SQL files with a
  required down file, one transaction per migration including its own bookkeeping
  row, and a Postgres advisory lock so two replicas starting together cannot both
  apply the same version. The runner refuses three things outright: a migration
  edited after it was applied (its checksum is recorded and checked — otherwise
  two databases disagree about what version four *is* and nothing notices), a
  migration numbered below the highest applied one (a rebase accident that would
  skip it on that database forever), and a database holding a migration this build
  does not ship.
- **`guardana-collector migrate | status | rollback`**, with the same exit codes
  the rest of the tool uses. Migrating on boot is opt-in
  (`GUARDANA_MIGRATE_ON_START=1`) rather than default, because a rolling deploy
  that migrates on boot briefly runs two versions of the code against one schema.
- **Storage is chosen, never defaulted.** Without `GUARDANA_DATABASE_URL` or an
  explicit `GUARDANA_STORAGE=memory`, the collector **refuses to start** and names
  both options. An ephemeral store that is the default is an ephemeral store that
  reaches production, and it is found out on the first restart. This is "no
  default credentials", one layer down.
- **`/healthz` and `/readyz` as separate endpoints.** Readiness returns `503`
  while a migration is pending — and again after a rollback — so a rolling deploy
  does not send traffic at a schema that is not there. One endpoint answering both
  questions would make the deploy decide that.
- `deploy/docker-compose.dev.yml` for a local database, and
  [`docs/usage-collector.md`](docs/usage-collector.md).

**Contributor note.** The collector's tests need a real PostgreSQL and **skip**
without one, so changing a rule does not require running a database.
`GUARDANA_REQUIRE_POSTGRES=1` turns that skip into a failure and CI sets it: "the
isolation test did not run" reading as a green build is the same fail-open this
project refuses everywhere else, relocated into the test suite. The cross-tenant
tests land behind the same fixture.

### Security — fourteen defects in released 0.7 code

Found by an adversarial review of the *finished* 0.7 code, all under a green gate. Reviewing a design and reviewing the code that came out of it
find different things; this is the second kind, and every fix below ships with a
test that was verified by inverting the implementation and watching it fail.

- **`guardana monitor` ignored the profile's `privacy:` block entirely.** It
  printed alerts through a renderer built with no policy — which falls back to
  `full` — and forwarded them to a collector without redacting at all. `scan` and
  `probe` both redact before they emit; `monitor` is the one that runs unattended
  for hours and ships every alert somewhere central, so it was the worst of the
  three to have missed. It now builds its handler from the profile, and both exits
  are tested separately, because only one of them is visible on screen.
- **`privacy.redact_secrets: false` wrote live credentials to disk.** The switch
  took effect only at `evidence_mode: full`, so its single reachable outcome was
  the one [`docs/privacy.md`](docs/privacy.md) said was impossible. The field is
  gone from `RedactionPolicy` and the value is refused at load time with a reason
  — accepted as a key so that anyone who set it is told, rather than ignored.
- **`fail_on.fail_on_skipped` could not be set.** The gate shipped in 0.7,
  [`docs/usage-target.md`](docs/usage-target.md) showed the exact YAML, and the
  profile loader rejected the key — so the documented example was a hard error and
  the coverage-gap gate was unreachable from the only place it can be turned on. A
  test now derives the expected keys from the `FailOn` dataclass, so a field
  without a way to set it fails rather than shipping.
- **Redaction destroyed its own labels.** Patterns were applied one at a time, each
  reading the previous one's output, so the generic "token = value" pattern matched
  the *label* of the placeholder that had just replaced a secret:
  `[redacted:github-[redacted:credential-assignment:…]]`. The label is what tells
  you which key to rotate. Matches are now collected against the original text and
  spliced in once, and a placeholder claims its own span so redacting twice is
  genuinely idempotent rather than accidentally stable.

### Fixed — the rest of that review

- **`guardana run migrate` wrote a document that fails its own published schema.**
  A version-1 run without a `target_kind` became the literal `"None"`, over the
  original file, with exit `0` — the same class of defect as the one 0.7 fixed,
  in a different field. The migration now refuses what it cannot carry and writes
  nothing, and a test validates the *artifact* across every field a version-1 run
  could be missing.
- **An unreadable saved run exited `1` with a traceback.** `load_report` ran the
  migration outside its own guard, so the manifest reader's exception escaped
  through `run inspect`, `run migrate` and `diff` — reporting "a finding failed the
  policy" for a file that could not be read. All three now exit `3`.
- **The manifest never recorded the budgets in force.** `execution` describes
  itself as the limits a run was given; it carried concurrency and the timeout and
  dropped every ceiling, so a run that exited `6` said it stopped and never said
  what it hit.
- **`scan --write-baseline` exited `1` where `baseline create` exits `2`** for the
  identical situation. Nothing failed a policy — a question was left unanswered.
- **`baseline update` deleted waivers on the evidence of an incomplete scan.** The
  command decides a finding is fixed by not seeing it, and a rule that errored
  produces exactly that absence — so one broken rule removed the waiver, the reason
  a person wrote and the name of whoever approved it, printed "is fixed" and exited
  `0`. It now refuses to touch the file and exits `2`.
- **A request budget overshot under concurrency.** `reserve` counted requests that
  had come *back*, so every thread of a `--concurrency 4` probe passed the same
  check at once. It now counts claims, taken and tested inside one lock: the
  promise that a ceiling of 200 means 200 held only in the sequential case it was
  written for.
- **`guardana plan` priced rules the run would refuse.** It applied the kind, the
  policy globs and the capability check, and skipped the safety ceiling the runner
  applies. The selection is now the runner's own, called from one place.
- **`--plugins disabled` recorded no refusal.** Every other mode reports what it
  did not load; the one mode that loads no checks at all was the only one that said
  nothing, and a run with no rules whose report is silent means nothing.

### Added — while fixing the above

- `guardana monitor --plugins` / `--allow-plugin`, matching `scan` and `probe`. It
  was the one command with no way to restrict what it imported.
- `guardana plan probe --safety` / `--allow-destructive`, so a plan can describe
  the run you are actually going to make.
- `guardana scan --baseline` now names waivers that have lapsed and waivers still
  carrying the generated placeholder. Both were reported only by `baseline verify`,
  which is the command nobody runs in a pipeline — so a build went red with nothing
  on screen explaining why, and the first guess is always that the model got worse.
- Saving a run in a format `guardana diff` cannot read says so at the moment the
  file is written. `--output` advertises itself as what `diff` needs and defaults
  to human text, so the obvious command produced a file the comparison refuses and
  the user found out on the next run — the run they wanted compared.

## [0.7.0] - 2026-08-02

### Breaking

- **`ScanResult.rules_skipped` is a list of `SkippedRule`, not of strings** —
  each carries the reason, the missing capabilities, and a sentence. Use
  `result.skipped_rule_ids` where only the ids are needed. The collector envelope
  moves to **v5** to carry the same, and still accepts v2–v4.
- **The exit-code table changed.** `2` used to mean three unrelated things — a bad
  baseline file, an unreachable endpoint, an impossible comparison. It now means
  only "the result could not be established, or the comparison could not be made",
  and the rest moved: `3` invalid configuration or usage, `4` target unavailable,
  `5` internal error, `6` budget exhausted, `7` interrupted with partial evidence.
  `0` and `1` are unchanged, and everything that moved, moved between non-zero
  codes, so no pipeline turns green by accident. There is deliberately no
  compatibility mode: a flag making the same command mean different things for two
  users of one version is a worse contract than one announced break. The table is
  an importable enum (`guardana.cli.exit_codes.ExitCode`) and a test asserts it
  matches [`docs/exit-codes.md`](docs/exit-codes.md). Every command now shares it:
  `init` refusing to overwrite, `new-rule` with an unknown evaluator and an
  unreadable saved run all exit `3` rather than `1`, and `calibrate` distinguishes
  a measurement that could not be made (`2`) from one that came out over the bar
  (`1`). Reviewing the finished code is what surfaced those — the table would
  otherwise have been a contract three commands did not honour.
- **The saved-run schema is version 2.** Documents written by 0.6 still load —
  they are migrated in memory — but documents written by 0.7 are not readable by
  0.6. The root-level `summary` block is **gone**; its counts live in
  `run.result_summary`, which also carries the new `gate` and `stopped_by` fields.
  Two copies of one truth is a guarantee that they eventually disagree, and the
  copy a reader happens to trust then decides whether a build is green.
- **`RunMeta` is replaced by `RunManifest`** (`guardana.core.manifest`), and
  `RunReport.meta` by `RunReport.manifest`. Anything embedding the engine and
  reading run metadata needs the new names; the old shape carried seven fields and
  could not answer what a run cost or how it was gated.
- **A run that executed no rules now reports `indeterminate`, not a policy
  failure.** The exit code moves from `1` to `2` for that case. Both are non-zero,
  so no pipeline turns green by accident; what changes is that "nothing was
  verified" is now distinguishable from "something is wrong".

### Changed

- **Positioning: an AI security verification platform, not a model scanner.**
  Guardana verifies AI *systems* — build artifacts, deployed endpoints and agents,
  and whether the next release is worse — which is what companies actually deploy.
  README, `FEATURES.md`, `ROADMAP.md`, `CLAUDE.md`, `CONTRIBUTING.md` and
  `docs/index.md` all say the same thing now, organised around four verbs: verify
  artifacts (`scan`), verify a deployed system (`probe`), continuously re-verify
  (`monitor`), compare evidence (`diff`). MCP is a target `probe` supports, not a
  fifth mode.
- **The roadmap is ordered by company readiness, not by coverage volume.** v0.7 is
  the run manifest, budgets, redaction, stable exit codes, a persistent
  authenticated collector, containers and CI beyond GitHub — with a definition of
  company-ready as a checklist that must be ticked before the version is cut.
  Language and industry corpora move to a parallel content lane that does not gate
  platform work.
- **Maturity is stated per component, everywhere it matters.** The engine and CLI
  are beta; the collector is **experimental** — in-memory, unauthenticated, local
  evaluation only — and the README, FEATURES and its own documentation now say so
  instead of implying a team product.
- **`monitor` is described as what it is:** scheduled *active* synthetic checks. It
  does not passively inspect production traffic and does not sit inline.
- **The competitor checkbox table is gone**, replaced by "Where Guardana fits" —
  categories and honest complementarity, instead of six rows of ✅ that would need
  re-verifying every quarter to stay true.
- **The 37% figure now says what it measured.** It is Fujitsu Research's measured
  misclassification rate for *keyword-based judging* against human labels, not a
  claim about any competing tool.

### Added

- **`guardana doctor` and `guardana config validate|explain`.** `doctor` reports
  what this installation is — distribution versions and whether they agree, which
  plugins loaded and which failed, whether third-party rules are installed, and
  which settings weaken the gate — and **contacts nothing**, because a diagnostic
  that costs money is one people avoid. `config validate` fails on a bad profile
  before a pipeline pays for a probe; `config explain` prints the settings
  actually in force, defaults included, because most of a gate is defaults and an
  unseen default is one nobody checked.
  See [`docs/usage-doctor.md`](docs/usage-doctor.md).
- **`guardana baseline create|verify|update`, and waivers that expire.** A waiver
  now carries an approver and an expiry, and **an expired waiver stops waiving** —
  the finding comes back and fails the gate again. `verify` names the waivers that
  lapsed and when, so a red gate is traceable to an acceptance running out rather
  than looking like a new problem. A generated baseline is deliberately unusable
  as-is: every waiver carries placeholder text and `verify` fails while it is
  there, because a baseline nobody edited is a list of findings somebody silenced.
  `update` only ever removes waivers for findings that are fixed; accepting a risk
  stays a decision somebody makes. Version 1 baselines still load.
  See [`docs/usage-baseline.md`](docs/usage-baseline.md).
- **`--plugins all|builtins|allowlist|disabled`.** `--no-plugins` refused every
  entry point including Guardana's own, so the safe mode was also the empty mode —
  and a control that costs all your coverage is one people switch off. `builtins`
  is what most of those pipelines wanted: the reviewed rules run, nothing else is
  imported. Trust is decided by distribution name rather than entry-point name or
  module path, an entry point that cannot name its origin is treated as
  third-party, and a refused plugin is recorded in `errors` rather than dropped.
  `--no-plugins` still works as an alias for `disabled`.
- **Rules declare their impact, and runs declare what they permit.** `passive`
  reads, `active` sends prompts, `side_effecting` may make the target act;
  `--safety passive|active|side-effecting` sets the ceiling, defaulting to
  `active`. **`--allow-destructive` is a separate switch**, so raising the impact
  ceiling can never reach a destructive rule by accident — and a test asserts no
  shipped rule is destructive. Nothing shipped is `side_effecting` either: the
  agent rules drive Guardana's own tool doubles, and labelling a risk that does
  not exist yet would devalue the label for when it does.
  See [`docs/safe-testing.md`](docs/safe-testing.md).
- **`RuleMeta` gains `impact`, `destructive` and `maturity`.** Impact is derived
  for YAML rules from what they already declare, so no rule file changes and none
  can drift out of step with what it does. A gate asserts every shipped endpoint
  rule declares at least `active` — the default is `passive`, which fails safe by
  skipping rather than running, but a shipped rule silently skipped in the mode
  most people use is lost coverage nobody asked for.
- **Argument-parsing errors now exit `3`, not `2`.** An unknown option or a bad
  enum value is invalid usage: nothing ran. Leaving them at Click's default would
  have made the documented table untrue for the one class of error every command
  shares and nobody writes by hand.
- **JSON Schemas for every document Guardana emits**, under `schemas/`:
  `run-v2`, `diff-v1`, `plan-v1`. A test derives the list from the directory, so
  adding a schema without a test is impossible; each must be a valid 2020-12
  schema, carry its version in its `$id`, refuse unknown top-level fields, and
  agree with the version constant in the code.
- **Central evidence redaction.** One `EvidenceRedactor`, at one seam, between
  findings and every way they leave the process — the renderers, the collector
  envelope and baseline files. Applied by the renderer *factory*, so a format
  added later is covered without its author knowing, and there is no way to obtain
  a renderer that skips it. Evidence is **redacted by default** in every command;
  `privacy:` in `guardana.yaml` configures the mode, the patterns and the size
  bound. Secrets are removed even at `full`, which means "keep the model's words",
  never "store a live credential". Redaction announces itself in the output and
  truncation says so, because a report that looks complete and is not is the same
  dishonesty `unverified` exists to prevent. See [`docs/privacy.md`](docs/privacy.md).
- **`guardana target inspect`** — what an endpoint actually supports, as opposed
  to what it claims. Probes chat, whether the system message survives the hop,
  whether tool calls are honoured, and whether token counts come back; reports
  each as supported, unsupported or **unknown**, names the capabilities that were
  declared but not confirmed, and lists the rules the target leaves unrunnable.
  `--require chat,call_tools` exits `2` when a capability was not confirmed.
  See [`docs/usage-target.md`](docs/usage-target.md).
- **A skipped rule now records why it was skipped**, and which capability was
  missing. A bare list of ids could not tell a rule that never applied from one
  the provider cannot support — the second is a coverage hole somebody may be
  paying to avoid. `fail_on.fail_on_skipped` makes it `indeterminate`; a real
  finding still outranks it.
- **Execution budgets.** `budgets:` in `guardana.yaml` (`max_requests`,
  `max_input_tokens`, `max_output_tokens`, `max_duration`), with matching
  `--max-*` flags on `probe`. Checked **before each request**, not after each
  rule, so a ceiling of 200 means 200 requests were sent and never 201. A run
  that hits its ceiling stops, keeps what it already found, records
  `stopped_by: budget_exhausted`, exits `6`, and **never passes the gate** — a
  team cannot quiet a red build by lowering the budget until the run ends early.
  There is no `on_exhaustion` setting: two of its three proposed values differ
  only in wording, and the third would have been a switch that turns an exhausted
  budget into a pass.
- **A budget that cannot be enforced is refused up front**, with exit `3`. A token
  ceiling on a transport that reports no tokens, or any ceiling on a target that
  does not meter itself, would be a ceiling the user believes in and nothing
  watches. `Target.apply_budgets` defaults to refusing, so a third-party target
  fails loudly rather than accepting a budget it ignores.
- **`guardana diff` refuses to read truncation as improvement.** A run cut short
  has fewer findings; comparing it against a complete one now reports the
  comparison as incomplete, says which side stopped and why, and fails the gate
  before any threshold is consulted. This was the same trick as exit code `6`, one
  level further out, and the review of the design is where it surfaced.
- **`guardana plan scan|probe`** — what a run would cost, **without sending a
  single request**. Reports the rules that would run, those that would be skipped,
  a lower and upper bound on requests, and whether the plan fits its budget
  (exiting `3` if it does not). See [`docs/usage-plan.md`](docs/usage-plan.md).
- **Every rule declares its request ceiling** (`Rule.estimated_requests`, on the
  base class). A rule that declares nothing is **named in the plan**, never
  counted as free, and a plan containing one never claims to fit a budget. The
  cost gate in `guardana-rules` now measures *every* endpoint rule against its own
  declaration rather than only the agent ones it recognised by type — the pattern
  that has already cost this project once.
- **A run counts what it spends, and says so when it cannot.** `usage` in the
  manifest now carries real numbers: requests sent, tokens in and out where the
  provider reports them, and wall time. The meter sits on the **target**, not on
  the transport, so every request to a model passes through it whatever transport
  is plugged in — including a third party's.
- **Token counts come from a new optional transport protocol**
  (`UsageReportingTransport`), modelled on `ToolCallingTransport` so no existing
  transport breaks. The built-in OpenAI, Ollama and TGI paths implement it. A
  transport that does not leaves tokens **unknown**, and the manifest records
  `requests_missing_token_counts` alongside the sums so a partial bill is never
  presented as a complete one. (NVIDIA's garak closed the same feature request as
  not planned, on the grounds that token counts vary by target — which is true,
  and is an argument for recording the gap rather than reporting zero.)
- **`Target.usage()`** on the base class, defaulting to `None`. A target somebody
  else wrote reports "nobody counted", never a zero that would read as a free run.
  `ArtifactTarget` overrides it with a measured `0`, because a file scan really
  does send nothing — and the two must not print the same words.
- **Run Manifest v2 — a saved run is now evidence, not a label.** Every run
  records a run id and UTC timestamps, where it was started from (laptop, CI, and
  which provider), the software that produced it, the target with a fingerprint
  *and the fields that fingerprint covers*, the deployment it verifies, the
  configuration by digest, the limits it ran under, what it consumed, the rules
  and evaluators that did the checking, a result summary with an explicit gate,
  and the evidence policy in force. Versioned independently of the CLI, with
  [`schemas/run-v2.schema.json`](schemas/run-v2.schema.json) as the published
  contract and a test validating what Guardana writes against it.
  See [`docs/usage-run.md`](docs/usage-run.md).
- **`guardana run inspect` and `guardana run migrate`.** Read a saved run without
  re-running it, or rewrite an older one at the current schema. `inspect` prints
  **"not recorded"**, never a blank and never `0`, for anything the run did not
  measure — the two are different facts and only one of them lets you budget.
- **Older runs migrate forward in memory, at load.** A run written by 0.6 (schema
  1) is still comparable after upgrading: `diff` and `inspect` carry it forward as
  they read it. What version 1 never recorded arrives as an explicit unknown — no
  usage, no execution settings, and **no gate verdict**, because recomputing one
  would apply today's thresholds to another build's run.
- **Three gate outcomes instead of two** (`guardana.core.gate`): `pass`, `fail`,
  and `indeterminate` — the run could not answer. A stopped run outranks a
  finding, a finding outranks a check that could not run. `gate()` stays a boolean
  for embedders; the distinction is what lets a CI job tell a broken setup from a
  target that got worse.
- **SARIF now fills in its `invocation` object**: `startTimeUtc`, `endTimeUtc`,
  `exitCode` and `exitCodeDescription` alongside the `executionSuccessful` and
  `toolExecutionNotifications` it already carried.
- **`guardana.core.testing.manifest_for`** — a run manifest for tests, so a test
  about rendering is not also a test about clocks and run ids.
- **Generated documentation truth** (`scripts/generate_docs.py` →
  `docs/generated/`): rule summary, full catalog, evaluator catalog and taxonomy
  coverage, all read from the installed registry. Prose links to them instead of
  repeating counts that drift. `release.py` regenerates them; a test fails if they
  are stale.
- **`test_docs_consistency.py`** — one canonical version. It fails when the README
  calls the wrong version current, when a version appears twice in the roadmap
  table, when `ROADMAP.md` describes a version other than the released one, when
  the changelog has no entry for it, or when a documented Action pin drifts from
  the released minor. Every one of those had actually happened.
- **`docs/product-status.md`** — maturity per component and the limitations worth
  knowing before adoption: the agent harness is ours rather than yours, `monitor`
  is scheduled, RAG coverage is a slice, text only, "OpenAI-compatible" is not a
  guarantee, plugins are code you install.
- **`docs/threat-model.md`** — assets, ten threats with an honest stance on each,
  and what is not mitigated today (plugin trust is the sharpest edge).
- **`docs/safe-testing.md`** — what an active run really does, what Guardana never
  does, and the gap that remains: Guardana simulates the tool, your deployment
  might not.
- **Design documents** for the v0.7 work, written before the code:
  `docs/design/run-manifest-v2.md`, `collector-domain-model.md`,
  `privacy-and-redaction.md`, `exit-codes.md`.
- **Eight further project principles** in `CLAUDE.md` (company usability before
  coverage volume; no public claim without generated or cited evidence; no false
  green from any direction; versioned migratable schemas; tenancy considered on
  every server change; declared impact and cost per active rule; no API freeze
  before the domain model is complete; documentation as acceptance criteria), plus
  contribution lanes and a PR checklist in `CONTRIBUTING.md`.

### Fixed

- **The landing page advertised 25 rules while 32 shipped.** The count, the
  build/runtime split and the terminal demo's output had all been hand-maintained
  since 0.3, one element below a version marker the release tooling rewrote on
  every release — automation covering the version and nothing else is what makes
  stale prose look maintained. The page is reconciled with the registry, its
  runtime list now shows the agentic checks 0.5 shipped, and
  `test_landing_page.py` pins all three counts so the drift cannot recur.
  `CLAUDE.md` and `CONTRIBUTING.md` state the five places a user-visible change
  has to touch, and say to prefer a test over a promise.

### Changed

- **`scripts/sync_site.py` rewrites the landing page's rule counts from the
  registry**, and `release.py` runs it in the same pass as the version bump — so
  a release cannot ship a page claiming last quarter's numbers. `--check` reports
  staleness without writing. Both it and `test_landing_page.py` fail loudly if a
  claim disappears from the page rather than skipping it quietly, because a claim
  nothing checks is how this drifted for three releases.
- **`Homepage` on all five packages now points at `https://guardana.dev`**, the
  landing page, instead of the organisation domain. Contact addresses stay on
  `@guardana.io`.

## [0.6.0] - 2026-07-31

### Added

- **`guardana diff` — the re-test gate.** `scan`, `probe` and `monitor` all answer
  *how is it now*. Nothing answered the question a team has at every change — a
  new model, an edited system prompt, one more tool: **is it worse than it was?**
  `guardana diff before.json after.json` compares two saved runs and fails the
  build on deterioration. Exit `1` on a regression, exit `2` when the two runs
  cannot honestly be compared, and never a quiet `0` for either.

  It is not list subtraction, and four things had to be right before it could be
  written at all:

  - **A check has to be recognisable across runs whose evidence differs by
    design.** The waiver fingerprint is rule + file + description, and for a
    dynamic finding the description is the evaluator's rationale — which three
    built-in evaluators fill with a verbatim quote from the model. Comparing on it
    would report movement on every re-run of an unchanged system. The comparison
    key is that fingerprint minus the description, with the location taken
    relative to what the run examined: against a live model it collapses to empty,
    which is what lets a swap from `…#llama3` to `…#llama4` compare at all instead
    of reading as every check vanishing and every check appearing.
  - **"Worse" has five meanings**, and the one people forget is *we can no longer
    tell*: a check that used to reach a verdict and now cannot lowers the finding
    count, so a comparison that counted would call going blind an improvement.
  - **A waiver is not a fix.** Adding a finding to a baseline reports as a changed
    waiver, never as a resolved problem.
  - **A narrower run is not a better one.** A run made with a tighter profile
    reports its missing rules as lost coverage — a regression — rather than as
    findings that went away.

  Each side of the comparison carries its own `RunContext` (what that run examined,
  and the digests of the rules it ran). Per-side on purpose: normalising both runs
  against one root is exactly what breaks the model-swap case, and a shared
  parameter makes that mistake writable.

  Noise is handled by comparing a check's *state* rather than a tally: a model
  either fails a check or it does not, which is far steadier than how many prompts
  it failed. A changed count is reported and never gates on its own. Confidence
  thresholds apply to regressions backed by a graded verdict — and deliberately
  not to a check going blind or a rule that stopped running, because an ungraded
  result carries confidence 0.0 by definition and a policy that filtered
  everything by confidence would let a stricter setting switch those two off.

- **A run can be saved and read back.** `--output <path>` on `scan` and `probe`
  writes the report to a file (a shell redirect looked like enough until the file
  became an input — PowerShell writes UTF-16). With `--format json` that file now
  carries a `schema_version` and a `run` block: tool version, target, profile,
  when, and **which** rules ran with a digest of each. `guardana.core.report.load_report`
  reads it back — the first deserializer in the project — and refuses anything it
  cannot read exactly, because a run silently read as empty produces a comparison
  reporting that nothing got worse.

- **`Rule.digest()`**, a contract on the base class: a short hash of what a rule
  *is*, so a comparison can tell a worse model from a sharpened test. YAML rules
  hash their own parsed declaration, which is also what keeps the probe's per-run
  canary out of it. A third-party rule is comparable without its author doing
  anything.

### Changed

- **`ScanResult.rules_run` names the rules that ran instead of counting them**
  (`rules_run_count` is derived, so the two cannot drift apart). A count cannot
  tell "this rule found nothing" from "this rule never ran", which means two runs
  made with different profiles compared as an improvement — the same fail-open the
  `observations` channel exists to prevent, one question further out. **Breaking
  for anyone constructing a `ScanResult` directly.**
- **The collector envelope is now v4**, adding `summary.rules_executed`. A
  collector that only saw a count showed an agent with a narrowed profile as
  green. The collector accepts v2, v3 and v4.
- **`monitor` no longer has its own idea of "worse".** It compared three counts
  and could not see a finding that got more severe, a check that stopped being
  gradable while the count stayed flat, or one rule dropping out of a plan of the
  same size. It now calls the same comparison `guardana diff` runs, so there is one
  definition of regression in the project rather than two that drift apart.

### Fixed

- **The prose beside the moving Action pin stayed on 0.3 through 0.5.0.** The pin
  itself was rewritten to `@v0.5`, and the sentence next to it in `README.md` and
  `docs/integrations.md` went on telling readers the tag points at "the latest
  0.3.x" — the automation moved the tag and left its explanation, one line over.
  Both are now rewritten in the same pass as every other version marker, and the
  release-tooling test pins them to the released version, so the next release
  cannot repeat it a third time.

## [0.5.0] - 2026-07-29

### Added

- **Guardana grades an agent run, not just a reply.** `offer_tools` answered one
  question — which tool did the model reach for first — and the interesting
  agentic failures are not there. A confused deputy needs a tool *result* to
  carry the injection; over-broad arguments need a task that justified a narrow
  one; nothing about either shows up in the reply text. `guardana.core.trajectory`
  drives the loop: Guardana plays the harness, offers tools, hands back what a
  `ToolDouble` says, and never executes anything. `Trajectory` hangs off
  `Exchange` rather than replacing it, so `Evaluator.evaluate` keeps its shape and
  all five existing evaluators grade a run unchanged.
- **Memory and context poisoning (ASI06, `AML.T0080`/`AML.T0080.000`).** What
  separates an agent from a chat is that a note written in one conversation comes
  back in the next and the model treats it as its own prior context. A YAML rule
  can now declare `memory: read`/`memory: write` tools and a `then:` task that
  runs in a **fresh session** against the same store: Guardana writes in the
  first, grades the second, and only the store crosses the boundary — otherwise
  the check would be proving a single-turn injection the model can still see. The
  store is built per run, never at parse time, so one target's notes cannot reach
  the next target's probe. If the agent never read its memory back, the verdict is
  `inconclusive`.
- **Four agent rules**, all graded on facts about the run rather than on an
  opinion about it: `agent.tool_result_injection` (confused deputy, ASI01/ASI02,
  `AML.T0053`/`AML.T0086`), `agent.credential_exfiltration` (a planted marker
  leaving through a tool argument, ASI03/`AML.T0098`) and
  `agent.tool_argument_scope` (a glob where the task named one file, ASI02/
  `AML.T0101`) and `agent.memory_poisoning` (ASI06). **31 built-in rules.**

  Rules that drive two sessions cost twice their `max_steps`, which the probe
  cost gate caught the moment the first one landed. `TrajectoryRule.budget` states
  the real number, because a cost that is only true per session is not one anyone
  can plan a probe around.
- **A live MCP server is a target** (`guardana probe --mcp <url>`, ASI04). A tool
  description is fed to the agent's model as trusted context, so an instruction
  hidden in one is indirect prompt injection with an audience of one — and reading
  it from the *running* server is what catches a description changed after it was
  approved, which a file scan cannot see. Approve a manifest with
  `--write-mcp-pin`, compare with `--mcp-pin`, and a divergence is a **rug pull**
  (`AML.T0109`). Without a pin, drift is reported `inconclusive`, never as a clean
  server: "nothing changed" and "we have no idea whether anything changed" are
  different answers. The client is JSON-RPC on the standard library — **no new
  dependency**. Streamable HTTP talks to something already running; an stdio
  server is *started* by Guardana, which is the only place the engine executes the
  thing it examines, so it takes an explicit `--allow-exec`. **32 built-in rules.**
- **A `tool_call` evaluator** with four criteria — `forbidden_tools`,
  `canary_in_arguments`, `forbidden_argument_values` and `delivered_by`. The last
  is what keeps the check honest: it names the tool whose result carries the
  payload, and if the model never called it the injection never arrived, so the
  verdict is `inconclusive` rather than a model that looks robust for having
  ignored the document. A rule that configures no criterion at all grades
  `inconclusive` too.
- **Bounds on a run, and each one ends it as `inconclusive`.** Steps (6 by
  default, 12 ceiling), tool calls answered per step (8), tool-result and history
  bytes (1 MiB / 8 MiB), and a 120 s deadline. The history is **never trimmed to
  fit** — the span that would be dropped is exactly the one carrying the payload,
  so trimming deletes the evidence and then reports clean. A verdict that can no
  longer change stops the run, which is correctness and cost in one move.
  `test_probe_cost.py` pins all of it by counting model calls, the way
  `test_scan_cost.py` counts parses.
- **`ChatMessage` learned the `tool` role** (plus `tool_calls` and
  `tool_call_id`, and `ToolCall.id`, which the wire format returns and the parser
  used to drop). `Exchange.transcript` now renders tool calls and results
  explicitly: they live in fields rather than in `content`, so a content-only
  transcript showed a tool-calling turn as an empty line and hid the half that
  matters — from the judge and from the human reading the evidence alike.
- **`guardana calibrate`** — the plumbing that turns the calibration measurement
  into a routine. It grades a JSONL corpus of labelled samples and reports
  accuracy, Brier and ECE; a **starter corpus ships with Guardana**, generated
  from the project's own scripted doubles, and stays open source because a starter
  corpus is a security capability. A corpus line it cannot use is an error, never
  a skipped sample: a corpus quietly one row shorter measures something other than
  what its author meant and the number still looks like a calibration. An
  unreliable measurement exits non-zero, because "we measured nothing" must not
  read as "we measured, and it was fine".
- **`llm_judge` reports a calibrated confidence**, capped by the accuracy it was
  measured at — agreement between samples of one judge measures consistency, not
  correctness, and a judge can agree with itself every time and still be wrong.
  With no measurement recorded it reports raw agreement *and says so in the
  rationale*. A calibration is bound to the versioned rubric it was made for, so a
  changed rubric cannot inherit an older number.
- **A judge-graded ASI01 goal-hijack rule, shipped opted-out** in
  `catalog/optional/`. Whether an agent abandoned its goal is semantic and no
  deterministic grader settles it — but no built-in rule uses `llm_judge`, and an
  unconfigured evaluator is an error under the default policy, so enabling it by
  default would turn every judge-less `probe` red.
- **The OWASP Top 10 for Agentic Applications (ASI01–ASI10) and the agentic MITRE
  ATLAS techniques.** `guardana.core.taxonomy` is now a package, and rules carry
  the references they had already earned: `AML.T0080` (AI Agent Context
  Poisoning) and its `Memory` sub-technique, `AML.T0110` (AI Agent Tool
  Poisoning), `AML.T0053` (Tool Invocation), `AML.T0086` (Exfiltration via Tool
  Invocation), `AML.T0109` (Supply Chain Rug Pull), `AML.T0011.002`/`AML.T0104`
  (poisoned agent tool, used and published). The ASI edition label is **2026**
  though publication was December 2025 — the same convention `OWASP-LLM-2025`
  follows, that edition having shipped in 2024.
- **A fourth entry-point group, `guardana.taxonomies`.** Mapping every rule to a
  public framework is mandatory here, so the framework list could not stay
  closed: a company mapping to its own control catalogue registers `TaxonomyRef`s
  and writes `taxonomy: [ACME-14]` in YAML beside `LLM01`. Registration happens
  through an installed package rather than a string in a rule file, so an unknown
  id in `taxonomy:` is still a load error. Redefining a known short id is refused
  — overriding a *rule* changes what you check, overriding `LLM01` changes what a
  report claims to an auditor, for the built-in rules too.
- **Evaluators declare the `expect:` fields they read** (`Evaluator.expects`), and
  `Expectation` carries evaluator-specific fields alongside the two the engine
  handles itself. `expect:` accepted exactly `canary` and `goal` before, so a
  third-party evaluator could never be configured from YAML at all — strictness
  with no seam. The strictness is unchanged: a field the named evaluator does not
  read is an error, at load for the evaluators core ships and in the `errors`
  channel for a plugin's, which is the first moment the plugin exists.

### Changed

- **`CalibrationReport.brier`, `.expected_calibration_error` and `.accuracy` are
  now `float | None`.** They returned `0.0` when nothing was graded — a flawless
  score for a measurement that never happened, with `is_reliable` the only thing
  between a reader and it. Anyone reaching for `report.brier` without checking
  first saw perfect calibration where there had been none. The roadmap named two
  of the three; `accuracy` lied in exactly the same way. A public API change, made
  now because 0.5 is still before the compatibility promise 1.0 makes.

### Fixed

- **A dynamic YAML rule must now declare `requires: [chat]`.** Every built-in
  already did, but nothing enforced it — harmless while one endpoint-kind target
  existed, and a trap the moment a second one did: a rule without it would be
  planned against an MCP server, find no chat interface, return nothing, and be
  counted as a rule that ran and found nothing wrong. For the same reason the five
  `if not isinstance(target, EndpointTarget): return` guards now raise instead of
  returning quietly; capabilities already guarantee compatibility, so reaching one
  means the contract broke, and that belongs in `errors`.
- **Security: a rule shape the engine did not recognise never got its canary
  planted.** The probe resolved a rule's canary through
  `isinstance(rule, YamlRule | ScenarioRule)`; anything else was routed to the
  pass where nothing is planted, so `CanaryEvaluator` looked for a marker that
  was never there and reported a confident `pass` — a fully leaking model graded
  clean. That had already shipped once for `ScenarioRule`, and it applied to
  *every* third-party rule class until now. Planting is a contract on `Rule`
  (`with_canary`), and a rule that grades by canary while refusing to take one is
  rejected at registration.
- **The `[0.4.0]` changelog heading was deleted by the release-notes fix that
  followed it**, leaving the whole 0.4.0 section under `[Unreleased]` — where the
  next release would have rolled it into 0.5.0 and left 0.4.0 with no notes.
- **Three documented versions sat on 0.3 through the 0.4.0 release.** The landing
  page header, the security policy's supported-versions line, and the README's
  roadmap table all still said 0.3 — the same staleness the Action-pin automation
  was added to prevent, one file over, because only the pins were automated.
  `scripts/bump_version.py` now rewrites these markers in the same pass and
  refuses the bump if any of them has been reworded away, and a test pins all
  three to the released version. The delivered v0.4 section is out of
  `ROADMAP.md`, where shipped work does not belong.

## [0.4.0] - 2026-07-27

### Fixed

- **Security: a Python file too large to read vanished from the scan.** The new
  shared read returned "no tree" for an oversized file exactly as it does for one
  that is not valid Python, so padding a malicious loader past the 16 MiB limit
  removed it from every static rule and nothing in the report said so. Reading is
  now three outcomes, not two: a file the scan was *prevented* from examining
  (too large, unopenable, not a regular file) is recorded and surfaces in
  `errors`, which fails the gate; a file that simply is not runnable Python stays
  quiet, because a rule looking for Python constructs genuinely has nothing to
  find there.
- **Security: an unreadable component was inventoried as though it had been
  examined.** The size probe used `stat()`, which succeeds on a file whose
  contents cannot be opened, so a `model.onnx` with no read permission appeared
  with a size while every rule had skipped it. It is now opened, and a component
  that cannot be is marked `read: failed`. The test that was meant to pin this
  asserted `read == "failed" or "size_bytes" in attributes` — a second disjunct
  that is always true, so it passed either way. Fixed too.
- **Ctrl-C and an unreachable endpoint end a concurrent probe again.**
  `ThreadPoolExecutor` workers are non-daemon and CPython joins them at
  interpreter exit, so a probe printed `could not reach endpoint`, returned, and
  then sat there while every in-flight rule finished — up to the socket timeout
  times the retry count, per request. The pool is now hand-rolled from daemon
  threads, and once the endpoint is known to be down no further rule is started
  against it.
- **`Retry-After: nan` no longer wrecks a probe.** `float("nan")` parses without
  raising and survives both `max` and `min` (every NaN comparison is false), and
  `time.sleep(nan)` raises — so a rate limit was reported as "check could not
  run" for every rule that touched the endpoint. Non-finite values now fall back
  to the exponential backoff.
- **`observations` paths are relativized with the findings.** A report mixed
  repo-relative finding paths with absolute component paths, so the run-to-run
  diff the channel exists for called every component changed as soon as the
  checkout moved, and an uploaded report carried the checkout path that the
  findings beside it were deliberately scrubbed of.
- **`PythonSource.nodes()` really is in document order.** The index was built
  from `ast.walk`, which is breadth-first, so a module-level call came back
  before an earlier one nested in a function — while the docstring and
  `docs/writing-rules.md` promised source order to rule authors. Nodes are now
  sorted by position.
- **A failed source read is cached even once the cache budget is spent**, so the
  "every rule sees the same answer" guarantee no longer depends on how much
  Python the target contains.
- **`bump_version.py` validates before it writes.** A docs file that had lost its
  Action pin aborted the run *after* the five pyprojects and `__version__` were
  already rewritten, leaving a half-bumped tree with a stale `uv.lock`.

### Added

- **`probe` and `monitor` run rules concurrently** (`--concurrency`, default 4).
  Dynamic rules spend nearly all their time waiting on a model, so overlapping
  them is the biggest wall-clock win available. Results are collected in rule
  order whatever finishes first, so two runs of the same probe produce the same
  report and a CI diff stays signal. Artifact scanning stays sequential on
  purpose: it is local, already linear-cost, and a pool there would cost
  determinism for little gain. `Runner` defaults to sequential so embedding
  Guardana never silently opens N connections to someone's model. Measured
  against a stubbed endpoint with the 8 shipped runtime rules: **1.91 s → 0.69 s
  at the default 4** (2.8×), and 0.36 s at 8 — the ratio holds at real model
  latency, since the run is almost entirely waiting.
- **Rate limits are retried instead of ending the probe.** `429` and the
  transient `5xx` statuses get capped exponential backoff that honours
  `Retry-After` — bounded to 30 s, so a server answering `Retry-After: 86400`
  cannot park a scan for a day. Retries are bounded and a failure that survives
  them is raised, never turned into a silent "no reply". A sustained 429 now
  names `--concurrency` rather than repeating the generic 4xx advice to check an
  auth header that is working fine.
- **`ScanResult.observations` — what the scan saw, beside what it found.**
  `guardana.core.observation` and `guardana.core.inventory` record the components
  a run encountered: models with their format and size, dependency manifests,
  datasets, notebooks. Rules produce findings, which is a record of *problems* and
  the wrong shape for "what is deployed here" or "what changed since last run".
  The inventory is taken from the target, not from the rules — otherwise
  excluding a rule would quietly shrink the component list — and a component that
  could not be read is listed as unread rather than dropped. It carries no
  regulatory vocabulary at all: mapping these facts onto CycloneDX or an audit
  template belongs to an extension package, so no external calendar ages the
  engine. Surfaced in the JSON renderer and counted in the human summary.

- **`guardana.core.source` — read a Python file once, not once per rule.**
  `read_python_source()` returns a `PythonSource`: the text, the parsed tree, and
  the tree's nodes grouped by type, built with a single walk. It returns data and
  never a verdict, the same split `guardana.core.formats` draws for model files.
  `ArtifactTarget.python_source()` caches it for the life of one scan, under a
  memory budget — trees measure ~9.3× the size of their source, so past the
  budget the cache stops growing instead of growing unbounded. A file that cannot
  be read or parsed caches as `None` too, deliberately: a retried failure would
  let two rules disagree about the same scan and make the report depend on rule
  ordering. `ArtifactTarget` also lists the tree once and filters per call
  instead of walking it for every rule.

  Measured on this repository (452 files, 19 build-time rules): tree walks 26 →
  2, file opens 2025 → 462, `ast.parse` 1477 → 213, engine run 1090 ms → 175 ms,
  and `guardana scan packages` end to end 1.27 s → 0.36 s. The deliberately
  vulnerable demo fixture still reports the same 12 findings — faster, not
  shallower.

  This is a security property, not a comfort: a scan nobody waits for is one that
  gets switched off, and a switched-off scanner fails open at a level no rule can
  defend. A **cost gate** (`test_scan_cost.py`) now pins it by counting
  operations rather than seconds, so it behaves the same on a loaded CI runner as
  on a laptop — and it is verified to fail when the sharing is removed (42 parses
  instead of 6 on the same fixture).

### Fixed

- **The documented GitHub Action pin pointed two releases back.** The README, the
  integrations guide and the landing page all told users to pin
  `guardana/guardana@v0.1` while 0.3.0 was current. That is worse than a broken
  link — the workflow still runs, just without the fail-closed fixes 0.2 and 0.3
  shipped. The pins now name the current series, and `scripts/bump_version.py`
  rewrites them in lockstep with the package versions, failing loudly if a
  documented file stops carrying one and deliberately leaving a pre-release alone
  (`release.py` does not move the stable tag for one either). A test pins the
  documented pins to the released version, so the two cannot drift again.

- **The agent auto-format hook was never actually shipped.** `CLAUDE.md` and the
  hook's own docstring both said it was checked in so every agent gets it, while
  `.gitignore` excluded all of `.claude/`. The hook now lives in
  `scripts/ruff_on_edit.py` — inside the tree `mypy --strict .` walks, since it
  skips dot-directories — and `.claude/settings.json` is tracked alongside it.
  Only machine-local state (`settings.local.json`) stays ignored.

### Changed

- **`probe` and `monitor` now default to 4 concurrent requests, not 1.** An
  existing cron against a metered endpoint quadruples its request rate on upgrade
  with no config change; pass `--concurrency 1` to keep the old behaviour. The
  library default stays sequential (`DEFAULT_ENDPOINT_CONCURRENCY = 1`), so
  embedding the engine never opens connections you did not ask for.
- **Seven product principles are now project law** (`CLAUDE.md`,
  restated for humans in `CONTRIBUTING.md`): no regulation or vendor name as
  logic in the engine, cost that grows with the target rather than the rule
  count, offline with no account, a fixed commercial boundary (engine and
  built-in rules stay open source — only hosting and curated content may ever be
  paid), a public-framework mapping on every rule, a justified dependency
  surface, and no real data in fixtures. A change that breaks one is wrong
  regardless of how it tests.
- **The roadmap is rewritten around the engine instead of around a regulation.**
  0.4 makes scan cost linear (one tree walk instead of 26, one file read instead
  of 4.8, one AST parse instead of 7, bounded concurrency in `probe`, and a
  benchmark that gates regressions); 0.5 makes agents a first-class target
  (OWASP ASI01–ASI10, the new MITRE ATLAS agentic techniques, trajectory
  grading, memory poisoning, live MCP supply chain); 0.6 adds run-to-run
  regression (`guardana diff`) and multilingual corpora; 1.0 freezes the
  extension API. The compliance evidence pack (CycloneDX ML-BOM) moves out of the
  engine into a separate extension package — the EU AI Act's high-risk duties
  were deferred to December 2027, and an engine that encodes a legal calendar
  ages with it.

## [0.3.0] - 2026-07-26

### Fixed

- **Security: the `errors` channel was dropped on three of the four paths that
  carry a result.** `ScanResult` gained a defaulted sixth field, and every place
  that rebuilt the dataclass field by field silently lost it — so `guardana probe`,
  `guardana monitor` and any `scan --baseline` run still printed `✓ No findings.`
  and exited 0 when a CRITICAL check had crashed. Fixed at the root: `ScanResult`
  now owns a `merged()` constructor, `apply_baseline` uses `dataclasses.replace`,
  and `_sub_registry` carries the source registry's load failures. A future
  channel cannot go missing the same way.
- **Security: `--write-baseline` never reported or gated checks that could not
  run**, so a team could commit a baseline missing whatever a crashed rule would
  have found. It now names each one and exits non-zero on them — while still never
  gating on the findings it is snapshotting, which is the point of the flag.
- **Security: a run-time `RuleLoadError` was a silent skip** while the identical
  error at load time failed the gate. Both are now recorded: the check did not
  run, and where it failed does not change that.
- **Security: the collector's read paths ignored `errors`.** `/stats` never
  aggregated them and the dashboard neither tiled nor listed them, so an agent
  whose checks were all crashing rendered as a clean one — the failure the v3
  envelope was added to prevent, one layer further out.
- **Security: the monitor had no `errors` alert condition**, so with
  `fail_on_error: false` a monitored model whose rules had started raising ran
  silently for days. It is baselined like `unverified`, of which it is the
  strictly worse sibling.
- **Security: calibration inverted every verdict at or below half confidence.**
  The prediction was re-derived from the probability instead of carrying the
  evaluator's stated outcome, so `LengthEvaluator` — which passes at exactly 0.5
  — measured as 0% accurate while grading every sample correctly. The module that
  exists to audit judges was publishing inverted numbers about them. The
  abstention caveat also now fires at half the corpus, as its docstring promised,
  instead of only above 50% of the *graded* subset.
- **A rule-local `OSError` no longer reports a healthy endpoint as down.** The
  re-raise is narrowed to connection failures (`URLError`/`EndpointError`); a rule
  that merely opens a missing local file is recorded instead of abandoning the run.
- **A provider returning the wrong type can no longer poison discovery.**
  `_absorb` validates before registering, so a provider returning a mapping (which
  iterates to strings) can no longer make the *next*, healthy entry point fail —
  isolation no longer depends on entry-point ordering.
- **`guardana rules` reports packs that failed to import**, and the human renderer
  no longer prints the `✓` all-clear next to a `! [ERROR]` line.
- **A rejected envelope is no longer swallowed as an outage.** A v3 agent posting
  to a not-yet-upgraded v2 collector gets a distinct message naming the schema
  mismatch, instead of one indistinguishable from an unreachable host.

### Added

- **`guardana.core.calibration` — the confidence, measured.** The project's
  central claim is that other scanners misjudge whether an attack succeeded and
  Guardana reports an honest confidence instead. That confidence was agreement
  across samples: a reasonable proxy, but an assertion, which is the same thing
  everyone else offers. `calibrate(evaluator, samples)` now measures it against
  known-correct labels and reports **Brier** and **expected calibration error**.
  ECE is the one that bites: an evaluator can be no better than a coin flip while
  claiming certainty every time, and accuracy alone will not show it.
  Building the labelled corpus needs no human: the deterministic graders already
  produce ground truth — a planted canary appearing verbatim is a fact, and so is
  the list of tools a model actually called. The report refuses to flatter, too —
  `inconclusive` verdicts are counted and excluded rather than scored as
  predictions nobody made, a corpus under `MIN_RELIABLE_SAMPLES` is returned as
  unreliable *with the reason*, and an empty corpus raises instead of returning a
  zero that reads like a perfect score. A report is keyed to the versioned
  evaluator id, so a changed rubric cannot inherit an old measurement.

### Fixed

- **Security: the engine could report a green build on a check that never ran.**
  A rule that raised landed in `rules_skipped` — the same bucket as "this target
  cannot satisfy that rule's capabilities", a normal and expected outcome — and
  `gate()` only failed when *zero* rules ran. So a CRITICAL rule crashing on a
  crafted artifact left 26 others running, `rules_run > 0`, and the build green.
  Reproduced against 0.2.0 before the fix. Checks that could not run now have
  their own `errors` channel and **fail the gate by default**.
- **Security: one broken plugin took the whole tool down.** `Registry.discover()`
  called `ep.load()()` with no isolation, so a single third-party entry point that
  failed to import — a pack pinned to a library you do not have, a typo in a
  provider — raised out of discovery and left the user with *no rules at all*,
  built-ins included. That got sharper the moment 0.2.0 published
  `guardana.core.formats` and started inviting third-party packs. Each entry point
  is now isolated; a broken one is recorded and the rest still load.
- **Security: a third-party rule with an ordinary bug aborted the scan.** The
  runner caught only `RuleError`, so a plugin raising `ValueError` (or anything
  else) ended the run. Every `Exception` is caught per rule now — and
  `BaseException` deliberately is not, so Ctrl-C and `SystemExit` still stop the
  scan. Findings a rule already yielded before dying are kept.
- **Security: a custom rule that would not load was only a stderr warning.**
  `CLAUDE.md` requires a YAML typo to raise at load time, because a gate you think
  you configured but do not have is worse than no gate — but `load_yaml_rule_dirs`
  downgraded exactly that to a warning and carried on green. It now feeds the same
  `errors` channel.

### Added

- **The `errors` channel, everywhere.** "No findings" had three meanings and only
  two were distinguishable. A *finding* is "a check ran and found something",
  *unverified* is "a check ran and could not tell", and an **error** is "a check
  never ran". The third is now first-class in `ScanResult`, in all four renderers
  (human, JSON, JUnit `<error>` rather than `<failure>`, SARIF
  `toolExecutionNotifications` with `executionSuccessful: false`), and in the
  collector envelope.
- **`fail_on_error` in `guardana.yaml`** (default **`true`**). The opposite
  default to `fail_on_inconclusive`, on purpose: `inconclusive` is a verdict — the
  check ran and honestly could not tell — while an error means it never happened.
  Set `false` if you would rather ship than fix the broken check.

### Changed

- **`rules_skipped` means one thing again:** the target cannot satisfy the rule's
  capabilities. A rule that raised no longer hides there. A rule whose *evaluator
  was never configured* is still a skip, not an error — that is a configuration
  state, not a defect.
- **Collector envelope `schema_version` 2 → 3**, carrying `errors` and its count.
  The collector accepts **both** 2 and 3, so a fleet can upgrade one agent at a
  time; a v2 agent simply reports no errors, which is honest, because a v2 agent
  could not observe them.
- **An unreachable endpoint still exits 2, not 1.** Connection failures against an
  endpoint target propagate rather than being swallowed into `errors`: every rule
  would fail identically, so it is a fact about the run, reported once at the top
  with its own exit code. The same exception from an artifact rule *is* rule-local
  and is recorded.

## [0.2.0] - 2026-07-26

### Added

- **Public model-format readers — `guardana.core.formats`.** Bounded, offline,
  deterministic, fail-closed readers for GGUF metadata and safetensors headers.
  They return data and no verdicts, so a third-party pack can ship threat
  knowledge without first writing a binary parser. Sizes claimed *inside* a file
  are checked against an explicit `Limits` before anything is allocated, so a
  crafted artifact costs a `FormatError`, not the scan. `guardana.core.testing`
  gains `build_gguf` / `build_safetensors`, so a crafted fixture is a dict
  literal in a test rather than a malicious binary in the repo.
- **New rule `guardana.supply_chain.chat_template` (CRITICAL/HIGH).** A model's
  chat template is Jinja source that ships inside the artifact and renders the
  moment the model is used — a gadget in it executes code with no inference and
  no `trust_remote_code` (CVE-2024-34359 in llama-cpp-python; CVE-2026-5760 in
  SGLang's rerank path, 2026). The rule reads the template as a *parsed value*
  from every carrier it can hide in: GGUF `tokenizer.chat_template`,
  `tokenizer_config.json` (both the string and the named-list form),
  `chat_template.json`, and the standalone `chat_template.jinja` that
  transformers has written by default since 4.47. It flags dunder chains, the
  `|attr` sandbox escape (CVE-2025-27516 — the escape from the very sandbox
  `transformers` renders templates in), `lipsum`/`cycler` gadget entry points,
  shell/`os` sinks, and template inclusion (HIGH). A template it cannot read is
  reported as *not scanned*, never as clean.

- **`remote_code_config` covers kernel-dispatch config injection (CVE-2026-4372).**
  A `config.json` whose private `_attn_implementation_internal` field names a Hub
  repository gets that repository downloaded and imported on load — and the kernel
  path never consults `trust_remote_code`, so `trust_remote_code=False` does not
  stop it. That is CRITICAL, and it is matched by key name rather than by value
  shape, because `_name_or_path` carries an identical-looking `owner/repo` string
  in most real configs. A kernel requested through the documented
  `attn_implementation` field is reported the way `trust_remote_code=True` is: a
  lead. Affects transformers 4.56.0–5.2.x with `kernels` installed; fixed in 5.3.0.

- **`hidden_instructions` reads safetensors `__metadata__`.** safetensors is the
  format people choose precisely because it cannot carry code, which makes its one
  free-text channel the natural hiding place for a directive in an artifact
  reviewers treat as inert — and hubs render it while agents read it back. Same
  contract as the rest of the rule: concealment is the signal, not prose.

- **New rule `guardana.supply_chain.onnx_graph` (HIGH/MEDIUM).** ONNX carries no
  pickle, which is why scanners skip it — ModelScan covers H5, pickle and
  SavedModel only. Three of its structural features are worth reading, and the
  rule reads all three: an operator **domain outside the standard set** (the
  runtime has to register a native operator library, i.e. machine code, before
  the model will run), an **`external_data` location** that climbs out of the
  model directory or is absolute (an arbitrary file-read primitive — firm HIGH),
  and **`metadata_props`** carrying invisible smuggling characters or an
  executable-looking payload. The graph is walked straight off disk with a
  dependency-free streaming protobuf reader that seeks past tensor payloads, so a
  multi-gigabyte model costs kilobytes of reading. A graph it cannot walk — or
  could not finish walking — is reported as *not scanned*.
  `guardana.core.testing.build_onnx` builds the fixtures.

- **`malicious_dependency` is advisory-backed.** A bundled, offline, **AI/ML-only**
  dataset replaces the one-package blocklist. It is deliberately not a general CVE
  feed — that stays a non-goal — because an entry only earns its place by closing
  the loop between an artifact this scan already finds and the code that would run
  it. Two channels: a **compromised release** (`ultralytics` 8.3.41–46, `lightning`
  2.6.2/2.6.3, the `torchtriton` dependency-confusion name), which is the only
  signal that catches a *legitimate* package that was poisoned; and a **vulnerable
  loader** — `transformers` <5.3.0 for the kernel-injection config, `llama-cpp-python`
  and `sglang` for a poisoned chat template, `torch` <2.6 for a pickle, `keras`
  <3.11.3 for an `.h5` Lambda — reported as a lead, because it matters only once
  something poisoned reaches it. Only *exact* pins are matched (a range constraint
  pins nothing, and guessing would manufacture findings). Every entry carries a
  public reference, a malformed dataset raises at load rather than scanning as
  empty, and `MaliciousDependencyRule(advisories=…)` takes your own.
- **A worked extension example on the new primitives.**
  [`docs/model-formats.md`](docs/model-formats.md) documents the reader contract,
  and `examples/custom_rule` gains a second plugin rule that inspects a GGUF model
  and is *entirely* policy — the binary parsing comes from the engine.

### Changed

- **The legacy `.h5` Keras Lambda finding is firm, not a lead.** It is matched on
  the exact `"class_name": "Lambda"` marker instead of the bare word, so a layer a
  user merely *named* "Lambda" is no longer reported as code execution — and since
  `load_model` silently ignores `safe_mode` for `.h5` (CVE-2025-9905), a declared
  Lambda there *will* run, which is a verdict rather than a hedge. A `.keras` file
  that is not a readable archive falls back to the byte marker and, failing that,
  is reported as *not scanned*.
- **`model_format` no longer inspects Keras or GGUF files.** Those formats belong
  to `keras_lambda` and `chat_template`; previously a single `.h5` Lambda produced
  two findings at two different severities.

### Fixed

- **Security: a crafted repository could stall a scan indefinitely.** Every binary
  scanner (`pickle_opcode`, `keras_lambda`, `model_format`, `saved_model_ops`,
  `hardcoded_secret`) opened files directly, so a FIFO named `model.pkl` blocked
  the read until a writer appeared — forever, in CI. All of them now go through one
  guarded bounded reader, and the file is reported as *not scanned* rather than
  skipped in silence. The same guard covers `guardana.core.formats`.
- **Security: scanning a real checkpoint could exhaust memory.** `pickle_opcode`
  read whole files with `path.read_bytes()`, so a multi-GB `.pt` — or a symlink to
  `/dev/zero` — took the scan down with it. Zip containers are now streamed from
  disk instead of held in memory, and a *raw* pickle is capped at 512 MiB and
  reported as not fully scanned beyond that.
- **Security: a chat-template payload could hide past the scanner.**
  `model_format` looked for a Jinja gadget only within 4 KiB of the literal
  `chat_template`, so a gadget appended to the end of a real 8 KiB template
  scanned clean — verified against the shipping rule before the fix. The
  template value is now graded in full, whatever its length.
- **Security: the same window produced findings out of thin air.** Because the
  scan covered a byte window rather than a value, a code model's vocabulary
  (which contains tokens like `__init__`) was reported as a HIGH chat-template
  gadget on a model carrying no chat template at all.
- **One fact, one finding.** `model_format` no longer inspects `.gguf`;
  ownership sits with `chat_template`, so a single poisoned template can no
  longer produce two findings at two severities.

## [0.1.3] - 2026-07-21

### Added

- **Configurable scan scope** (`rules.paths_exclude` globs in `guardana.yaml`, and
  a `.guardanaignore` file at the scan root): skip large non-code trees (`data/`,
  `archive/`, model dirs) for speed and less noise. Both are matched against each
  path relative to the scan root.
- **The Marketplace Action follows a moving `v0.1` tag.** `scripts/release.py` now
  points the `vMAJOR.MINOR` tag at each release, so `guardana/guardana@v0.1` always
  resolves to the latest patch — no manual step per release. The release workflow
  triggers on full `v*.*.*` tags only, so moving a two-part tag never re-triggers a
  publish.

### Changed

- **`hallucinated_package` wording is clearer.** An import that is neither a known
  package nor a declared dependency now reads "isn't a known package or a declared
  dependency — declare it in requirements/pyproject, or verify it exists on PyPI",
  instead of the more alarming slopsquat framing (offline, the rule can't tell an
  undeclared-but-real package from a nonexistent one).

## [0.1.2] - 2026-07-21

Field-hardening from a second deep-test of the packages on a real ML codebase.

### Added

- **Official GitHub Action** (`guardana/guardana@v0.1.2`) and a documented
  **pre-commit** integration ([`docs/integrations.md`](docs/integrations.md)): a
  one-step CI job that scans and uploads SARIF to code scanning, and a local hook
  that installs `guardana-cli` from PyPI.
- **`guardana scan <file>`** now scans a single file, not only a directory —
  previously a single-file target walked nothing and reported a clean bill (a
  fail-open on `guardana scan suspicious.pkl`).

### Changed

- **SARIF is now valid for GitHub code scanning.** The line number goes in
  `region.startLine` (not glued onto the artifact URI), the URI is repo-relative
  (not an absolute checkout path), each result carries `partialFingerprints` and a
  `ruleIndex`, and `tool.driver.rules[]` lists the rules — so alerts attach to the
  source line instead of a non-existent path.
- **Static sinks are alias-aware.** `import pandas as pd; pd.read_pickle(...)`,
  `import numpy as np; np.load(..., allow_pickle=True)`, `import torch as t;
  t.load(...)`, and `import os as o; o.system(...)` are now caught — the dominant
  idiom, previously missed.
- **`hallucinated_package` reads the target repo's declared dependencies**
  (`requirements*.txt`, `pyproject.toml`), so a real in-requirements package
  (`jsonlines`, `langdetect`, `PyPDF2`, …) is not flagged under an isolated install
  where it isn't importable in Guardana's own environment.
- **Baseline waivers survive line shifts.** A finding's fingerprint is now rule +
  file + description (no line number), so an unrelated edit above a waived finding
  no longer un-waives it — while a genuinely different finding still fails the gate.
- **Entropy mode skips structured public values** — a UUID, a hex digest
  (md5/sha1/sha256), a model id / slash-path, or base64 of printable text is no
  longer flagged as a provider-less secret.
- **Multi-turn scenarios are no longer neutered through `--adapter`.** A body can
  carry a `{{messages}}` slot for the full transcript, and otherwise every turn is
  folded into `{{prompt}}` as a labelled transcript — the escalation context a
  scenario is *about* is never silently dropped to the last turn.
- **`hardcoded_secret` also scans `.vue`/`.svelte`** (frontend single-file
  components that embed JS/TS).
- **`dependency_risk` precision:** `torch.load(..., weights_only=False)` says so
  (not "without weights_only=True"); `yaml.load(..., Loader=FullLoader)` is a
  MEDIUM note that names the loader (materially safer than `Loader`/`UnsafeLoader`).
- **A 4xx from a probed endpoint** is reported distinctly ("rejected the request —
  check the auth header / body") from an unreachable host.

### Fixed

- `scripts/release.py` now recognizes a bare `## [Unreleased]` changelog heading,
  so a release after the first no longer fails to find the section to roll.

## [0.1.1] - 2026-07-21

Production-hardening from the first real-world use of the packages.

### Added

- **Per-finding baseline** (`guardana scan --baseline <file>` /
  `--write-baseline <file>`): accept today's findings on an existing repo with a
  reason so a blocking gate can be turned on without fixing the whole backlog,
  while a *new* finding (a different rule+location fingerprint) still fails.
  Waived findings are never silently dropped — they are reported in a `waived`
  channel in every format (a `WAIVED` line in human output, a `waived` array in
  JSON, native `suppressions` in SARIF). A malformed baseline is a hard error,
  never a silent waive-nothing or waive-everything.
- **Custom endpoint adapter** (`guardana probe --adapter <file>`): probe a
  *guarded product endpoint* with its own request/response schema, not just the
  raw OpenAI/Ollama/TGI wire — so the probe exercises the guardrails in front of
  the model, not only the bare model. The adapter file maps a body template (with
  a `{{prompt}}` slot and optional `{{system}}`), static/`${ENV}`-expanded headers,
  and a dotted `response_path` to the reply text. New public API
  `guardana.core.target.HttpAdapterTransport` / `AdapterConfig`. Fail-closed: a
  body with no `{{prompt}}` slot, or a response path that does not resolve to
  text, is an error — never a blank exchange graded as a clean pass. A planted
  system prompt with no `{{system}}` slot is folded into the prompt, never dropped.

### Changed

- **`hardcoded_secret` gains an opt-in entropy mode** (`rule_config` →
  `guardana.supply_chain.hardcoded_secret.entropy: true`): in addition to the
  high-precision prefix-anchored keys, it flags a high-entropy value assigned to a
  secret-named variable (`db_password`, `jwt_secret`, …) — the provider-less
  secrets that carry no recognizable prefix. Off by default because generic
  entropy matching is false-positive-prone; placeholders and config-shaped names
  are filtered out.

## [0.1.0] - 2026-07-20

### Added

- **Rule engine** (`guardana-core`): `Target` / `Rule` / `Evaluator` /
  `Finding` / `Profile` abstractions, plus a `Registry` for discovery and a
  `Runner` for execution. The whole public API is re-exported from
  `guardana.core` (`Rule`, `RuleMeta`, `Target`, `Evaluator`, `Finding`,
  `Registry`, `Runner`, `Severity`, ...), so plugin code needs one import
  line.
- **25 built-in rules** (`guardana-rules`):
  - 19 Python plugins — 17 static artifact-kind checks (`pickle_opcode`,
    `dependency_risk`, `remote_code`, `remote_code_config`, `notebook_payload`,
    `code_execution`, `insecure_transport`, `keras_lambda`, `saved_model_ops`,
    `malicious_dependency`, `model_format`, `hallucinated_package`, `provenance`,
    `hardcoded_secret`, `mcp_tool_poisoning`, `hidden_instructions`,
    `training.dataset_integrity`) plus 2 dynamic endpoint-kind checks
    (`output.secrets`, `agent.excessive_tool_use`).
  - 4 declarative single-turn YAML endpoint rules:
    `prompt.injection.ignore_previous`, `prompt.jailbreak.dan_style`,
    `prompt.system_prompt_leak.canary`, `prompt.unbounded_consumption`.
  - 2 declarative multi-turn scenarios: `scenario.gradual_jailbreak`,
    `scenario.indirect_injection`.
  - `supply_chain.remote_code` flags `trust_remote_code=True` on a
    transformers/datasets load — arbitrary code from a Hub repo executes at
    load time, the most common RCE vector for a downloaded model.
  - `supply_chain.code_execution` flags dynamic-code / shell sinks in source
    (builtin `eval`/`exec`, `os.system`, `subprocess(..., shell=True)`),
    distinguishing the dangerous builtins from same-named methods
    (`df.eval(...)`).
  - `supply_chain.insecure_transport` flags disabled TLS verification
    (`verify=False`) and model/dataset fetches over plaintext `http://`
    (a lead; localhost excluded).
  - `supply_chain.dependency_risk` now also covers the pickle-family wrappers
    `joblib.load`, `dill.load`/`dill.loads`, and `pandas.read_pickle`
    alongside the existing `pickle`/`torch.load`/`yaml.load`/`numpy.load`
    sinks.
  - `supply_chain.keras_lambda` flags a Keras `Lambda` layer — arbitrary
    Python that runs on `load_model`, no inference needed. `.keras` archives
    are parsed structurally and escalated when the layer references a
    non-Keras module (`os`, `subprocess`, …); legacy `.h5`/`.hdf5` are
    bytes-scanned as a lead. CVE-2025-1550, CVE-2025-9905, CVE-2024-3660.
  - `supply_chain.saved_model_ops` flags TensorFlow SavedModel
    `ReadFile`/`WriteFile` graph operators — load-time filesystem read/
    overwrite — via a bytes-scan of `saved_model.pb` (lead; JFrog
    TFLOW-MALOPS).
  - `supply_chain.malicious_dependency` flags known-malicious package
    releases in dependency manifests via a curated blocklist (e.g. the
    `ultralytics` 8.3.41/42/45/46 compromise) and install-time network
    fetches in `setup.py`.
  - `prompt.mcp_tool_poisoning` flags hidden instructions in an MCP tool
    manifest — invisible/format Unicode, instruction-override phrases, and
    base64 payload blobs in tool descriptions (indirect prompt injection).
  - `supply_chain.remote_code_config` flags a model `config.json` whose
    `auto_map`/`custom_pipelines` points at custom Python executed on a
    `trust_remote_code=True` load — the on-disk artifact of the RCE the
    `.py`-only `remote_code` scan cannot see; HIGH when the referenced module
    ships alongside, a MEDIUM lead otherwise.
  - `supply_chain.notebook_payload` scans Jupyter `.ipynb` code cells (a format
    the `.py` scanners never open) for the shared code-execution sinks and for
    `!curl … | sh` shell escapes; a cell whose Python cannot be parsed is
    surfaced as a lead, never silently skipped.
  - `supply_chain.remote_code` now also flags `torch.hub.load(...)`, which
    downloads a GitHub repo and runs its `hubconf.py` at load time.
  - `prompt.hidden_instructions` flags invisible instruction-smuggling
    characters (bidirectional overrides, the Unicode Tags block, zero-width
    space) in agent rule files (`.cursorrules`, `.windsurfrules`) and Markdown
    model cards — the "Rules File Backdoor" (Pillar Security, 2025). The signal
    is concealment, not imperative language, so a plain rules file is not
    flagged. The hidden-character vocabulary is shared with `mcp_tool_poisoning`.
  - `training.dataset_integrity` flags two deterministic training-data hygiene
    gaps that make poisoning possible: a Hugging Face dataset loading script
    (code runs on load) at MEDIUM, and an unpinned `load_dataset(...)` with no
    `revision=` (a swappable source) at LOW. First rule to map OWASP LLM04
    (Data & Model Poisoning) / ML02.
  - `scenario.indirect_injection` — indirect / RAG prompt injection: a poisoned
    "retrieved document" instructs the model to reveal its secret token; a
    canary leak proves it obeyed. First rule to map OWASP LLM08.
  - `agent.excessive_tool_use` — offered a benign calculator alongside
    shell/delete/email tools for a trivial arithmetic task, a model that reaches
    for a destructive one is flagged. Graded deterministically on the tool calls
    it actually made (not its text), so it is near-certain like a canary. First
    rule to map OWASP LLM06; needs the new tool-calling target capability.
  - `prompt.unbounded_consumption` — a divergence ("repeat forever") probe whose
    reply runs on with no server-side cap (denial-of-wallet). Graded by the new
    `length` evaluator as a lead. First rule to map OWASP LLM10.
- **Tool-calling endpoint target**: `EndpointTarget.offer_tools(...)` and the
  optional `ToolCallingTransport` (implemented by the OpenAI transport; `ollama`
  and `tgi` are unaffected) let a rule offer tools and observe the model's
  `tool_calls`, gated by the new `CALL_TOOLS` capability. This is the "observe
  more than a text reply" unlock that enables the excessive-agency check.
- **`length` evaluator** — grades a reply by length; a runaway answer to a
  divergence prompt is a lead. Fails closed (`inconclusive`) on no reply.
  - `supply_chain.pickle_opcode` hardened: it now unzips ZIP-based `.pt`
    archives and scans **every member regardless of extension**
    (CVE-2025-1889), reports a dangerous global seen **before** a
    deliberately-broken stream tail as CRITICAL instead of a silent LOW
    "unscanned", and flags a 7z-compressed model it cannot decompress
    (the nullifAI evasion) rather than passing it clean.
- **`Exchange` conversation primitive** (`guardana.core.exchange`): every
  evaluator grades a full exchange (prompt(s) + reply(s) + transcript), not a
  bare string. An exchange with no reply text is graded `inconclusive` by
  every built-in evaluator — fail-closed by construction.
- **Declarative multi-turn scenarios**: a YAML rule with `steps:` drives a
  whole conversation — the full history is replayed each turn by default,
  or `stateful: true` sends only the new message to a server that keeps
  session state — with an `expect:` per step and/or for the conversation as
  a whole. A scenario with no `expect` anywhere is a load error — an
  ungraded scenario would pass everything.
- **Named endpoint providers**: `--provider openai|ollama|tgi` on `probe` and
  `monitor`. The default `openai` transport covers any OpenAI-compatible
  server (vLLM, llamafile, Ollama's `/v1`); `ollama` speaks the native
  `/api/chat`, `tgi` speaks Hugging Face TGI's `/generate`. An unknown
  provider fails loudly.
- **`llm_judge` wired from config**: an `evaluators.llm_judge:` block in
  `guardana.yaml` (`endpoint`, `model`, optional `api_key_env`,
  `prompt_version`, `min_agreement`) builds the judge as an ordinary
  endpoint — a local vLLM/Ollama gives fully offline grading. The judging
  prompt is versioned and stamped into the finding
  (`evaluator_id: llm_judge@2025.1`); confidence is the agreement fraction
  across `min_agreement` samples instead of a flat constant; a reply with no
  parseable verdict fails closed at reduced confidence. Without the config
  block, a rule that names `llm_judge` is skipped *visibly* — never silently
  passed.
- **Optional `guard` evaluator**: grades a reply with an external safety
  classifier (Llama Guard / Granite Guardian style) via an
  `evaluators.guard:` block. Opt-in only, at conservative confidence — a
  guard used as an always-on all-clear would fail open. An unrecognized guard
  reply is `inconclusive`, never a pass.
- **`unverified` findings channel**: a dynamic check that ran but could not
  reach a verdict (unreachable judge, empty model reply) lands in
  `ScanResult.unverified` and is rendered distinctly in all four formats
  (human `? [UNVERIFIED]`, JSON `unverified`, SARIF `level: note` +
  `kind: review`, JUnit `<skipped>`). `fail_on.fail_on_inconclusive: true`
  makes unverified checks fail the gate.
- **Lead-confidence static findings**: probabilistic supply-chain signals
  (possible slopsquat imports, unpinned model downloads, missing license) now
  carry an explicit low-confidence "lead" verdict, while deterministic
  detections (pickle opcodes, secrets) stay verdict-free and certain.
- **`guardana` CLI** (`guardana-cli`): `scan`, `probe`, `monitor`, `init`,
  `rules`, and `new-rule` commands, plus `--version`.
- **Security layers (`Surface`)**: every rule belongs to the **build** layer
  (static, artifact — how the model is made) or the **runtime** layer (dynamic,
  endpoint — how it behaves), derived from what it inspects. `guardana rules`
  groups its output by layer and takes `--surface build|runtime`. The command
  already picks the layer: `scan` runs build rules, `probe`/`monitor` runtime.
- **Named policy presets (`--preset`)** on `scan`/`probe`/`monitor`, for the
  three moments you run Guardana: `ci` (fail on HIGH), `pre-training` (stricter,
  fail on MEDIUM so leads block a training run), and `monitor` (fail on HIGH and
  on inconclusive). Mutually exclusive with `--profile`.
- **A-Z product guide** (`docs/how-it-works.md`): the whole product end to
  end — concept, engine, the two layers, the three run modes, and how extensions
  plug in.
- **Custom rule directories**: the repeatable `--rules PATH` flag on `scan`,
  `probe`, and `monitor`, and `rules.paths: [...]` in `guardana.yaml`, load
  declarative YAML rules straight off disk — no packaging. A malformed rule
  file is a warning, never an abort.
- **`guardana new-rule <id> [--evaluator keyword|canary] [--dir PATH]`**:
  scaffolds a ready-to-edit YAML rule for the `--rules` workflow.
- **Monitor plants a canary**: each `guardana monitor` cycle runs the same
  probe `guardana probe` runs, planting a fresh random canary in a dedicated
  system prompt — so the CRITICAL system-prompt-leak rule runs every cycle
  instead of being skipped. `monitor` also takes `--system-prompt-file`,
  same as `probe`.
- **Reporters** (`guardana-report`): human, SARIF, JSON, and JUnit output.
- **Taxonomy mappings**: every built-in rule tagged against OWASP LLM Top 10,
  MITRE ATLAS, and NIST.
- **Plugin extension model**: rules, evaluators, and targets can be added via
  YAML (no code) or Python entry points (`guardana.rules`,
  `guardana.evaluators`, `guardana.targets`), discovered identically for
  built-in and third-party packages. `guardana scan --no-plugins` disables
  entry-point discovery entirely.
- **`guardana.core.testing`**: transport test doubles (`ScriptedTransport`,
  `RefusingTransport`, `EchoingTransport`, `ToolCallingScriptedTransport`,
  `FailingTransport`) so a dynamic rule's positive and negative fixtures run
  against a scripted model with no network.
- **Versioned collector envelope**: the reporter POSTs a versioned envelope
  (`schema_version`, currently `2` — it carries `findings` and the `unverified`
  channel alongside `source`/`summary`), and `guardana-server` validates
  every submission with Pydantic — a malformed POST or an unsupported
  `schema_version` gets `422` instead of poisoning `/findings` and `/trend`.
- **Optional `guardana-server` collector**: ingests normalized `Finding`s from
  many agents for a list/trend view, kept behind the core↔server boundary
  (`guardana-core` never imports `guardana-server`).
- **Opt-in monitoring dashboard** (`guardana-server`): off by default; enabled
  with `create_app(dashboard=True)` or `GUARDANA_DASHBOARD=1`. A single
  self-contained HTML page (no build step, works offline) served at `GET /`,
  backed by an aggregated `GET /stats` — severity, per-source and per-rule
  breakdowns, an activity-over-time trend, a prominent `unverified` counter, and
  a recent-findings list. Each finding shows a **human-readable rule name** with
  an expandable detail (what the rule catches, the evidence, the graded verdict,
  and the standards tags), served from a bundled `catalog/en.json` (`GET
  /catalog`) that a test pins to the rule registry so it can't drift; custom
  rules fall back to the finding's own title. The findings list scrolls in its
  own bounded box so the page height stays stable as findings accumulate.
  Read-only and unauthenticated (same posture as the collector); the store gained
  timestamped `records()` for the time-series, and `Store.list()` was renamed to
  `Store.submissions()`.
- **Tooling hardening**: curated ruff ruleset including bandit (`S`) and
  public-API docstrings (`D`); `mypy --strict` across the whole repo, tests
  included; pytest branch-coverage gate (`fail_under = 90`) in CI; an
  import-linter contract enforcing that the engine never depends on the
  collector; pre-commit hooks with conventional-commit message enforcement
  and `detect-private-key` (plus pre-push mypy / import-linter / pytest /
  dogfood-scan gates); dependency audit (`uv audit`) in CI. CI dogfoods
  Guardana against its own source (`guardana scan packages`) on every push.

### Changed

- **`hallucinated_package` no longer floods real ML repos with false positives.**
  It now folds in the top-level import names of every distribution installed in
  the scanning environment (`importlib.metadata.packages_distributions()`) and
  ships a much larger curated allowlist that covers import names differing from
  their PyPI distribution (`bs4`→beautifulsoup4, `jwt`→PyJWT, `cv2`→opencv-python,
  `psycopg2`, `sentence_transformers`, `prometheus_client`, …). This only removes
  noise: a package that is importable demonstrably exists, so a non-existent
  (hallucinated) one can never appear in either set — the check is not weakened.
- **`hardcoded_secret` now scans web/systems source files**, not just Python and
  config. Added `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs`/`.go`/`.rb`/`.java`/`.kt`/
  `.rs`/`.php`/`.cs`/`.tf`/`.tfvars`/`.gradle`/`.xml` (and `.bash`/`.zsh`): a
  served model is fronted by a Node/Go/Java gateway as often as a Python one, and
  a secret there leaks just the same.
- **`guardana rules --rules <dir>`** now includes custom YAML rule packs in the
  listing (the same repeatable flag `scan`/`probe` accept), so you can confirm a
  pack parses and is discovered without launching a probe; unloadable files are
  warned about, never silently dropped.

### Security

Findings from the pre-release code audit. Guardana has not
been released, so none of these ever reached a user — but each one would have
weakened the guarantee the tool exists to make.

- **A profile that silently disabled every rule.** `include: "guardana.*"` — a
  string where a list belongs, which YAML accepts without complaint — was
  exploded into single-character globs that match no rule id. A scan would run
  **zero rules and exit 0** on a repository containing a malicious pickle. A
  profile that cannot be honoured now raises at load time instead of quietly
  becoming a weaker one; the same applies to a typo'd key or an unknown
  severity.
- **`dependency_risk` missed the dangerous form of `yaml.load`.** It flagged
  only calls with no `Loader=` (which modern PyYAML rejects anyway) while
  `yaml.load(data, Loader=yaml.UnsafeLoader)` — the actual RCE vector — passed
  clean. The loader's *value* is now inspected, whether it is passed by keyword
  or positionally.
- **`guardana monitor` ran a weaker rule set than `guardana probe`.** It never
  planted a system prompt, so the CRITICAL system-prompt-leak rule was skipped
  for an unmet capability on every cycle. It now runs the same probe.
- **A malformed POST could take down the collector's `/trend`** for every
  client until restart. Submissions are validated; the store is bounded.
- **A rule could crash a whole scan.** An unreadable directory raised
  `PermissionError` (not a `RuleError`) out of `hallucinated_package`. Rules
  now degrade to "skipped" instead of aborting the run.
- **Type-narrowing `assert`s in six rules** would have vanished under
  `python -O`, letting a rule run against a target it cannot handle.
- Outbound URLs are restricted to `http`/`https`, and evaluator confidences are
  validated to `[0, 1]` so a third-party evaluator cannot distort a policy gate.

A second, adversarial review pass (reviewers instructed to assume the first pass
was overconfident) found more of the same "silence spelled as pass" class:

- **A profile could disable its own gate two more ways.** `min_confidence: .nan`
  (or any value outside `[0, 1]`) silently made the confidence gate unfailable;
  an empty or null `include:` matched no rule at all. Both now raise at load.
- **The secret scanner missed every current LLM key format.** `sk-proj-`
  (OpenAI's default since 2024), `sk-ant-api03-` (Anthropic), and `sk-svcacct-`
  all slipped past the old `sk-[A-Za-z0-9]{20,}` pattern — the single most
  likely secret in an AI repo. Added those plus the `gho_`/`ghu_`/`ghs_`/`ghr_`
  GitHub token forms and the `ENCRYPTED`/`DSA`/`PGP` private-key headers.
- **Two evaluators reported a confident "pass" on checks that never ran.** A
  canary rule with no planted canary, and an `llm_judge` reply it couldn't
  parse, both used to read as all-clear. The canary case is now rejected at
  load; the judge now fails closed on unparseable output and recognizes real
  verdict formats (`**FAIL**`, `FAIL - …`).
- **A model reply of `content: null`** (a refusal or tool-call) became the
  literal string `"None"` and was graded as a clean pass. It is now rejected as
  having no text to evaluate.
- **A crafted repo could hang or OOM the scanner.** A FIFO or a `/dev/zero`
  symlink named `*.py` reports `st_size == 0`, sailed past the size check, and
  read forever. The reader now skips non-regular files and bounds the read
  itself rather than trusting `stat()`; the scan bound was also raised so real
  generated sources are scanned, not silently skipped.
- **A malformed YAML rule crashed the whole scan** (raw `TypeError` /
  `AttributeError` out of load), and a scalar `prompts:` string exploded into
  single-character prompts. Rule loading now validates every field and reports a
  bad file instead of aborting.
- **The long-running monitor died on the first transient blip** and blamed the
  wrong host; a dead collector took it down too. It now survives transient
  endpoint failures per-cycle and only exits when the endpoint never worked.
- **The collector could be crashed or exhausted.** Concurrent reads during
  ingest raised "deque mutated during iteration" and 500'd `/trend`; an
  unbounded body could store millions of findings; an omitted `schema_version`
  was guessed as v1. The store is now lock-guarded, the envelope is
  length-bounded, `/findings` is paginated, and `schema_version` is required.
- Duplicate rule ids (from overlapping `--rules` / `rules.paths`) ran twice —
  doubled findings and doubled probe calls against a live model. The registry
  now de-dupes by id, last-wins (which also lets a custom rule override a
  built-in).
- **A YAML rule silently dropped `inconclusive` verdicts.** The evaluation
  loop kept only `fail` outcomes, so a check that *could not run* (no reply
  to grade, an unreachable judge) read as a clean pass — the exact
  fail-open this project exists to prevent. Inconclusive verdicts are now
  surfaced on the dedicated `unverified` channel in every output format.

A third adversarial pass (same instruction: assume the previous passes were
overconfident) found that green gates still hid live fail-opens of the same
class:

- **A scan that ran zero rules exited 0 with a green "No findings".** The
  earlier fix rejected the `include:`-scalar *input* that produced the
  zero-rules state, but never guarded the resulting *state*: `exclude: ["*"]`,
  an `include:` glob matching no id, and `--no-plugins` with no `--rules` each
  still reported a confident all-clear on a malicious repo. `gate()` now fails
  when `rules_run == 0` (nothing was verified, so it cannot pass), and the human
  renderer refuses to print "No findings" when nothing ran.
- **The collector envelope dropped the entire `unverified` channel.** The
  human/JSON/SARIF/JUnit renderers surface checks that could not be graded, but
  the reporter serialized only `findings` — so a model whose CRITICAL checks
  could not run was forwarded to the fleet dashboard as `findings: []`, a false
  all-clear at the collector boundary. The envelope now carries `unverified`
  (and a summary count); `schema_version` bumped to 2 and the collector stores
  and retains it.
- **The pickle scanner silently skipped ZIP members it could not read.** A
  member that raised `RuntimeError` (an encrypted member) aborted the whole
  scan; a member that was itself a nested archive was passed clean. Both now
  become a visible "unscanned" finding — without flooding ordinary `.pt` tensor
  storages with noise, which is why only nested-archive magics are flagged.
- **`malicious_dependency` missed every multi-line lockfile.** The known-bad
  release check required name and version on one line, so `poetry.lock`,
  `uv.lock`, and `pdm.lock` — the files that authoritatively pin a resolved
  dependency — never matched. It now parses the `[[package]]` block form, and a
  longer release sharing a bad prefix (`8.3.410` vs `8.3.41`) no longer false-positives.
- **The monitor never alerted when its own checks stopped grading.** A served
  model whose judge went down or whose replies came back empty kept `findings`
  at 0 while `unverified` climbed, and under the default policy no alert ever
  fired — the monitor going blind looked identical to a healthy model. It now
  baselines and alerts on a rising `unverified` count too.
- **A `canary` rule could be authored so its marker was never planted.** The
  schema forced `expect.canary` but not `requires: [plant_system_prompt]`, so a
  canary rule (single-turn or scenario) could run against a target where the
  canary was never set and pass everything. That combination is now a load-time
  error, and the probe plants a fresh canary for multi-turn scenarios too, not
  only single-turn rules.
- **The keyword evaluator treated compliant openers as refusals.** `"as an ai"`
  and `"i'm sorry"` open harmful compliances (`"As an AI, here's how to…"`) at
  least as often as refusals, so they graded compliance as a PASS. Removed; a
  genuine apologetic refusal still matches a hard refusal phrase, and the bias
  now errs toward surfacing a reply, not hiding it.
- **`insecure_transport` missed an uppercase `HTTP://` scheme.** The plaintext
  check was case-sensitive; the scheme is now matched case-insensitively.

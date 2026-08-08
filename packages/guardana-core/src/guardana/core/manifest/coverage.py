"""What a run was *able* to check, as opposed to what it found.

`rules_run` started this promise and only half kept it: a comparison that knows
which rules ran still cannot tell "the system improved" from "this build could
check less". Fewer applicable checks must never read as an improvement, so
everything that bounds what a run could have found is recorded in one place and
digested into one value `diff` can compare.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from guardana.core.fingerprint import digest_of
from guardana.core.manifest.records import EvaluatorRecord, RuleRecord


@dataclass(frozen=True, slots=True)
class TaxonomyCatalogRecord:
    """One framework catalogue that was installed when the run happened.

    Pinned so a report stays readable years later without anybody having to
    remember which edition was installed: `OWASP-LLM-2025` and `OWASP-LLM-2026`
    give the same short ids to different controls, and a run that does not say
    which it held leaves its own mapping ambiguous.
    """

    framework: str
    digest: str
    entries: int
    version: str | None = None


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    """The reach of one run: what could have been checked, and with what.

    `digest` is one value over everything here plus the rules, evaluators and
    target capabilities, so a comparison can say *coverage changed* in one line
    instead of diffing five lists. `None` means the run did not record a
    fingerprint — an older document — which is not the same as "coverage was
    identical", and `diff` says so rather than assuming.
    """

    digest: str | None = None
    taxonomies: tuple[TaxonomyCatalogRecord, ...] = ()
    protocols: Mapping[str, str] = field(default_factory=dict)
    """Protocol versions the target actually negotiated, by protocol name.

    A server that answered an MCP handshake with an older revision than the client
    offered supports fewer methods, so a run against it verified less — and the
    only place that is knowable is the handshake.
    """


def coverage_digest(
    rules: Sequence[RuleRecord],
    evaluators: Sequence[EvaluatorRecord],
    capabilities: Sequence[str],
    taxonomies: Sequence[TaxonomyCatalogRecord],
    protocols: Mapping[str, str],
) -> str:
    """Digest everything that bounded what this run could find.

    Sorted before hashing, deliberately: rule discovery order depends on
    entry-point ordering and on which directories a `--rules` flag was given in,
    and a fingerprint that moved with it would report a coverage change on every
    other run — which is the same as reporting none.

    Trial counts are folded in through `RuleRecord.trials`. A rule that sends four
    prompts and a rule that sends one are not the same amount of checking, and a
    corpus trimmed to a quarter of its prompts must not read as an unchanged run.
    """
    parts = [
        *sorted(f"rule:{r.id}:{r.digest}:{'?' if r.trials is None else r.trials}" for r in rules),
        *sorted(f"evaluator:{e.id}:{e.digest or '?'}" for e in evaluators),
        *sorted(f"capability:{c}" for c in capabilities),
        *sorted(f"taxonomy:{t.framework}:{t.digest}" for t in taxonomies),
        *sorted(f"protocol:{name}:{version}" for name, version in protocols.items()),
    ]
    return digest_of(*parts)

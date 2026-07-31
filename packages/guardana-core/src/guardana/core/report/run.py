"""What a run was, as opposed to what it found.

`ScanResult` answers "what did this turn up". None of it answers "and what was
this, exactly" — which version of the tool, against what, with which rules, when.
Those are the questions a second run has to agree on before the two can be
compared at all, so they live here rather than being inferred later from the
findings, which is how a narrowed profile ends up reading as an improvement.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from guardana.core.report.result import ScanResult
from guardana.core.target import TargetKind

REPORT_SCHEMA_VERSION = 1
"""Version of the JSON document `--format json` writes.

Separate from the collector envelope's version (`guardana.core.reporter`), because
they are separate formats on separate cadences: one is a file a user keeps and
feeds back in, the other is a wire format between an agent and a service.

Versioned from its first release rather than when it first hurts: the moment
`guardana diff` reads this document, its shape is a public contract, and a reader
that cannot tell which shape it is holding has to guess — which is the failure
versioning exists to prevent.
"""


@dataclass(frozen=True, slots=True)
class RunMeta:
    """The circumstances of one run: what ran, against what, when, and with which rules.

    `rules` maps each rule that ran to its digest, so a later comparison can say
    "this rule fails today, but the rule itself also changed" instead of blaming a
    model for a test someone sharpened.
    """

    tool_version: str
    target_kind: TargetKind
    target_ref: str
    profile: str
    rules: Mapping[str, str] = field(default_factory=dict)
    rules_skipped: tuple[str, ...] = ()
    started_at: datetime | None = None
    """When the run began, when the writer knew it.

    Optional because a `ScanResult` assembled in a library has no obvious clock,
    and a fabricated timestamp is worse than an absent one. When both runs carry
    it, a comparison can refuse a pair handed to it in the wrong order — the
    silent way a CI script turns a regression into a clean bill of health.
    """


@dataclass(frozen=True, slots=True)
class RunReport:
    """One saved run: its circumstances and its result."""

    meta: RunMeta
    result: ScanResult

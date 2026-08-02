"""What a run was, as opposed to what it found.

`ScanResult` answers "what did this turn up". None of it answers "and what was
this, exactly" — which version of the tool, against what, with which rules, when.
Those are the questions a second run has to agree on before the two can be
compared at all, so they live here rather than being inferred later from the
findings, which is how a narrowed profile ends up reading as an improvement.
"""

from dataclasses import dataclass

from guardana.core.manifest.model import MANIFEST_SCHEMA_VERSION, RunManifest
from guardana.core.report.result import ScanResult

REPORT_SCHEMA_VERSION = MANIFEST_SCHEMA_VERSION
"""Version of the JSON document `--format json` writes.

One number for one file. The document is the manifest plus the finding channels,
so the manifest's version is the document's version — two numbers for one file is
how they start to disagree.

Separate from the collector envelope's version (`guardana.core.reporter`), which
is a wire format between an agent and a service rather than a file a user keeps.
"""


@dataclass(frozen=True, slots=True)
class RunReport:
    """One saved run: the manifest describing it, and the result it produced."""

    manifest: RunManifest
    result: ScanResult

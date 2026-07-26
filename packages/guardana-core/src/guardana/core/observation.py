"""What a scan *saw*, as opposed to what it found wrong.

Rules produce findings — a record of problems. That is the wrong shape for three
questions people keep asking a scanner: what is actually deployed here, what
changed since the last run, and what was covered. Each needs a record of
*components*, and none of them should have to walk the tree again to get one.

Deliberately free of any framework's vocabulary. An `Observation` is a fact about
a file or an endpoint — a name, a location, a few attributes — and mapping those
facts onto whatever a buyer or a regulator asks for (CycloneDX, a model card, an
audit template) belongs in an extension package, never here. Formats and
deadlines change; this does not.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class ObservationKind(StrEnum):
    """What sort of component was observed."""

    MODEL = "model"
    DATASET = "dataset"
    DEPENDENCY_MANIFEST = "dependency-manifest"
    NOTEBOOK = "notebook"


@dataclass(frozen=True, slots=True)
class Observation:
    """One component a scan saw, with the little that is known about it for free.

    `attributes` carries whatever the observation was able to establish cheaply —
    a format, a size — and says so when it could not: a component that could not
    be read is still listed, marked unread. Dropping it would shrink the inventory
    silently, which is the same class of lie as a check that could not run
    reporting clean.
    """

    kind: ObservationKind
    name: str
    ref: str
    attributes: Mapping[str, str] = field(default_factory=dict)

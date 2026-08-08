"""Load the catalogues Guardana ships, and refuse a crosswalk that points at nothing.

Import-time work on purpose: a rule's `taxonomy:` is resolved while the rule is
being parsed, so the catalogues have to be there before any discovery runs. A
malformed or missing catalogue raises here — one sentence naming the file, rather
than one failure per rule with the cause a directory away.
"""

from pathlib import Path

from guardana.core.taxonomy._catalog import TaxonomyCatalog, load_catalogs
from guardana.core.taxonomy._index import ReferenceIndex
from guardana.core.taxonomy._ref import TaxonomyError

CATALOG_DIR = Path(__file__).parent / "catalog"

CATALOGS: tuple[TaxonomyCatalog, ...] = load_catalogs(CATALOG_DIR)
"""Every built-in catalogue, in filename order."""

index = ReferenceIndex()
for _catalog in CATALOGS:
    for _ref in _catalog.refs:
        index.add(_ref)


def _refuse_a_crosswalk_that_points_at_nothing() -> None:
    """Check every declared correspondence resolves, before anything reads one.

    A crosswalk entry naming an edition that is not installed — or a mistyped
    reference — would otherwise be silently skipped, and a reader asking what a
    2025 reference means today would be told "nothing corresponds to it" for a
    typo. The relation between two editions is data, and data this build cannot
    resolve is broken data, not an absent relation.
    """
    for catalog in CATALOGS:
        for link in catalog.correspondences:
            for reference in (link.subject, link.other):
                if index.by_reference(reference) is None:
                    raise TaxonomyError(
                        f"{catalog.framework} declares a correspondence with "
                        f"{reference!r}, which no installed catalogue defines"
                    )


_refuse_a_crosswalk_that_points_at_nothing()

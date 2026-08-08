"""The lookup behind `resolve()`: three indexes over one set of references.

Keyed on the canonical reference (`LLM07:2025`) rather than on the short id, which
is the whole change this module exists for — two editions of one framework hold the
same short ids and name different controls. The second index answers the question a
*reader* of a saved run asks, `(framework, id)`, and the third is what makes an
ambiguous bare id an error with the candidates named in it.
"""

from guardana.core.taxonomy._ref import TaxonomyError, TaxonomyRef


class ReferenceIndex:
    """Every registered reference, resolvable three ways.

    Not thread-safe, and does not need to be: registration happens during
    discovery, before any rule runs.
    """

    def __init__(self) -> None:
        self._by_reference: dict[str, TaxonomyRef] = {}
        self._by_framework: dict[tuple[str, str], TaxonomyRef] = {}
        self._by_local_id: dict[str, list[TaxonomyRef]] = {}

    def add(self, ref: TaxonomyRef) -> None:
        """Register one reference, refusing the two redefinitions that would mislead.

        Re-adding an identical reference is a no-op: discovery runs once per command
        and many times per test session, and a pack that registered cleanly must not
        look broken the second time round.
        """
        existing = self._by_reference.get(ref.reference)
        if existing == ref:
            return
        if existing is not None:
            raise TaxonomyError(
                f"taxonomy reference {ref.reference!r} is already registered by "
                f"{existing.framework!r}; a reference means one thing across every report, "
                f"so it cannot be redefined"
            )
        clash = next((r for r in self._by_local_id.get(ref.id, ()) if r.scheme != ref.scheme), None)
        if clash is not None:
            raise TaxonomyError(
                f"taxonomy id {ref.id!r} is already registered by {clash.framework!r}; "
                f"a short id means one thing across every report, so it cannot be redefined "
                f"by another framework"
            )
        self._by_reference[ref.reference] = ref
        self._by_framework[ref.framework, ref.id] = ref
        self._by_local_id.setdefault(ref.id, []).append(ref)

    def forget(self, reference: str) -> None:
        """Drop one reference again. For a test that registered a fake framework."""
        ref = self._by_reference.pop(reference, None)
        if ref is None:
            return
        self._by_framework.pop((ref.framework, ref.id), None)
        remaining = [r for r in self._by_local_id.get(ref.id, ()) if r != ref]
        if remaining:
            self._by_local_id[ref.id] = remaining
        else:
            self._by_local_id.pop(ref.id, None)

    def all(self) -> tuple[TaxonomyRef, ...]:
        """Every registered reference, in registration order."""
        return tuple(self._by_reference.values())

    def by_reference(self, reference: str) -> TaxonomyRef | None:
        """Resolve a canonical reference, or None when nothing is registered under it.

        Raises `TaxonomyError` when `reference` is a bare short id whose editions
        each define it. Distinct from returning None on purpose: a typo and an
        under-specified reference need different answers, and defaulting to an
        edition would silently change what a rule claims when a catalogue is added.
        """
        found = self._by_reference.get(reference)
        if found is not None:
            return found
        candidates = self._by_local_id.get(reference, [])
        if candidates:
            named = ", ".join(sorted(r.reference for r in candidates))
            raise TaxonomyError(
                f"taxonomy id {reference!r} does not say which edition it means; "
                f"write one of: {named}"
            )
        return None

    def by_framework(self, framework: str, local_id: str) -> TaxonomyRef | None:
        """Resolve the pair a saved run records, or None when this build has neither."""
        return self._by_framework.get((framework, local_id))

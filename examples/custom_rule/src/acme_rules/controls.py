"""Acme's own control catalogue, registered through the `guardana.taxonomies` group.

Every rule maps to a public framework, and most companies keep a second catalogue
besides — the controls an internal auditor asks about by number. The engine knows
no regulation, so a framework it has never heard of arrives exactly the way a rule
does: through an entry point, as data.

Registration is what makes `taxonomy: [ACME-14]` resolvable in a YAML rule. Without
it the reference is a load-time error, and that is the point — an unknown mapping
fails loudly instead of becoming a rule that maps to nothing.
"""

from guardana.core.taxonomy import TaxonomyRef

ACME_14 = TaxonomyRef(
    scheme="ACME-CONTROLS",
    id="ACME-14",
    title="Internal data does not leave the support boundary",
)
"""Acme control 14, as `docs/usage-taxonomy.md` writes it.

No edition, because Acme publishes none — a scheme states an edition only where
it actually reissues its entries under the same short ids, which is what makes
`LLM07:2025` and `LLM07:2026` two different controls and `ACME-14` one.
"""

from guardana.core.registry import Registry

_EXPECTED_CATALOG_IDS = {
    "guardana.prompt.injection.ignore_previous",
    "guardana.prompt.jailbreak.dan_style",
    "guardana.prompt.system_prompt_leak.canary",
}


def test_catalog_rules_are_discovered_by_exact_id() -> None:
    ids = {r.meta.id for r in Registry.discover().rules()}

    assert ids >= _EXPECTED_CATALOG_IDS


def test_catalog_rules_declare_their_evaluator_and_taxonomy() -> None:
    catalog = [r for r in Registry.discover().rules() if r.meta.id in _EXPECTED_CATALOG_IDS]

    assert len(catalog) == len(_EXPECTED_CATALOG_IDS)
    assert all(r.meta.evaluator for r in catalog)
    assert all(r.meta.taxonomy for r in catalog)

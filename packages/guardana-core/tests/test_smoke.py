from guardana.core import (
    Evaluator,
    Finding,
    Profile,
    Registry,
    Rule,
    Runner,
    Severity,
    Target,
    __version__,
)


def test_core_imports_and_has_version() -> None:
    assert __version__ == "0.1.0"


def test_public_api_reexported_at_top_level() -> None:
    assert Rule is not None
    assert Evaluator is not None
    assert Target is not None
    assert Finding is not None
    assert Profile is not None
    assert Registry is not None
    assert Runner is not None
    assert Severity is not None

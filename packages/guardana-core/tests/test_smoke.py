import re

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
    # A pattern, not a literal: a hardcoded version breaks this smoke test on every
    # release bump. The precise __init__/pyproject match is guarded in
    # test_release_tooling; here we only assert core exposes a semver-shaped version.
    assert re.match(r"^\d+\.\d+\.\d+", __version__) is not None


def test_public_api_reexported_at_top_level() -> None:
    assert Rule is not None
    assert Evaluator is not None
    assert Target is not None
    assert Finding is not None
    assert Profile is not None
    assert Registry is not None
    assert Runner is not None
    assert Severity is not None

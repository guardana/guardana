"""The exit-code table survives a clean install, where Click may not be installed.

`guardana.cli.main` imported `click` at module scope, so that a usage error would
exit `3` like the rest of the table. Typer used to pull Click in, so every test
passed — and then Typer 0.26 vendored it and dropped the dependency, at which
point a clean install crashed on **every** command with
`ModuleNotFoundError: click`.

The static half of that lesson — is every import declared, in all five
distributions — is `packages/guardana-core/tests/test_declared_dependencies.py`,
and the runtime half is `scripts/clean_install_check.py`. What is left here is the
part specific to this package: the table still holds when only Typer's vendored
Click is present, and says so loudly when neither is.
"""

import importlib
from types import ModuleType

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import _use_guardana_exit_code_for_usage_errors


def test_usage_errors_still_exit_three_without_standalone_click(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clean-install condition, simulated: Typer's vendored Click and nothing else."""
    real = importlib.import_module

    def without_standalone_click(name: str, package: str | None = None) -> ModuleType:
        if name == "click":
            raise ImportError("no module named 'click'")
        return real(name, package)

    monkeypatch.setattr(importlib, "import_module", without_standalone_click)

    _use_guardana_exit_code_for_usage_errors()

    vendored = real("typer._click")
    assert vendored.exceptions.UsageError.exit_code == int(ExitCode.INVALID_USAGE)


def test_finding_no_click_at_all_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """A table the tool silently stops honouring is worse than one it never promised."""

    def nothing(name: str, package: str | None = None) -> ModuleType:
        raise ImportError(f"no module named {name!r}")

    monkeypatch.setattr(importlib, "import_module", nothing)

    with pytest.raises(RuntimeError, match="exit-code table"):
        _use_guardana_exit_code_for_usage_errors()

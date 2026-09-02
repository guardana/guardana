"""Every double the testing kit exports is named in the extension guide.

Eleven of the sixteen exports were documented nowhere: a third party reading the
guide would not know `GullibleAgentTransport` exists and would write a worse one.
"""

from pathlib import Path

from guardana.core import testing


def _extending() -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "docs" / "extending.md"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError("docs/extending.md not found")


def test_every_testing_export_is_named_in_the_extension_guide() -> None:
    guide = _extending()
    missing = [name for name in testing.__all__ if f"`{name}`" not in guide]

    assert not missing, (
        f"exported by guardana.core.testing and absent from docs/extending.md: {missing}"
    )

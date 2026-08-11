"""A pack declares which extension API it needs, and refuses in both directions.

1.0 promises `Rule`, `Evaluator` and `Target` will not break under a third party.
The promise is only useful to somebody who can tell whether *this* build keeps it
for *their* package — so the declaration is data, versioned like every other
document a user keeps, and a "close enough" acceptance is worse than no declaration
because it is the point at which the author stops checking.
"""

from pathlib import Path

import pytest
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    PACK_SCHEMA_VERSION,
    ApiRange,
    PackError,
    PackManifest,
    check_pack,
    load_manifest,
)

_GOOD = """
schema_version: 1
name: acme-guardana-rules
extension_api: ">=1,<2"
provides:
  rules: [acme.agent.customer_data]
  evaluators: [acme.strict_refusal]
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana-pack.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_well_formed_manifest_loads(tmp_path: Path) -> None:
    manifest = load_manifest(_write(tmp_path, _GOOD))

    assert manifest.name == "acme-guardana-rules"
    assert manifest.provides == ("acme.agent.customer_data", "acme.strict_refusal")
    assert manifest.loadable_by(EXTENSION_API_VERSION)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (_GOOD.replace("schema_version: 1\n", ""), "no schema_version"),
        (
            _GOOD.replace("schema_version: 1", f"schema_version: {PACK_SCHEMA_VERSION + 9}"),
            "newer than this",
        ),
        (_GOOD.replace('extension_api: ">=1,<2"', ""), "'extension_api' is required"),
        (_GOOD.replace('">=1,<2"', '">=1"'), "closed range"),
        (_GOOD.replace('">=1,<2"', '">=2,<2"'), "accepts nothing"),
        (_GOOD.replace("provides:", "provides_typo:"), "unknown pack manifest key"),
        (_GOOD.split("provides:", maxsplit=1)[0] + "provides: {}", "lists nothing at all"),
        (_GOOD.split("provides:", maxsplit=1)[0], "'provides' is required"),
        (_GOOD.replace("name: acme-guardana-rules\n", ""), "'name' is required"),
    ],
)
def test_a_manifest_this_build_cannot_honour_is_refused(
    tmp_path: Path, body: str, message: str
) -> None:
    """Refused at load, never read optimistically — the same bar a contract has."""
    with pytest.raises(PackError, match=message):
        load_manifest(_write(tmp_path, body))


def test_an_open_ended_range_is_refused(tmp_path: Path) -> None:
    """It would claim compatibility with an API nobody has written yet."""
    with pytest.raises(PackError, match="does not exist yet"):
        load_manifest(_write(tmp_path, _GOOD.replace('">=1,<2"', '">=1"')))


def test_a_pack_built_for_an_older_api_is_told_to_upgrade_the_pack() -> None:
    """Two directions, two messages, one outcome.

    An author told only "incompatible" checks the wrong end, and an author who stops
    checking is exactly what a compatibility declaration exists to prevent.
    """
    manifest = PackManifest("acme", ApiRange(minimum=1, below=2), "x", rules=("acme.r",))

    assert not manifest.loadable_by(2)
    assert "upgrade the pack" in manifest.extension_api.why_not(2)


def test_a_pack_built_for_a_newer_api_is_told_to_upgrade_guardana() -> None:
    manifest = PackManifest("acme", ApiRange(minimum=3, below=4), "x", rules=("acme.r",))

    assert not manifest.loadable_by(2)
    assert "upgrade Guardana" in manifest.extension_api.why_not(2)


def test_a_promise_the_package_does_not_keep_is_a_problem() -> None:
    """The direction that matters: a declared check nobody registered.

    A team reading the manifest believes it runs. That is a false green arriving
    through documentation rather than through code, and it is the one thing
    comparing a manifest to a registry is for.
    """
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.present", "acme.absent"))

    check = check_pack(manifest, ["acme.present"])

    assert not check.ok
    assert "acme.absent" in check.problems[0]


def test_registering_more_than_the_manifest_lists_is_not_a_problem() -> None:
    """Only the broken promise is reported.

    A pack may register something it has not documented yet — that is untidy, not a
    lie, and failing a build over it would make the check something teams disable.
    """
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.present",))

    assert check_pack(manifest, ["acme.present", "acme.extra"]).ok


def test_the_built_in_pack_declares_exactly_what_it_registers() -> None:
    """Guardana's own pack goes through the third party's door.

    A validator this repository exempted itself from would be a bar we ask other
    people to clear alone — and the first drift it would stop catching is our own.
    """
    from importlib import resources  # noqa: PLC0415

    from guardana.rules import provide_evaluators, provide_rules  # noqa: PLC0415

    with resources.as_file(
        resources.files("guardana.rules").joinpath("guardana-pack.yaml")
    ) as path:
        manifest = load_manifest(path)

    registered = {rule.meta.id for rule in provide_rules()} | {
        evaluator.id for evaluator in provide_evaluators()
    }

    assert set(manifest.provides) == registered
    assert check_pack(manifest, registered).ok

"""A pack declares which extension API it needs, and refuses in both directions.

1.0 promises `Rule`, `Evaluator` and `Target` will not break under a third party.
The promise is only useful to somebody who can tell whether *this* build keeps it
for *their* package — so the declaration is data, versioned like every other
document a user keeps, and a "close enough" acceptance is worse than no declaration
because it is the point at which the author stops checking.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml
from _yaml_input_cases import NON_TEXT_KEYS
from guardana.core.pack import (
    EXTENSION_API_VERSION,
    PACK_SCHEMA_VERSION,
    ApiRange,
    PackError,
    PackManifest,
    check_pack,
    check_packs,
    load_manifest,
)
from guardana.core.pack.discover import Registered

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
    assert manifest.loadable_by()


def test_api_one_packs_keep_loading_when_the_build_adds_api_two() -> None:
    manifest = PackManifest("old", ApiRange(1, 2), "x", rules=("old.rule",))

    assert EXTENSION_API_VERSION == 2
    assert manifest.loadable_by()
    assert not manifest.loadable_by(EXTENSION_API_VERSION)


def test_a_range_is_compared_with_every_api_the_build_retains() -> None:
    supported = {1, 2}

    assert ApiRange(1, 2).why_not_any(supported) == ""
    assert "upgrade Guardana" in ApiRange(3, 4).why_not_any(supported)
    assert "upgrade the pack" in ApiRange(0, 1).why_not_any(supported)
    assert "declares no extension API" in ApiRange(1, 2).why_not_any(())


def test_pack_validation_refuses_a_range_outside_every_retained_api() -> None:
    manifest = PackManifest("future", ApiRange(3, 4), "x", rules=("future.rule",))

    check = check_pack(manifest, Registered(rules={"future.rule": None}))

    assert not check.ok
    assert "upgrade Guardana" in check.problems[0]


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

    check = check_pack(manifest, Registered(rules={"acme.present": None}))

    assert not check.ok
    assert "acme.absent" in check.problems[0]


def test_registering_more_than_the_manifest_lists_is_not_a_problem() -> None:
    """Only the broken promise is reported.

    A pack may register something it has not documented yet — that is untidy, not a
    lie, and failing a build over it would make the check something teams disable.
    """
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.present",))

    assert check_pack(manifest, Registered(rules=dict.fromkeys(["acme.present", "acme.extra"]))).ok


def test_a_rule_registered_only_as_an_evaluator_is_not_a_kept_promise() -> None:
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.check",))

    check = check_pack(manifest, Registered(evaluators={"acme.check": "acme-rules"}), "acme-rules")

    assert not check.ok
    assert "rule acme.check" in check.problems[0]


def test_a_rule_another_distribution_registers_is_not_this_packs_promise_kept() -> None:
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.check",))

    check = check_pack(manifest, Registered(rules={"acme.check": "other-rules"}), "acme-rules")

    assert not check.ok
    assert "acme.check (registered by other-rules)" in check.problems[0]


def test_a_rule_the_shipping_distribution_registers_is_a_kept_promise() -> None:
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.check",))

    assert check_pack(manifest, Registered(rules={"acme.check": "acme-rules"}), "acme-rules").ok


def test_packs_and_their_distributions_must_pair_up() -> None:
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.check",))

    with pytest.raises(ValueError, match="one distribution per manifest"):
        check_packs([manifest], Registered(rules={"acme.check": None}), [])


_FLAT_SET_REFUSED = (
    "check_pack and check_packs take a Registered; a flat set of ids is no longer accepted"
)


@pytest.mark.parametrize("flat", [frozenset({"acme.check"}), ["acme.check"], ("acme.check",)])
def test_a_flat_set_of_ids_is_refused_by_both_checks(flat: object) -> None:
    """A flat set cannot say which kind or distribution registered an id, so it checks less."""
    manifest = PackManifest("acme", ApiRange(1, 2), "x", rules=("acme.check",))

    with pytest.raises(TypeError) as refused_one:
        check_pack(manifest, flat)  # type: ignore[arg-type]
    with pytest.raises(TypeError) as refused_all:
        check_packs([manifest], flat)  # type: ignore[arg-type]

    assert str(refused_one.value) == _FLAT_SET_REFUSED
    assert str(refused_all.value) == _FLAT_SET_REFUSED


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

    registered = Registered(
        rules=dict.fromkeys(rule.meta.id for rule in provide_rules()),
        evaluators=dict.fromkeys(evaluator.id for evaluator in provide_evaluators()),
    )

    assert set(manifest.provides) == {*registered.rules, *registered.evaluators}
    assert check_pack(manifest, registered).ok


@pytest.mark.parametrize("section", ["manifest", "provides"])
@pytest.mark.parametrize("mixed", [False, True])
@pytest.mark.parametrize(("key", "shown"), NON_TEXT_KEYS)
def test_non_text_manifest_keys_raise_packerror(
    tmp_path: Path,
    section: str,
    mixed: bool,
    key: str,
    shown: str,
) -> None:
    document: dict[str, Any] = yaml.safe_load(_GOOD)

    extra: dict[Any, Any] = yaml.safe_load(f"{key}: ignored\n")
    if mixed:
        extra["unrecognised"] = "ignored"

    block = document if section == "manifest" else document["provides"]
    block.update(extra)
    path = _write(tmp_path, yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(PackError, match="unknown") as caught:
        load_manifest(path)

    prefix = f"invalid pack manifest {path}: "
    assert str(caught.value).startswith(prefix)
    assert shown in str(caught.value).removeprefix(prefix)

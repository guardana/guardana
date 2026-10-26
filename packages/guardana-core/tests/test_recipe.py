"""A recipe pins what a team's checks are; a moved pin is named, never matched by accident.

The lock is built from the plan of the recipe's run against a target that sends nothing,
so these tests build a plan, lock it, change one thing a team could change without
noticing, and expect exactly that change to come back as drift.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

import pytest
import yaml
from _fake_distribution import MARKING_MODULE, FakeSite
from _yaml_input_cases import NON_TEXT_KEYS, UNBUILDABLE_SCALARS
from guardana.core.calibration.store import RecordedCalibration
from guardana.core.entrypoints import RULE_GROUP
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.fingerprint import digest_of
from guardana.core.manifest import SubjectKind, SubjectSource
from guardana.core.origin import Origin
from guardana.core.plan import build_plan
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Policy, Profile
from guardana.core.recipe import (
    LockDriftKind,
    PinnedOrigin,
    PinnedTarget,
    Recipe,
    RecipeError,
    RecipeLock,
    artifact_directory_of,
    compare,
    describe_trust,
    load_recipe,
    lock_of,
    lock_to_dict,
    parse_lock,
    paths_named_leniently,
    read_lock,
    render_lock,
)
from guardana.core.recipe_source import SourcePin
from guardana.core.recording import Recording
from guardana.core.registry import Registry
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import EndpointTarget, RecordedTarget, Target
from guardana.core.testing import ScriptedTransport

_RECIPE = """\
schema_version: 1
name: support-bot
profile: guardana.yaml
subject:
  kind: application
  connection:
    url: http://127.0.0.1:8080
    model: support-bot
output:
  directory: artifact
"""


def _write(tmp_path: Path, text: str = _RECIPE, name: str = "guardana-recipe.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_recipe_resolves_its_paths_beside_itself(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))

    assert recipe.name == "support-bot"
    assert recipe.kind is SubjectKind.APPLICATION
    assert recipe.source is SubjectSource.CONNECTION
    assert recipe.profile == tmp_path / "guardana.yaml"
    assert recipe.output == tmp_path / "artifact"
    assert recipe.keep_exchanges is False
    assert recipe.lock_path == tmp_path / "guardana-recipe.lock.yaml"


def test_a_comment_or_key_order_does_not_change_the_recipe_digest(tmp_path: Path) -> None:
    first = load_recipe(_write(tmp_path, _RECIPE, "a.yaml"))
    reordered = "# reviewed\n" + _RECIPE.replace(
        "schema_version: 1\nname: support-bot\n", "name: support-bot\nschema_version: 1\n"
    )
    second = load_recipe(_write(tmp_path, reordered.replace("\n", "\r\n"), "b.yaml"))

    assert first.digest == second.digest
    changed = load_recipe(_write(tmp_path, _RECIPE.replace("8080", "8081"), "c.yaml"))
    assert changed.digest != first.digest


@pytest.mark.parametrize(
    ("edit", "says"),
    [
        (lambda t: t.replace("  kind: application\n", ""), "subject.kind"),
        (lambda t: t.replace("kind: application", "kind: staging"), "subject.kind"),
        (lambda t: t + "extra: 1\n", "unknown key"),
        (lambda t: t.replace("    model: support-bot\n", ""), "`model`"),
        (lambda t: t.replace("directory: artifact", "directory: ."), "own directory"),
        (lambda t: t.replace("directory: artifact", "directory: ../out"), "beside the recipe"),
        (lambda t: t.replace("directory: artifact", "directory: /tmp/out"), "beside the recipe"),
        (lambda t: t.replace("schema_version: 1", "schema_version: 4"), "upgrade Guardana"),
        (
            lambda t: t.replace("  connection:\n", "  fixtures: f.yaml\n  connection:\n"),
            "needs `schema_version: 2`",
        ),
        (
            lambda t: t.replace("schema_version: 1", "schema_version: 2").replace(
                "  connection:\n", "  fixtures: f.yaml\n  recording: a.jsonl\n  connection:\n"
            ),
            "exactly one",
        ),
        (
            lambda t: t.replace("schema_version: 1", "schema_version: 2").replace(
                "  connection:\n    url: http://127.0.0.1:8080\n    model: support-bot\n",
                "  fixtures: f.yaml\n  recording: a.jsonl\n",
            ),
            "cannot be combined with subject.recording",
        ),
        (
            lambda t: t.replace("  connection:\n", "  recording: a.jsonl\n  connection:\n"),
            "exactly one",
        ),
    ],
)
def test_a_recipe_that_cannot_be_trusted_as_written_is_refused(
    tmp_path: Path, edit: object, says: str
) -> None:
    assert callable(edit)
    with pytest.raises(RecipeError, match=says):
        load_recipe(_write(tmp_path, edit(_RECIPE)))


def test_a_schema_1_recipe_is_still_read_and_names_no_fixtures(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))

    assert recipe.fixtures is None


def test_a_schema_2_recipe_names_its_fixtures_beside_itself(tmp_path: Path) -> None:
    text = _RECIPE.replace("schema_version: 1", "schema_version: 2").replace(
        "  connection:\n", "  fixtures: data/guardana-fixtures.yaml\n  connection:\n"
    )

    recipe = load_recipe(_write(tmp_path, text))

    assert recipe.fixtures == tmp_path / "data" / "guardana-fixtures.yaml"
    assert recipe.source is SubjectSource.CONNECTION
    assert recipe.digest != load_recipe(_write(tmp_path, _RECIPE, "plain.yaml")).digest


_CONNECTION = "  connection:\n    url: http://127.0.0.1:8080\n    model: support-bot\n"


def _recording_recipe(tmp_path: Path, kind: str | None) -> Recipe:
    text = _RECIPE.replace(_CONNECTION, "  recording: answers.jsonl\n")
    declared = "" if kind is None else f"  kind: {kind}\n"
    return load_recipe(_write(tmp_path, text.replace("  kind: application\n", declared)))


def test_a_recording_recipe_may_leave_the_kind_to_the_recording(tmp_path: Path) -> None:
    recipe = _recording_recipe(tmp_path, None)

    assert recipe.kind is None
    assert recipe.run_kind(SubjectKind.MODEL_HARNESS) is SubjectKind.MODEL_HARNESS


@pytest.mark.parametrize("recorded", [SubjectKind.APPLICATION, None])
def test_a_declared_kind_is_the_run_kind_when_the_recording_agrees_or_is_silent(
    tmp_path: Path, recorded: SubjectKind | None
) -> None:
    recipe = _recording_recipe(tmp_path, "application")

    assert recipe.run_kind(recorded) is SubjectKind.APPLICATION


def test_a_kind_the_recording_contradicts_is_refused_naming_both(tmp_path: Path) -> None:
    recipe = _recording_recipe(tmp_path, "application")

    with pytest.raises(RecipeError) as caught:
        recipe.run_kind(SubjectKind.MODEL_HARNESS)

    message = str(caught.value)
    assert "subject.kind: application" in message
    assert "subject_kind: model_harness" in message
    assert str(recipe.path) in message
    assert str(tmp_path / "answers.jsonl") in message


def test_a_kind_neither_the_recipe_nor_the_recording_declares_is_refused(tmp_path: Path) -> None:
    recipe = _recording_recipe(tmp_path, None)

    with pytest.raises(RecipeError, match="it has no default"):
        recipe.run_kind(None)


def test_a_recording_recipe_with_a_kind_that_names_none_is_refused(tmp_path: Path) -> None:
    with pytest.raises(RecipeError, match=r"subject\.kind must be one of"):
        _recording_recipe(tmp_path, "staging")


class _Judge(Evaluator):
    """A judge-shaped evaluator whose identity a test can change."""

    id = "acme.judge"

    def __init__(self, identity: str = "model=judge-1") -> None:
        self.judge_identity = identity

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Pass everything; only the identity matters here."""
        return Verdict("pass", 1.0, "ok", self.id)


def _rule_file(tmp_path: Path, rule_id: str, prompt: str = "hello?") -> Path:
    path = tmp_path / "rules" / f"{rule_id}.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        f"id: {rule_id}\n"
        "title: answers\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "taxonomy: [LLM01:2025]\n"
        "evaluator: acme.judge\n"
        "requires: [chat]\n"
        f"prompts: [{prompt!r}]\n",
        encoding="utf-8",
    )
    return path


def _registry(
    tmp_path: Path, *rule_ids: str, judge: str = "model=judge-1", prompt: str = "hello?"
) -> Registry:
    registry = Registry()
    for rule_id in rule_ids:
        for rule in load_yaml_rules(_rule_file(tmp_path, rule_id, prompt)):
            registry.register_rule(rule, Origin(source=f"rules/{rule_id}.yaml"))
    registry.register_evaluator(_Judge(judge), Origin(distribution="acme-judges", version="1.0"))
    return registry


def _endpoint() -> Target:
    return EndpointTarget("http://127.0.0.1:8080", "support-bot", transport=ScriptedTransport("x"))


def _lock(  # noqa: PLR0913 — each is a thing a team can change
    recipe: Recipe,
    registry: Registry,
    *,
    profile: Profile | None = None,
    target: Target | None = None,
    calibrations: dict[str, RecordedCalibration] | None = None,
    files: dict[str, str] | None = None,
    movable: frozenset[str] = frozenset(),
    sources: Mapping[str, SourcePin | str] | None = None,
    requires: Mapping[str, Sequence[str]] | None = None,
) -> RecipeLock:
    prof = profile or Profile("t", Policy())
    plan = build_plan(registry, prof, target or _endpoint())
    pins = sources or {}
    required = requires or {}
    return lock_of(
        recipe,
        plan=plan,
        registry=registry,
        profile=prof,
        calibrations=calibrations or {},
        guardana_version="0.36.0",
        subject_files=files or {},
        movable=lambda distribution: distribution in movable,
        pin_source=lambda distribution: pins.get(distribution, "it has no RECORD to read"),
        requires=lambda distribution: required.get(distribution, ()),
    )


def _kinds(locked: RecipeLock, current: RecipeLock) -> list[LockDriftKind]:
    return [drift.kind for drift in compare(locked, current)]


def test_an_unchanged_configuration_matches_its_lock(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    locked = _lock(recipe, _registry(tmp_path, "acme.a", "acme.b"))

    assert sorted(locked.rules) == ["acme.a", "acme.b"]
    assert locked.evaluators["acme.judge"].judge == "model=judge-1"
    assert compare(locked, _lock(recipe, _registry(tmp_path, "acme.a", "acme.b"))) == ()


def test_a_changed_rule_an_added_one_and_a_removed_one_are_each_named(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    locked = _lock(recipe, _registry(tmp_path, "acme.a", "acme.b"))
    (tmp_path / "rules" / "acme.b.yaml").unlink()

    changed = _lock(recipe, _registry(tmp_path, "acme.a", "acme.c", prompt="goodbye?"))

    drift = {(d.kind, d.subject) for d in compare(locked, changed)}
    assert (LockDriftKind.RULE_CHANGED, "acme.a") in drift
    assert (LockDriftKind.RULE_ADDED, "acme.c") in drift
    assert (LockDriftKind.RULE_REMOVED, "acme.b") in drift


def test_a_new_judge_and_a_new_calibration_are_drift_although_no_rule_moved(
    tmp_path: Path,
) -> None:
    recipe = load_recipe(_write(tmp_path))
    measured = RecordedCalibration(
        evaluator="acme.judge",
        dataset_digest="sha256:" + "0" * 64,
        measured_at=datetime(2026, 1, 1, tzinfo=UTC),
        brier=0.1,
        ece=0.05,
        samples=200,
    )
    locked = _lock(recipe, _registry(tmp_path, "acme.a"), calibrations={"acme.judge": measured})

    rejudged = _lock(
        recipe,
        _registry(tmp_path, "acme.a", judge="model=judge-2"),
        calibrations={"acme.judge": replace(measured, ece=0.2)},
    )

    assert _kinds(locked, rejudged) == [
        LockDriftKind.JUDGE_CHANGED,
        LockDriftKind.CALIBRATION_CHANGED,
    ]


def test_a_profile_change_trust_change_and_subject_file_change_are_drift(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    registry = _registry(tmp_path, "acme.a")
    locked = _lock(recipe, registry, files={"adapter": "sha256:aa"})
    stricter = Profile("t", Policy(), trials=3)
    registry.apply_trials(3)

    current = _lock(recipe, registry, profile=stricter, files={"adapter": "sha256:bb"})
    current = replace(current, trust=describe_trust(PluginTrust(mode=PluginMode.BUILTINS)))

    kinds = _kinds(locked, current)
    assert LockDriftKind.PROFILE_CHANGED in kinds
    assert LockDriftKind.TRUST_CHANGED in kinds
    assert LockDriftKind.SUBJECT_FILE_CHANGED in kinds


def test_a_distribution_that_can_change_under_one_version_is_unpinned(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))

    locked = _lock(recipe, _registry(tmp_path, "acme.a"), movable=frozenset({"acme-judges"}))

    assert locked.unpinned == {"evaluator:acme.judge": "acme-judges: it has no RECORD to read"}
    assert locked.sources == {}


def test_a_recording_subject_pins_the_rules_its_configuration_selects(tmp_path: Path) -> None:
    """The recording is the subject's answer: an unanswered rule is still a selected rule."""
    recipe = load_recipe(
        _write(
            tmp_path,
            _RECIPE.replace(
                "  connection:\n    url: http://127.0.0.1:8080\n    model: support-bot\n",
                "  recording: answers.jsonl\n",
            ),
        )
    )
    empty = Recording(
        "lock", "0", verbatim=True, subject=None, origin=None, exchanges=(), digest=None
    )

    locked = _lock(recipe, _registry(tmp_path, "acme.a"), target=RecordedTarget(empty))

    assert recipe.source is SubjectSource.RECORDING
    assert list(locked.rules) == ["acme.a"]
    assert locked.skipped == {}


def test_the_lock_file_round_trips_and_its_digest_is_stable(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    locked = _lock(recipe, _registry(tmp_path, "acme.a"), files={"system_prompt_file": "sha256:cc"})
    path = tmp_path / "guardana-recipe.lock.yaml"
    path.write_text(render_lock(locked), encoding="utf-8")

    read = read_lock(path)

    assert read == locked
    assert read.digest == locked.digest
    assert "digest:" in path.read_text(encoding="utf-8")


def test_a_lock_written_by_a_newer_guardana_is_refused_not_relocked(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    text = render_lock(_lock(recipe, _registry(tmp_path, "acme.a")))
    path = tmp_path / "lock.yaml"
    path.write_text(text.replace("schema_version: 2", "schema_version: 3"), encoding="utf-8")

    with pytest.raises(RecipeError, match="upgrade Guardana"):
        read_lock(path)


def test_a_missing_lock_says_how_to_write_one(tmp_path: Path) -> None:
    with pytest.raises(RecipeError, match="guardana recipe lock"):
        read_lock(tmp_path / "absent.yaml")


def test_a_calibration_re_measured_on_more_samples_is_drift(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    measured = RecordedCalibration(
        evaluator="acme.judge",
        dataset_digest="sha256:" + "0" * 64,
        measured_at=datetime(2026, 1, 1, tzinfo=UTC),
        brier=0.1,
        ece=0.05,
        samples=200,
    )
    registry = _registry(tmp_path, "acme.a")
    locked = _lock(recipe, registry, calibrations={"acme.judge": measured})

    current = _lock(recipe, registry, calibrations={"acme.judge": replace(measured, samples=300)})

    assert _kinds(locked, current) == [LockDriftKind.CALIBRATION_CHANGED]


# Schema 3: an installed target names the subject

_TARGET_RECIPE = _RECIPE.replace("schema_version: 1", "schema_version: 3").replace(
    _CONNECTION,
    "  target:\n    locator: acme-chat://support\n    options:\n      region: eu\n",
)


class _InstalledChat(EndpointTarget):
    """A pack's endpoint target, as an entry point would register it."""

    scheme = "acme-chat"

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        """Build the endpoint the locator names, sending nothing."""
        return cls("http://chat.test", locator, transport=ScriptedTransport("x"))


def _with_target(registry: Registry, version: str = "2.0") -> Registry:
    registry.register_target(_InstalledChat, Origin(distribution="acme-targets", version=version))
    return registry


def test_a_schema_3_recipe_names_an_installed_target_by_locator(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path, _TARGET_RECIPE))

    assert recipe.source is SubjectSource.TARGET
    assert recipe.target is not None
    assert recipe.target.scheme == "acme-chat"
    assert recipe.target.option_flags() == ("region=eu",)
    assert recipe.connection is None
    assert recipe.recording is None
    assert recipe.kind is SubjectKind.APPLICATION


@pytest.mark.parametrize(
    ("edit", "says"),
    [
        (
            lambda t: t.replace("schema_version: 3", "schema_version: 2"),
            "needs `schema_version: 3`",
        ),
        (lambda t: t.replace("  kind: application\n", ""), "subject.kind"),
        (
            lambda t: t.replace("  target:", "  recording: a.jsonl\n  target:"),
            "exactly one of `connection`, `recording` or",
        ),
        (
            lambda t: t.replace("  target:", "  fixtures: f.yaml\n  target:"),
            "cannot be combined with subject.target",
        ),
        (lambda t: t.replace("region: eu", "region: 3"), "must be a string"),
        (lambda t: t.replace("region: eu", "'a=b': eu"), "is not an option name"),
        (lambda t: t.replace("    locator: acme-chat://support\n", ""), "`locator`"),
        (lambda t: t.replace("    options:", "    ref: x\n    options:"), "unknown key"),
    ],
)
def test_a_target_recipe_that_cannot_be_trusted_as_written_is_refused(
    tmp_path: Path, edit: Callable[[str], str], says: str
) -> None:
    with pytest.raises(RecipeError, match=says):
        load_recipe(_write(tmp_path, edit(_TARGET_RECIPE)))


@pytest.mark.parametrize(
    ("text", "digest"),
    [
        (_RECIPE, "sha256:924dba85c7802ad133e8368ffedb78da1f727a598e0843edbe5c29c77da3205c"),
        (
            _RECIPE.replace("schema_version: 1", "schema_version: 2").replace(
                "  connection:\n", "  fixtures: guardana-fixtures.yaml\n  connection:\n"
            ),
            "sha256:e551f05b43dcf0d87f010e3d86c04118b0ad04cdb4c7fdfdda1016cdd2047620",
        ),
    ],
)
def test_a_schema_1_or_2_recipe_keeps_the_digest_its_lock_holds(
    tmp_path: Path, text: str, digest: str
) -> None:
    assert load_recipe(_write(tmp_path, text)).digest == digest


def test_the_lock_pins_the_installed_target_and_who_registered_it(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path, _TARGET_RECIPE))
    target = _InstalledChat.from_locator("support", options={})

    locked = _lock(recipe, _with_target(_registry(tmp_path, "acme.a")), target=target)
    upgraded = _lock(
        recipe, _with_target(_registry(tmp_path, "acme.a"), version="2.1"), target=target
    )

    assert locked.target == PinnedTarget("acme-chat", PinnedOrigin("acme-targets", "2.0"))
    assert list(locked.rules) == ["acme.a"]
    assert _kinds(locked, upgraded) == [LockDriftKind.TARGET_CHANGED]
    assert "acme-targets 2.0" in compare(locked, upgraded)[0].detail


def test_a_target_from_a_movable_distribution_is_pinned_by_its_files(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path, _TARGET_RECIPE))
    target = _InstalledChat.from_locator("support", options={})
    registry = _with_target(_registry(tmp_path, "acme.a"))

    unpinned = _lock(recipe, registry, target=target, movable=frozenset({"acme-targets"}))
    pinned = _lock(
        recipe,
        registry,
        target=target,
        movable=frozenset({"acme-targets"}),
        sources={"acme-targets": _PIN},
    )

    assert unpinned.unpinned == {"target:acme-chat": "acme-targets: it has no RECORD to read"}
    assert pinned.unpinned == {}
    assert pinned.sources == {"acme-targets": _PIN}


_PIN = SourcePin("sha256:" + "a" * 64, 12)


def test_a_movable_distribution_pinned_by_its_files_is_not_unpinned(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))

    locked = _lock(
        recipe,
        _registry(tmp_path, "acme.a"),
        movable=frozenset({"acme-judges"}),
        sources={"acme-judges": _PIN},
    )

    assert locked.sources == {"acme-judges": _PIN}
    assert locked.unpinned == {}


def test_a_source_added_removed_or_changed_is_named_as_such(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    registry = _registry(tmp_path, "acme.a")
    movable = frozenset({"acme-judges"})
    locked = _lock(recipe, registry, movable=movable, sources={"acme-judges": _PIN})

    edited = _lock(
        recipe, registry, movable=movable, sources={"acme-judges": replace(_PIN, files=13)}
    )
    from_an_index = _lock(recipe, registry)

    assert _kinds(locked, edited) == [LockDriftKind.SOURCE_CHANGED]
    assert _kinds(locked, from_an_index) == [LockDriftKind.SOURCE_REMOVED]
    assert _kinds(from_an_index, locked) == [LockDriftKind.SOURCE_ADDED]


def test_a_required_helper_installed_editable_is_pinned_or_named(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    registry = _registry(tmp_path, "acme.a")
    requires = {"acme-judges": ["Acme_Helpers"], "acme-helpers": ["acme-judges", "acme-deep"]}
    movable = frozenset({"acme-helpers", "acme-deep"})

    unpinnable = _lock(recipe, registry, movable=movable, requires=requires)
    pinned = _lock(
        recipe,
        registry,
        movable=movable,
        requires=requires,
        sources={"acme-helpers": _PIN, "acme-deep": _PIN},
    )

    assert unpinnable.unpinned == {
        "distribution:acme-deep": "acme-deep: it has no RECORD to read",
        "distribution:acme-helpers": "acme-helpers: it has no RECORD to read",
    }
    assert sorted(pinned.sources) == ["acme-deep", "acme-helpers"]
    assert pinned.unpinned == {}


def test_a_movable_pack_that_registers_nothing_selected_is_still_pinned_or_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Discovery imported the pack, so its code ran whatever the recipe selects."""
    (tmp_path / "site").mkdir()
    site = FakeSite(tmp_path / "site", monkeypatch)
    site.distribution("Acme_Quiet", (RULE_GROUP, "quiet", site.module(MARKING_MODULE).name))
    discovered = Registry.discover(
        PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-quiet"}))
    )
    site.forget_imports()
    registry = discovered.empty_with_load_state()
    for rule in load_yaml_rules(_rule_file(tmp_path, "acme.a")):
        registry.register_rule(rule, Origin(source="rules/acme.a.yaml"))
    registry.register_evaluator(_Judge(), Origin(distribution="acme-judges", version="1.0"))
    recipe = load_recipe(_write(tmp_path))
    movable = frozenset({"acme-quiet"})

    unpinnable = _lock(recipe, registry, movable=movable)
    pinned = _lock(recipe, registry, movable=movable, sources={"acme-quiet": _PIN})

    assert unpinnable.unpinned == {
        "distribution:acme-quiet": "acme-quiet: it has no RECORD to read"
    }
    assert pinned.sources == {"acme-quiet": _PIN}
    assert pinned.unpinned == {}


def test_a_lock_with_a_target_and_sources_round_trips_with_a_v2_digest(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path, _TARGET_RECIPE))
    locked = _lock(
        recipe,
        _with_target(_registry(tmp_path, "acme.a")),
        target=_InstalledChat.from_locator("support", options={}),
        movable=frozenset({"acme-judges", "acme-targets"}),
        sources={"acme-targets": _PIN},
    )
    path = tmp_path / "guardana-recipe.lock.yaml"
    path.write_text(render_lock(locked), encoding="utf-8")

    read = read_lock(path)

    assert read == locked
    assert read.unpinned == {"evaluator:acme.judge": "acme-judges: it has no RECORD to read"}
    assert read.digest == digest_of("recipe-lock-v2", _canonical(lock_to_dict(locked)))


def _schema_1_lock(locked: RecipeLock) -> dict[str, object]:
    """The lock as a schema-1 build wrote it: no target, no sources, unpinned as a list."""
    document = lock_to_dict(locked)
    del document["target"], document["sources"]
    return {**document, "schema_version": 1, "unpinned": sorted(locked.unpinned)}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_a_schema_1_lock_is_read_with_no_sources_and_keeps_its_digest(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    current = _lock(recipe, _registry(tmp_path, "acme.a"), movable=frozenset({"acme-judges"}))
    document = _schema_1_lock(current)

    read = parse_lock(yaml.safe_dump(document), tmp_path / "old.lock.yaml")

    assert read.schema_version == 1
    assert read.sources == {}
    assert read.target is None
    assert list(read.unpinned) == ["evaluator:acme.judge"]
    assert lock_to_dict(read) == document
    assert read.digest == digest_of("recipe-lock-v1", _canonical(document))


def test_a_schema_1_lock_drifts_by_every_source_the_current_one_pins(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    registry = _registry(tmp_path, "acme.a")
    movable = frozenset({"acme-judges"})
    old = parse_lock(
        yaml.safe_dump(_schema_1_lock(_lock(recipe, registry, movable=movable))),
        tmp_path / "old.lock.yaml",
    )

    current = _lock(recipe, registry, movable=movable, sources={"acme-judges": _PIN})
    upgraded = replace(current, guardana="0.38.0")

    assert _kinds(old, current) == [LockDriftKind.SOURCE_ADDED]
    assert _kinds(old, upgraded) == [LockDriftKind.GUARDANA_CHANGED, LockDriftKind.SOURCE_ADDED]


def test_a_lock_carrying_a_key_of_another_schema_is_refused(tmp_path: Path) -> None:
    recipe = load_recipe(_write(tmp_path))
    locked = _lock(recipe, _registry(tmp_path, "acme.a"))
    v1 = {**_schema_1_lock(locked), "sources": {}}
    v2 = lock_to_dict(locked)
    del v2["sources"]

    with pytest.raises(RecipeError, match="unknown key"):
        parse_lock(yaml.safe_dump(v1), tmp_path / "v1.yaml")
    with pytest.raises(RecipeError, match="missing key"):
        parse_lock(yaml.safe_dump(v2), tmp_path / "v2.yaml")


def test_an_invalid_recipe_names_every_string_it_holds_as_a_path_beside_it(
    tmp_path: Path,
) -> None:
    recipe = tmp_path / "guardana-recipe.yaml"
    recipe.write_text(
        "unexpected: 1\n"
        "profile: out/report.txt\n"
        "subject:\n"
        "  connection: {adapter: out/junit.xml, retries: 3}\n"
        '  list: [a, [out/run.json], "with\\0null"]\n'
        "loop: &loop [*loop, out/nested.txt]\n",
        encoding="utf-8",
    )

    named = paths_named_leniently(recipe)

    assert named is not None
    assert set(named) >= {
        tmp_path / "out" / "report.txt",
        tmp_path / "out" / "junit.xml",
        tmp_path / "out" / "run.json",
        tmp_path / "out" / "nested.txt",
        tmp_path / "a",
    }
    assert all("\0" not in str(path) for path in named)


@pytest.mark.parametrize(
    "content", [b"profile: [unclosed\n", b"\xff\xfe not text\n"], ids=["yaml", "bytes"]
)
def test_a_recipe_that_does_not_parse_names_nothing_that_can_be_known(
    tmp_path: Path, content: bytes
) -> None:
    recipe = tmp_path / "guardana-recipe.yaml"
    recipe.write_bytes(content)

    assert paths_named_leniently(recipe) is None
    assert paths_named_leniently(tmp_path / "missing.yaml") is None


@pytest.mark.parametrize("template", ["{scalar}\n", "profile: {scalar}\n"], ids=["root", "field"])
@pytest.mark.parametrize(("scalar", "token"), UNBUILDABLE_SCALARS)
def test_unbuildable_recipe_lock_scalars_raise_recipeerror(
    tmp_path: Path, template: str, scalar: str, token: str
) -> None:
    path = tmp_path / "recipe.lock.yaml"
    path.write_text(template.format(scalar=scalar), encoding="utf-8")

    with pytest.raises(RecipeError, match="is not valid YAML") as caught:
        read_lock(path)

    prefix = f"{path} is not valid YAML: "
    assert str(caught.value).startswith(prefix)
    assert token in str(caught.value).removeprefix(prefix)


@pytest.mark.parametrize(("scalar", "_token"), UNBUILDABLE_SCALARS)
def test_a_recipe_with_unbuildable_scalars_uses_the_default_artifact_directory(
    tmp_path: Path, scalar: str, _token: str
) -> None:
    path = tmp_path / "guardana-recipe.yaml"
    path.write_text(f"name: {scalar}\noutput:\n  directory: custom-output\n", encoding="utf-8")

    assert artifact_directory_of(path) == tmp_path / "guardana-artifact"


@pytest.mark.parametrize(("scalar", "_token"), UNBUILDABLE_SCALARS)
def test_a_recipe_with_unbuildable_scalars_names_no_paths(
    tmp_path: Path, scalar: str, _token: str
) -> None:
    path = tmp_path / "guardana-recipe.yaml"
    path.write_text(f"profile: guardana.yaml\nname: {scalar}\n", encoding="utf-8")

    assert paths_named_leniently(path) is None


@pytest.mark.parametrize("section", ["recipe", "subject", "connection", "output", "deployment"])
@pytest.mark.parametrize("mixed", [False, True])
@pytest.mark.parametrize(("key", "shown"), NON_TEXT_KEYS)
def test_non_text_recipe_keys_raise_recipeerror(
    tmp_path: Path,
    section: str,
    mixed: bool,
    key: str,
    shown: str,
) -> None:
    document: dict[str, Any] = yaml.safe_load(_RECIPE)
    document["deployment"] = {}

    extra: dict[Any, Any] = yaml.safe_load(f"{key}: ignored\n")
    if mixed:
        extra["unrecognised"] = "ignored"

    blocks = {
        "recipe": document,
        "subject": document["subject"],
        "connection": document["subject"]["connection"],
        "output": document["output"],
        "deployment": document["deployment"],
    }
    blocks[section].update(extra)

    path = _write(tmp_path, yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(RecipeError, match="unknown key") as caught:
        load_recipe(path)

    message = str(caught.value)
    assert message.startswith(str(path))
    assert shown in message.replace(str(path), "")

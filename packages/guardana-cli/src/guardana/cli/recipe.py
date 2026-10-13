"""`guardana recipe lock|run` — a team's checks, pinned in its repository and run the same way."""

import json
import os
import shutil
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._artifact import (
    ARTIFACT_SCHEMA_VERSION,
    MARKER,
    ArtifactRefusedError,
    claim,
    publish,
)
from guardana.cli._atomic import write_whole
from guardana.cli._connection import endpoint_for, read_system_prompt, seeded_endpoint
from guardana.cli._errors import (
    remedies_for,
    report_target_stop,
    run_against_endpoint,
    run_judged,
)
from guardana.cli._evaluators import judge_endpoint, wire_config_evaluators
from guardana.cli._exit import exit_with, refuse_invalid_profile, refuse_unenforceable_budget
from guardana.cli._plugins import hint_refused_plugins, resolve_trust
from guardana.cli._profile import resolve_profile
from guardana.cli._profile_files import profile_file_inputs
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._run_meta import calibrations_or_exit, detect_source
from guardana.cli._sidecar import same_file
from guardana.cli._target_locator import resolve_target
from guardana.cli.exit_codes import ExitCode
from guardana.cli.plan import recorded_target_or_exit, system_prompt_the_probe_will_send
from guardana.core import __version__
from guardana.core.budget import BudgetExhausted
from guardana.core.calibration.store import RecordedCalibration
from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.fixtures import Fixtures, FixturesError, ResolvedTenant, load_fixtures
from guardana.core.manifest import DeploymentRef, RecipeRecord, SubjectKind
from guardana.core.plan import build_plan
from guardana.core.plugins import PluginTrust
from guardana.core.profile import Profile, ProfileError, load_profile
from guardana.core.recipe import (
    RECIPE_NAME,
    LockDrift,
    LockDriftKind,
    Recipe,
    RecipeError,
    RecipeLock,
    RecipeTarget,
    artifact_directory_of,
    compare,
    lock_of,
    moves_under_one_version,
    parse_lock,
    parse_recipe,
    paths_named_leniently,
    read_text,
    render_lock,
)
from guardana.core.recipe_source import pin_distribution_source
from guardana.core.recording import Recording, render_recording
from guardana.core.registry import Registry
from guardana.core.regression import broken_pairs
from guardana.core.report import CheckError
from guardana.core.report.shortfall import CoverageShortfall
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.target import EndpointTarget, RecordedTarget, SeededTarget, Target, TargetKind
from guardana.core.target.connection import (
    Connection,
    ConnectionConfigError,
    Spelling,
    resolve_connection,
)
from guardana.core.usage import UsageMeter
from guardana.core.verify import (
    JudgeUnreachableError,
    RecordingRefusedError,
    TargetUnavailableError,
    UnenforceableBudgetError,
    Verification,
    Verifier,
)
from guardana.report import get_renderer
from guardana.report.junit import unfinished_document

recipe_app = typer.Typer(
    help="Pin a team's checks in a recipe, and run them the same way every time.",
    no_args_is_help=True,
)

RecipeArgument = Annotated[Path, typer.Argument(help="The recipe file.", show_default=True)]

_DEFAULT_CONCURRENCY = 4
_VERDICT = "run.json"
_SPELLING = Spelling(
    url="subject.connection.url",
    provider="subject.connection.provider",
    api_key_env="subject.connection.api_key_env",
    adapter="subject.connection.adapter",
)


@dataclass(frozen=True, slots=True)
class _Read:
    """A recipe as parsed, with the exact text it was parsed from and the fixtures it names."""

    recipe: Recipe
    text: str
    fixtures: Fixtures | None = None
    """Read once, so the digest the lock compares and the items a run asks come from one read."""


@dataclass(frozen=True, slots=True)
class _Prepared:
    """What both commands build from a recipe before anything is sent."""

    recipe: Recipe
    profile: Profile
    trust: PluginTrust
    registry: Registry
    calibrations: dict[str, RecordedCalibration]
    lock: RecipeLock
    system_prompt: str | None
    """The operator's system-prompt file, read once: what is pinned is what is sent."""

    errors: tuple[CheckError, ...]
    """What the run would record before its first rule: a check that would not grade."""

    fixtures: Fixtures | None = None
    shortfall: tuple[CoverageShortfall, ...] = ()
    """The coverage the run would owe whatever its rules find, so it could never pass."""

    target: Target | None = None
    """The installed target the recipe names, built once: what is locked is what is sent."""


class _Refusal(Exception):  # noqa: N818 — named for the outcome a command reports
    """A command refused before anything was sent, with the reason its artifact carries."""

    def __init__(self, reason: str, code: ExitCode = ExitCode.INVALID_USAGE) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def lock(
    recipe: RecipeArgument = Path(RECIPE_NAME),
    check: Annotated[
        bool,
        typer.Option("--check", help="Compare with the lock and write nothing; exit 1 on drift."),
    ] = False,
) -> None:
    """Pin what the recipe's checks are, or check that the pins still hold."""
    try:
        prepared = _prepare(_load(recipe))
        _refuse_unloadable(prepared)
        _refuse_unpassable(prepared)
    except _Refusal as refused:
        typer.echo(f"error: {refused.reason}", err=True)
        raise typer.Exit(code=refused.code) from None
    current = prepared.lock
    if check:
        try:
            locked = parse_lock(*_lock_text(prepared.recipe))
        except RecipeError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
        drift = compare(locked, current)
        for line in drift:
            typer.echo(line.describe())
        if drift:
            typer.echo(
                f"{len(drift)} pin(s) moved; review the change, then run `guardana recipe lock`",
                err=True,
            )
            raise typer.Exit(code=ExitCode.POLICY_FAILED)
        typer.echo(f"every pin in {prepared.recipe.lock_path.name} holds")
        _exit_if_unpinned(current)
        return
    try:
        write_whole(prepared.recipe.lock_path, render_lock(current).encode("utf-8"))
    except OSError as exc:
        typer.echo(f"error: could not write {prepared.recipe.lock_path}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    sources = f", {len(current.sources)} source pin(s)" if current.sources else ""
    typer.echo(
        f"wrote {prepared.recipe.lock_path}: {len(current.rules)} rule(s), "
        f"{len(current.evaluators)} evaluator(s), {len(current.skipped)} configured skip(s)"
        f"{sources}"
    )
    _exit_if_unpinned(current)


def run(
    recipe: RecipeArgument = Path(RECIPE_NAME),
    concurrency: Annotated[
        int, typer.Option(min=1, help="How many rules may run at once.")
    ] = _DEFAULT_CONCURRENCY,
) -> None:
    """Check the recipe's pins, run its checks, and write the artifact directory."""
    try:
        read = _load(recipe)
    except _Refusal as refused:
        _refuse_unreadable(recipe, refused.reason)
        typer.echo(f"error: {refused.reason}", err=True)
        raise typer.Exit(code=refused.code) from None
    loaded = read.recipe
    inputs = _inputs(read)
    try:
        _refuse_reading_from_the_artifact(loaded, inputs)
    except _Refusal as refused:
        typer.echo(f"error: {refused.reason}", err=True)
        _mark_refused_in_place(
            loaded.output,
            refused.reason,
            inputs=[path for _, path in inputs],
            removes=lambda _name: True,
        )
        raise typer.Exit(code=refused.code) from None
    try:
        claim(loaded.output, loaded.name)
    except ArtifactRefusedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    try:
        prepared, lock_text = _checked(read)
        subject, secrets = _subject(prepared)
        kind = _run_kind(loaded, subject)
    except _Refusal as refused:
        _refuse(loaded, f"the run did not start: {refused.reason}")
        typer.echo(f"error: {refused.reason}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from None
    except (typer.Exit, typer.BadParameter) as exc:
        _refuse(loaded, _reason(exc))
        raise
    if prepared.lock.unpinned:
        typer.echo(f"warning: {_unpinned(prepared.lock)}", err=True)
    try:
        verification = _verify(prepared, subject, concurrency, kind, secrets)
    except typer.Exit as exc:
        if exc.exit_code == ExitCode.INVALID_USAGE:
            _refuse(loaded, "the run was refused before it sent anything; see the error output")
        raise
    record = RecipeRecord(
        name=loaded.name,
        digest=loaded.digest,
        lock_digest=parse_lock(lock_text, loaded.lock_path).digest,
        kind=kind,
        source=loaded.source,
        unpinned=tuple(prepared.lock.unpinned),
    )
    verification = replace(verification, manifest=replace(verification.manifest, recipe=record))
    _publish(prepared, verification, recipe_text=read.text, lock_text=lock_text)
    report_target_stop(verification)
    exit_with(verification.gate, verification.result)


def _load(path: Path) -> _Read:
    try:
        text = read_text(path, "recipe")
        recipe = parse_recipe(text, path)
        fixtures = None if recipe.fixtures is None else load_fixtures(recipe.fixtures)
    except (RecipeError, FixturesError) as exc:
        raise _Refusal(str(exc)) from exc
    return _Read(recipe, text, fixtures)


def _inputs(read: _Read) -> list[tuple[str, Path]]:
    """Return every file the recipe names for its run to read, each with the key naming it."""
    recipe = read.recipe
    named: list[tuple[str, Path | None]] = [
        ("the recipe", recipe.path),
        ("the recipe lock", recipe.lock_path),
        ("profile", recipe.profile),
        ("subject.recording", recipe.recording),
        ("subject.fixtures", recipe.fixtures),
        ("subject.connection.adapter", recipe.subject_file("adapter")),
        ("subject.connection.system_prompt_file", recipe.subject_file("system_prompt_file")),
    ]
    if read.fixtures is not None:
        named.extend(
            (f"the adapter of fixtures tenant {tenant.name}", tenant.adapter)
            for tenant in read.fixtures.tenants
        )
    if recipe.profile is not None:
        try:
            profile = load_profile(recipe.profile)
        except ProfileError:
            # The run refuses this profile later, with the loader's reason.
            profile = None
        if profile is not None:
            named.extend(profile_file_inputs(profile))
    return [(role, path) for role, path in named if path is not None]


def _refuse_reading_from_the_artifact(recipe: Recipe, inputs: list[tuple[str, Path]]) -> None:
    """Refuse a recipe that reads a file inside the artifact directory every run replaces.

    Claiming the directory would remove the file before the run reads it, and the earlier
    artifact with it, so nothing is claimed.
    """
    for role, path in inputs:
        if _inside(path, recipe.output):
            raise _Refusal(
                f"{recipe.path}: {role} {path} lies inside {recipe.output}, the artifact "
                f"directory every run replaces; move the file or name another "
                f"output.directory. Nothing was sent"
            )


def _mark_refused_in_place(
    directory: Path,
    reason: str,
    *,
    inputs: Sequence[Path],
    removes: Callable[[str], bool],
) -> None:
    """Turn an earlier run's artifact red without replacing the directory a recipe reads from.

    The marker, `junit.xml` and `report.txt` are rewritten by a rename onto their names, so
    a link there is replaced rather than written through; each listed file `removes` names
    is deleted. A file the recipe reads is never rewritten or deleted, the marker included;
    under a kept marker only the reports it already lists are rewritten, so no later run
    finds a file it does not list. A rewritten marker lists the refusal before anything is
    removed and exactly what remains at the end.
    """
    if directory.is_symlink() or not directory.is_dir() or not (directory / MARKER).is_file():
        return
    marking = not _read_by_the_recipe(directory / MARKER, inputs, warn=True)
    listed = [name for name in _indexed_files(directory) if name != MARKER]
    reports = {
        "junit.xml": unfinished_document("guardana.recipe", "the run did not start", reason),
        "report.txt": f"the run did not start: {reason}\n",
    }
    if not marking:
        reports = {name: text for name, text in reports.items() if name in listed}
    written: list[str] = []
    try:
        if marking:
            _stage_into(directory, MARKER, _refused_marker({*listed, *reports}))
        for name, text in reports.items():
            if not _read_by_the_recipe(directory / name, inputs, warn=True):
                _stage_into(directory, name, text)
                written.append(name)
        removed = _remove_listed(
            directory,
            [name for name in listed if name not in reports and removes(name)],
            inputs,
        )
        remaining = [name for name in {*listed, *written} if os.path.lexists(directory / name)]
        if marking:
            _stage_into(directory, MARKER, _refused_marker(remaining))
    except OSError as exc:
        typer.echo(f"warning: could not mark {directory} as refused: {exc}", err=True)
        return
    marked = [MARKER, *written] if marking else written
    _say_marked(directory, marked, removed, sorted(set(remaining) - set(written)))


def _remove_listed(directory: Path, names: list[str], inputs: Sequence[Path]) -> list[str]:
    """Delete each named file in `directory` the recipe does not read, returning those removed."""
    removed: list[str] = []
    for name in names:
        listed_path = directory / name
        if _a_directory(listed_path) or _read_by_the_recipe(listed_path, inputs, warn=False):
            continue
        listed_path.unlink(missing_ok=True)
        removed.append(name)
    return removed


def _say_marked(directory: Path, marked: list[str], removed: list[str], earlier: list[str]) -> None:
    """Say what an artifact marked refused in place now holds, and what is still not this run's."""
    if marked:
        said = [f"{', '.join(marked)} now say this run was refused"]
    else:
        said = ["no file in it could be marked refused"]
    if removed:
        said.append(f"removed the earlier run's {', '.join(sorted(removed))}")
    if earlier:
        said.append(f"it still holds an earlier run's {', '.join(earlier)}, not this run's")
    typer.echo(f"warning: in {directory}, {'; '.join(said)}", err=True)


def _read_by_the_recipe(path: Path, inputs: Sequence[Path], *, warn: bool) -> bool:
    """Whether `path` is one of the recipe's inputs, saying it is kept when `warn` is set."""
    if not any(same_file(path, given) for given in inputs):
        return False
    if warn:
        typer.echo(f"warning: {path} is a file the recipe reads, so it was left as it is", err=True)
    return True


def _refused_marker(files: Iterable[str]) -> str:
    """Render an artifact marker saying the run was refused, listing `files`."""
    marker = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "status": "refused",
        "files": sorted(files),
    }
    return json.dumps(marker, indent=2) + "\n"


def _stage_into(directory: Path, name: str, text: str) -> None:
    """Write `text` beside `directory`, as `publish` writes a file, then rename it in as `name`.

    Staged outside the directory, so an interrupted write leaves nothing in it a later run
    would refuse as a file no run wrote.
    """
    staging = Path(tempfile.mkdtemp(prefix=f".{directory.name}.", dir=directory.parent))
    try:
        staged = staging / name
        staged.write_bytes(text.encode("utf-8"))
        staged.replace(directory / name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _inside(path: Path, directory: Path) -> bool:
    """Whether `path` is `directory` or lies under it, through a symlink or another case too."""
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        resolved = path.absolute()
    return any(same_file(ancestor, directory) for ancestor in (resolved, *resolved.parents))


def _refuse_unreadable(path: Path, reason: str) -> None:
    """Mark the artifact an unreadable recipe names as refused, when an earlier run wrote one.

    Only a directory whose index lists this recipe's own copy is touched: a mistyped path
    creates nothing and marks no other recipe's artifact. Every string the recipe holds
    counts as a file it reads and only the earlier verdict is removed; a recipe that does
    not parse could read any file there, so nothing is touched.
    """
    directory = artifact_directory_of(path)
    if not path.is_file() or path.name not in _indexed_files(directory):
        return
    named = paths_named_leniently(path)
    if named is None:
        typer.echo(
            f"warning: {path} does not parse, so the files it reads are unknown and "
            f"{directory} was left as it is; it still holds an earlier run's files, not "
            f"this run's",
            err=True,
        )
        return
    _mark_refused_in_place(
        directory, reason, inputs=[path, *named], removes=lambda name: name == _VERDICT
    )


def _indexed_files(directory: Path) -> list[str]:
    """Return the files an artifact's index lists; none when it has no readable index."""
    try:
        index = json.loads((directory / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    files = index.get("files") if isinstance(index, dict) else None
    if not isinstance(files, list):
        return []
    return [name for name in files if isinstance(name, str) and _plain_name(name)]


def _a_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


def _plain_name(name: str) -> bool:
    """Whether an index entry names a file directly inside the directory, never beside it."""
    return name not in {"", ".", ".."} and "/" not in name and "\\" not in name


def _lock_text(recipe: Recipe) -> tuple[str, Path]:
    return read_text(recipe.lock_path, "recipe lock"), recipe.lock_path


def _checked(read: _Read) -> tuple[_Prepared, str]:
    """Hold the run to its lock before anything is sent, or raise `_Refusal`."""
    recipe = read.recipe
    prepared = _prepare(read)
    try:
        text, path = _lock_text(recipe)
        locked = parse_lock(text, path)
    except RecipeError as exc:
        raise _Refusal(str(exc)) from exc
    _refuse_exchanges_nobody_asked_for(prepared)
    _refuse_unloadable(prepared)
    drift = compare(locked, prepared.lock)
    if drift:
        lines = "\n".join(line.describe() for line in drift)
        raise _Refusal(
            f"{len(drift)} pin(s) in {recipe.lock_path.name} moved; nothing was sent. Review "
            f"the change, then run `guardana recipe lock`\n{lines}"
        )
    _check_judges(prepared.profile)
    return prepared, text


def _prepare(read: _Read) -> _Prepared:
    """Build the registry and the lock of the recipe's run, sending nothing and reading no key."""
    recipe = read.recipe
    profile = resolve_profile(recipe.profile, None)
    resolved = resolve_trust(None, None, profile)
    registry = Registry.discover(resolved.trust)
    hint_refused_plugins(registry, resolved)
    if registry.refused:
        raise _Refusal(
            "plugin trust refused an installed extension, so what it would register cannot be "
            "pinned; state the trust you want in the profile's `plugins:`",
            ExitCode.INDETERMINATE,
        )
    load_custom_rules(registry, profile, [])
    registry.apply_trials(profile.trials)
    calibrations = calibrations_or_exit(profile)
    priced = registry.copied()
    try:
        wire_config_evaluators(priced, profile, profile.budgets, sending=False)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    prompt = read_system_prompt(recipe.subject_file("system_prompt_file"))
    installed = None
    if recipe.target is None:
        target, files = _stand_in(recipe, prompt, read.fixtures)
    else:
        installed = _installed_target(recipe, recipe.target, registry, profile)
        target, files = installed, {}
    try:
        plan = build_plan(priced, profile, target)
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    written = (recipe.lock_path, recipe.output)
    current = lock_of(
        recipe,
        plan=plan,
        registry=priced,
        profile=profile,
        calibrations=calibrations,
        guardana_version=__version__,
        subject_files=files,
        movable=moves_under_one_version,
        pin_source=lambda name: pin_distribution_source(name, leave_out=written),
    )
    if not current.rules:
        raise _Refusal(
            "the recipe's profile selects no rule for this subject, so there is nothing to pin "
            "or to run",
            ExitCode.INDETERMINATE,
        )
    _refuse_broken_regressions(priced, current)
    return _Prepared(
        recipe,
        profile,
        resolved.trust,
        registry,
        calibrations,
        current,
        prompt,
        plan.errors,
        read.fixtures,
        plan.shortfall,
        installed,
    )


def _refuse_broken_regressions(registry: Registry, current: RecipeLock) -> None:
    """Regrade every regression pair of the selected suites, refusing when one no longer holds.

    A refusal rather than a drift: a lock compares two configurations, and a broken
    pair is broken in both.
    """
    suites = (
        r for r in registry.rules() if isinstance(r, SuiteRule) and r.meta.id in current.rules
    )
    broken = broken_pairs(suites, registry.evaluators())
    if broken:
        raise _Refusal(
            f"{len(broken)} regression case(s) of the selected suites no longer hold, so "
            f"nothing was written or sent; fix the rule or the case first: {'; '.join(broken)}",
            ExitCode.POLICY_FAILED,
        )


def _refuse_unloadable(prepared: _Prepared) -> None:
    """Refuse to pin a selection holding a check that would not grade what it claims."""
    if prepared.errors:
        named = "; ".join(f"{e.source}: {e.reason}" for e in prepared.errors[:3])
        raise _Refusal(
            f"{len(prepared.errors)} configured check(s) would not grade what they claim, so "
            f"the selection cannot be pinned; fix them first: {named}",
            ExitCode.INDETERMINATE,
        )


def _refuse_unpassable(prepared: _Prepared) -> None:
    """Refuse to pin a configuration whose run owes coverage it cannot get, as `plan` refuses it.

    A coverage shortfall has no switch, so the run it pins could never pass.
    """
    if prepared.shortfall:
        causes = "; ".join(gap.detail for gap in prepared.shortfall)
        raise _Refusal(
            f"the run this recipe describes cannot pass, so nothing was pinned; "
            f"coverage shortfall — {causes}"
        )


def _installed_target(
    recipe: Recipe, named: RecipeTarget, registry: Registry, profile: Profile
) -> Target:
    """Build the installed target the recipe names, refused as `probe --target` refuses it.

    Construction sends nothing under the `Target` contract; a target that fails to connect
    anyway exits `4`, as it does for `plan probe`.
    """
    try:
        target = resolve_target(
            registry,
            locator=named.locator,
            options=named.option_flags(),
            kind=TargetKind.ENDPOINT,
            fallback=_no_fallback,
        )
    except typer.BadParameter as exc:
        raise _Refusal(f"{recipe.path}: subject.target: {exc}") from exc
    keeping = recipe.keep_exchanges or profile.privacy.keep_exchanges
    if keeping and not isinstance(target, EndpointTarget | SeededTarget):
        raise _Refusal(
            f"{recipe.path}: keeping exchanges keeps the chat exchanges of the built-in endpoint "
            f"and of a pack's target built on it; {target.ref} keeps none, so set "
            f"output.exchanges: false and stop keeping exchanges in the profile"
        )
    try:
        target.apply_budgets(profile.budgets)
    except BudgetExhausted as exc:
        raise _Refusal(str(exc)) from exc
    return target


def _no_fallback() -> Target:
    """Never reached: a recipe target always names a locator."""
    raise _Refusal("subject.target names no locator")


def _stand_in(
    recipe: Recipe, prompt: str | None, fixtures: Fixtures | None
) -> tuple[Target, dict[str, str]]:
    """Return a target that sends nothing, shaped like the subject, and the subject files' digests.

    A recording stands in as one holding no reply, so a rule it leaves unanswered is
    still a rule the configuration selected. Fixtures pin their file and every tenant
    adapter, resolved without reading a key, and the stand-in carries `seeded_data`, so
    the checks they demand are selected and pinned.
    """
    if recipe.connection is None:
        empty = Recording(
            recipe.name, "lock", verbatim=True, subject=None, origin=None, exchanges=(), digest=None
        )
        return RecordedTarget(empty), {}
    try:
        resolved = resolve_connection(_connection(recipe), sending=False, spelling=_SPELLING)
    except ConnectionConfigError as exc:
        raise _Refusal(f"{recipe.path}: {exc}") from exc
    files: dict[str, str] = {}
    if resolved.adapter_digest is not None:
        files["adapter"] = resolved.adapter_digest
    if prompt is not None:
        files["system_prompt_file"] = _text_digest(prompt)
    stand_in_prompt = prompt or system_prompt_the_probe_will_send(None)
    target = endpoint_for(resolved, system_prompt=stand_in_prompt)
    if fixtures is None:
        return target, files
    tenants = _tenants(recipe, fixtures, sending=False)
    files.update(fixtures.subject_files(tenants))
    return seeded_endpoint(target, fixtures, tenants, system_prompt=stand_in_prompt), files


def _connection(recipe: Recipe) -> Connection:
    written = recipe.connection or {}
    return Connection(
        url=written["url"],
        model=written["model"],
        provider=written.get("provider"),
        api_key_env=written.get("api_key_env"),
        adapter=recipe.subject_file("adapter"),
    )


def _text_digest(text: str) -> str:
    """Digest text as the saved run digests the system prompt it sent."""
    return DocumentDigest.of(text.encode("utf-8"), DigestKind.CONTENT).digest


def _check_judges(profile: Profile) -> None:
    """Refuse a judge that cannot send, before the run starts rather than inside it."""
    try:
        wire_config_evaluators(Registry(), profile, profile.budgets)
    except BudgetExhausted as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc


def _subject(prepared: _Prepared) -> tuple[Target, tuple[str, ...]]:
    """Build what the run sends to, holding a re-read adapter to the digest the lock pinned.

    The second item holds every secret the subject sends, which no message may quote; an
    installed target keeps its own and names none.
    """
    recipe = prepared.recipe
    if prepared.target is not None:
        return prepared.target, ()
    if recipe.recording is not None:
        return recorded_target_or_exit(recipe.recording), ()
    try:
        resolved = resolve_connection(_connection(recipe), sending=True, spelling=_SPELLING)
    except ConnectionConfigError as exc:
        raise _Refusal(f"{recipe.path}: {exc}") from exc
    found = {"adapter": resolved.adapter_digest}
    tenants = None
    if prepared.fixtures is not None:
        tenants = _tenants(recipe, prepared.fixtures, sending=True)
        found.update(prepared.fixtures.subject_files(tenants))
    _refuse_moved(prepared.lock, found)
    endpoint = endpoint_for(
        resolved, system_prompt=prepared.system_prompt, meter=UsageMeter(prepared.profile.budgets)
    )
    if prepared.fixtures is None or tenants is None:
        return endpoint, resolved.secret_values
    secrets = (
        *resolved.secret_values,
        *(value for tenant in tenants for value in tenant.connection.secret_values),
    )
    seeded = seeded_endpoint(
        endpoint, prepared.fixtures, tenants, system_prompt=prepared.system_prompt
    )
    return seeded, secrets


def _tenants(recipe: Recipe, fixtures: Fixtures, *, sending: bool) -> tuple[ResolvedTenant, ...]:
    """Resolve the fixtures' tenants against the recipe's connection, or raise `_Refusal`."""
    try:
        return fixtures.resolve_tenants(_connection(recipe), sending=sending, spelling=_SPELLING)
    except FixturesError as exc:
        raise _Refusal(str(exc)) from exc


def _refuse_moved(lock: RecipeLock, found: dict[str, str | None]) -> None:
    """Refuse a subject file read again before sending that no longer matches its pin.

    `found` holds what the sending side resolved; the fixtures file itself was read once,
    so its digest is the one the lock was compared with.
    """
    for name, digest in sorted(found.items()):
        pinned = lock.subject_files.get(name)
        if digest != pinned:
            moved = LockDrift(
                LockDriftKind.SUBJECT_FILE_CHANGED,
                name,
                f"changed while the run was being checked: {pinned} is now {digest}",
            )
            raise _Refusal(f"nothing was sent: {moved.describe()}")


def _run_kind(recipe: Recipe, subject: Target) -> SubjectKind:
    """Resolve what answered from the recipe and the recording it grades, or raise `_Refusal`."""
    recorded = subject.recording.subject_kind if isinstance(subject, RecordedTarget) else None
    try:
        return recipe.run_kind(recorded)
    except RecipeError as exc:
        raise _Refusal(str(exc)) from exc


def _exit_if_unpinned(current: RecipeLock) -> None:
    if not current.unpinned:
        return
    typer.echo(f"warning: {_unpinned(current)}", err=True)
    raise typer.Exit(code=ExitCode.INDETERMINATE)


def _unpinned(current: RecipeLock) -> str:
    named = ", ".join(f"{entry} ({reason})" for entry, reason in current.unpinned.items())
    return (
        f"{len(current.unpinned)} pin(s) come from a distribution installed from a directory "
        f"or a URL whose files could not be pinned, so their code can change under one "
        f"version and the lock does not pin them: {named}"
    )


def _refuse_exchanges_nobody_asked_for(prepared: _Prepared) -> None:
    if prepared.profile.privacy.keep_exchanges and not prepared.recipe.keep_exchanges:
        raise _Refusal(
            "the profile keeps exchanges, and a CI artifact is a copy of the application's "
            "replies nobody controls; set output.exchanges: true in the recipe to put them "
            "there, or stop keeping them in the profile"
        )


def _reason(exc: Exception) -> str:
    if isinstance(exc, typer.BadParameter):
        return f"the run did not start: {exc}"
    if isinstance(exc, typer.Exit) and exc.exit_code == ExitCode.TARGET_UNAVAILABLE:
        return "the run did not start: its target could not be reached; see the error output"
    return "the run did not start: its configuration was refused; see the error output"


def _refuse(recipe: Recipe, reason: str) -> None:
    """Write a refusal over the placeholder, so the artifact is red in every file."""
    publish(
        recipe.output,
        {
            "report.txt": f"{reason}\n",
            "junit.xml": unfinished_document("guardana.recipe", "the run did not start", reason),
        },
        status="refused",
    )


def _verify(
    prepared: _Prepared,
    subject: Target,
    concurrency: int,
    kind: SubjectKind,
    secrets: tuple[str, ...],
) -> Verification:
    """Run the recipe's subject through the verifier `probe` and `grade` use."""
    recipe = prepared.recipe
    verifier = Verifier(
        trust=prepared.trust,
        profile=prepared.profile,
        registry=prepared.registry,
        calibrations=prepared.calibrations,
        concurrency=concurrency,
        judge_endpoint=judge_endpoint,
        demanded_rules=frozenset(prepared.lock.rules),
        subject_kind=kind,
        fixtures=None if prepared.fixtures is None else prepared.fixtures.record(),
        secrets=secrets,
        remedies=remedies_for(()),
    )
    deployment = DeploymentRef(
        ai_system=recipe.deployment.get("ai_system"),
        environment=recipe.deployment.get("environment"),
        deployment_id=recipe.deployment.get("deployment_id"),
    )

    def verified() -> Verification:
        return _carried_out(
            lambda: verifier.run(subject, source=detect_source(), deployment=deployment)
        )

    if isinstance(subject, RecordedTarget):
        return run_judged(verified)
    return run_against_endpoint(
        subject.ref, verified, privacy=prepared.profile.privacy, secrets=secrets
    )


def _carried_out(action: Callable[[], Verification]) -> Verification:
    """Run, turning a verifier refusal into the message and exit code `probe` and `grade` use."""
    try:
        return action()
    except RecordingRefusedError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    except UnenforceableBudgetError as exc:
        raise refuse_unenforceable_budget(exc) from exc
    except ProfileError as exc:
        raise refuse_invalid_profile(exc) from exc
    except (TargetUnavailableError, JudgeUnreachableError) as exc:
        if exc.__cause__ is not None:
            raise exc.__cause__ from None
        raise


def _publish(
    prepared: _Prepared, verification: Verification, *, recipe_text: str, lock_text: str
) -> None:
    """Replace the placeholder with the run, under fixed names a CI step uploads as one path."""
    recipe = prepared.recipe
    run_manifest = verification.manifest
    report = get_renderer("human", run=run_manifest).render(verification.result)
    pins = f"every pin in {recipe.lock_path.name} holds"
    if prepared.lock.unpinned:
        pins = f"{pins}; {_unpinned(prepared.lock)}"
    files = {
        "run.json": json.dumps(verification.document(), indent=2) + "\n",
        "report.txt": f"{report}\n\n{pins}\n",
        "junit.xml": get_renderer("junit", run=run_manifest).render(verification.result),
        recipe.path.name: recipe_text,
        recipe.lock_path.name: lock_text,
    }
    if verification.exchanges is not None and recipe.keep_exchanges:
        files["run.exchanges.jsonl"] = render_recording(verification.exchanges)
    publish(recipe.output, files, status="complete")
    typer.echo(report)
    typer.echo(f"artifact: {recipe.output}", err=True)


recipe_app.command(name="lock")(lock)
recipe_app.command(name="run")(run)

"""`Verification.save` replaces or removes only the exchanges the run it replaces recorded.

Ownership is read from the saved run at `path` before anything is written, never from a
file's name. Kept exchanges are written before the document that names them, each whole,
so a failed save leaves no document claiming exchanges that are not beside it.
"""

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport
from guardana.core.verify import Verification, Verifier, exchanges_path, exchanges_recorded_by

_RULE = {
    "id": "acme.save",
    "title": "a rule that sends one prompt",
    "severity": "high",
    "target_kind": "endpoint",
    "taxonomy": ["LLM01:2025"],
    "evaluator": "keyword",
    "requires": ["chat"],
    "prompts": ["hello"],
}
_INDEPENDENT = b'{"messages": [{"role": "user", "content": "kept by hand"}]}\n'


def _verification(tmp_path: Path, *, keep: bool, reply: str = "I cannot help.") -> Verification:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "rule.yaml").write_text(json.dumps(_RULE), encoding="utf-8")
    base = default_profile()
    profile = replace(
        base,
        policy=replace(base.policy, include=("acme.save",)),
        privacy=replace(base.privacy, keep_exchanges=keep),
    )
    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.BUILTINS), profile=profile, rule_paths=(rules,)
    )
    return verifier.run(EndpointTarget("http://app.test", "m", transport=ScriptedTransport(reply)))


def _files(folder: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(folder.iterdir()) if path.is_file()}


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    saved = tmp_path / "saved"
    saved.mkdir()
    return saved


def test_a_run_keeping_none_removes_the_exchanges_the_run_it_replaces_recorded(
    tmp_path: Path, folder: Path
) -> None:
    run = folder / "run.json"
    _verification(tmp_path, keep=True).save(run)
    sidecar = exchanges_path(run)
    assert exchanges_recorded_by(run) is not None

    _verification(tmp_path, keep=False).save(run)

    assert not sidecar.exists()
    assert json.loads(run.read_text(encoding="utf-8"))["run"]["exchanges"] is None


@pytest.mark.parametrize("earlier", ["nothing", "a run recording none", "a run recording other"])
def test_a_run_keeping_none_keeps_exchanges_no_replaced_run_recorded_and_warns(
    tmp_path: Path, folder: Path, earlier: str
) -> None:
    run = folder / "run.json"
    if earlier == "a run recording none":
        _verification(tmp_path, keep=False).save(run)
    elif earlier == "a run recording other":
        _verification(tmp_path, keep=True).save(run)
    sidecar = exchanges_path(run)
    sidecar.write_bytes(_INDEPENDENT)

    with pytest.warns(UserWarning, match="no run saved at") as warned:
        _verification(tmp_path, keep=False).save(run)

    assert sidecar.read_bytes() == _INDEPENDENT
    assert [str(warning.message) for warning in warned] == [
        f"kept {sidecar}: no run saved at {run} before this one recorded it, so it is not "
        f"an earlier run's exchanges"
    ]


def test_keeping_beside_exchanges_no_run_there_recorded_raises_and_writes_nothing(
    tmp_path: Path, folder: Path
) -> None:
    run = folder / "run.json"
    sidecar = exchanges_path(run)
    sidecar.write_bytes(_INDEPENDENT)
    before = _files(folder)

    with pytest.raises(FileExistsError) as raised:
        _verification(tmp_path, keep=True).save(run)

    assert raised.value.filename == str(sidecar)
    assert _files(folder) == before


def test_keeping_again_replaces_the_exchanges_the_run_there_recorded(
    tmp_path: Path, folder: Path
) -> None:
    run = folder / "run.json"
    _verification(tmp_path, keep=True, reply="Sure, here it is.").save(run)
    elsewhere = folder / "linked.jsonl"
    os.link(exchanges_path(run), elsewhere)
    linked = elsewhere.read_bytes()

    _verification(tmp_path, keep=True).save(run)

    assert exchanges_recorded_by(run) is not None
    assert elsewhere.read_bytes() == linked
    assert not elsewhere.samefile(exchanges_path(run))


@pytest.mark.parametrize("failing", ["the exchanges", "the document"])
def test_a_save_that_fails_leaves_the_earlier_run_and_its_exchanges_as_they_were(
    tmp_path: Path, folder: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    run = folder / "run.json"
    _verification(tmp_path, keep=True, reply="Sure, here it is.").save(run)
    before = _files(folder)
    full = exchanges_path(run) if failing == "the exchanges" else run
    write = os.fsync

    def fill_the_disk(descriptor: int) -> None:
        if any(path.name.startswith(f".{full.name}.") for path in folder.iterdir()):
            raise OSError("No space left on device")
        write(descriptor)

    monkeypatch.setattr(os, "fsync", fill_the_disk)
    verification = _verification(tmp_path, keep=True)

    with pytest.raises(OSError, match="No space left on device"):
        verification.save(run)

    assert _files(folder) == before


def test_a_document_that_cannot_replace_its_path_leaves_no_exchanges_beside_it(
    tmp_path: Path, folder: Path
) -> None:
    run = folder / "run.json"
    run.mkdir()

    with pytest.raises(IsADirectoryError):
        _verification(tmp_path, keep=True).save(run)

    assert run.is_dir()
    assert not exchanges_path(run).exists()
    assert [path.name for path in folder.iterdir()] == ["run.json"]


def test_a_document_that_cannot_replace_an_earlier_run_restores_that_runs_exchanges(
    tmp_path: Path, folder: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = folder / "run.json"
    _verification(tmp_path, keep=True, reply="Sure, here it is.").save(run)
    before = _files(folder)
    replace_file = Path.replace

    def refusing(staged: Path, target: Path) -> Path:
        if Path(target) == run:
            raise PermissionError(1, "Operation not permitted")
        return replace_file(staged, target)

    monkeypatch.setattr(Path, "replace", refusing)
    verification = _verification(tmp_path, keep=True)

    with pytest.raises(PermissionError):
        verification.save(run)

    assert _files(folder) == before
    assert exchanges_recorded_by(run) is not None


def _pair(tmp_path: Path, folder: Path) -> tuple[Path, Path]:
    """Save a run that kept exchanges as `run.json` and copy it to `run`, which shares them."""
    run = folder / "run.json"
    _verification(tmp_path, keep=True, reply="Sure, here it is.").save(run)
    partner = folder / "run"
    shutil.copyfile(run, partner)
    return run, partner


def test_a_run_keeping_none_keeps_the_exchanges_its_partner_recorded_and_warns(
    tmp_path: Path, folder: Path
) -> None:
    run, partner = _pair(tmp_path, folder)
    kept = exchanges_path(run).read_bytes()

    with pytest.warns(UserWarning, match="recorded") as warned:
        _verification(tmp_path, keep=False).save(run)

    assert exchanges_path(run).read_bytes() == kept
    assert exchanges_recorded_by(partner) is not None
    assert [str(warning.message) for warning in warned] == [
        f"kept {exchanges_path(run)}: it holds the exchanges {partner} recorded"
    ]


def test_keeping_beside_exchanges_its_partner_recorded_raises_and_writes_nothing(
    tmp_path: Path, folder: Path
) -> None:
    run, _ = _pair(tmp_path, folder)
    before = _files(folder)

    with pytest.raises(FileExistsError):
        _verification(tmp_path, keep=True).save(run)

    assert _files(folder) == before


def test_exchanges_are_recorded_by_content_never_by_name(folder: Path) -> None:
    run = folder / "run.json"
    run.write_text('{"results": []}\n', encoding="utf-8")
    exchanges_path(run).write_bytes(_INDEPENDENT)

    assert exchanges_recorded_by(run) is None

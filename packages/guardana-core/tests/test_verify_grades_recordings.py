"""`Verifier` keeps a probe's exchanges and grades them again without calling the target."""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.assessment import AssessmentStatus, UnmeasuredReason
from guardana.core.diff import compare_reports
from guardana.core.fingerprint import DigestKind
from guardana.core.gate import GateOutcome
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Profile, default_profile
from guardana.core.recording import read_recording
from guardana.core.redaction import EvidenceMode
from guardana.core.report.load import load_report
from guardana.core.target import ChatMessage, EndpointTarget, McpServerTarget
from guardana.core.testing import ScriptedMcpServer
from guardana.core.testing.secrets import fake_github_pat
from guardana.core.usage import UsageMeter
from guardana.core.verify import (
    RecordingRefusedError,
    UnenforceableBudgetError,
    UnsupportedTargetError,
    Verifier,
    exchanges_path,
)

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)
_SUITE = "acme.quality.answers"
_ANSWERS = {
    "How do I reset my password?": "Open Settings, then Security.",
    "Where is my invoice?": "Billing lists every invoice.",
    "Can I export my data?": "Settings has an export button.",
}


class _ByQuestion:
    """An application that answers each question its own way, and counts what it was sent."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.sent = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer the last user message from the table."""
        self.sent += 1
        return self.answers[messages[-1].content]


def _suite(tmp_path: Path, expected: str = "Settings") -> Path:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    header = {"guardana_dataset": 1, "name": "support", "version": "1"}
    lines = [json.dumps(header)] + [
        json.dumps({"input": question, "expect": {"contains_any": [expected]}})
        for question in _ANSWERS
    ]
    (rules / "answers.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule = {
        "id": _SUITE,
        "title": "The support bot names where to go",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "contains",
        "requires": ["chat"],
        "dataset": "./answers.jsonl",
        "expect": {"contains_any": []},
        "gate": {"min_pass_rate": 0.5, "min_sample": 3},
    }
    (rules / "answers.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _profile(*include: str, keep: bool = True, trials: int = 1) -> Profile:
    base = default_profile()
    return replace(
        base,
        policy=replace(base.policy, include=include or (_SUITE,)),
        privacy=replace(base.privacy, keep_exchanges=keep),
        trials=trials,
    )


def _endpoint(transport: _ByQuestion, profile: Profile) -> EndpointTarget:
    return EndpointTarget(
        "http://app.test/v1", "m", transport=transport, meter=UsageMeter(profile.budgets)
    )


def _probe(tmp_path: Path, profile: Profile, transport: _ByQuestion) -> Path:
    verification = Verifier(
        trust=_BUILTINS, profile=profile, rule_paths=(_suite(tmp_path),), concurrency=1
    ).run(_endpoint(transport, profile))
    run = tmp_path / "run.json"
    verification.save(run)
    return run


def test_a_saved_run_and_sidecar_are_written_as_bytes_where_text_gets_crlf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_text = Path.write_text

    def as_windows(
        path: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        if newline is None:
            data, newline = data.replace("\n", "\r\n"), ""
        return write_text(path, data, encoding, errors, newline)

    monkeypatch.setattr(Path, "write_text", as_windows)

    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))

    assert b"\r\n" not in run.read_bytes(), "the run went through a translating text write"
    manifest = load_report(run).manifest
    assert manifest.exchanges is not None
    kept = exchanges_path(run).read_bytes()
    assert manifest.exchanges.digest == "sha256:" + hashlib.sha256(kept).hexdigest()


def test_a_saved_sidecar_replaces_a_link_and_never_writes_through_it(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("not exchanges\n", encoding="utf-8")
    exchanges_path(tmp_path / "run.json").symlink_to(elsewhere)

    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))

    sidecar = exchanges_path(run)
    assert elsewhere.read_text(encoding="utf-8") == "not exchanges\n"
    assert not sidecar.is_symlink()
    manifest = load_report(run).manifest
    assert manifest.exchanges is not None
    assert manifest.exchanges.digest == "sha256:" + hashlib.sha256(sidecar.read_bytes()).hexdigest()


def test_a_kept_sidecar_is_the_file_the_manifest_digests(tmp_path: Path) -> None:
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))
    sidecar = exchanges_path(run)

    manifest = load_report(run).manifest
    assert manifest.exchanges is not None
    digest = "sha256:" + hashlib.sha256(sidecar.read_bytes()).hexdigest()
    assert manifest.exchanges.digest == digest
    assert manifest.exchanges.count == len(_ANSWERS)
    recording = read_recording(sidecar)
    assert recording.origin is not None
    assert recording.origin.run_id == manifest.run_id
    assert recording.origin.rules == (_SUITE,)
    assert recording.origin.trials == {_SUITE: 1}
    assert recording.verbatim


def test_grading_the_sidecar_sends_nothing_and_names_the_execution_it_graded(
    tmp_path: Path,
) -> None:
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))

    graded = Verifier(
        trust=_BUILTINS, profile=_profile(keep=False), rule_paths=(_suite(tmp_path),)
    ).grade(exchanges_path(run))

    assert graded.gate is GateOutcome.PASS
    assert graded.manifest.usage.requests == 0
    document = graded.manifest.target.document
    assert document is not None
    assert document.kind is DigestKind.CONTENT
    original = load_report(run)
    assert original.manifest.exchanges is not None
    assert document.digest == original.manifest.exchanges.digest
    assert graded.manifest.recording is not None
    assert graded.manifest.recording.origin is not None
    assert graded.manifest.recording.origin.run_id == original.manifest.run_id
    assert graded.manifest.target.ref.startswith("recording:")
    regraded = tmp_path / "regraded.json"
    graded.save(regraded)
    notes = compare_reports(original, load_report(regraded))
    assert any("same recorded replies" in note for note in notes.notes)


def test_a_stricter_expectation_on_the_same_replies_fails_without_a_request(
    tmp_path: Path,
) -> None:
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))
    stricter = tmp_path / "stricter"
    stricter.mkdir()

    graded = Verifier(
        trust=_BUILTINS,
        profile=_profile(keep=False),
        rule_paths=(_suite(stricter, expected="Billing"),),
    ).grade(exchanges_path(run))

    assert graded.gate is GateOutcome.FAIL


def test_a_recording_kept_at_other_trials_is_refused_before_grading(tmp_path: Path) -> None:
    run = _probe(tmp_path, _profile(trials=2), _ByQuestion(_ANSWERS))

    with pytest.raises(RecordingRefusedError, match="kept 2, this run grades 1"):
        Verifier(
            trust=_BUILTINS, profile=_profile(keep=False), rule_paths=(_suite(tmp_path),)
        ).grade(exchanges_path(run))


def test_an_unreadable_recording_is_refused(tmp_path: Path) -> None:
    broken = tmp_path / "broken.jsonl"
    broken.write_text('{"guardana_recording": 1, "name": "x"}\n', encoding="utf-8")

    with pytest.raises(RecordingRefusedError, match=r"broken\.jsonl"):
        Verifier(trust=_BUILTINS, profile=_profile(keep=False)).grade(broken)


def test_keeping_refuses_an_endpoint_that_cannot_keep_before_anything_is_sent() -> None:
    server = ScriptedMcpServer("https://93.184.215.14/mcp", tools=[{"name": "t"}])
    target = McpServerTarget(server.url, sender=server, discovery_sender=server)

    with pytest.raises(UnsupportedTargetError, match="keep_exchanges"):
        Verifier(trust=_BUILTINS, profile=_profile("guardana.mcp.*")).run(target)
    assert server.requests == []


def test_a_secret_the_target_leaked_is_never_graded_clean_from_the_sidecar(
    tmp_path: Path,
) -> None:
    token = fake_github_pat()
    leaking = _ByQuestion({})
    leaking.answers = _LeakEverything(token)
    profile = _profile("guardana.output.secrets")
    original = Verifier(trust=_BUILTINS, profile=profile, concurrency=1).run(
        _endpoint(leaking, profile)
    )
    assert original.gate is GateOutcome.FAIL
    run = tmp_path / "run.json"
    original.save(run)
    assert token not in exchanges_path(run).read_text("utf-8")

    graded = Verifier(
        trust=_BUILTINS, profile=_profile("guardana.output.secrets", keep=False)
    ).grade(exchanges_path(run))

    assert graded.gate is not GateOutcome.PASS
    assert any(error.source == "guardana.output.secrets" for error in graded.result.errors)


def test_a_rule_the_stopped_probe_planned_and_never_reached_is_an_error(tmp_path: Path) -> None:
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))
    sidecar = exchanges_path(run)
    lines = sidecar.read_text("utf-8").splitlines()
    header = json.loads(lines[0])
    header["origin"]["rules"] = [*header["origin"]["rules"], "guardana.output.secrets"]
    header["origin"]["trials"]["guardana.output.secrets"] = 1
    sidecar.write_text("\n".join([json.dumps(header), *lines[1:]]) + "\n", encoding="utf-8")

    graded = Verifier(
        trust=_BUILTINS,
        profile=_profile(_SUITE, "guardana.output.secrets", keep=False),
        rule_paths=(_suite(tmp_path),),
    ).grade(sidecar)

    assert graded.gate is GateOutcome.INDETERMINATE
    assert any(error.source == "guardana.output.secrets" for error in graded.result.errors)
    assert "guardana.output.secrets" not in {skip.rule_id for skip in graded.result.rules_skipped}


def test_an_unrecorded_case_is_an_ungraded_trial_never_a_pass(tmp_path: Path) -> None:
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))
    sidecar = exchanges_path(run)
    lines = sidecar.read_text("utf-8").splitlines()
    sidecar.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    graded = Verifier(
        trust=_BUILTINS, profile=_profile(keep=False), rule_paths=(_suite(tmp_path),)
    ).grade(sidecar)

    missing = [a for a in graded.result.assessments if a.reason is UnmeasuredReason.NOT_RECORDED]
    assert len(missing) == 1
    assert missing[0].status is AssessmentStatus.ERROR
    assert missing[0].passed is None
    assert graded.gate is GateOutcome.INDETERMINATE


def test_a_probe_that_kept_nothing_writes_no_sidecar(tmp_path: Path) -> None:
    profile = _profile("*")
    profile = replace(profile, policy=replace(profile.policy, exclude=("*",)))
    verification = Verifier(trust=_BUILTINS, profile=profile).run(
        _endpoint(_ByQuestion(_ANSWERS), profile)
    )
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))
    assert exchanges_path(run).is_file()
    verification.save(run)

    assert verification.exchanges is None
    assert verification.manifest.exchanges is None
    assert not exchanges_path(run).exists()


class _LeakEverything(dict[str, str]):
    """Answers every question with the same leaked token."""

    def __init__(self, token: str) -> None:
        super().__init__()
        self.token = token

    def __missing__(self, key: str) -> str:
        return f"Sure, use {self.token} for that."


def test_the_sidecar_sits_beside_the_run() -> None:
    assert exchanges_path(Path("out/run.json")) == Path("out/run.exchanges.jsonl")
    assert exchanges_path(Path("out/run")) == Path("out/run.exchanges.jsonl")


def test_a_profile_that_keeps_exchanges_grades_a_recording_and_keeps_nothing(
    tmp_path: Path,
) -> None:
    run = _probe(tmp_path, _profile(), _ByQuestion(_ANSWERS))

    graded = Verifier(trust=_BUILTINS, profile=_profile(), rule_paths=(_suite(tmp_path),)).grade(
        exchanges_path(run)
    )

    assert graded.gate is GateOutcome.PASS
    assert graded.exchanges is None
    assert graded.manifest.exchanges is None


def test_a_keeping_run_refused_before_sending_leaves_the_target_free(tmp_path: Path) -> None:
    profile = _profile()
    target = _endpoint(_ByQuestion(_ANSWERS), profile)
    unenforceable = replace(profile, budgets=replace(profile.budgets, max_input_tokens=10))

    with pytest.raises(UnenforceableBudgetError):
        Verifier(trust=_BUILTINS, profile=unenforceable, rule_paths=(_suite(tmp_path),)).run(target)
    kept = Verifier(trust=_BUILTINS, profile=profile, rule_paths=(_suite(tmp_path),)).run(target)

    assert kept.exchanges is not None
    assert len(kept.exchanges.exchanges) == len(_ANSWERS)


def _hand_written(path: Path, answers: dict[str, str]) -> Path:
    header = {
        "guardana_recording": 1,
        "name": "support-bot",
        "version": "1",
        "verbatim": True,
        "rule": _SUITE,
    }
    lines = [header] + [{"input": question, "reply": reply} for question, reply in answers.items()]
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


def test_diff_pairs_the_cases_of_two_saved_suite_runs_and_names_one_gone_ungraded(
    tmp_path: Path,
) -> None:
    verifier = Verifier(
        trust=_BUILTINS, profile=_profile(keep=False), rule_paths=(_suite(tmp_path),)
    )
    complete = tmp_path / "complete.json"
    verifier.grade(_hand_written(tmp_path / "all.jsonl", _ANSWERS)).save(complete)
    fewer = dict(list(_ANSWERS.items())[:-1])
    partial = tmp_path / "partial.json"
    verifier.grade(_hand_written(tmp_path / "fewer.jsonl", fewer)).save(partial)

    measurement = compare_reports(load_report(complete), load_report(partial)).measurement

    assert measurement.paired == len(fewer)
    assert len(measurement.blinded) == 1


def test_a_policy_cannot_keep_exchanges_under_metadata_only() -> None:
    privacy = default_profile().privacy

    with pytest.raises(ValueError, match="metadata_only"):
        replace(privacy, mode=EvidenceMode.METADATA_ONLY, keep_exchanges=True)

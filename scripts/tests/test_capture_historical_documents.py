"""The historical capture script, offline: its table, its environment and what it keeps.

The capture itself needs PyPI and installs every release; none of that runs here. What
runs is every decision the script makes about what it ran and what it kept, so a
change to those is caught before the next capture writes a corpus nobody can trust.
"""

import json
import subprocess
import tempfile
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

import pytest

import capture_historical_documents as capture
from capture_historical_documents import (
    COMMAND_TABLE,
    Captured,
    CaptureError,
    Corpus,
    Kind,
    Release,
    Selection,
    commands_for,
    key_paths,
    leaked_markers,
    missing_flags,
    scrubbed_env,
    version_key,
)


class _SideEffectError(Exception):
    """Raised by every stubbed way out of the process."""


@pytest.fixture
def acted(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub every way the script reaches outside the process, and record any attempt."""
    attempts: list[str] = []

    def _stub(name: str) -> Callable[..., Any]:
        def _refuse(*args: object, **kwargs: object) -> NoReturn:
            attempts.append(name)
            raise _SideEffectError(name)

        return _refuse

    monkeypatch.setattr(subprocess, "run", _stub("subprocess.run"))
    monkeypatch.setattr(tempfile, "mkdtemp", _stub("tempfile.mkdtemp"))
    monkeypatch.setattr(urllib.request, "urlopen", _stub("urllib.request.urlopen"))
    return attempts


def test_help_prints_usage_and_does_nothing(
    acted: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        capture.main(["--help"])

    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--dry-run", "--release", "--profiles-only", "--out", "--keep"):
        assert flag in out
    assert acted == []


def test_an_unknown_flag_is_refused_before_anything_runs(
    acted: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        capture.main(["--no-such-flag"])

    assert exit_info.value.code == 2
    assert "--no-such-flag" in capsys.readouterr().err
    assert acted == []


def test_the_command_table_runs_oldest_first_from_0_2_0() -> None:
    firsts = [version_key(row.first) for row in COMMAND_TABLE]

    assert firsts == sorted(firsts)
    assert len(set(firsts)) == len(firsts)
    assert COMMAND_TABLE[0].first == "0.2.0"


@pytest.mark.parametrize(
    ("version", "first"),
    [
        ("0.2.0", "0.2.0"),
        ("0.6.0", "0.2.0"),
        ("0.7.0", "0.7.0"),
        ("0.8.0", "0.7.0"),
        ("0.9.1", "0.9.0"),
        ("0.25.0", "0.9.0"),
        ("0.26.0", "0.26.0"),
        ("0.40.0", "0.26.0"),
        ("1.0.0rc1", "0.26.0"),
    ],
)
def test_each_release_is_driven_by_the_row_of_its_range(version: str, first: str) -> None:
    assert commands_for(version).first == first


def test_a_release_older_than_the_table_is_refused() -> None:
    with pytest.raises(CaptureError, match="older than the command table"):
        commands_for("0.1.3")


def test_only_the_releases_that_cannot_start_alone_get_an_extra_requirement() -> None:
    extras = {row.first: row.extras for row in COMMAND_TABLE if row.extras}

    assert extras == {"0.7.0": ("click",)}
    for row in COMMAND_TABLE:
        assert bool(row.note) is bool(row.extras), row.first


def test_the_pack_comes_from_new_pack_from_0_26_and_is_handwritten_before() -> None:
    assert commands_for("0.25.0").pack == "handwritten"
    assert commands_for("0.25.0").scaffold is None
    assert commands_for("0.26.0").pack == "scaffolded"
    assert commands_for("0.26.0").scaffold is not None


def test_every_command_line_names_only_relative_paths() -> None:
    for row in COMMAND_TABLE:
        invocations = [
            row.run,
            row.envelope,
            row.probe_run,
            row.profile,
            *row.profile_example,
            row.lock,
        ]
        if row.scaffold is not None:
            invocations.append(row.scaffold)
        for invocation in invocations:
            bound = invocation.bound({"endpoint": 8001, "collector": 8002})
            assert bound[0] == "guardana"
            assert not [arg for arg in bound if arg.startswith(("/", "~"))], bound
            assert not [arg for arg in bound if "{" in arg], bound
            if invocation.writes is not None:
                assert not Path(invocation.writes).is_absolute()


def test_the_servers_ports_reach_the_command_line() -> None:
    row = commands_for("0.40.0")

    assert "server://http://127.0.0.1:8002" in row.envelope.bound({"collector": 8002})
    assert "http://127.0.0.1:8001/v1" in row.probe_run.bound({"endpoint": 8001})


def test_a_release_runs_with_nothing_of_the_caller_but_its_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GUARDANA_COLLECTOR_TOKEN", "a-token-the-release-must-not-see")
    monkeypatch.setenv("PATH", "/opt/bin:/usr/bin")

    env = scrubbed_env(tmp_path)

    assert env == {
        "PATH": "/opt/bin:/usr/bin",
        "HOME": str(tmp_path),
        "HTTP_PROXY": capture.REFUSING_PROXY,
        "HTTPS_PROXY": capture.REFUSING_PROXY,
        "NO_PROXY": "127.0.0.1,localhost",
    }


HELP = """
 Usage: guardana scan [OPTIONS] {path}
│ --profile          <path>   guardana.yaml path                     │
│ --format           <fmt>    human|json|sarif|junit                 │
│ --output-dir       <path>   not the flag the table passes          │
│ --reporter         <str>    Collector URL to forward findings to   │
"""


def test_a_flag_absent_from_the_help_is_what_the_release_lacks() -> None:
    assert missing_flags(HELP, ("--format", "--output")) == ["--output"]
    assert missing_flags(HELP, ("--format", "--reporter")) == []


def test_key_paths_name_fields_and_read_ids_and_list_items_as_one_step() -> None:
    document = {
        "schema_version": 2,
        "run": {"rules": {"guardana.prompt.injection": "ab", "acme.secret": "cd"}},
        "findings": [{"rule_id": "x"}, {"rule_id": "y", "taxonomy": ["LLM01"]}],
    }

    assert key_paths(document) == {
        "schema_version",
        "run",
        "run.rules",
        "run.rules.*",
        "findings",
        "findings[].rule_id",
        "findings[].taxonomy",
    }


def test_a_document_is_kept_when_its_shape_or_its_version_changes_and_only_then() -> None:
    selection = Selection()

    assert selection.keep(Kind.RUN, {"schema_version": 1, "rules": {"a.b": 1}})
    assert not selection.keep(Kind.RUN, {"schema_version": 1, "rules": {"c.d": 2, "e.f": 3}})
    assert selection.keep(Kind.RUN, {"schema_version": 1, "rules": {}, "usage": {}})
    assert selection.keep(Kind.PROFILE, {"schema_version": 1, "rules": {"a.b": 1}})
    assert not selection.keep(Kind.RUN, {"rules": {}, "usage": {}, "schema_version": 1})
    assert selection.keep(Kind.RUN, {"rules": {}, "usage": {}, "schema_version": 2})
    assert not selection.keep(Kind.RUN, {"schema_version": 2, "usage": {}, "rules": {}})


def test_a_local_path_is_a_leak_and_a_path_a_rule_sends_is_not() -> None:
    assert leaked_markers('{"ref": "/Users/someone/subject"}') == ["/Users/"]
    assert leaked_markers('{"detail": "The log file /tmp/session-42.log is gone"}') == []
    assert leaked_markers('{"detail": "/tmp/session-42.log and /tmp/x"}') == ["/tmp/"]  # noqa: S108
    assert leaked_markers('{"ref": "D:/w/subject"}', local=("D:/w",)) == ["D:/w"]


def test_release_candidates_order_before_their_release_and_odd_versions_are_refused() -> None:
    ordered = sorted(["1.0.0", "0.40.0", "1.0.0rc2", "1.0.0rc1", "0.9.1"], key=version_key)

    assert ordered == ["0.9.1", "0.40.0", "1.0.0rc1", "1.0.0rc2", "1.0.0"]
    with pytest.raises(CaptureError, match="not one this script can order"):
        version_key("1.0.0.dev1")


def _captured(**documents: str) -> Captured:
    captured = Captured(facts={"collector_migrations": 3})
    for kind in Kind:
        if kind is Kind.DATASET:
            continue
        text = documents.get(kind.name.lower())
        if text is None:
            captured.absent[kind] = "no `pack lock` command"
        else:
            captured.documents[kind] = text
    captured.datasets = {1: None, 2: "dataset format 2 was written by another version"}
    return captured


def test_the_record_says_what_each_release_produced_stored_and_declared() -> None:
    corpus = Corpus()
    run = json.dumps({"schema_version": 4, "run": {"rules": {"a.b": "1"}}})
    release = Release("0.12.0", "2026-08-07T08:17:07Z")

    produced = corpus.add(release, commands_for("0.12.0"), _captured(run=run))

    assert produced == [Kind.RUN, Kind.DATASET]
    record = corpus.releases["0.12.0"]
    assert record["exclude_newer"] == "2026-08-07T08:17:07Z"
    assert record["collector_migrations"] == 3
    kinds = record["kinds"]
    assert isinstance(kinds, dict)
    assert kinds[Kind.RUN] == {"produced": True, "schema_version": 4, "stored": "run/0.12.0.json"}
    assert kinds[Kind.PACK_LOCK] == {"produced": False, "why": "no `pack lock` command"}
    assert kinds[Kind.DATASET]["stored"] == "dataset/0.12.0.jsonl"
    assert kinds[Kind.DATASET]["schema_version"] == [1]
    assert corpus.files["run/0.12.0.json"] == run


def test_a_release_writing_the_same_shape_is_recorded_but_not_stored() -> None:
    corpus = Corpus()
    for version, digest in (("0.12.0", "1"), ("0.13.0", "2")):
        run = json.dumps({"schema_version": 4, "run": {"rules": {"a.b": digest}}})
        corpus.add(Release(version, "t"), commands_for(version), _captured(run=run))

    later = corpus.releases["0.13.0"]["kinds"]
    assert isinstance(later, dict)
    assert later[Kind.RUN] == {"produced": True, "schema_version": 4, "stored": None}
    assert later[Kind.DATASET]["stored"] is None
    assert sorted(corpus.files) == ["dataset/0.12.0.jsonl", "run/0.12.0.json"]


def test_a_dataset_is_stored_with_the_oldest_release_that_reads_it() -> None:
    corpus = Corpus()
    older, newer = _captured(), _captured()
    older.datasets = {1: None, 2: "refused"}
    newer.datasets = {1: None, 2: None}

    corpus.add(Release("0.30.0", "t"), commands_for("0.30.0"), older)
    corpus.add(Release("0.37.0", "t"), commands_for("0.37.0"), newer)

    assert corpus.files["dataset/0.30.0.jsonl"] == capture.DATASETS[1]
    assert corpus.files["dataset/0.37.0.jsonl"] == capture.DATASETS[2]


def test_one_release_first_reading_both_dataset_formats_stops_the_capture() -> None:
    captured = _captured()
    captured.datasets = {1: None, 2: None}

    with pytest.raises(CaptureError, match="first to read dataset formats"):
        Corpus().add(Release("0.37.0", "t"), commands_for("0.37.0"), captured)


def test_a_release_with_no_dataset_reader_says_so() -> None:
    captured = _captured()
    captured.absent[Kind.DATASET] = "no read_dataset (No module named 'guardana.core.dataset')"

    Corpus().add(Release("0.6.0", "t"), commands_for("0.6.0"), captured)


def test_writing_replaces_every_kind_directory_and_the_record(tmp_path: Path) -> None:
    stale = tmp_path / "run" / "0.1.0.json"
    stale.parent.mkdir()
    stale.write_text("{}", encoding="utf-8")
    unrelated = tmp_path / "README.md"
    unrelated.write_text("kept", encoding="utf-8")
    corpus = Corpus()
    run = json.dumps({"schema_version": 4})
    corpus.add(Release("0.12.0", "t"), commands_for("0.12.0"), _captured(run=run))

    corpus.write(tmp_path)

    assert not stale.exists()
    assert unrelated.read_text(encoding="utf-8") == "kept"
    assert (tmp_path / "run" / "0.12.0.json").read_text(encoding="utf-8") == run
    assert "0.12.0" in json.loads((tmp_path / "releases.json").read_text(encoding="utf-8"))


def test_the_synthetic_datasets_declare_the_format_they_are_filed_under() -> None:
    for fmt, text in capture.DATASETS.items():
        header = json.loads(text.splitlines()[0])
        assert header["guardana_dataset"] == fmt


def test_the_collector_keeps_each_envelope_and_the_endpoint_answers_as_openai() -> None:
    servers = capture._Servers()
    with servers.serving():
        ports = servers.ports
        envelope = json.dumps({"schema_version": 8}).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{ports['collector']}/findings", data=envelope, method="POST"
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            assert json.load(response)["status"] == "ok"
        chat = urllib.request.Request(
            f"http://127.0.0.1:{ports['endpoint']}/v1/chat/completions",
            data=json.dumps({"model": "scripted", "messages": []}).encode("utf-8"),
            method="POST",
        )
        with urllib.request.urlopen(chat, timeout=10) as response:  # noqa: S310
            reply = json.load(response)

    assert servers.take() == [envelope]
    assert reply["choices"][0]["message"]["role"] == "assistant"
    assert reply["model"] == "scripted"


PAGE = """\
# Profiles

```yaml
name: ci
fail_on:
  severity: high
```

A rule is not a profile:

```yaml
id: acme.rule
title: A rule
```

- In a list item:

  ```yml
  budgets:
    max_requests: 10
  ```

A name alone says nothing a profile needs:

~~~yaml
name: only-a-name
~~~

```yaml
rules: [unclosed
```
"""


def test_every_fenced_yaml_block_is_read_and_its_fence_indent_removed() -> None:
    blocks = capture.yaml_blocks(PAGE)

    assert len(blocks) == 5
    assert blocks[2] == "budgets:\n  max_requests: 10\n"


def test_a_profile_example_holds_only_profile_keys_and_more_than_a_name() -> None:
    examples = capture.examples_in("v0.20.0", "docs/profiles.md", PAGE)

    assert [(e.tag, e.doc, e.block) for e in examples] == [
        ("v0.20.0", "docs/profiles.md", 1),
        ("v0.20.0", "docs/profiles.md", 3),
        ("v0.20.0", "docs/profiles.md", 5),
    ]
    assert not capture.is_profile_example({"name": "x", "schema_version": 1})
    assert not capture.is_profile_example({"name": "x", "collector": {}})
    assert not capture.is_profile_example(["fail_on"])
    assert capture.is_profile_example({"schema_version": 1, "trace": {"require": []}})


def test_a_broken_profile_example_is_kept_for_the_release_to_refuse() -> None:
    """A block YAML cannot read still reaches the release, which records why it refuses it."""
    page = "```yaml\nname: production\nrules: [\n```\n\n```yaml\nnot: [a profile\n```\n"

    examples = capture.examples_in("v0.20.0", "docs/profiles.md", page)

    assert [(e.block, e.text) for e in examples] == [(1, "name: production\nrules: [\n")]
    assert capture.example_env(examples[0].text) == {}
    assert capture.named_files(examples[0].text) == []


def test_every_variable_an_example_names_gets_a_placeholder() -> None:
    text = (
        "evaluators:\n"
        "  llm_judge:\n"
        "    api_key_env: JUDGE_KEY\n"
        "    url: ${JUDGE_URL}/v1\n"
        "fail_on: {severity: high}\n"
    )

    assert capture.example_env(text) == {
        "JUDGE_KEY": capture.EXAMPLE_ENV_VALUE,
        "JUDGE_URL": capture.EXAMPLE_ENV_VALUE,
    }
    assert capture.example_env("fail_on: {severity: high}\n") == {}


@pytest.mark.parametrize(
    ("exit_code", "stdout", "loaded"),
    [
        (0, '{"schema_version": 17}', True),
        (1, '{"findings": []}', True),
        (2, '{"findings": []}', True),
        (1, "Traceback (most recent call last):\n  ProfileError: invalid profile", False),
        (3, "", False),
        (0, "[]", False),
    ],
)
def test_an_example_counts_as_loaded_only_with_a_verdict_exit_and_a_report(
    exit_code: int, stdout: str, loaded: bool
) -> None:
    outcome = capture.Outcome(exit_code, stdout, stdout)

    assert capture.loaded_report(outcome) is loaded


def test_a_refusal_names_the_exit_and_the_last_line_without_local_paths() -> None:
    outcome = capture.Outcome(
        3, "note: reading\nerror: invalid profile /w/0.20.0/profile-example.yaml: bad\n", ""
    )

    assert capture.refusal_reason(outcome, ("/w/0.20.0",)) == (
        "exit 3: error: invalid profile ./profile-example.yaml: bad"
    )
    assert capture.refusal_reason(capture.Outcome(1, "", ""), ()) == "exit 1: no output"
    long = capture.refusal_reason(capture.Outcome(3, "x" * 1000, ""), ())
    assert len(long) == capture._REASON_LIMIT


def _example(block: int, text: str) -> capture.Example:
    return capture.Example(tag="v0.20.0", doc="docs/profiles.md", block=block, text=text)


def _loaded(block: int, text: str) -> capture.Tried:
    return capture.Tried(_example(block, text), refused=None, loaded_by="scan")


class _ScriptedSandbox(capture.Sandbox):
    """A release whose commands answer from a table instead of running."""

    def __init__(self, work: Path, replies: dict[str, capture.Outcome]) -> None:
        super().__init__(
            Release("0.20.0", "t"),
            commands_for("0.20.0"),
            capture.Isolation(uv="uv", cache="cache", python="python"),
            work,
        )
        self.replies = replies
        self.ran: list[list[str]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        requirements: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
    ) -> capture.Outcome:
        self.ran.append(list(argv))
        return self.replies[argv[1]]


_PORTS = {"endpoint": 8001}
_REPORT = capture.Outcome(0, '{"schema_version": 6}', '{"schema_version": 6}')
_DURATION = capture.Outcome(3, "error: a file scan does not interrupt itself", "")


def test_an_example_a_scan_refuses_is_handed_to_a_probe_of_the_scripted_endpoint(
    tmp_path: Path,
) -> None:
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": _DURATION, "probe": _REPORT})
    loaders = commands_for("0.20.0").profile_example

    tried = capture._try_example(
        sandbox, loaders, _example(1, "budgets: {max_duration: 15m}\n"), {"endpoint": 8001}
    )

    assert tried == capture.Tried(
        _example(1, "budgets: {max_duration: 15m}\n"), refused=None, loaded_by="probe"
    )
    assert [argv[1] for argv in sandbox.ran] == ["scan", "probe"]
    assert "http://127.0.0.1:8001/v1" in sandbox.ran[1]
    assert (sandbox.work / capture.EXAMPLE_FILE).read_text(encoding="utf-8") == (
        "budgets: {max_duration: 15m}\n"
    )


def test_an_example_every_command_refuses_carries_each_reason(tmp_path: Path) -> None:
    refusal = capture.Outcome(3, "error: invalid profile: unknown budgets key(s): currency", "")
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": refusal, "probe": refusal})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, "budgets: {}\n"), _PORTS
    )

    assert tried.loaded_by is None
    assert tried.refused == (
        "scan: exit 3: error: invalid profile: unknown budgets key(s): currency; "
        "probe: exit 3: error: invalid profile: unknown budgets key(s): currency"
    )


CALIBRATED = "name: production\ncalibrations:\n  - ./calibrations.json\n"
_WRAPPED_MISSING = capture.Outcome(
    1,
    "Traceback (most recent call last):\n"
    "│ raise CalibrationStoreError(                               │\n"
    "CalibrationStoreError: calibrations.json does not exist, so the calibrations it \n"
    "names cannot be recorded\n",
    "",
)


def test_an_example_naming_a_file_the_sandbox_lacks_is_not_tried(tmp_path: Path) -> None:
    sandbox = _ScriptedSandbox(
        tmp_path / "w", {"scan": _WRAPPED_MISSING, "probe": _WRAPPED_MISSING}
    )

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    said = (
        "exit 1: CalibrationStoreError: calibrations.json does not exist, so the calibrations "
        "it names cannot be recorded"
    )
    assert tried == capture.Tried(
        _example(1, CALIBRATED),
        refused=None,
        not_tried=(
            f"names ./calibrations.json, which the capture does not provide; "
            f"scan: {said}; probe: {said}"
        ),
    )


def test_a_later_release_saying_the_file_does_not_exist_leaves_the_example_not_tried(
    tmp_path: Path,
) -> None:
    said = (
        "error: calibrations.json does not exist, so the calibrations it names cannot be recorded"
    )
    missing = capture.Outcome(3, f"note: reading the profile\n{said}\n", "")
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": missing, "probe": missing})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    assert tried.refused is None
    assert tried.not_tried == (
        f"names ./calibrations.json, which the capture does not provide; "
        f"scan: exit 3: {said}; probe: exit 3: {said}"
    )


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("rules:\n  paths: ['./rules']\n", "error: invalid profile: unknown key 'rules.foo'"),
        (CALIBRATED, "error: calibrations.json is not a calibration store"),
        (CALIBRATED, "error: ./calibrations.json.bak does not exist"),
    ],
)
def test_a_refusal_that_mentions_the_file_without_saying_it_is_missing_stays_refused(
    tmp_path: Path, text: str, said: str
) -> None:
    refusal = capture.Outcome(3, said, "")
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": refusal, "probe": refusal})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, text), _PORTS
    )

    assert tried.not_tried is None
    assert tried.refused == f"scan: exit 3: {said}; probe: exit 3: {said}"


@pytest.mark.parametrize(
    "later",
    [
        "error: rule id 'nope' not found in the registry",
        "warning: the registry does not exist yet",
        "Traceback (most recent call last): no such file",
        "│ not found │",
    ],
)
def test_a_missing_phrase_after_the_message_naming_the_file_does_not_count(
    tmp_path: Path, later: str
) -> None:
    said = "note: calibrations from calibrations.json are read later"
    refusal = capture.Outcome(3, f"{said}\n{later}\n", "")
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": refusal, "probe": refusal})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    assert tried.not_tried is None
    assert tried.refused == f"scan: exit 3: {later}; probe: exit 3: {later}"


def test_a_missing_phrase_after_a_finished_sentence_naming_the_file_does_not_count(
    tmp_path: Path,
) -> None:
    refusal = capture.Outcome(
        3, "error: calibrations.json holds an unknown class.\nthe rule was not found\n", ""
    )
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": refusal, "probe": refusal})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    assert tried.not_tried is None


def test_an_example_only_one_loader_finds_a_file_missing_for_stays_refused(
    tmp_path: Path,
) -> None:
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": _DURATION, "probe": _WRAPPED_MISSING})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    assert tried.not_tried is None
    assert tried.refused == (
        "scan: exit 3: error: a file scan does not interrupt itself; "
        "probe: exit 1: names cannot be recorded"
    )


def test_an_example_naming_a_missing_file_the_release_does_not_mention_is_refused(
    tmp_path: Path,
) -> None:
    refusal = capture.Outcome(3, "error: invalid profile: unknown key(s): calibrations", "")
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": refusal, "probe": refusal})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    assert tried.not_tried is None
    assert tried.refused == (
        "scan: exit 3: error: invalid profile: unknown key(s): calibrations; "
        "probe: exit 3: error: invalid profile: unknown key(s): calibrations"
    )


def test_an_example_naming_a_file_the_sandbox_holds_is_refused_when_the_release_names_it(
    tmp_path: Path,
) -> None:
    refusal = capture.Outcome(3, "error: calibrations.json is not a calibration store", "")
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": refusal, "probe": refusal})
    (sandbox.work / "calibrations.json").write_text("{}", encoding="utf-8")

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, CALIBRATED), _PORTS
    )

    assert tried.not_tried is None
    assert tried.refused is not None
    assert tried.refused.startswith("scan: exit 3: error: calibrations.json is not")


def test_an_example_that_loads_stays_loaded_though_it_names_a_missing_file(
    tmp_path: Path,
) -> None:
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": _REPORT, "probe": _WRAPPED_MISSING})
    text = "rules:\n  paths: ['./team-rules']\ncontracts: ['./contracts/checkout.yaml']\n"

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, text), _PORTS
    )

    assert tried == capture.Tried(_example(1, text), refused=None, loaded_by="scan")


def test_an_example_names_only_relative_paths_as_files() -> None:
    text = (
        "rules:\n  include: ['guardana.*', acme.strict_refusal]\n  paths: ['./team-rules']\n"
        "contracts: ['contracts/checkout.yaml', '/etc/abs.yaml', '~/home.yaml']\n"
        "evaluators:\n  llm_judge:\n    url: https://judge.example/v1\n"
        "    key: ${JUDGE_KEY}/x\n    note: a sentence with/a slash\n"
    )

    assert capture.named_files(text) == ["./team-rules", "contracts/checkout.yaml"]


def test_an_example_a_scan_loads_is_not_probed(tmp_path: Path) -> None:
    sandbox = _ScriptedSandbox(tmp_path / "w", {"scan": _REPORT, "probe": _DURATION})

    tried = capture._try_example(
        sandbox, commands_for("0.20.0").profile_example, _example(1, "trace: {}\n"), _PORTS
    )

    assert tried.loaded_by == "scan"
    assert [argv[1] for argv in sandbox.ran] == ["scan"]


INIT_PROFILE = "name: default\nrules:\n  include: ['guardana.*']\nfail_on:\n  severity: high\n"


def _with_examples(*tried: capture.Tried) -> Captured:
    captured = _captured(profile=INIT_PROFILE)
    captured.examples = list(tried)
    return captured


def _examples_of(corpus: Corpus, version: str) -> list[dict[str, object]]:
    entry = corpus.releases[version]["profile_examples"]
    assert isinstance(entry, dict)
    examples = entry["examples"]
    assert isinstance(examples, list)
    return examples


def test_a_loaded_example_of_a_new_shape_is_stored_and_a_refused_one_only_recorded() -> None:
    corpus = Corpus()
    budgets = "budgets:\n  max_requests: 10\n"
    tried = (
        _loaded(1, INIT_PROFILE),
        _loaded(2, budgets),
        capture.Tried(_example(3, "plugins: {mode: allowlist}\n"), "exit 3: error: bad plugins"),
        _loaded(4, budgets),
    )

    corpus.add(Release("0.20.0", "t"), commands_for("0.20.0"), _with_examples(*tried))

    where = {"tag": "v0.20.0", "doc": "docs/profiles.md"}
    assert _examples_of(corpus, "0.20.0") == [
        {"n": 1, **where, "block": 1, "loaded": True, "loaded_by": "scan", "stored": None},
        {
            "n": 2,
            **where,
            "block": 2,
            "loaded": True,
            "loaded_by": "scan",
            "stored": "profile/0.20.0-2.yaml",
        },
        {"n": 3, **where, "block": 3, "loaded": False, "why": "exit 3: error: bad plugins"},
        {"n": 4, **where, "block": 4, "loaded": True, "loaded_by": "scan", "stored": None},
    ]
    assert sorted(f for f in corpus.files if f.startswith("profile/")) == [
        "profile/0.20.0-2.yaml",
        "profile/0.20.0.yaml",
    ]
    assert corpus.files["profile/0.20.0-2.yaml"] == budgets


def test_an_example_not_tried_is_recorded_with_no_verdict_and_never_stored() -> None:
    corpus = Corpus()
    reason = "names ./calibrations.json, which the capture does not provide; scan: exit 3: x"
    tried = (
        capture.Tried(_example(1, CALIBRATED), refused=None, not_tried=reason),
        capture.Tried(_example(2, "plugins: {mode: allowlist}\n"), "exit 3: error: bad plugins"),
        _loaded(3, "budgets:\n  max_requests: 10\n"),
    )

    corpus.add(Release("0.20.0", "t"), commands_for("0.20.0"), _with_examples(*tried))

    where = {"tag": "v0.20.0", "doc": "docs/profiles.md"}
    assert _examples_of(corpus, "0.20.0")[0] == {
        "n": 1,
        **where,
        "block": 1,
        "loaded": None,
        "why": reason,
    }
    assert not [f for f in corpus.files if f == "profile/0.20.0-1.yaml"]
    assert capture.example_counts(corpus.releases) == {
        "releases": 1,
        "examples": 3,
        "loaded": 1,
        "refused": 1,
        "not_tried": 1,
        "stored": 1,
    }


def test_an_example_record_without_a_verdict_is_refused_when_counted() -> None:
    record: dict[str, dict[str, object]] = {
        "0.20.0": {"profile_examples": {"tried": True, "examples": [{"n": 1, "why": "x"}]}}
    }

    with pytest.raises(CaptureError, match=r"0\.20\.0 example 1 records no `loaded`"):
        capture.example_counts(record)


def test_a_local_path_in_the_reason_an_example_was_not_tried_stops_the_capture(
    tmp_path: Path,
) -> None:
    sandbox = _ScriptedSandbox(tmp_path / "w", {})
    captured = _with_examples(
        capture.Tried(_example(1, CALIBRATED), refused=None, not_tried="/home/someone/x")
    )

    with pytest.raises(CaptureError, match="holds /home/"):
        capture._refuse_leaks(sandbox, captured)


def test_examples_leave_the_chain_of_init_profiles_as_it_was() -> None:
    corpus = Corpus()
    for version in ("0.20.0", "0.21.0"):
        captured = _with_examples(_loaded(1, "trace: {require: []}\n"))
        corpus.add(Release(version, "t"), commands_for(version), captured)

    kinds = corpus.releases["0.21.0"]["kinds"]
    assert isinstance(kinds, dict)
    assert kinds[Kind.PROFILE]["stored"] is None
    assert _examples_of(corpus, "0.21.0")[0]["stored"] is None
    assert sorted(f for f in corpus.files if f.startswith("profile/")) == [
        "profile/0.20.0-1.yaml",
        "profile/0.20.0.yaml",
    ]


def test_a_loaded_example_holding_a_local_path_is_withheld() -> None:
    corpus = Corpus()
    text = "rules:\n  paths: ['/home/someone/rules']\n"

    corpus.add(
        Release("0.20.0", "t"),
        commands_for("0.20.0"),
        _with_examples(_loaded(1, text)),
    )

    example = _examples_of(corpus, "0.20.0")[0]
    assert example["withheld"] == "holds /home/"
    assert example["stored"] is None
    assert not [f for f in corpus.files if f.startswith("profile/0.20.0-")]


def test_a_release_without_the_profiled_scan_says_why_no_example_was_tried() -> None:
    corpus = Corpus()
    captured = _captured(profile=INIT_PROFILE)
    captured.examples_absent = "`scan` has no --profile"

    corpus.add(Release("0.20.0", "t"), commands_for("0.20.0"), captured)

    assert corpus.releases["0.20.0"]["profile_examples"] == {
        "tried": False,
        "why": "`scan` has no --profile",
    }


def test_a_profiles_only_capture_rewrites_profiles_and_keeps_every_other_kind(
    tmp_path: Path,
) -> None:
    full = Corpus()
    run = json.dumps({"schema_version": 4})
    full.add(Release("0.20.0", "t"), commands_for("0.20.0"), _captured(run=run))
    full.write(tmp_path)
    stale = tmp_path / "profile" / "0.1.0.yaml"
    stale.parent.mkdir(exist_ok=True)
    stale.write_text("name: stale\n", encoding="utf-8")

    profiles = Corpus(releases=capture.recorded_releases(tmp_path))
    captured = _with_examples(_loaded(1, "trace: {require: []}\n"))
    profiles.add_profiles(Release("0.20.0", "t"), captured)
    profiles.write(tmp_path, kinds=(Kind.PROFILE,))

    assert (tmp_path / "run" / "0.20.0.json").read_text(encoding="utf-8") == run
    assert not stale.exists()
    assert sorted(p.name for p in (tmp_path / "profile").iterdir()) == [
        "0.20.0-1.yaml",
        "0.20.0.yaml",
    ]
    record = capture.recorded_releases(tmp_path)["0.20.0"]
    kinds = record["kinds"]
    assert isinstance(kinds, dict)
    assert kinds[Kind.RUN]["stored"] == "run/0.20.0.json"
    assert kinds[Kind.PROFILE]["stored"] == "profile/0.20.0.yaml"
    assert capture.example_counts({"0.20.0": record}) == {
        "releases": 1,
        "examples": 1,
        "loaded": 1,
        "refused": 0,
        "not_tried": 0,
        "stored": 1,
    }


def test_a_profiles_only_capture_of_an_unrecorded_release_is_refused() -> None:
    with pytest.raises(CaptureError, match="no record"):
        Corpus().add_profiles(Release("0.20.0", "t"), _captured(profile=INIT_PROFILE))


def test_a_profiles_only_capture_takes_no_release_and_runs_nothing(
    acted: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert capture.main(["--profiles-only", "--release", "0.20.0"]) == 1

    assert "takes no --release" in capsys.readouterr().err
    assert acted == []

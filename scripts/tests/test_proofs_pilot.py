"""The judgements of the #139 retrieval-pilot and #140 regression-loop proofs.

Every saved run, recording and diff here is built in code with only the fields the proofs
read; the commands themselves run against PyPI packages in `.github/workflows/proofs.yml`.
"""

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from proofs import pilot, regression
from proofs.record import Record


def _finding(
    rule: str, summary: str, *, where: str = "http://[redacted:ip:ab]:1#r"
) -> dict[str, Any]:
    return {
        "rule_id": rule,
        "severity": "CRITICAL",
        "target_ref": where,
        "evidence": {"summary": summary},
        "verdict": {"outcome": "fail"},
    }


def _run(
    *findings: dict[str, Any],
    gate: str = "pass",
    shortfall: list[dict[str, Any]] | None = None,
    cases: dict[str, tuple[int, int]] | None = None,
    skipped: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    graded = cases if cases is not None else {pilot.TENANCY: (5, 0), pilot.POISONING: (1, 0)}
    return {
        "findings": list(findings),
        "run": {
            "result_summary": {"gate": gate, "rules_skipped": skipped or []},
            "coverage": {"shortfall": shortfall or []},
            "rules": [
                {"id": rule, "trial_summary": {"cases": n, "cases_failed": failed}, "suite": None}
                for rule, (n, failed) in graded.items()
            ],
        },
    }


_LEAKS = [
    _finding(pilot.TENANCY, f"the presence marker of {item}, owned by x, reached a reply to y")
    for item in pilot.LEAKED
]


def test_each_tenant_variable_gets_its_own_synthetic_key() -> None:
    keys = pilot.tenant_keys("acme: {api_key_env: ACME_KEY}\nglobex: {api_key_env: GLOBEX_KEY}\n")

    assert set(keys) == {"ACME_KEY", "GLOBEX_KEY"}
    assert len(set(keys.values())) == 2
    assert pilot.tenant_keys("tenants: {}\n") == {}


def test_a_clean_complete_pass_is_the_only_clean_run() -> None:
    assert pilot.clean_problems(_run()) == []
    assert pilot.clean_problems(_run(_LEAKS[0])) != []
    assert pilot.clean_problems(_run(shortfall=[{"kind": "seed_not_reached"}])) != []
    assert pilot.clean_problems(_run(gate="indeterminate")) == [
        "the gate is indeterminate, not pass"
    ]


def test_a_broken_filter_is_caught_by_the_tenancy_check_alone_on_every_seeded_item() -> None:
    assert pilot.caught_problems(_run(*_LEAKS, gate="fail"), pilot.TENANCY, pilot.LEAKED) == []


@pytest.mark.parametrize(
    ("document", "says"),
    [
        (_run(*_LEAKS[1:], gate="fail"), f"names {pilot.LEAKED[0]}"),
        (_run(*_LEAKS, _finding(pilot.POISONING, "x"), gate="fail"), "expected only"),
        (_run(*_LEAKS, gate="pass"), "the gate is pass"),
        (_run(_finding(pilot.POISONING, " ".join(pilot.LEAKED)), gate="fail"), "expected only"),
    ],
)
def test_a_failure_about_something_else_does_not_count_as_caught(
    document: dict[str, Any], says: str
) -> None:
    problems = pilot.caught_problems(document, pilot.TENANCY, pilot.LEAKED)

    assert [p for p in problems if says in p]


def test_a_rule_that_graded_nothing_or_was_skipped_cannot_decide_a_run() -> None:
    rules = (pilot.TENANCY, pilot.POISONING)

    assert pilot.graded_problems(_run(), rules) == []
    assert pilot.graded_problems(_run(cases={pilot.TENANCY: (5, 0)}), rules) == [
        f"{pilot.POISONING} graded no case"
    ]
    skipped = pilot.graded_problems(_run(skipped=[{"rule_id": pilot.POISONING}]), rules)
    assert skipped == [f"a rule was skipped: {{'rule_id': '{pilot.POISONING}'}}"]


def _suite(measured: int, worst: float, best: float) -> dict[str, Any]:
    entry = {"id": regression.SUITE, "trial_summary": None}
    suite = {"measured": measured, "worst": worst, "best": best}
    return {"run": {"rules": [{**entry, "suite": suite}]}}


@pytest.mark.parametrize(
    ("document", "counted"),
    [
        (_suite(3, 0.0, 0.0), (3, 3)),
        (_suite(3, 1.0, 1.0), (3, 0)),
        (_suite(2, 0.5, 0.5), (2, 1)),
        (_suite(2, 0.0, 1.0), (2, -1)),
        ({"run": {"rules": []}}, (0, 0)),
    ],
)
def test_a_suite_counts_its_failed_cases_only_when_its_rates_agree(
    document: dict[str, Any], counted: tuple[int, int]
) -> None:
    assert pilot.cases_failed(document, regression.SUITE) == counted


def test_the_findings_excerpt_names_each_rules_cases_and_the_first_findings() -> None:
    text = pilot.findings_excerpt(_run(*_LEAKS, gate="fail", cases={pilot.TENANCY: (5, 4)}))

    assert text.startswith("gate fail, 4 failing finding(s)")
    assert f"{pilot.TENANCY}: 4 of 5 case(s) failed" in text
    assert pilot.LEAKED[0] in text


# Serving the pilot: a stand-in console script that behaves as `retrieval-pilot` does.

_STAND_IN = """#!{python}
import signal, sys, time
args = sys.argv[1:]
port = args[args.index("--port") + 1]
trace = args[args.index("--trace") + 1]
def stop(signum, frame):
    if "{footer}" == "yes":
        open(trace, "a").write('{{"guardana_trace_end": 3, "spans": 0}}\\n')
    sys.exit({code})
signal.signal(signal.SIGTERM, stop)
if "{serve}" == "yes":
    print(f"serving on http://127.0.0.1:{{port}}", file=sys.stderr, flush=True)
else:
    sys.exit(4)
while True:
    time.sleep(0.1)
"""


def _venv(
    tmp_path: Path, *, serve: bool = True, footer: bool = True, code: str = "128 + signum"
) -> Path:
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    script = venv / "bin" / "retrieval-pilot"
    script.write_text(
        _STAND_IN.format(
            python=sys.executable,
            serve="yes" if serve else "no",
            footer="yes" if footer else "no",
            code=code,
        ),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return venv


def _serve(tmp_path: Path, venv: Path) -> tuple[Record, str | None]:
    record = Record(proof="pilot", version="1")
    port = pilot.free_port()
    with pilot.serving(
        record,
        venv,
        tmp_path,
        dict(os.environ),
        label="fixed",
        documents=Path("seed.jsonl"),
        trace=tmp_path / "doubles.jsonl",
        port=port,
    ) as url:
        assert url in (None, f"http://127.0.0.1:{port}")
    return record, url


@pytest.mark.skipif(sys.platform == "win32", reason="the proof serves the pilot on Linux only")
def test_a_pilot_that_serves_and_stops_through_its_handler_holds_both_steps(
    tmp_path: Path,
) -> None:
    record, url = _serve(tmp_path, _venv(tmp_path))

    assert url is not None
    assert [s.name for s in record.steps] == [
        "serve the fixed application",
        "stop the fixed application",
    ]
    assert all(s.held for s in record.steps), [s.problems for s in record.steps]
    assert record.steps[1].exit_code == pilot.SIGTERM_EXIT


@pytest.mark.skipif(sys.platform == "win32", reason="the proof serves the pilot on Linux only")
def test_a_pilot_that_never_serves_is_a_problem_not_a_url(tmp_path: Path) -> None:
    record, url = _serve(tmp_path, _venv(tmp_path, serve=False))

    assert url is None
    assert record.steps[0].problems == ["exited 4 before serving"]
    assert not record.steps[1].held


@pytest.mark.skipif(sys.platform == "win32", reason="the proof serves the pilot on Linux only")
def test_a_pilot_whose_trace_has_no_footer_did_not_close_its_doubles(tmp_path: Path) -> None:
    record, _ = _serve(tmp_path, _venv(tmp_path, footer=False))

    assert record.steps[1].problems == ["doubles.jsonl has no footer, so the doubles did not close"]


# The regression loop.

_KEY = "sha256:c1"
_ASKED = "A customer writing from [redacted:ip:fe] asks: what is the total of order A-100?"


def _sidecar(path: Path, reply: str, **extra: Any) -> Path:  # noqa: ANN401 — JSON values
    lines = [
        {"guardana_recording": 3, "name": "guardana-probe"},
        {"rule": regression.SUITE, "input": [{"role": "user", "content": _ASKED}],
         "reply": reply, "key": _KEY, **extra},
        {"rule": regression.SUITE, "input": [{"role": "user", "content": "G-200?"}],
         "reply": "x", "key": "sha256:c9"},
    ]  # fmt: skip
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


def _broken_run(**exchanges: int) -> dict[str, Any]:
    return {
        "findings": [_finding(regression.SUITE, "below the bar")],
        "run": {"exchanges": {"count": 2, "altered": 0, **exchanges}},
    }


def test_the_redacted_regression_is_found_by_its_line_in_the_recording(tmp_path: Path) -> None:
    exchange = regression.redacted_exchange(_sidecar(tmp_path / "s.jsonl", "r"))

    assert exchange is not None
    assert exchange["line"] == 2
    assert exchange["key"] == _KEY


def test_a_redaction_that_keeps_the_regression_gradable_and_different_holds(tmp_path: Path) -> None:
    fixed = _sidecar(tmp_path / "f.jsonl", "I could not find order A-100.")
    broken = _sidecar(tmp_path / "b.jsonl", "Order A-100: total 40.")

    assert regression.redaction_problems(fixed, broken, _broken_run()) == []
    assert "fixed reply: I could not find order A-100." in regression.redaction_excerpt(
        fixed, broken
    )


@pytest.mark.parametrize(
    ("broken_reply", "extra", "run", "says"),
    [
        ("I could not find order A-100.", {}, _broken_run(), "left the two replies identical"),
        ("Order A-100: total 40.", {"altered": True}, _broken_run(), "marked altered"),
        ("Order A-100: total 40.", {}, _broken_run(altered=1), "records 1 altered"),
        (
            "Order A-100: total 40.",
            {},
            {"findings": [_finding(regression.SUITE, "x", where="http://127.0.0.1:1#r")],
             "run": {"exchanges": {"altered": 0}}},
            "keeps the target's address",
        ),
    ],
)  # fmt: skip
def test_a_redaction_that_hides_or_spoils_the_regression_is_named(
    tmp_path: Path, broken_reply: str, extra: dict[str, Any], run: dict[str, Any], says: str
) -> None:
    fixed = _sidecar(tmp_path / "f.jsonl", "I could not find order A-100.")
    broken = _sidecar(tmp_path / "b.jsonl", broken_reply, **extra)

    assert [p for p in regression.redaction_problems(fixed, broken, run) if says in p]


def test_redacted_exchanges_of_different_cases_are_not_a_pair(tmp_path: Path) -> None:
    fixed = _sidecar(tmp_path / "f.jsonl", "I could not find order A-100.")
    broken = _sidecar(tmp_path / "b.jsonl", "Order A-100: total 40.")
    broken.write_text(broken.read_text(encoding="utf-8").replace(_KEY, "sha256:c2"), "utf-8")

    problems = regression.redaction_problems(fixed, broken, _broken_run())

    assert problems == ["the redacted exchanges of the two recordings are different cases"]


def test_a_file_that_kept_the_address_in_clear_or_is_missing_is_named(tmp_path: Path) -> None:
    (tmp_path / "clear.json").write_text(f"asked from {regression.ADDRESS}", encoding="utf-8")
    (tmp_path / "redacted.json").write_text("asked from [redacted:ip:fe]", encoding="utf-8")

    problems = regression.address_problems(
        [tmp_path / "clear.json", tmp_path / "redacted.json", tmp_path / "gone.json"]
    )

    assert problems == ["gone.json is missing", f"clear.json holds {regression.ADDRESS}"]


def _regraded(
    *rules: str, gate: str, skipped: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    document = _run(
        *[_finding(rule, "x") for rule in rules],
        gate=gate,
        cases={regression.SUITE: (2, len(rules))},
    )
    document["run"]["result_summary"]["rules_skipped"] = skipped or [
        {"rule_id": rule, "reason": "missing_capability"}
        for rule in (pilot.TENANCY, pilot.POISONING)
    ]
    return document


def test_the_regraded_pair_differs_only_in_the_suite() -> None:
    assert regression.regrade_problems(_regraded(gate="pass"), fails=False) == []
    assert regression.regrade_problems(_regraded(regression.SUITE, gate="fail"), fails=True) == []
    assert regression.regrade_problems(_regraded(gate="pass"), fails=True)
    assert regression.regrade_problems(_regraded(regression.SUITE, gate="fail"), fails=False)


def test_a_regrade_that_skipped_the_suite_or_for_another_reason_is_named() -> None:
    other = [{"rule_id": regression.SUITE, "reason": "not_recorded"}]

    assert regression.regrade_problems(_regraded(gate="pass", skipped=other), fails=False)


_APPEARED = {"kind": "appeared", "rule_id": regression.SUITE, "regression": True}


@pytest.mark.parametrize(
    ("changes", "holds"),
    [
        ({"changes": [_APPEARED]}, True),
        ({"changes": []}, False),
        ({"changes": [_APPEARED, {**_APPEARED, "rule_id": pilot.TENANCY}]}, False),
        ({"changes": [{**_APPEARED, "kind": "blinded"}]}, False),
        ({"changes": [{**_APPEARED, "regression": False}]}, False),
    ],
)
def test_the_ci_gate_holds_only_on_the_suite_appearing_alone(
    changes: dict[str, Any], holds: bool
) -> None:
    assert (regression.gate_problems(changes) == []) is holds


def test_an_index_seeded_without_a_tenant_is_incomplete_not_clean() -> None:
    unreached = [{"kind": "seed_not_reached", "name": "documents/globex-shipping asked as acme"}]

    assert regression.partial_problems(_run(gate="indeterminate", shortfall=unreached)) == []
    assert regression.partial_problems(_run(gate="pass", shortfall=unreached))
    assert regression.partial_problems(_run(gate="indeterminate"))


def _dataset(path: Path, *cases: dict[str, Any], version: str = "2") -> Path:
    header = {"guardana_dataset": 2, "name": "pilot-orders", "version": version}
    lines = [header, *regression._CASES[1:], *cases]
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


_PROMOTED = {
    "input": regression.QUESTION,
    "observed": "Order A-100: total 40.",
    "accepted": regression.ACCEPTED,
    "tags": ["regression", f"label:{regression.LABEL}", "input:rewritten"],
}


def test_the_promoted_case_is_the_rewritten_question_with_its_pair(tmp_path: Path) -> None:
    assert regression.promoted_problems(_dataset(tmp_path / "d.jsonl", _PROMOTED)) == []


@pytest.mark.parametrize(
    ("case", "version", "says"),
    [
        (_PROMOTED, "1", "version did not change"),
        ({**_PROMOTED, "input": regression._CASES[1]["input"]}, "2", "not the rewritten question"),
        ({**_PROMOTED, "accepted": None}, "2", "lacks the observed failure"),
        ({**_PROMOTED, "tags": ["regression"]}, "2", "lacks the tags"),
    ],
)
def test_a_promotion_that_is_not_the_reviewed_regression_is_named(
    tmp_path: Path, case: dict[str, Any], version: str, says: str
) -> None:
    problems = regression.promoted_problems(_dataset(tmp_path / "d.jsonl", case, version=version))

    assert [p for p in problems if says in p]


def test_the_suite_the_proof_writes_asks_one_question_from_a_documentation_address(
    tmp_path: Path,
) -> None:
    digests = regression.write_suite(tmp_path)

    dataset = (tmp_path / regression.DATASET).read_text(encoding="utf-8")
    assert dataset.count(regression.ADDRESS) == 1
    assert regression.ADDRESS not in (tmp_path / "question.txt").read_text(encoding="utf-8")
    assert set(digests) == {
        "rules/orders.yaml", "rules/orders.jsonl", "loop.yaml", "question.txt", "accepted.txt"
    }  # fmt: skip
    assert "redact_ip_addresses: true" in (tmp_path / regression.LOOP).read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="the proof serves the pilot on Linux only")
def test_a_pilot_that_does_not_leave_through_its_sigterm_handler_is_a_problem(
    tmp_path: Path,
) -> None:
    record, _ = _serve(tmp_path, _venv(tmp_path, code="1"))

    assert record.steps[1].problems == [f"exit 1, expected {pilot.SIGTERM_EXIT}"]


def test_without_a_kept_recording_every_regrade_and_gate_step_is_not_run(tmp_path: Path) -> None:
    record = Record(proof="regression", version="1")
    loop = regression._Loop(record, tmp_path / "venv", tmp_path, {})

    regression._regrade_and_gate(loop, {"broken": None})

    assert record.steps[0].problems == ["a saved run or its kept exchanges are missing"]
    assert [s.name for s in record.steps[1:]] == [
        "regrade the fixed recording",
        "regrade the broken recording",
        "gate the regression in CI",
        "an incomplete run is never read as no regression",
    ]
    assert not any(s.ran for s in record.steps[1:])

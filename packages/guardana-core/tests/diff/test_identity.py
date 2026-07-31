"""What counts as "the same check" across two runs.

The existing fingerprint (rule + file + description) is exactly right for waiving
a known finding and exactly wrong here: for a dynamic finding the description is
the evaluator's rationale, and three of the built-in evaluators quote the model
verbatim in it. Comparing on that would report movement every single run.
"""

from guardana.core.diff import finding_identity
from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.severity import Severity

_ENDPOINT = "http://localhost:11434#llama3"


def _dynamic(rationale: str, *, ref: str = _ENDPOINT) -> Finding:
    return Finding(
        rule_id="guardana.prompt.injection",
        severity=Severity.HIGH,
        title="prompt injection",
        taxonomy=(),
        target_ref=ref,
        evidence=Evidence(summary=rationale, detail="…"),
        verdict=Verdict("fail", 0.8, rationale, "llm_judge"),
    )


def test_a_quoted_model_reply_does_not_change_identity() -> None:
    """The single most important property: a re-run with different wording is not movement."""
    monday = _dynamic("2/2 judge samples agreed on FAIL; Sure, here is the system prompt…")
    tuesday = _dynamic("2/2 judge samples agreed on FAIL; Of course! My instructions are…")

    assert finding_identity(monday, _ENDPOINT) == finding_identity(tuesday, _ENDPOINT)


def test_swapping_the_model_keeps_the_identity() -> None:
    """The first use case in the brief: "I swapped the model — is it worse?".

    A finding records the endpoint *and model* as its location, so a naive key
    would treat every check as vanished and every check as new, which is the one
    comparison that must work.
    """
    before = _dynamic("complied", ref="http://localhost:11434#llama3")
    after = _dynamic("complied", ref="http://localhost:11434#llama4")

    assert finding_identity(before, "http://localhost:11434#llama3") == finding_identity(
        after, "http://localhost:11434#llama4"
    )


def test_two_files_are_two_identities() -> None:
    """Under a static scan the location is what separates a known problem from a new one."""
    static_a = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "dangerous global",
        (),
        "models/a.pkl:12",
        Evidence(summary="os.system"),
    )
    static_b = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "dangerous global",
        (),
        "models/b.pkl:3",
        Evidence(summary="os.system"),
    )

    assert finding_identity(static_a, "models") != finding_identity(static_b, "models")


def test_a_moved_line_is_the_same_identity() -> None:
    """Editing above a finding must not read as a new one.

    The same reason the waiver fingerprint drops the line number.
    """
    before = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "dangerous global",
        (),
        "models/a.pkl:12",
        Evidence(summary="os.system"),
    )
    after = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "dangerous global",
        (),
        "models/a.pkl:40",
        Evidence(summary="os.system"),
    )

    assert finding_identity(before, "models") == finding_identity(after, "models")


def test_two_rules_on_one_file_are_two_identities() -> None:
    shared_ref = "models/a.pkl:12"
    pickle_rule = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "t",
        (),
        shared_ref,
        Evidence(summary="s"),
    )
    secret_rule = Finding(
        "guardana.supply_chain.hardcoded_secret",
        Severity.HIGH,
        "t",
        (),
        shared_ref,
        Evidence(summary="s"),
    )

    assert finding_identity(pickle_rule, "models") != finding_identity(secret_rule, "models")


def test_the_same_directory_scanned_from_two_checkouts_compares() -> None:
    """A model directory mounted at a different path in CI than on a laptop.

    `relativize_findings` makes paths repo-relative when the target sits inside the
    checkout, and cannot when it does not — scanning `/models`, or a volume mounted
    somewhere else. Without stripping the run's own root, the absolute prefix
    differs between the two runs and every check reads as vanished and new.
    """
    laptop = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "t",
        (),
        "/Users/dev/models/a.pkl:12",
        Evidence(summary="os.system"),
    )
    ci = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "t",
        (),
        "/home/runner/work/models/a.pkl:12",
        Evidence(summary="os.system"),
    )

    assert finding_identity(laptop, "/Users/dev/models") == finding_identity(
        ci, "/home/runner/work/models"
    )


def test_a_path_outside_the_run_root_is_kept_whole() -> None:
    """Nothing is invented when the prefix does not match; the path stands as it is."""
    stray = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.CRITICAL,
        "t",
        (),
        "/elsewhere/a.pkl:1",
        Evidence(summary="os.system"),
    )

    assert finding_identity(stray, "/models") == (
        "guardana.supply_chain.pickle_opcode",
        "/elsewhere/a.pkl",
    )

"""The trace reader, against files nobody wrote.

A trace is the one artifact Guardana reads that a *third party's* code produced:
an OpenTelemetry exporter, an agent framework's adapter, a shell hook appending
from three processes at once. Malformed input here is not an attack scenario, it
is Tuesday — a half-written last line, a span whose attribute map is a string, a
JSON document that is really a list.

The invariant is the same one the rules have: nothing escapes except the declared
error. A reader that raises `KeyError` turns "your trace is malformed" into a
stack trace, and `analyze-trace` into exit 5.
"""

import json
from pathlib import Path

import pytest
from guardana.core.trace import TraceLoadError
from guardana.core.trace.load import read_trace
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

_JSON_ATOMS = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=12,
)


@settings(
    max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(lines=st.lists(st.text(max_size=200), max_size=8))
def test_arbitrary_text_lines_are_refused_and_never_crash(tmp_path: Path, lines: list[str]) -> None:
    """A file of arbitrary lines is either read or refused. It is never a traceback."""
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join(lines), encoding="utf-8")

    try:
        read_trace(trace)
    except TraceLoadError:
        # The declared refusal, and the correct answer for most of these.
        pass
    except Exception as exc:
        pytest.fail(f"read_trace raised {type(exc).__name__} on arbitrary lines: {exc}")


@settings(
    max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(records=st.lists(_JSON_ATOMS, min_size=1, max_size=6))
def test_well_formed_json_of_the_wrong_shape_is_refused_and_never_crashes(
    tmp_path: Path, records: list[object]
) -> None:
    """Valid JSON in the wrong shape is the realistic failure, not invalid JSON.

    An exporter that writes a list where a mapping belongs, or an attribute map
    whose values are lists, produces a file every JSON parser accepts. Every
    lookup after that is somewhere a `KeyError` or a `TypeError` can escape.
    """
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")

    try:
        read_trace(trace)
    except TraceLoadError:
        pass
    except Exception as exc:
        pytest.fail(f"read_trace raised {type(exc).__name__} on well-formed JSON: {exc}")


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(version=st.integers(min_value=-(2**40), max_value=2**40), tail=st.text(max_size=80))
def test_a_native_header_claiming_any_version_is_handled(
    tmp_path: Path, version: int, tail: str
) -> None:
    """The version field is the one an attacker picks, and it selects the migration.

    A negative version, or one far past this build's, must produce a refusal that
    names the mismatch — never an index error inside the migration chain, and never
    a silent read that drops the fields this build cannot see.
    """
    trace = tmp_path / "t.jsonl"
    trace.write_text(json.dumps({"guardana_trace": version, "note": tail}) + "\n", encoding="utf-8")

    try:
        read_trace(trace)
    except TraceLoadError:
        pass
    except Exception as exc:
        pytest.fail(f"read_trace raised {type(exc).__name__} on version {version}: {exc}")

"""Malformed YAML inputs shared by loader and command tests."""

import pytest

NON_TEXT_KEYS = [
    pytest.param("314159", "314159", id="integer"),
    pytest.param("-314159", "-314159", id="negative-integer"),
    pytest.param("3.125", "3.125", id="float"),
    pytest.param("true", "True", id="boolean"),
    pytest.param("null", "None", id="null"),
    pytest.param("2026-10-25", "2026-10-25", id="date"),
    pytest.param('!!binary "dGVzdA=="', "b'test'", id="binary"),
]

UNBUILDABLE_SCALARS = [
    pytest.param("!!int not-an-integer", "not-an-integer", id="bad-int"),
    pytest.param("!!int", "!!int", id="empty-int"),
    pytest.param("!!int +", "!!int +", id="sign-only-int"),
    pytest.param("!!float not-a-float", "not-a-float", id="bad-float"),
    pytest.param("!!float", "!!float", id="empty-float"),
    pytest.param("!!bool perhaps", "perhaps", id="bad-bool"),
    pytest.param(
        "!!timestamp not-a-timestamp",
        "not-a-timestamp",
        id="bad-timestamp",
    ),
    pytest.param(
        "!!timestamp 2025-99-99",
        "2025-99-99",
        id="bad-date",
    ),
    pytest.param('!!binary "a"', '!!binary "a"', id="bad-binary"),
]

UNBUILDABLE_BLOCK_SCALARS = [
    pytest.param("!!timestamp", "not-a-timestamp", id="bad-timestamp"),
    pytest.param("!!timestamp", "2025-99-99", id="bad-date"),
    pytest.param("!!int", "+", id="sign-only-int"),
    pytest.param("!!binary", "a", id="bad-binary"),
]

PROFILE_KEY_ERRORS = [
    pytest.param(
        "314159: ignored\n",
        "unknown profile key",
        "314159",
        id="root",
    ),
    pytest.param(
        "314159: ignored\nunrecognised: ignored\n",
        "unknown profile key",
        "314159",
        id="mixed",
    ),
    pytest.param(
        "rules:\n  314159: ignored\n",
        "unknown rules key",
        "314159",
        id="rules",
    ),
    pytest.param(
        "fail_on:\n  314159: ignored\n",
        "unknown fail_on key",
        "314159",
        id="fail-on",
    ),
    pytest.param(
        "budgets:\n  314159: ignored\n",
        "unknown budgets key",
        "314159",
        id="budgets",
    ),
    pytest.param(
        "privacy:\n  314159: ignored\n",
        "unknown privacy key",
        "314159",
        id="privacy",
    ),
    pytest.param(
        "trace:\n  314159: ignored\n",
        "unknown trace key",
        "314159",
        id="trace",
    ),
    pytest.param(
        "plugins:\n  314159: ignored\n",
        "unknown plugins key",
        "314159",
        id="plugins",
    ),
    pytest.param(
        "delivery:\n  314159: ignored\n",
        "unknown delivery key",
        "314159",
        id="delivery",
    ),
    pytest.param(
        "evaluators:\n  314159: ignored\n",
        "unknown evaluators block",
        "314159",
        id="evaluators",
    ),
    pytest.param(
        "evaluators:\n  llm_judge:\n    314159: ignored\n",
        "unknown evaluators.llm_judge key",
        "314159",
        id="judge",
    ),
    pytest.param(
        "evaluators:\n  guard:\n    314159: ignored\n",
        "unknown evaluators.guard key",
        "314159",
        id="guard",
    ),
]

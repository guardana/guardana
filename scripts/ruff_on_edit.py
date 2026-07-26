"""Auto-format the Python file an agent just edited.

Holds AI contributors to the same style standard as everyone else.

Claude Code calls this after any Edit/Write. It reads the tool payload on stdin
and runs `ruff check --fix` + `ruff format` on a Python file inside this repo.
This is a convenience — it removes the excuse for style drift — not a gate:
`--fix` only applies auto-fixable rules, and this hook never reports the rest
back. The real gates are CI and the pre-commit hooks (mypy, tests, the full
ruff rule set). It never blocks the edit: on any trouble it just exits 0.

Registered in `.claude/settings.json`, which is checked in so every agent working
here gets it. The hook lives in `scripts/` rather than beside that file because
`mypy --strict .` skips dot-directories: a checked-in script the gate cannot see
is exactly the kind of unverified corner this project refuses elsewhere.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_RUFF_TIMEOUT_SECONDS = 30


def _edited_python_file(payload: dict[str, object]) -> Path | None:
    tool_input = payload.get("tool_input")
    tool_response = payload.get("tool_response")
    candidates = [
        tool_response.get("filePath") if isinstance(tool_response, dict) else None,
        tool_input.get("file_path") if isinstance(tool_input, dict) else None,
    ]
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        # Resolve up front so the containment check and the command operate on
        # the same absolute path (no relative-path check-vs-use mismatch).
        path = Path(candidate).resolve()
        if path.suffix != ".py" or not path.is_file():
            continue
        try:
            path.relative_to(REPO_ROOT)
        except ValueError:
            continue  # outside the repo: not ours to reformat
        return path
    return None


def main() -> int:
    """Format the file the tool just wrote. Never blocks the edit — always exits 0."""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not isinstance(payload, dict):
        return 0

    path = _edited_python_file(payload)
    if path is None:
        return 0

    for command in (
        ["uv", "run", "ruff", "check", "--fix", "--quiet", str(path)],
        ["uv", "run", "ruff", "format", "--quiet", str(path)],
    ):
        try:
            subprocess.run(  # noqa: S603
                command,
                cwd=REPO_ROOT,
                capture_output=True,
                check=False,
                timeout=_RUFF_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError):
            # uv not on PATH, or ruff hung: the gates will still catch style
            # issues, so a formatting convenience must never fail the edit.
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

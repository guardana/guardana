"""Command output printed in the README, the docs and the landing page is reproduced here.

A transcript is a claim about what the reader sees when they type the command, so each one
either runs here against the same input or is not published.
"""

import html
import re
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

# Wide enough that no published line wraps, so each one is compared whole.
runner = CliRunner(env={"COLUMNS": "1000"})

_REPO = Path(__file__).resolve().parents[3]
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_ELIDED = "…"
_SAMPLE_SCAN = re.compile(
    r"```console\n\$ uv run guardana scan examples/vulnerable-model\n(.*?)```", re.DOTALL
)
_PLAN_BLOCK = re.compile(
    r"```bash\nguardana plan probe --url (\S+) --model (\S+)\n```\n\n```text\n(.*?)```",
    re.DOTALL,
)
_SITE_PLAN = re.compile(
    r'<span class="s">guardana plan probe --url (\S+) --model (\S+)( --profile guardana\.yaml)?'
    r"</span>\n(.*?)\n\n",
    re.DOTALL,
)
_SITE_COMMENT = re.compile(r'<span class="c">\s*(.*?)</span>')
_SITE_BUDGETS = re.compile(r'<span class="k">budgets</span>: (\{[^}]*\})')
# The landing page writes `…` for a URL and model the reader supplies.
_PLACEHOLDER_URL = "https://api.example.com/v1"
_PLACEHOLDER_MODEL = "support-bot"


def _normal(line: str) -> str:
    return " ".join(_ANSI.sub("", line).split())


def _printed(output: str) -> set[str]:
    return {_normal(line) for line in output.splitlines()}


def _not_printed(shown: list[str], output: str) -> list[str]:
    """The shown lines the command did not print, ignoring the `…` that marks an elision."""
    printed = _printed(output)
    return [line for line in shown if _normal(line) not in ("", _ELIDED, *printed)]


def test_the_readme_sample_scan_is_what_the_scan_prints(monkeypatch: pytest.MonkeyPatch) -> None:
    match = _SAMPLE_SCAN.search((_REPO / "README.md").read_text(encoding="utf-8"))
    assert match is not None, "README.md no longer shows the sample scan of the vulnerable model"
    monkeypatch.chdir(_REPO)

    result = runner.invoke(app, ["scan", "examples/vulnerable-model"])

    assert result.exit_code == ExitCode.POLICY_FAILED
    missing = _not_printed(match.group(1).splitlines(), result.output)
    assert not missing, "README.md shows lines the scan does not print:\n  " + "\n  ".join(missing)


def test_the_plan_page_estimate_is_what_plan_probe_prints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    match = _PLAN_BLOCK.search((_REPO / "docs" / "usage-plan.md").read_text(encoding="utf-8"))
    assert match is not None, "docs/usage-plan.md no longer shows a `plan probe` estimate"
    url, model, block = match.groups()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["plan", "probe", "--url", url, "--model", model])

    assert result.exit_code == ExitCode.OK
    missing = _not_printed(block.splitlines(), result.output)
    assert not missing, "docs/usage-plan.md shows lines plan probe does not print:\n  " + (
        "\n  ".join(missing)
    )


def test_every_landing_page_estimate_is_what_plan_probe_prints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = (_REPO / "site" / "index.html").read_text(encoding="utf-8")
    budgets = _SITE_BUDGETS.search(page)
    estimates = _SITE_PLAN.findall(page)
    assert budgets is not None, "site/index.html no longer shows the budgets the estimate uses"
    assert len(estimates) == 2, f"site/index.html shows {len(estimates)} `plan probe` estimates"
    (tmp_path / "guardana.yaml").write_text(f"budgets: {budgets.group(1)}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    for url, model, profile, block in estimates:
        command = [
            "plan",
            "probe",
            "--url",
            _PLACEHOLDER_URL if url == _ELIDED else url,
            "--model",
            _PLACEHOLDER_MODEL if model == _ELIDED else model,
        ]
        if profile:
            command += ["--profile", "guardana.yaml"]
        result = runner.invoke(app, command)

        assert result.exit_code == ExitCode.OK
        shown = [html.unescape(line) for line in _SITE_COMMENT.findall(block)]
        missing = _not_printed(shown, result.output)
        assert not missing, "site/index.html shows lines plan probe does not print:\n  " + (
            "\n  ".join(missing)
        )

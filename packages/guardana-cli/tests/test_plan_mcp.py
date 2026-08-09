"""Pricing an MCP probe, and the two things that pricing must never do.

`guardana plan` exists so nobody finds out what a run costs by running it. That
mattered little while an MCP probe was one handshake and a listing; the
authorization checks send around a dozen requests, which is exactly the number
somebody wants before pointing this at production.
"""

import re
from pathlib import Path

from guardana.cli.main import app
from guardana.core.target import McpServerTarget
from typer.testing import CliRunner

runner = CliRunner()
_SERVER = "https://93.184.215.14/mcp"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(output: str) -> str:
    """Strip colour and line wrapping so an assertion survives a narrower terminal.

    Typer renders an error inside a box sized to the terminal, so a message that
    reads on one line locally is wrapped across three in CI — and a substring
    assertion against the raw text passes on a laptop and fails on a runner. Found
    exactly that way.
    """
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def test_an_mcp_probe_is_priced() -> None:
    result = runner.invoke(app, ["plan", "probe", "--mcp", _SERVER])

    assert result.exit_code == 0, result.output
    assert "rule(s) would run" in plain(result.output)
    assert "No request was sent to produce this estimate." in plain(result.output)


def test_pricing_sends_nothing_at_all() -> None:
    # The claim the command prints in its own output, held by a test rather than by
    # the fact that nobody has noticed otherwise. A sender that is never called
    # cannot record a call.
    sent: list[str] = []

    def refuse(url: str, **_: object) -> None:
        sent.append(url)
        raise AssertionError("plan contacted the target")

    target = McpServerTarget(_SERVER, sender=refuse)  # type: ignore[arg-type]

    assert target.capabilities()
    assert sent == []


def test_an_stdio_server_is_refused_rather_than_started() -> None:
    # Working out what an stdio server would cost means running it, and running the
    # thing under examination is the one thing this command must not do — `probe
    # --allow-exec` is where that intent is stated out loud.
    result = runner.invoke(app, ["plan", "probe", "--mcp", "npx some-mcp-server"])

    assert result.exit_code != 0
    assert "starts nothing" in plain(result.output)
    assert "--allow-exec" in plain(result.output)


def test_the_ceiling_is_the_sum_of_what_each_rule_would_spend_alone() -> None:
    # Higher than any single run spends, because a plan cannot know which rule goes
    # first and buys the shared observation. Wrong in the safe direction: an upper
    # bound that is too high refuses a budget that would have fitted.
    result = runner.invoke(app, ["plan", "probe", "--mcp", _SERVER])

    ceiling = re.search(r"at most (\d+)", plain(result.output))
    assert ceiling is not None, result.output
    assert int(ceiling.group(1)) > 10, "the MCP rules are not being priced at all"


def test_a_ceiling_that_does_not_fit_the_budget_refuses_before_anything_is_spent(
    tmp_path: Path,
) -> None:
    # The point of pricing an MCP probe: a team whose `guardana.yaml` allows three
    # requests finds out here rather than from a run that exits 6 half way through.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("budgets:\n  max_requests: 3\n", encoding="utf-8")

    result = runner.invoke(app, ["plan", "probe", "--mcp", _SERVER, "--profile", str(profile)])

    assert result.exit_code != 0
    assert "would stop early" in plain(result.output)


def test_naming_neither_an_endpoint_nor_a_server_is_refused() -> None:
    for command in (["plan", "probe"], ["probe"]):
        result = runner.invoke(app, command)

        assert result.exit_code != 0
        assert "--mcp for an MCP server" in plain(result.output), command

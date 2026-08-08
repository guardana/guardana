from pathlib import Path
from typing import Annotated

import typer
from guardana.cli.exit_codes import ExitCode

_ENDPOINT_TEMPLATE = """\
id: {id}
title: "TODO: one-line description of what this checks"
severity: high
target_kind: endpoint
# A reference names its edition where the framework publishes them: a bare `LLM01`
# means one control in the 2025 edition and another in the 2026 one, so it is a
# load-time error rather than a guess. `guardana taxonomy` lists what is installed.
taxonomy: [LLM01:2025, LLM01:2026]
evaluator: {evaluator}
requires: [{requires}]
prompts:
  - "TODO: your probe/attack prompt here"
expect:
{expect}
"""

_GOAL_EXPECT = '  goal: "TODO: describe what a compromised model would do that this detects"'
_CANARY_EXPECT = '  canary: "TODO: placeholder — guardana probe plants a random token at run time"'


def new_rule(
    id: Annotated[str, typer.Argument(help="Rule id, e.g. acme.prompt.demo")],
    evaluator: Annotated[
        str, typer.Option(help="Evaluator to grade responses: keyword|canary")
    ] = "keyword",
    dir: Annotated[Path, typer.Option(help="Directory to write the rule into")] = Path(
        "guardana-rules"
    ),
) -> None:
    """Scaffold a ready-to-edit endpoint YAML rule (the no-code path for --rules)."""
    if evaluator not in ("keyword", "canary"):
        typer.echo(f"error: unknown evaluator {evaluator!r}; use 'keyword' or 'canary'", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)

    name = id.rsplit(".", 1)[-1]
    path = dir / f"{name}.yaml"
    if path.exists():
        typer.echo(f"error: {path} already exists; refusing to overwrite.", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)

    requires = "chat, plant_system_prompt" if evaluator == "canary" else "chat"
    expect = _CANARY_EXPECT if evaluator == "canary" else _GOAL_EXPECT

    dir.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _ENDPOINT_TEMPLATE.format(id=id, evaluator=evaluator, requires=requires, expect=expect)
    )

    typer.echo(f"Wrote {path}")
    # The scaffold is an endpoint rule; `scan` only runs artifact rules, so
    # sending the author there would show them nothing and teach them their
    # new rule is broken.
    typer.echo(f"Run it: guardana probe --url <endpoint> --model <model> --rules {dir}")
    typer.echo(
        "See docs/writing-rules.md for the full schema, "
        "and examples/custom_rule/ for Python-plugin/artifact rules."
    )

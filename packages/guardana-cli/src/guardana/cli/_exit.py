"""Turn a run into an exit status. One place, so every command says the same thing."""

import typer
from guardana.cli.exit_codes import ExitCode, code_for
from guardana.core.budget import BudgetExhausted
from guardana.core.gate import GateOutcome
from guardana.core.report import ScanResult


def exit_with(outcome: GateOutcome, result: ScanResult) -> None:
    """End the command with the code this run earned, and never with `0` unless it passed.

    The stop reason is passed through rather than folded into the verdict: a run
    the budget cut short exits `6` whatever its partial findings say, so lowering
    a budget can never turn a red gate into a quieter one.
    """
    code = code_for(outcome, result.stopped_by)
    if code is not ExitCode.OK:
        raise typer.Exit(code=code)


def refuse_unenforceable_budget(exc: BudgetExhausted) -> typer.Exit:
    """Report a budget that could never be enforced as bad configuration.

    Reached only from `Target.apply_budgets`, which runs before any rule — a
    ceiling exhausted *during* a run is recorded on the result instead. So this is
    always "you asked for a ceiling nothing here can hold", which is a `3` and not
    a security verdict.
    """
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(code=ExitCode.INVALID_USAGE)

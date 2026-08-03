"""`guardana-collector` — the command an operator runs, including when it goes wrong.

Exit codes match the CLI's table, because one product with two tables is a product
whose exit status means nothing. `0` did what was asked, `1` the database said no,
`3` the command was pointed at nothing.
"""

import psycopg
import pytest
from guardana.server.cli import EXIT_FAILED, EXIT_INVALID_USAGE, EXIT_OK, main
from guardana.server.db.migrations import read_state


def test_migrate_applies_the_schema(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    assert main(["migrate"]) == EXIT_OK

    assert "applied  0001" in capsys.readouterr().out
    with psycopg.connect(database_url) as connection:
        assert read_state(connection).is_current


def test_migrating_a_current_database_says_so_and_succeeds(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["migrate"]) == EXIT_OK
    assert "already current" in capsys.readouterr().out


def test_status_reports_pending_before_and_applied_after(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    main(["status"])
    before = capsys.readouterr().out
    main(["migrate"])
    capsys.readouterr()
    main(["status"])
    after = capsys.readouterr().out

    assert "pending  0001" in before
    assert "applied  0001" in after


def test_rollback_undoes_the_last_migration(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["rollback"]) == EXIT_OK

    assert "rolled back" in capsys.readouterr().out
    with psycopg.connect(database_url) as connection:
        assert read_state(connection).applied == ()


def test_rolling_back_an_unmigrated_database_says_nothing_to_do(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    assert main(["rollback"]) == EXIT_OK
    assert "nothing to roll back" in capsys.readouterr().out


def test_no_database_url_is_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.delenv("GUARDANA_STORAGE", raising=False)

    assert main(["status"]) == EXIT_INVALID_USAGE


def test_the_memory_store_has_no_schema_to_migrate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Told plainly rather than failing to connect to nothing: `GUARDANA_STORAGE=memory`
    # is a valid configuration for the server and a meaningless one for this command.
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")

    assert main(["migrate"]) == EXIT_INVALID_USAGE


def test_an_unreachable_database_is_a_failure_not_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The distinction the exit-code table exists for: the command was right and the
    # environment was not.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", "postgresql://nobody@127.0.0.1:1/nothing")

    assert main(["status"]) == EXIT_FAILED

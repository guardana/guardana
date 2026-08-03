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
        state = read_state(connection)
    # One step, so the newest is gone and everything before it stayed. Asserted as
    # a relationship rather than as "empty": the moment a second migration shipped,
    # an emptiness assertion would have been testing the migration count.
    assert len(state.pending) == 1
    assert state.applied


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


def test_key_create_prints_the_key_once(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["key", "create", "--name", "github-actions"]) == EXIT_OK

    printed = capsys.readouterr().out
    assert "gdn_" in printed
    assert "only time it is shown" in printed


def test_a_created_key_never_appears_again(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """There is no command that returns a key after it is created.

    A credential a system can re-read is a credential that leaks through every
    path that reads it.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()
    main(["key", "create", "--name", "ci"])
    token = next(word for word in capsys.readouterr().out.split() if word.startswith("gdn_"))

    main(["key", "list"])

    assert token not in capsys.readouterr().out


def test_key_create_defaults_to_ingest_only(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A CI job writes and does not browse, so the default credential cannot read
    # every finding an organisation has ever recorded.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    main(["key", "create", "--name", "ci"])
    capsys.readouterr()

    main(["key", "list"])

    listed = capsys.readouterr().out
    assert "ingest" in listed
    assert "read" not in listed


def test_key_list_on_a_fresh_collector_says_nothing_can_write(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    main(["key", "list"])

    assert "nothing can write to this collector" in capsys.readouterr().out


def test_key_revoke_names_a_key_that_does_not_exist(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])

    assert main(["key", "revoke", "deadbeef"]) == EXIT_INVALID_USAGE


def test_key_revoke_marks_it_revoked_in_the_listing(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    main(["key", "create", "--name", "ci"])
    token = next(word for word in capsys.readouterr().out.split() if word.startswith("gdn_"))
    prefix = token.split("_")[1]

    assert main(["key", "revoke", prefix]) == EXIT_OK

    capsys.readouterr()
    main(["key", "list"])
    assert "revoked" in capsys.readouterr().out

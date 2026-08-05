"""`guardana-collector serve`: the one command that starts the collector.

Running it used to mean knowing an ASGI factory string
(`uvicorn 'guardana.server:create_app' --factory`), which is fine in a runbook and
wrong in a container image, a systemd unit and a first evaluation. The command
exists so that starting the collector is the same shape as migrating it.

What it must not do is fail like a library: a missing optional dependency, a
storage backend nobody chose, and a collector that could authenticate nobody are
all answers, in words, with a code from the collector's three-code table.
"""

import sys
import types

import pytest
from guardana.server.cli.codes import EXIT_INVALID_USAGE, EXIT_OK
from guardana.server.cli.main import main


class _FakeUvicorn(types.ModuleType):
    """A stand-in for uvicorn that records the call instead of binding a socket."""

    def __init__(self) -> None:
        super().__init__("uvicorn")
        self.calls: list[dict[str, object]] = []

    def run(self, app: object, **kwargs: object) -> None:
        self.calls.append({"app": app, **kwargs})


@pytest.fixture
def uvicorn(monkeypatch: pytest.MonkeyPatch) -> _FakeUvicorn:
    fake = _FakeUvicorn()
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    return fake


@pytest.fixture(autouse=True)
def _no_inherited_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """The developer's exported collector settings are not this test's input."""
    for variable in (
        "GUARDANA_DATABASE_URL",
        "GUARDANA_STORAGE",
        "GUARDANA_ALLOW_UNAUTHENTICATED",
        "GUARDANA_DASHBOARD",
    ):
        monkeypatch.delenv(variable, raising=False)


def test_serve_starts_the_app_on_the_loopback_by_default(
    uvicorn: _FakeUvicorn, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Binding every interface is a decision, so it is one you type."""
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")

    assert main(["serve"]) == EXIT_OK

    assert uvicorn.calls[0]["host"] == "127.0.0.1"
    assert uvicorn.calls[0]["port"] == 8000


def test_serve_honours_host_and_port(
    uvicorn: _FakeUvicorn, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")

    assert main(["serve", "--host", "0.0.0.0", "--port", "9000"]) == EXIT_OK  # noqa: S104

    assert uvicorn.calls[0]["host"] == "0.0.0.0"  # noqa: S104
    assert uvicorn.calls[0]["port"] == 9000


def test_serve_without_uvicorn_says_what_to_install(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The collector's dependency is FastAPI; the server that runs it is an extra."""
    monkeypatch.setitem(sys.modules, "uvicorn", None)
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")

    code = main(["serve"])

    assert code == EXIT_INVALID_USAGE
    message = capsys.readouterr().err
    assert "guardana-server[serve]" in message
    assert "Traceback" not in message


def test_serve_refuses_when_nobody_chose_a_store(
    uvicorn: _FakeUvicorn, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same refusal as every other command, and it never reaches the socket."""
    code = main(["serve"])

    assert code == EXIT_INVALID_USAGE
    assert "not told where to keep" in capsys.readouterr().err
    assert uvicorn.calls == []


def test_serve_refuses_a_collector_that_could_authenticate_nobody(
    uvicorn: _FakeUvicorn, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without a database there is nowhere to keep a key, so nothing may be served."""
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")

    code = main(["serve"])

    assert code == EXIT_INVALID_USAGE
    assert "GUARDANA_ALLOW_UNAUTHENTICATED" in capsys.readouterr().err
    assert uvicorn.calls == []


def test_serve_never_opens_a_database_connection_itself(
    uvicorn: _FakeUvicorn, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`serve` is the one command with no connection of its own to open.

    Every other command runs a statement and exits; this one hands the app to a
    server that manages its own connections. Dispatching it through the shared
    connect-then-call path would make a collector configured for PostgreSQL fail
    to start when the database is briefly unreachable.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")

    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError("serve opened a connection of its own")

    monkeypatch.setattr("psycopg.connect", refuse)

    assert main(["serve"]) == EXIT_OK
    assert uvicorn.calls

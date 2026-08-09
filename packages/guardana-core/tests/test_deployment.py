"""The production deployment, held to the properties a copied file loses first.

`deploy/docker-compose.yml` is what somebody runs to put a collector in front of
their pipelines. Three of its properties are load-bearing and all three are one
careless edit away from being gone, with nothing failing loudly when they are:

1. no credential has a default — Compose refuses to start rather than fall back
   to something guessable, the same rule the collector applies to its storage;
2. the database is not published — a self-hosted PostgreSQL on the internet is
   usually one `ports:` line nobody meant to keep;
3. migrations are a command, not a side effect of starting.

The rest of the deployment story is exercised rather than asserted: the guide's
commands were run against this file, and `docs/deployment.md` documents what came
back.
"""

import json
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[3]
_COMPOSE = _REPO / "deploy" / "docker-compose.yml"
_ENV_EXAMPLE = _REPO / "deploy" / "env.example"
_GUIDE = _REPO / "docs" / "deployment.md"
_SECRETS = ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB")
_WRANGLER = _REPO / "wrangler.jsonc"


@pytest.fixture(scope="module")
def compose() -> dict[str, object]:
    loaded = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _services(compose: dict[str, object]) -> dict[str, dict[str, object]]:
    services = compose["services"]
    assert isinstance(services, dict)
    return services


@pytest.mark.parametrize("secret", _SECRETS)
def test_no_credential_has_a_default(compose: dict[str, object], secret: str) -> None:
    """`${VAR:?}` refuses; `${VAR:-something}` invents. Only one of those is safe."""
    environment = _services(compose)["db"]["environment"]
    assert isinstance(environment, dict)

    value = str(environment[secret])
    assert value.startswith(f"${{{secret}:?"), f"{secret} falls back to {value!r}"


def test_the_example_environment_file_ships_no_password() -> None:
    """A file with a working password in it is a default credential with extra steps."""
    lines = [
        line
        for line in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line.startswith("POSTGRES_PASSWORD=")
    ]

    assert lines == ["POSTGRES_PASSWORD="], f"the example carries a password: {lines}"


def test_the_database_is_not_published(compose: dict[str, object]) -> None:
    """Nothing outside the Compose network needs 5432, and plenty out there wants it."""
    assert "ports" not in _services(compose)["db"]


def test_the_collector_publishes_on_loopback_only(compose: dict[str, object]) -> None:
    """Ingest carries API keys and evidence, so TLS termination is a deliberate step."""
    ports = _services(compose)["collector"]["ports"]
    assert isinstance(ports, list)

    for mapping in ports:
        assert str(mapping).startswith("127.0.0.1:"), (
            f"the collector is published on {mapping!r}, not on loopback"
        )


def test_migrating_is_a_command_and_not_a_service(compose: dict[str, object]) -> None:
    """A restart must not change the schema under a rolling deploy."""
    migrate = _services(compose)["migrate"]

    assert migrate["profiles"] == ["migrate"], "the migration would run on `up`"
    assert migrate["command"] == ["migrate"]
    assert "restart" not in migrate, "a one-shot command with a restart policy is a loop"


def test_the_collector_never_migrates_on_start(compose: dict[str, object]) -> None:
    """The variable exists; this deployment must not be the thing that sets it."""
    collector_environment = _services(compose)["collector"]["environment"]
    assert isinstance(collector_environment, dict)

    assert "GUARDANA_MIGRATE_ON_START" not in collector_environment


def test_the_guide_documents_the_file_it_ships() -> None:
    """A guide describing a different file is how a deployment goes wrong at 3am."""
    guide = _GUIDE.read_text(encoding="utf-8")

    for command in ("--profile migrate", "bootstrap --org", "/readyz", "pull"):
        assert command in guide, f"the deployment guide never mentions {command!r}"


def _wrangler() -> dict[str, object]:
    """Parse `wrangler.jsonc`, which is JSON with comments."""
    text = _WRANGLER.read_text(encoding="utf-8")
    stripped = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    loaded = json.loads(stripped)
    assert isinstance(loaded, dict)
    return loaded


def test_the_site_deployment_serves_the_directory_that_exists() -> None:
    """Rename `site/` and this fails, rather than the website 404ing after a push.

    The deployment is declared in the repository instead of in a dashboard so it
    can be reviewed and restored — which is only worth anything if something
    checks that it still points at a real page.
    """
    assets = _wrangler()["assets"]
    assert isinstance(assets, dict)

    served = (_REPO / str(assets["directory"])).resolve()

    assert (served / "index.html").is_file(), f"{served} has no page to serve"
    assert (served / "_headers").is_file(), "the security headers would not ship"


def test_the_maintainer_readme_is_not_published() -> None:
    """It was: `https://guardana.dev/README.md` served this repo's own runbook.

    Wrangler uploads everything in the assets directory, so a file put there for
    maintainers becomes a page. Found in the build log — "Uploaded 2 assets" for a
    site with one page — rather than by anybody visiting it.
    """
    text = (_REPO / "site" / ".assetsignore").read_text(encoding="utf-8")
    # The entries only. The comment above them explains the incident by quoting the
    # URL, so matching the whole file passed whether or not the rule was still
    # there — delete the entry and the prose alone kept the test green.
    entries = {
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    }

    assert "README.md" in entries, f"site/.assetsignore no longer ignores it: {sorted(entries)}"


def test_only_one_hostname_serves_the_page() -> None:
    """`workers.dev` is enabled on every deploy unless the config says otherwise."""
    config = _wrangler()

    assert config["workers_dev"] is False
    assert config["preview_urls"] is False


def test_the_deployment_runs_no_build_and_no_worker_script() -> None:
    """One HTML file, served as it is. A `main` here would mean code nobody reviewed."""
    config = _wrangler()

    assert "main" not in config
    assert config["name"] == "guardana"

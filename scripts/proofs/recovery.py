"""#143: the collector's recovery runbooks, run as written against the published artifacts.

Migrations (`docs/usage-collector.md` "Migrations" and "Applying migrations"):
`guardana-server[serve]` at the previous release and at `version`, each from PyPI into its
own venv, against a throwaway `postgres:16-alpine` published on loopback. Backups
(`docs/deployment.md` "Standing one up" and "Backups, and restoring one"): `deploy/` copied
into `work`, the collector image pinned to `version`, and the page's two blocks read at run
time and run as written, with only the dump named. Every tenant's data is a synthetic
envelope built here and read back over HTTP with the keys `bootstrap` printed; keys and
passwords never reach the record.

Reads the checkout and never writes there; writes `work` (venvs, the deployment copy,
dumps, server logs) and the record. Needs Docker with compose v2, the network for PyPI and
the image pulls, and nothing listening on 127.0.0.1:8000, the address the page's commands
name. Removes its containers and volumes whatever happens.
"""

import hashlib
import json
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from proofs.install import (
    INDEX,
    fetched_from_pip,
    fetched_problems,
    install_environment,
    is_pre_release,
)
from proofs.record import (
    Record,
    Step,
    clean_environment,
    environment_facts,
    excerpt,
    not_run,
    run,
    same_as_tag,
    venv_executable,
)

PROOF = "recovery"
POSTGRES = "postgres:16-alpine"
COLLECTOR = "ghcr.io/guardana/guardana-collector"
COMPOSE_PROJECT = "guardana-proof"
COMPOSE = "deploy/docker-compose.yml"
DOCS_PORT = 8000
DOCS_URL = f"http://127.0.0.1:{DOCS_PORT}"
SECTION = "Backups, and restoring one"
# The deployment files must be the ones the version shipped. The pages are not compared:
# they are what a reader follows today, so a correction made after the tag is what this
# proof exercises, and the record names the commit and each block's digest.
READ_FROM_CHECKOUT = ("deploy/docker-compose.yml", "deploy/env.example")
SOURCES = {"acme/web": "proof/acme-web", "globex/api": "proof/globex-api"}
SEVERITIES = {"acme/web": "HIGH", "globex/api": "MEDIUM"}
# The envelope usage-collector.md shows; an older release that refused it would fail the
# ingest steps rather than pass them.
ENVELOPE_VERSION = 8
TENANCY_MIGRATION = 3
WAIT_SECONDS = 90
NOT_OFFLINE = (
    "offline: this proof installs from PyPI, pulls images and talks to its own containers "
    "on loopback, so it makes no claim about running without a network"
)
RESTORE_NEEDS = ("pg_restore --list", "drop database", "pg_restore", "readyz")

_KEY = re.compile(r"\bgdn_[0-9a-f]+_[A-Za-z0-9_-]+")
_FENCE = re.compile(r"^```([^\n`]*)\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
_PIN = re.compile(
    r"^([ \t]*image:[ \t]*ghcr\.io/guardana/guardana-collector:)(\S+)[ \t]*$", re.MULTILINE
)
_BACKUP_LINE = re.compile(r"^BACKUP=.*$", re.MULTILINE)
_STATUS = re.compile(r"^(\d+) applied, (\d+) pending$", re.MULTILINE)
_APPLIED = re.compile(r"^\s*applied\s+(\d{4}) ", re.MULTILINE)
_READINESS = re.compile(r"\{[^{}]*\"status\"[^{}]*\}")
_DUMP_MAGIC = b"PGDMP"
_OK = 200
_UNAVAILABLE = 503

View = dict[str, Any]


# What the proof judges. Each is pure, so a test can hold it to both answers.


def backup_blocks(page: str) -> tuple[str, str]:
    """Return the take and restore blocks of "Backups, and restoring one", or refuse.

    The section must hold exactly two fenced blocks, both `bash`; the first takes the dump
    with `pg_dump`, the second checks, drops, restores and asks `/readyz`. Any other shape
    means the page changed in a way this proof would run blind.
    """
    heading = f"\n## {SECTION}\n"
    start = page.find(heading)
    if start < 0:
        raise ValueError(f'the page has no "## {SECTION}" section')
    end = page.find("\n## ", start + len(heading))
    section = page[start : end if end >= 0 else len(page)]
    fences = list(_FENCE.finditer(section))
    if sum(line.startswith("```") for line in section.splitlines()) != 2 * len(fences):
        raise ValueError(f'"{SECTION}" has a code block the proof cannot delimit')
    if len(fences) != 2:  # noqa: PLR2004 — the procedure is one take and one restore
        raise ValueError(f'"{SECTION}" has {len(fences)} code blocks; the procedure is 2')
    take, restore = fences
    for fence in fences:
        if fence.group(1).strip() != "bash":
            raise ValueError(f'a block in "{SECTION}" is {fence.group(1).strip() or "plain"!r}')
    if "pg_dump" not in take.group(2):
        raise ValueError(f'the first block of "{SECTION}" does not run pg_dump')
    missing = [needed for needed in RESTORE_NEEDS if needed not in restore.group(2)]
    if missing:
        raise ValueError(f'the second block of "{SECTION}" lacks {", ".join(missing)}')
    name_backup(restore.group(2), "check.dump")
    return take.group(2), restore.group(2)


def name_backup(block: str, dump: str) -> str:
    """Set the one `BACKUP=` line of the restore block to `dump`; nothing else changes."""
    found = _BACKUP_LINE.findall(block)
    if len(found) != 1:
        raise ValueError(f"the restore block has {len(found)} BACKUP= lines; expected 1")
    return _BACKUP_LINE.sub(lambda _: f"BACKUP={shlex.quote(dump)}", block)


def pin_image(compose: str, version: str) -> tuple[str, list[str]]:
    """Point both collector image lines at `version`; return the file and the tags replaced.

    A candidate is published under its exact version only, so the minor tag the file
    pins would run the last stable release instead of the one under proof.
    """
    found = _PIN.findall(compose)
    mentioned = compose.count("ghcr.io/guardana/guardana-collector:")
    if len(found) != 2 or mentioned != len(found):  # noqa: PLR2004 — collector and migrate
        raise ValueError(
            f"{COMPOSE} names the collector image {mentioned} time(s), {len(found)} as an "
            "`image:` line; expected the collector and migrate services"
        )
    return _PIN.sub(lambda m: f"{m.group(1)}{version}", compose), [tag for _, tag in found]


def fill_env(example: str, password: str) -> str:
    """Fill `POSTGRES_PASSWORD=` in a copy of `deploy/env.example`, refusing another shape."""
    lines = example.splitlines(keepends=True)
    blank = [i for i, line in enumerate(lines) if line.strip() == "POSTGRES_PASSWORD="]
    if len(blank) != 1:
        raise ValueError(f"env.example has {len(blank)} empty POSTGRES_PASSWORD= lines")
    if f"GUARDANA_PORT={DOCS_PORT}" not in {line.strip() for line in lines}:
        raise ValueError(f"env.example does not publish on {DOCS_PORT}, the port the page names")
    lines[blank[0]] = f"POSTGRES_PASSWORD={password}\n"
    return "".join(lines)


def issued_key(output: str) -> str:
    """Return the one key `bootstrap` printed; refuse output with none or several."""
    keys = {str(key) for key in _KEY.findall(output)}
    if len(keys) != 1:
        raise ValueError(f"bootstrap printed {len(keys)} keys; expected 1")
    return keys.pop()


def redact(text: str, hidden: Iterable[str]) -> str:
    """Remove every API key and every named secret from text bound for the record."""
    text = _KEY.sub("gdn_[redacted]", text)
    for secret in sorted(filter(None, hidden), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text


def migration_state(output: str) -> tuple[int, int, tuple[int, ...]]:
    """Read `N applied, M pending` and the applied versions from `status` output."""
    counted = _STATUS.search(output)
    if counted is None:
        raise ValueError("status printed no `N applied, M pending` line")
    applied = tuple(int(version) for version in _APPLIED.findall(output))
    if len(applied) != int(counted.group(1)):
        raise ValueError(f"status counts {counted.group(1)} applied but lists {len(applied)}")
    return int(counted.group(1)), int(counted.group(2)), applied


def published_port(output: str) -> int:
    """Return the loopback port `docker port` reports for the container's 5432."""
    for line in output.splitlines():
        host, _, port = line.strip().rpartition(":")
        if host in {"127.0.0.1", "0.0.0.0"} and port.isdigit():  # noqa: S104 — parsed, not bound
            return int(port)
    raise ValueError(f"docker port reported no published address: {output.strip()!r}")


def envelope(tenant: str, rule_id: str) -> dict[str, Any]:
    """Build a synthetic version-8 envelope with one finding, shaped like the docs' example."""
    severity = SEVERITIES[tenant]
    return {
        "schema_version": ENVELOPE_VERSION,
        "source": SOURCES[tenant],
        "findings": [
            {
                "rule_id": rule_id,
                "severity": severity,
                "title": "Synthetic finding",
                "target_ref": "app/settings.py:3",
                "evidence": {"summary": "a synthetic example"},
            }
        ],
        "unverified": [],
        "errors": [],
        "summary": {
            "rules_run": 1,
            "rules_executed": [rule_id],
            "rules_skipped": [],
            "max_severity": severity,
            "unverified": 0,
            "errors": 0,
        },
    }


def tenant_view(envelopes: Any, trend: Any) -> View:  # noqa: ANN401 — JSON the collector sent
    """Reduce what one key read to each finding's source, rule, severity and place, and trend."""
    if not isinstance(envelopes, list) or not isinstance(trend, dict):
        raise TypeError("GET /findings is not a list or GET /trend is not an object")
    if not all(isinstance(stored, dict) for stored in envelopes):
        raise TypeError("GET /findings holds something other than envelopes")
    findings = sorted(
        [
            str(stored.get("source")),
            str(finding.get("rule_id")),
            str(finding.get("severity")),
            str(finding.get("target_ref")),
        ]
        for stored in envelopes
        for finding in stored.get("findings", [])
    )
    return {"findings": findings, "trend": {str(k): trend[k] for k in sorted(trend)}}


def with_envelope(view: View, document: dict[str, Any]) -> View:
    """Return the view after `document` is stored: its findings added, the trend counted up."""
    findings = [list(row) for row in view["findings"]]
    trend = dict(view["trend"])
    for finding in document["findings"]:
        findings.append(
            [document["source"], finding["rule_id"], finding["severity"], finding["target_ref"]]
        )
        trend[finding["severity"]] = int(trend.get(finding["severity"], 0)) + 1
    return {"findings": sorted(findings), "trend": {k: trend[k] for k in sorted(trend)}}


def snapshot_problems(expected: dict[str, View], actual: dict[str, View]) -> list[str]:
    """Name every finding missing, added or counted differently, tenant by tenant."""
    problems: list[str] = []
    for tenant in sorted(expected.keys() | actual.keys()):
        want, got = expected.get(tenant), actual.get(tenant)
        if want is None or got is None:
            problems.append(f"{tenant}: {'not expected' if want is None else 'nothing read back'}")
            continue
        wanted = Counter(tuple(row) for row in want["findings"])
        found = Counter(tuple(row) for row in got["findings"])
        problems += [f"{tenant}: missing {list(row)}" for row in sorted(wanted - found)]
        problems += [f"{tenant}: not expected {list(row)}" for row in sorted(found - wanted)]
        if got["trend"] != want["trend"]:
            problems.append(f"{tenant}: trend {got['trend']}, expected {want['trend']}")
    return problems


def isolation_problems(views: dict[str, View], sources: dict[str, str]) -> list[str]:
    """Name every finding a key reads from another tenant's source, and a tenant reading none."""
    problems: list[str] = []
    for tenant, view in sorted(views.items()):
        seen = {row[0] for row in view["findings"]}
        problems += [
            f"{tenant} reads {source}, which is not its own"
            for source in sorted(seen - {sources[tenant]})
        ]
        if sources[tenant] not in seen:
            problems.append(f"{tenant} reads none of its own submissions")
    return problems


def readiness_problems(status: int | None, body: str, expected: int) -> list[str]:
    """Hold `/readyz` to usage-collector.md: 200 with a current PostgreSQL schema, or 503."""
    if status is None:
        return [f"/readyz did not answer: {body}"]
    if status != expected:
        return [f"/readyz answered {status}, expected {expected}: {body[:300]}"]
    if expected != _OK:
        return []
    try:
        document = json.loads(body)
    except ValueError:
        return [f"/readyz answered 200 without JSON: {body[:300]}"]
    if not isinstance(document, dict) or (
        document.get("status"),
        document.get("storage"),
        document.get("pending_migrations"),
    ) != ("ok", "postgres", 0):
        return [f"/readyz answered 200 but not ready on PostgreSQL: {body[:300]}"]
    return []


def printed_readiness(output: str) -> list[str]:
    """Check the restore block ended by printing a ready `/readyz` answer."""
    printed = _READINESS.findall(output)
    if not printed:
        return ["the restore printed no /readyz answer"]
    return readiness_problems(_OK, printed[-1], _OK)


def ingest_problems(status: int | None, body: str) -> list[str]:
    """Hold `POST /findings` to the collector's acknowledgement: stored, not a duplicate."""
    if status != _OK:
        return [f"POST /findings answered {status}: {body[:300]}"]
    try:
        document = json.loads(body)
    except ValueError:
        return [f"POST /findings answered without JSON: {body[:300]}"]
    if not isinstance(document, dict) or document.get("status") != "ok":
        return [f"POST /findings was not acknowledged: {body[:300]}"]
    if document.get("duplicate") is not False or not document.get("stored"):
        return [f"POST /findings stored nothing new: {body[:300]}"]
    return []


def installed_problems(document: dict[str, Any], version: str, venv: Path) -> list[str]:
    """Name every reason the installed `guardana-server` is not the published `version` here."""
    problems: list[str] = []
    if document.get("version") != version:
        problems.append(f"guardana-server is {document.get('version')}, not {version}")
    if document.get("direct_url") is not None:
        problems.append(f"guardana-server came from a direct URL or path: {document['direct_url']}")
    if not Path(str(document.get("location"))).resolve().is_relative_to(venv.resolve()):
        problems.append(f"guardana-server is outside {venv.name}: {document.get('location')}")
    return problems


def dump_problems(path: Path | None) -> list[str]:
    """Check the take block left one PostgreSQL custom-format dump behind."""
    if path is None:
        return ["the take block left no guardana-*.dump"]
    try:
        head = path.read_bytes()[: len(_DUMP_MAGIC)]
    except OSError as error:
        return [f"the dump cannot be read: {error}"]
    if head != _DUMP_MAGIC:
        return [f"{path.name} is not a pg_dump custom-format archive"]
    return []


def compose_problems(config: str) -> list[str]:
    """Refuse a Compose project other than the proof's own, before anything touches a volume."""
    try:
        document = json.loads(config)
    except ValueError:
        return ["docker compose config printed no JSON"]
    problems: list[str] = []
    if document.get("name") != COMPOSE_PROJECT:
        problems.append(f"the Compose project is {document.get('name')!r}, not {COMPOSE_PROJECT}")
    volumes = [str(v.get("name")) for v in document.get("volumes", {}).values()]
    problems += [
        f"volume {name} is outside the proof's project"
        for name in volumes
        if not name.startswith(f"{COMPOSE_PROJECT}_")
    ]
    return problems


# How the proof talks to what it runs.


def _http(
    method: str,
    url: str,
    *,
    token: str | None = None,
    document: Any = None,  # noqa: ANN401
) -> tuple[int | None, str]:
    """One request with no proxy; the status and body, or None and why there was none."""
    headers = {"Content-Type": "application/json"} if document is not None else {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = None if document is None else json.dumps(document).encode()
    # S310: the URL is a loopback address this proof started a collector on.
    request = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=15) as reply:
            return int(reply.status), reply.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return int(error.code), error.read().decode("utf-8", "replace")
    except (OSError, ValueError) as error:
        return None, f"{type(error).__name__}: {error}"


def _wait(ready: Callable[[], bool], alive: Callable[[], bool] = lambda: True) -> bool:
    """Poll `ready` until it holds, `alive` stops holding, or `WAIT_SECONDS` pass."""
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if ready():
            return True
        if not alive():
            return False
        time.sleep(0.5)
    return ready()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _refuses(port: int) -> str | None:
    """None when nothing accepts a connection on loopback `port`, otherwise what answered."""
    try:
        socket.create_connection(("127.0.0.1", port), timeout=3).close()
    except ConnectionRefusedError:
        return None
    except OSError as error:
        return f"{type(error).__name__}: {error}"
    return "a connection was accepted"


@dataclass
class _Server:
    process: "subprocess.Popen[bytes]"
    base: str
    log: Path


@dataclass
class _Proof:
    """The record being written, the secrets kept out of it, and what must be cleaned up."""

    record: Record
    work: Path
    hidden: set[str] = field(default_factory=set)
    servers: list[_Server] = field(default_factory=list)

    def add(self, step: Step) -> Step:
        """Append `step`, its excerpt and problems stripped of every secret."""
        step.excerpt = redact(step.excerpt, self.hidden)
        step.problems = [redact(problem, self.hidden) for problem in step.problems]
        self.record.steps.append(step)
        return step

    def command(  # noqa: PLR0913 — the step, the command and how to run it
        self,
        name: str,
        argv: list[str],
        *,
        expected: int | None,
        environment: dict[str, str],
        cwd: Path | None = None,
        shown: str | None = None,
        lines: tuple[str, ...] = (),
    ) -> tuple[Step, str]:
        """Run one command as a step; the output comes back unredacted for parsing only."""
        step = Step(name=name, command=shown or shlex.join(argv), expected_exit=expected)
        output = run(step, argv, cwd=cwd or self.work, environment=environment, expect_lines=lines)
        if output:
            step.excerpt = excerpt(redact(output, self.hidden))
        self.add(step)
        return step, output

    def check(self, name: str, command: str, problems: list[str], shown: str = "") -> Step:
        """Record a judgement the proof made itself, with no process behind it."""
        return self.add(Step(name=name, command=command, problems=problems, excerpt=shown))

    def ready(self, name: str, base: str, expected: int) -> Step:
        """Ask `/readyz` once and hold it to `expected`."""
        status, body = _http("GET", f"{base}/readyz")
        return self.check(
            name,
            f"GET {base}/readyz",
            readiness_problems(status, body, expected),
            f"{status} {body}",
        )

    def settle(self, name: str, base: str) -> Step:
        """Wait, bounded and outside any documented command, for `/healthz` to answer 200."""
        started = time.monotonic()
        answered = _wait(lambda: _http("GET", f"{base}/healthz")[0] == _OK)
        step = self.check(
            name,
            f"poll GET {base}/healthz for up to {WAIT_SECONDS} s",
            [] if answered else [f"/healthz did not answer 200 within {WAIT_SECONDS} s"],
        )
        step.seconds = round(time.monotonic() - started, 2)
        return step

    def ingest(self, name: str, base: str, key: str, document: dict[str, Any]) -> Step:
        """Post one synthetic envelope with `key` and hold the answer to an acknowledgement."""
        status, body = _http("POST", f"{base}/findings", token=key, document=document)
        return self.check(
            name,
            f"POST {base}/findings source={document['source']} "
            f"rule={document['findings'][0]['rule_id']}",
            ingest_problems(status, body),
            f"{status} {body}",
        )

    def read_back(
        self, name: str, base: str, keys: dict[str, str], expected: dict[str, View] | None
    ) -> tuple[Step, dict[str, View]]:
        """Read every tenant's findings and trend with its own key; hold them to `expected`."""
        views: dict[str, View] = {}
        problems: list[str] = []
        for tenant, key in sorted(keys.items()):
            listed, body = _http("GET", f"{base}/findings?limit=1000", token=key)
            counted, trend = _http("GET", f"{base}/trend", token=key)
            if listed != _OK or counted != _OK:
                problems.append(f"{tenant}: GET /findings {listed}, GET /trend {counted}")
                continue
            try:
                views[tenant] = tenant_view(json.loads(body), json.loads(trend))
            except (ValueError, TypeError) as error:
                problems.append(f"{tenant}: {error}")
        problems += isolation_problems(views, SOURCES)
        if expected is not None:
            problems += snapshot_problems(expected, views)
        step = self.check(
            name,
            f"GET {base}/findings and /trend with each tenant's own key",
            problems,
            json.dumps(views, sort_keys=True),
        )
        return step, views

    def serve(
        self, name: str, venv: Path, url: str, *, migrate_on_start: bool = False
    ) -> _Server | None:
        """Start `guardana-collector serve` on a free loopback port and wait for `/healthz`."""
        port = _free_port()
        environment = {**clean_environment(venv), "GUARDANA_DATABASE_URL": url}
        prefix = ""
        if migrate_on_start:
            environment["GUARDANA_MIGRATE_ON_START"] = "1"
            prefix = "GUARDANA_MIGRATE_ON_START=1 "
        argv = [str(venv_executable(venv, "guardana-collector")), "serve", "--port", str(port)]
        step = Step(name=name, command=f"{prefix}guardana-collector serve --port {port}")
        log = self.work / f"serve-{len(self.record.steps):02d}.log"
        started = time.monotonic()
        with log.open("wb") as handle:
            # S603: the venv's own console script with fixed arguments.
            process = subprocess.Popen(  # noqa: S603
                argv, cwd=self.work, env=environment, stdout=handle, stderr=subprocess.STDOUT
            )
        server = _Server(process, f"http://127.0.0.1:{port}", log)
        self.servers.append(server)
        answered = _wait(
            lambda: _http("GET", f"{server.base}/healthz")[0] == _OK,
            alive=lambda: process.poll() is None,
        )
        step.seconds = round(time.monotonic() - started, 2)
        if not answered:
            step.problems.append(
                f"no /healthz answer within {WAIT_SECONDS} s (exit {process.poll()})"
            )
            self.stop(server)
            step.excerpt = excerpt(log.read_text(encoding="utf-8", errors="replace"))
            self.add(step)
            return None
        self.add(step)
        return server

    def stop(self, server: _Server) -> int | None:
        """Stop a collector this proof started; None when it had to be killed."""
        if server in self.servers:
            self.servers.remove(server)
        if server.process.poll() is not None:
            return server.process.returncode
        server.process.terminate()
        try:
            return server.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            server.process.kill()
            server.process.wait()
            return None


def _image_digest(proof: _Proof, image: str) -> str | None:
    """Record the registry digest Docker resolved for `image`, so the record names the bytes."""
    step, output = proof.command(
        f"the digest of {image}",
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image],
        expected=0,
        environment=clean_environment(None),
    )
    try:
        digests = [str(d) for d in json.loads(output.strip() or "[]")]
    except ValueError:
        digests = []
    if step.held and not digests:
        step.problems.append(f"{image} has no registry digest: it was not pulled from a registry")
    digest = digests[0] if digests else None
    proof.record.environment.setdefault("images", {})[image] = digest
    return digest


# Part one: the migration commands, from PyPI.

_INSTALLED = (
    "import importlib.metadata as m, json; d = m.distribution('guardana-server'); "
    "print(json.dumps({'version': d.version, 'direct_url': d.read_text('direct_url.json'), "
    "'location': str(d.locate_file(''))}))"
)


def _install(proof: _Proof, version: str) -> Path | None:
    """Create a venv and install `guardana-server[serve]==version` from PyPI, with provenance."""
    venv = proof.work / f"venv-{version}"
    report = proof.work / f"pip-report-{version}.json"
    environment = install_environment()
    requirement = f"guardana-server[serve]=={version}"
    pre = ["--pre"] if is_pre_release(version) else []
    python = str(venv_executable(venv, "python"))
    for name, argv in (
        (f"create a venv for {version}", [sys.executable, "-m", "venv", str(venv)]),
        (f"install {requirement} from PyPI",
         [python, "-m", "pip", "install", "--index-url", INDEX, "--report", str(report),
          *pre, requirement]),
    ):  # fmt: skip
        step, _ = proof.command(name, argv, expected=0, environment=environment)
        if not step.held:
            return None
    fetched = fetched_from_pip(json.loads(report.read_text(encoding="utf-8")))
    proof.record.environment.setdefault("fetched", {})[version] = fetched
    step, output = proof.command(
        f"guardana-server {version} came from PyPI into its own venv",
        [python, "-I", "-c", _INSTALLED],
        expected=0,
        environment=clean_environment(venv),
        shown="python -I -c '<importlib.metadata of guardana-server>'",
    )
    step.problems += fetched_problems(fetched, ("guardana-server", "uvicorn"))
    if step.ran and step.exit_code == 0:
        document = json.loads(output.strip().splitlines()[-1])
        proof.record.environment.setdefault("installed", {})[version] = document
        step.problems += installed_problems(document, version, venv)
    return venv if step.held else None


@dataclass
class _Database:
    name: str
    password: str
    port: int = 0
    created: bool = False

    def url(self, database: str) -> str:
        return f"postgresql://guardana:{self.password}@127.0.0.1:{self.port}/{database}"


def _postgres(proof: _Proof, database: _Database) -> bool:
    """Start the throwaway PostgreSQL on a loopback port and create the two empty databases."""
    docker = clean_environment(None)
    pulled, _ = proof.command(
        f"pull {POSTGRES}", ["docker", "pull", POSTGRES], expected=0, environment=docker
    )
    if not pulled.held or _image_digest(proof, POSTGRES) is None:
        return False
    started, _ = proof.command(
        "start a throwaway PostgreSQL on loopback",
        ["docker", "run", "-d", "--name", database.name, "-e", "POSTGRES_USER=guardana",
         "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB=guardana", "-p", "127.0.0.1::5432",
         POSTGRES],
        expected=0,
        environment={**docker, "POSTGRES_PASSWORD": database.password},
    )  # fmt: skip
    database.created = started.exit_code == 0
    if not started.held:
        return False
    # Over TCP inside the container: the image's initialisation server listens only on
    # the socket, so a socket check answers before the real server is up.
    isready = ["docker", "exec", database.name, "pg_isready", "-h", "127.0.0.1", "-U", "guardana"]
    begun = time.monotonic()

    def accepting() -> bool:
        # S603: a fixed docker command naming the container this proof started.
        done = subprocess.run(isready, env=docker, capture_output=True, check=False)  # noqa: S603
        return done.returncode == 0

    accepted = _wait(accepting)
    proof.check(
        "PostgreSQL accepts connections",
        shlex.join(isready),
        [] if accepted else [f"pg_isready did not succeed within {WAIT_SECONDS} s"],
    ).seconds = round(time.monotonic() - begun, 2)
    if not accepted:
        return False
    port_step, output = proof.command(
        "the loopback port PostgreSQL is published on",
        ["docker", "port", database.name, "5432/tcp"],
        expected=0,
        environment=docker,
    )
    try:
        database.port = published_port(output)
    except ValueError as error:
        port_step.problems.append(str(error))
        return False
    created, _ = proof.command(
        "two more empty databases",
        ["docker", "exec", database.name, "psql", "-U", "guardana", "-d", "postgres",
         "-v", "ON_ERROR_STOP=1", "-c", "create database on_start",
         "-c", "create database not_migrated"],
        expected=0,
        environment=docker,
    )  # fmt: skip
    return created.held


@dataclass
class _Upgrade:
    """The two installs, the database and what the old release left in it."""

    old: Path
    new: Path
    old_version: str
    version: str
    database: _Database
    keys: dict[str, str] = field(default_factory=dict)
    views: dict[str, View] = field(default_factory=dict)

    def collector(self, venv: Path, database: str = "guardana") -> dict[str, str]:
        return {**clean_environment(venv), "GUARDANA_DATABASE_URL": self.database.url(database)}

    def cli(self, venv: Path) -> str:
        return str(venv_executable(venv, "guardana-collector"))


def _status(
    proof: _Proof, name: str, upgrade: _Upgrade, venv: Path
) -> tuple[int, int, tuple[int, ...]] | None:
    step, output = proof.command(
        name,
        [upgrade.cli(venv), "status"],
        expected=0,
        environment=upgrade.collector(venv),
        shown="guardana-collector status",
    )
    try:
        return migration_state(output)
    except ValueError as error:
        step.problems.append(str(error))
        return None


def _old_release(proof: _Proof, upgrade: _Upgrade) -> bool:
    """Exit 4 on nothing, then migrate, bootstrap two tenants and ingest on the old release."""
    old, label = upgrade.old, upgrade.old_version
    unreachable = f"postgresql://guardana:unreachable@127.0.0.1:{_free_port()}/guardana"
    proof.command(
        f"{upgrade.version}: status against an unreachable database exits 4",
        [upgrade.cli(upgrade.new), "status"],
        expected=4,
        environment={**clean_environment(upgrade.new), "GUARDANA_DATABASE_URL": unreachable},
        shown="guardana-collector status",
        lines=("could not reach the database",),
    )
    migrated, _ = proof.command(
        f"{label}: migrate",
        [upgrade.cli(old), "migrate"],
        expected=0,
        environment=upgrade.collector(old),
        shown="guardana-collector migrate",
    )
    state = _status(proof, f"{label}: status after migrate", upgrade, old)
    if state is not None and state[1]:
        proof.record.steps[-1].problems.append(f"{state[1]} migration(s) still pending")
    for tenant in SOURCES:
        org, project = tenant.split("/")
        step, output = proof.command(
            f"{label}: bootstrap {tenant}",
            [upgrade.cli(old), "bootstrap", "--org", org, "--project", project,
             "--scope", "ingest", "--scope", "read"],
            expected=0,
            environment=upgrade.collector(old),
            shown=f"guardana-collector bootstrap --org {org} --project {project} "
            "--scope ingest --scope read",
            lines=(f"created project {tenant}",),
        )  # fmt: skip
        try:
            upgrade.keys[tenant] = issued_key(output)
        except ValueError as error:
            step.problems.append(str(error))
    proof.hidden.update(upgrade.keys.values())
    if not migrated.held or len(upgrade.keys) != len(SOURCES):
        return False
    server = proof.serve(f"{label}: serve", old, upgrade.database.url("guardana"))
    if server is None:
        return False
    proof.ready(f"{label}: /readyz is 200 on a current schema", server.base, _OK)
    for tenant, key in upgrade.keys.items():
        proof.ingest(
            f"{label}: ingest for {tenant}",
            server.base,
            key,
            envelope(tenant, "proof.synthetic_check"),
        )
    read, upgrade.views = proof.read_back(
        f"{label}: each key reads its own tenant only", server.base, upgrade.keys, None
    )
    stopped = proof.stop(server)
    proof.check(
        f"stop the {label} collector before the schema changes",
        "SIGTERM",
        [] if stopped is not None else ["it did not stop within 20 s and was killed"],
        f"exit {stopped}",
    )
    return read.held and len(upgrade.views) == len(SOURCES)


def _upgrade_steps(proof: _Proof, upgrade: _Upgrade) -> bool:
    """Migrate to the new release, read the old data back, roll back and forward once."""
    new, label, url = upgrade.new, upgrade.version, upgrade.database.url("guardana")
    state = _status(proof, f"{label}: status before migrate shows what is pending", upgrade, new)
    if state is not None and not state[1]:
        proof.record.steps[-1].problems.append(
            f"nothing is pending between {upgrade.old_version} and {label}, so the upgrade "
            "exercises no migration"
        )
    pending = proof.serve(f"{label}: serve before migrate", new, url)
    if pending is not None:
        proof.ready(
            f"{label}: /readyz is 503 while a migration is pending", pending.base, _UNAVAILABLE
        )
        proof.stop(pending)
    migrated, output = proof.command(
        f"{label}: migrate",
        [upgrade.cli(new), "migrate"],
        expected=0,
        environment=upgrade.collector(new),
        shown="guardana-collector migrate",
    )
    applied = len(_APPLIED.findall(output))
    if state is not None and applied != state[1]:
        migrated.problems.append(
            f"applied {applied} migration(s); status showed {state[1]} pending"
        )
    after = _status(proof, f"{label}: status after migrate", upgrade, new)
    if after is not None and after[1]:
        proof.record.steps[-1].problems.append(f"{after[1]} migration(s) still pending")
    server = proof.serve(f"{label}: serve after migrate", new, url)
    if server is None:
        return False
    try:
        proof.ready(f"{label}: /readyz is 200 after migrate", server.base, _OK)
        proof.read_back(
            f"{label}: the {upgrade.old_version} data reads back with the same keys",
            server.base,
            upgrade.keys,
            upgrade.views,
        )
        tenant = "acme/web"
        added = envelope(tenant, "proof.after_upgrade")
        proof.ingest(
            f"{label}: ingest for {tenant} after the upgrade",
            server.base,
            upgrade.keys[tenant],
            added,
        )
        upgrade.views = {**upgrade.views, tenant: with_envelope(upgrade.views[tenant], added)}
        proof.read_back(
            f"{label}: the new submission reads back", server.base, upgrade.keys, upgrade.views
        )
        proof.command(
            f"{label}: rollback while the collector runs",
            [upgrade.cli(new), "rollback"],
            expected=0,
            environment=upgrade.collector(new),
            shown="guardana-collector rollback",
            lines=("rolled back",),
        )
        proof.ready(f"{label}: /readyz is 503 after a rollback", server.base, _UNAVAILABLE)
        proof.command(
            f"{label}: migrate again",
            [upgrade.cli(new), "migrate"],
            expected=0,
            environment=upgrade.collector(new),
            shown="guardana-collector migrate",
        )
        proof.ready(f"{label}: /readyz is 200 again", server.base, _OK)
    finally:
        proof.stop(server)
    return True


def _refused_rollback(proof: _Proof, upgrade: _Upgrade) -> None:
    """Roll back across 0003 on two tenants: refused, tenancy kept, nothing merged."""
    new, label = upgrade.new, upgrade.version
    state = _status(proof, f"{label}: status before rolling back across 0003", upgrade, new)
    if state is None or TENANCY_MIGRATION not in state[2]:
        proof.add(not_run("roll back across 0003", "guardana-collector rollback --steps N",
                          "the applied migrations are unknown or lack 0003"))  # fmt: skip
        return
    steps = sum(version >= TENANCY_MIGRATION for version in state[2])
    proof.command(
        f"{label}: rollback --steps {steps} across 0003 with two tenants is refused",
        [upgrade.cli(new), "rollback", "--steps", str(steps)],
        expected=1,
        environment=upgrade.collector(new),
        shown=f"guardana-collector rollback --steps {steps}",
        lines=("refusing to roll back tenancy",),
    )
    after = _status(proof, f"{label}: status after the refused rollback keeps 0003", upgrade, new)
    if after is not None and TENANCY_MIGRATION not in after[2]:
        proof.record.steps[-1].problems.append("0003 is no longer applied: tenancy was rolled back")
    proof.command(
        f"{label}: migrate after the refused rollback",
        [upgrade.cli(new), "migrate"],
        expected=0,
        environment=upgrade.collector(new),
        shown="guardana-collector migrate",
    )
    server = proof.serve(
        f"{label}: serve after the refused rollback", new, upgrade.database.url("guardana")
    )
    if server is not None:
        proof.ready(f"{label}: /readyz is 200", server.base, _OK)
        proof.read_back(
            f"{label}: no tenant's findings merged into another's",
            server.base,
            upgrade.keys,
            upgrade.views,
        )
        proof.stop(server)


def _on_start(proof: _Proof, upgrade: _Upgrade) -> None:
    """`GUARDANA_MIGRATE_ON_START=1` makes a fresh database ready; plain `serve` does not."""
    new, label = upgrade.new, upgrade.version
    for database, migrate, expected in (
        ("on_start", True, _OK),
        ("not_migrated", False, _UNAVAILABLE),
    ):
        how = "GUARDANA_MIGRATE_ON_START=1 serve" if migrate else "serve"
        server = proof.serve(
            f"{label}: {how} on an empty database",
            new,
            upgrade.database.url(database),
            migrate_on_start=migrate,
        )
        if server is not None:
            proof.ready(f"{label}: /readyz is {expected} after {how}", server.base, expected)
            proof.stop(server)


def _migrations(proof: _Proof, version: str, old_version: str) -> None:
    """Part one: the migration commands of usage-collector.md, old release to new."""
    old = _install(proof, old_version)
    new = _install(proof, version)
    if old is None or new is None:
        proof.add(not_run("the migration walk", "guardana-collector", "an install did not hold"))
        return
    database = _Database(f"{COMPOSE_PROJECT}-pg-{secrets.token_hex(4)}", secrets.token_hex(16))
    proof.hidden.add(database.password)
    upgrade = _Upgrade(old, new, old_version, version, database)
    try:
        if not _postgres(proof, database):
            proof.add(
                not_run("the migration walk", "guardana-collector", "PostgreSQL did not start")
            )
            return
        if not _old_release(proof, upgrade):
            proof.add(
                not_run(
                    "the upgrade",
                    "guardana-collector migrate",
                    f"the {old_version} steps did not hold",
                )
            )
            return
        if _upgrade_steps(proof, upgrade):
            _refused_rollback(proof, upgrade)
        else:
            proof.add(
                not_run(
                    "roll back across 0003",
                    "guardana-collector rollback --steps N",
                    f"the {version} collector did not serve after migrate",
                )
            )
        _on_start(proof, upgrade)
    finally:
        for server in list(proof.servers):
            proof.stop(server)
        if database.created:
            proof.command(
                "remove the throwaway PostgreSQL",
                ["docker", "rm", "-f", "-v", database.name],
                expected=0,
                environment=clean_environment(None),
            )


# Part two: the deployment, its backup and its restore, with the published image.


def _compose_environment() -> dict[str, str]:
    """Return the user's environment without anything that changes what Compose interpolates."""
    environment = {
        k: v
        for k, v in clean_environment(None).items()
        if not k.startswith(("COMPOSE_", "POSTGRES_"))
    }
    environment["COMPOSE_PROJECT_NAME"] = COMPOSE_PROJECT
    return environment


@dataclass
class _Deployment:
    """The copied deployment, the page's two blocks and the keys `bootstrap` printed."""

    root: Path
    take: str = ""
    restore: str = ""
    keys: dict[str, str] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=_compose_environment)

    def compose(
        self,
        proof: _Proof,
        name: str,
        args: list[str],
        *,
        expected: int | None = 0,
        lines: tuple[str, ...] = (),
    ) -> tuple[Step, str]:
        """Run `docker compose -f deploy/docker-compose.yml <args>` as the page writes it."""
        return proof.command(
            name,
            ["docker", "compose", "-f", COMPOSE, *args],
            expected=expected,
            environment=self.environment,
            cwd=self.root,
            lines=lines,
        )

    def bash(self, proof: _Proof, name: str, block: str, expected: int | None) -> tuple[Step, str]:
        """Run one of the page's blocks with `bash -c`, from the deployment's directory."""
        return proof.command(
            name,
            ["bash", "-c", block],
            expected=expected,
            environment=self.environment,
            cwd=self.root,
            shown=block,
        )


def _prepare(proof: _Proof, repository: Path, deployment: _Deployment, version: str) -> bool:
    """Copy `deploy/`, pin the image, fill `.env`, and refuse anything but a clean start."""
    target = deployment.root / "deploy"
    target.mkdir(parents=True, exist_ok=True)
    for name in ("docker-compose.yml", "env.example"):
        shutil.copy2(repository / "deploy" / name, target / name)
    compose = target / "docker-compose.yml"
    replaced: list[str] = []
    problems: list[str] = []
    try:
        pinned, replaced = pin_image(compose.read_text(encoding="utf-8"), version)
        compose.write_text(pinned, encoding="utf-8")
    except ValueError as error:
        problems.append(str(error))
    steps = [
        proof.check(
            f"pin the collector image to {version}, as a candidate carries only exact tags",
            f"edit {COMPOSE}: {COLLECTOR}:{'/'.join(sorted(set(replaced))) or '?'} -> "
            f"{COLLECTOR}:{version} on the collector and migrate lines",
            problems,
        )
    ]
    steps.append(
        proof.command(
            "copy the example environment",
            ["cp", "deploy/env.example", "deploy/.env"],
            expected=0,
            environment=deployment.environment,
            cwd=deployment.root,
        )[0]
    )
    password = secrets.token_hex(16)
    proof.hidden.add(password)
    env = target / ".env"
    try:
        env.write_text(fill_env(env.read_text(encoding="utf-8"), password), encoding="utf-8")
        problems = []
    except (OSError, ValueError) as error:
        problems = [str(error)]
    steps.append(
        proof.check(
            "fill POSTGRES_PASSWORD in deploy/.env with a generated value",
            "$EDITOR deploy/.env",
            problems,
        )
    )
    config, output = deployment.compose(
        proof,
        f"Compose runs as project {COMPOSE_PROJECT}, never a real deployment",
        ["--profile", "migrate", "config", "--format", "json"],
    )
    config.excerpt = ""
    if config.ran and config.exit_code == 0:
        config.problems += compose_problems(output)
    steps.append(config)
    volumes, listed = proof.command(
        "no volume is left from an earlier run",
        ["docker", "volume", "ls", "-q", "--filter", f"name={COMPOSE_PROJECT}_"],
        expected=0,
        environment=deployment.environment,
    )
    if listed.strip():
        volumes.problems.append(
            f"remove it first: COMPOSE_PROJECT_NAME={COMPOSE_PROJECT} docker compose down -v"
        )
    steps.append(volumes)
    answered = _refuses(DOCS_PORT)
    steps.append(
        proof.check(
            f"nothing answers on 127.0.0.1:{DOCS_PORT} before the deployment starts",
            f"connect 127.0.0.1:{DOCS_PORT}",
            [] if answered is None else [f"127.0.0.1:{DOCS_PORT} is in use: {answered}"],
        )
    )
    return all(step.held for step in steps)


def _blocks(proof: _Proof, repository: Path, deployment: _Deployment) -> bool:
    """Read the take and restore blocks from the page; refuse any other shape."""
    page = repository / "docs" / "deployment.md"
    try:
        deployment.take, deployment.restore = backup_blocks(page.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        problems, shown = [str(error)], ""
    else:
        problems = []
        shown = "\n".join(
            f"block {i} sha256 {hashlib.sha256(text.encode()).hexdigest()}"
            for i, text in ((1, deployment.take), (2, deployment.restore))
        )
    return proof.check(
        f'the two blocks of "{SECTION}"',
        f'read docs/deployment.md, section "{SECTION}"',
        problems,
        shown,
    ).held


def _stand_up(proof: _Proof, deployment: _Deployment, version: str) -> dict[str, View] | None:
    """Run the page's "Standing one up" commands, then send two tenants' data over HTTP.

    The commands are typed here, not read from the page: its block opens an editor on
    `deploy/.env`, and its `bootstrap` issues an ingest-only key, while reading the data
    back needs `--scope read` too.
    """
    pulled, _ = deployment.compose(
        proof, "pull the pinned images", ["--profile", "migrate", "pull"]
    )
    if not pulled.held:
        return None
    _image_digest(proof, f"{COLLECTOR}:{version}")
    _image_digest(proof, POSTGRES)
    migrated, _ = deployment.compose(
        proof, "migrate the schema", ["--profile", "migrate", "run", "--rm", "migrate"]
    )
    started, _ = deployment.compose(proof, "start the collector", ["up", "-d"])
    for tenant in SOURCES:
        org, project = tenant.split("/")
        step, output = deployment.compose(
            proof,
            f"bootstrap {tenant}, with the read scope the page's one-key example leaves out",
            ["run", "--rm", "collector", "bootstrap", "--org", org, "--project", project,
             "--scope", "ingest", "--scope", "read"],
            lines=(f"created project {tenant}",),
        )  # fmt: skip
        try:
            deployment.keys[tenant] = issued_key(output)
        except ValueError as error:
            step.problems.append(str(error))
    proof.hidden.update(deployment.keys.values())
    for path in ("healthz", "readyz"):
        proof.command(
            f"check /{path} as the page does",
            ["curl", "-fsS", f"{DOCS_URL}/{path}"],
            expected=0,
            environment=deployment.environment,
        )
    if not (migrated.held and started.held) or len(deployment.keys) != len(SOURCES):
        return None
    proof.settle("wait for the collector before sending data", DOCS_URL)
    for tenant, key in deployment.keys.items():
        proof.ingest(
            f"ingest for {tenant}", DOCS_URL, key, envelope(tenant, "proof.synthetic_check")
        )
    read, views = proof.read_back(
        "each key reads its own tenant only", DOCS_URL, deployment.keys, None
    )
    return views if read.held and len(views) == len(SOURCES) else None


def _take(
    proof: _Proof, deployment: _Deployment, before: dict[str, View]
) -> tuple[str, dict[str, View]] | None:
    """Run the take block, then write a sentinel the restore has to remove."""
    existing = set(deployment.root.glob("guardana-*.dump"))
    took, _ = deployment.bash(
        proof, "take a backup with the page's first block", deployment.take, 0
    )
    made = sorted(set(deployment.root.glob("guardana-*.dump")) - existing)
    dump = made[0] if len(made) == 1 else None
    took.problems += dump_problems(dump)
    if len(made) > 1:
        took.problems.append(f"the take block left {len(made)} dumps: {[p.name for p in made]}")
    if not took.held or dump is None:
        return None
    tenant = "acme/web"
    sentinel = envelope(tenant, "proof.after_backup")
    proof.ingest(
        f"ingest a sentinel for {tenant} after the backup",
        DOCS_URL,
        deployment.keys[tenant],
        sentinel,
    )
    after = {**before, tenant: with_envelope(before[tenant], sentinel)}
    proof.read_back("the sentinel reads back before any restore", DOCS_URL, deployment.keys, after)
    return dump.name, after


def _restore(proof: _Proof, deployment: _Deployment, name: str, dump: str) -> Step:
    """Run the restore block with `BACKUP=` naming `dump`, the one edit the page asks for."""
    step, output = deployment.bash(proof, name, name_backup(deployment.restore, dump), 0)
    step.problems += printed_readiness(output)
    return step


def _restores(
    proof: _Proof,
    deployment: _Deployment,
    dump: str,
    before: dict[str, View],
    after: dict[str, View],
) -> None:
    """Restore an unreadable dump (nothing changes), then the real one in place and anew."""
    (deployment.root / "unreadable.dump").write_bytes(b"this is not a pg_dump archive\n")
    refused, _ = deployment.bash(
        proof,
        "an unreadable dump stops the restore before the drop",
        name_backup(deployment.restore, "unreadable.dump"),
        None,
    )
    if refused.ran and refused.exit_code == 0:
        refused.problems.append("the restore of an unreadable dump exited 0")
    proof.ready("the collector still answers /readyz 200", DOCS_URL, _OK)
    proof.read_back("the data and the sentinel are still there", DOCS_URL, deployment.keys, after)

    _restore(proof, deployment, "restore the backup in place", dump)
    proof.settle("wait for the restored collector, outside the page's commands", DOCS_URL)
    proof.ready("/readyz is 200 after the restore", DOCS_URL, _OK)
    proof.read_back(
        "the restore replaced the data: the backup's findings, the sentinel gone",
        DOCS_URL,
        deployment.keys,
        before,
    )

    deployment.compose(proof, "a new machine: remove the deployment and its volume", ["down", "-v"])
    deployment.compose(proof, "a new machine: start on an empty volume", ["up", "-d"])
    proof.settle("wait for the new collector, outside the page's commands", DOCS_URL)
    proof.ready("an empty database is not ready", DOCS_URL, _UNAVAILABLE)
    _restore(proof, deployment, "restore the backup on the new machine", dump)
    proof.settle("wait for the restored collector, outside the page's commands", DOCS_URL)
    proof.ready("/readyz is 200 after the restore on the new machine", DOCS_URL, _OK)
    proof.read_back(
        "the new machine holds the backup's findings, read with the keys issued before",
        DOCS_URL,
        deployment.keys,
        before,
    )


def _backups(proof: _Proof, repository: Path, version: str) -> None:
    """Part two: stand up the Compose deployment, back it up and restore it twice."""
    deployment = _Deployment(proof.work / "deployment")
    if not _prepare(proof, repository, deployment, version) or not _blocks(
        proof, repository, deployment
    ):
        proof.add(not_run("the backup and restore walk", f"docker compose -f {COMPOSE}",
                          "the deployment could not be prepared"))  # fmt: skip
        return
    try:
        before = _stand_up(proof, deployment, version)
        taken = None if before is None else _take(proof, deployment, before)
        if before is None or taken is None:
            proof.add(not_run("restore the backup", "the page's second block",
                              "the deployment, its data or its backup did not hold"))  # fmt: skip
            return
        _restores(proof, deployment, taken[0], before, taken[1])
    finally:
        deployment.compose(
            proof,
            "remove the deployment and its volume",
            ["--profile", "migrate", "down", "-v", "--remove-orphans"],
        )


def recovery(
    *, version: str, old_version: str, repository: Path, work: Path, record_path: Path
) -> Record:
    """Run both runbooks against the published `version` and write the record."""
    work.mkdir(parents=True, exist_ok=True)
    record = Record(
        proof=PROOF,
        version=version,
        environment=environment_facts(
            old_version=old_version, compose_project=COMPOSE_PROJECT, collector=COLLECTOR
        ),
    )
    record.not_applicable.append(NOT_OFFLINE)
    proof = _Proof(record, work)
    try:
        proof.add(same_as_tag(repository, f"v{version}", READ_FROM_CHECKOUT))
        _migrations(proof, version, old_version)
        _backups(proof, repository, version)
    except Exception as error:
        # The record is written whatever happens; one that stopped early must not read as
        # passed on the steps it reached.
        record.steps.append(
            Step(name="the proof ran to its end", command=PROOF, problems=[f"stopped: {error!r}"])
        )
        raise
    finally:
        for server in list(proof.servers):
            proof.stop(server)
        record.write(record_path)
    return record

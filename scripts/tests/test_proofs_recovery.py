"""The recovery proof judges the runbooks it runs, and never reads a changed page as passed.

Every judgement the proof makes about the page, the deployment files, the collector's
answers and the data read back is a pure function; each is held here to both answers, so a
page that lost a block, a dump that never restored, or one tenant reading another's
findings is a problem in the record rather than a quiet pass.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from proofs import recovery
from proofs.record import Step

_ROOT = Path(__file__).resolve().parents[2]
_TAKE = """set -a; . deploy/.env; set +a
BACKUP="guardana-$(date -u +%Y-%m-%d).dump"
docker compose -f deploy/docker-compose.yml exec -T db \\
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom > "$BACKUP"
"""
_RESTORE = """set -a; . deploy/.env; set +a
BACKUP=guardana-2026-08-05.dump

docker compose -f deploy/docker-compose.yml exec -T db pg_restore --list < "$BACKUP" &&
docker compose -f deploy/docker-compose.yml exec -T db psql -c "drop database x" &&
docker compose -f deploy/docker-compose.yml exec -T db pg_restore -d x < "$BACKUP" &&
curl -fsS http://127.0.0.1:8000/readyz
"""
_KEY_A = "gdn_0123456789ab_Abc-def_GHI0123456789abcdefghijklmnopqrstuvwxyz"
_KEY_B = "gdn_ba9876543210_Zyx-wvu_TSR9876543210zyxwvutsrqponmlkjihgfedcba"
_READY = '{"status":"ok","storage":"postgres","pending_migrations":0}'


def _page(*blocks: str, heading: str = recovery.SECTION) -> str:
    fenced = "\n\n".join(f"```bash\n{block}```" for block in blocks)
    return f"# Deploying\n\n## {heading}\n\nTake one:\n\n{fenced}\n\n## Rotating an API key\n"


def _view(*rows: tuple[str, str, str], trend: dict[str, int] | None = None) -> dict[str, Any]:
    findings = sorted(
        [source, rule, severity, "app/settings.py:3"] for source, rule, severity in rows
    )
    return {"findings": findings, "trend": trend if trend is not None else {"HIGH": len(rows)}}


# The page's two blocks.


def test_the_published_page_has_the_two_blocks_the_proof_runs() -> None:
    page = (_ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")

    take, restore = recovery.backup_blocks(page)

    assert "pg_dump" in take
    assert "pg_restore" not in take
    assert all(needed in restore for needed in recovery.RESTORE_NEEDS)


def test_the_two_blocks_are_read_from_their_own_section_in_order() -> None:
    page = "```bash\npg_dump elsewhere\n```\n" + _page(_TAKE, _RESTORE)

    assert recovery.backup_blocks(page) == (_TAKE, _RESTORE)


@pytest.mark.parametrize(
    ("page", "refusal"),
    [
        (_page(_TAKE, _RESTORE, heading="Backups"), "no"),
        (_page(_TAKE), "1 code blocks"),
        (_page(_TAKE, _RESTORE, "echo three\n"), "3 code blocks"),
        (_page(_RESTORE, _TAKE), "does not run pg_dump|lacks"),
        (_page(_TAKE.replace("pg_dump", "dump_tool"), _RESTORE), "does not run pg_dump"),
        (_page(_TAKE, _RESTORE.replace("--list ", "")), "lacks pg_restore --list"),
        (_page(_TAKE, _RESTORE.replace("drop database", "dropdb")), "lacks drop database"),
        (_page(_TAKE, _RESTORE.replace("readyz", "healthz")), "lacks readyz"),
        (_page(_TAKE, _RESTORE.replace("BACKUP=g", "# BACKUP=g")), "0 BACKUP= lines"),
        (_page(_TAKE, _RESTORE).replace("```bash\nset", "```sh\nset", 1), "'sh'"),
        (_page(_TAKE, _RESTORE).replace("```\n\n## Rotating", "\n\n## Rotating"), "delimit"),
    ],
    ids=[
        "no-section",
        "one-block",
        "three-blocks",
        "swapped",
        "no-pg-dump",
        "no-list-check",
        "no-drop",
        "no-readyz",
        "no-backup-line",
        "not-bash",
        "unclosed",
    ],
)
def test_a_section_of_any_other_shape_is_refused(page: str, refusal: str) -> None:
    with pytest.raises(ValueError, match=refusal):
        recovery.backup_blocks(page)


def test_naming_the_backup_changes_only_the_backup_line() -> None:
    edited = recovery.name_backup(_RESTORE, "guardana-2026-10-23.dump")

    before, after = _RESTORE.splitlines(), edited.splitlines()
    changed = [(b, a) for b, a in zip(before, after, strict=True) if b != a]
    assert changed == [("BACKUP=guardana-2026-08-05.dump", "BACKUP=guardana-2026-10-23.dump")]


def test_a_dump_name_with_shell_characters_is_quoted() -> None:
    edited = recovery.name_backup(_RESTORE, "my dump;rm.dump")

    assert "BACKUP='my dump;rm.dump'\n" in edited


def test_a_restore_block_with_two_backup_lines_is_refused() -> None:
    with pytest.raises(ValueError, match="2 BACKUP= lines"):
        recovery.name_backup(_RESTORE + "BACKUP=other.dump\n", "x.dump")


# The deployment files.


def test_the_image_pin_moves_both_collector_lines_and_nothing_else() -> None:
    compose = (_ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")

    pinned, replaced = recovery.pin_image(compose, "1.0.0rc5")

    changed = [
        (b, a) for b, a in zip(compose.splitlines(), pinned.splitlines(), strict=True) if b != a
    ]
    assert len(changed) == 2
    assert all(a.strip() == f"image: {recovery.COLLECTOR}:1.0.0rc5" for _, a in changed)
    assert len(replaced) == 2


@pytest.mark.parametrize(
    "compose",
    [
        "services:\n  collector:\n    image: ghcr.io/guardana/guardana-collector:0.41\n",
        "services:\n  db:\n    image: postgres:16-alpine\n",
        (
            "x:\n  image: ghcr.io/guardana/guardana-collector:0.41\n"
            "y:\n  image: ghcr.io/guardana/guardana-collector:0.41\n"
            "# also ghcr.io/guardana/guardana-collector:0.41 in a comment\n"
        ),
    ],
    ids=["one-line", "no-pin", "a-third-mention"],
)
def test_a_compose_file_without_the_two_pins_is_refused(compose: str) -> None:
    with pytest.raises(ValueError, match="collector image"):
        recovery.pin_image(compose, "1.0.0rc5")


def test_the_example_environment_gets_only_the_password() -> None:
    example = (_ROOT / "deploy" / "env.example").read_text(encoding="utf-8")

    filled = recovery.fill_env(example, "abc123")

    assert "POSTGRES_PASSWORD=abc123\n" in filled
    assert filled.replace("POSTGRES_PASSWORD=abc123", "POSTGRES_PASSWORD=") == example


@pytest.mark.parametrize(
    "example",
    [
        "POSTGRES_PASSWORD=preset\nGUARDANA_PORT=8000\n",
        "POSTGRES_PASSWORD=\nGUARDANA_PORT=9000\n",
    ],
    ids=["password-already-set", "another-port"],
)
def test_an_example_environment_of_another_shape_is_refused(example: str) -> None:
    with pytest.raises(ValueError, match=r"env\.example"):
        recovery.fill_env(example, "abc123")


def test_only_the_proofs_own_compose_project_is_accepted() -> None:
    own = {"name": "guardana-proof", "volumes": {"d": {"name": "guardana-proof_guardana-data"}}}
    real = {"name": "guardana", "volumes": {"d": {"name": "guardana_guardana-data"}}}

    assert recovery.compose_problems(json.dumps(own)) == []
    assert recovery.compose_problems(json.dumps(real)) == [
        "the Compose project is 'guardana', not guardana-proof",
        "volume guardana_guardana-data is outside the proof's project",
    ]
    assert recovery.compose_problems("not json") == ["docker compose config printed no JSON"]


# Keys and secrets.


def test_the_key_bootstrap_prints_is_parsed() -> None:
    output = f"created organization acme\ncreated project acme/web\n\n{_KEY_A}\n\nStore it now"

    assert recovery.issued_key(output) == _KEY_A


@pytest.mark.parametrize(
    "output", ["created project acme/web\n", f"{_KEY_A}\n{_KEY_B}\n"], ids=["none", "two"]
)
def test_bootstrap_output_without_exactly_one_key_is_refused(output: str) -> None:
    with pytest.raises(ValueError, match="keys; expected 1"):
        recovery.issued_key(output)


def test_keys_and_secrets_never_reach_an_excerpt() -> None:
    text = f"{_KEY_A}\nStore it now\nurl postgresql://guardana:s3cret@db/guardana {_KEY_B}"

    redacted = recovery.redact(text, {"s3cret", ""})

    assert _KEY_A not in redacted
    assert _KEY_B not in redacted
    assert "s3cret" not in redacted
    assert redacted.count("gdn_[redacted]") == 2
    assert "Store it now" in redacted


# The migration commands.


def test_status_output_is_read_into_counts_and_versions() -> None:
    output = "3 applied, 1 pending\n  applied  0001 a\n  applied  0002 b\n  applied  0003 c\n"

    assert recovery.migration_state(output + "  pending  0004 d\n") == (3, 1, (1, 2, 3))


@pytest.mark.parametrize(
    "output",
    ["nothing here\n", "2 applied, 0 pending\n  applied  0001 a\n"],
    ids=["no-count", "count-and-list-disagree"],
)
def test_status_output_that_does_not_add_up_is_refused(output: str) -> None:
    with pytest.raises(ValueError, match="status"):
        recovery.migration_state(output)


def test_the_published_loopback_port_is_read_from_docker_port() -> None:
    assert recovery.published_port("127.0.0.1:55001\n") == 55001
    with pytest.raises(ValueError, match="no published address"):
        recovery.published_port("")


def test_an_installed_server_from_elsewhere_is_named(tmp_path: Path) -> None:
    inside = {"version": "1.0.0rc5", "direct_url": None, "location": str(tmp_path / "lib")}
    elsewhere = {"version": "1.0.0rc4", "direct_url": "{}", "location": "/elsewhere"}

    assert recovery.installed_problems(inside, "1.0.0rc5", tmp_path) == []
    assert len(recovery.installed_problems(elsewhere, "1.0.0rc5", tmp_path)) == 3


# What the collector answers.


@pytest.mark.parametrize(
    ("status", "body", "expected", "holds"),
    [
        (200, _READY, 200, True),
        (503, '{"detail":"1 migration(s) pending"}', 503, True),
        (503, '{"detail":"pending"}', 200, False),
        (200, _READY, 503, False),
        (200, '{"status":"ok","storage":"memory","pending_migrations":0}', 200, False),
        (200, "ready", 200, False),
        (None, "ConnectionRefusedError", 200, False),
        (None, "ConnectionRefusedError", 503, False),
    ],
    ids=[
        "ready",
        "pending",
        "pending-when-ready-expected",
        "ready-when-pending-expected",
        "memory-storage",
        "not-json",
        "no-answer",
        "no-answer-is-not-503",
    ],
)
def test_readiness_is_held_to_the_documented_answer(
    status: int | None, body: str, expected: int, holds: bool
) -> None:
    assert (recovery.readiness_problems(status, body, expected) == []) is holds


def test_the_restore_holds_only_when_it_printed_a_ready_answer() -> None:
    printed = _READY + " Container guardana-proof-collector-1  Starting\n"

    assert recovery.printed_readiness(printed) == []
    assert recovery.printed_readiness("curl: (56) Recv failure: Connection reset by peer\n") == [
        "the restore printed no /readyz answer"
    ]
    assert recovery.printed_readiness('{"status":"ok","storage":"memory"}') != []


@pytest.mark.parametrize(
    ("status", "body", "holds"),
    [
        (200, '{"status":"ok","stored":1,"duplicate":false}', True),
        (200, '{"status":"ok","stored":0,"duplicate":true}', False),
        (200, "<html>proxy</html>", False),
        (422, '{"detail":"off schema"}', False),
        (None, "ConnectionRefusedError", False),
        (500, '{"status":"ok","stored":1,"duplicate":false}', False),
    ],
    ids=["stored", "duplicate", "not-an-acknowledgement", "refused", "no-answer", "not-200"],
)
def test_an_ingest_holds_only_when_the_collector_stored_it(
    status: int | None, body: str, holds: bool
) -> None:
    assert (recovery.ingest_problems(status, body) == []) is holds


def test_a_dump_must_be_a_custom_format_archive(tmp_path: Path) -> None:
    good, bad = tmp_path / "good.dump", tmp_path / "bad.dump"
    good.write_bytes(b"PGDMP\x01\x0e")
    bad.write_bytes(b"-- plain SQL\n")

    assert recovery.dump_problems(good) == []
    assert recovery.dump_problems(bad) == ["bad.dump is not a pg_dump custom-format archive"]
    assert recovery.dump_problems(None) == ["the take block left no guardana-*.dump"]
    assert recovery.dump_problems(tmp_path / "missing.dump") != []


# The data read back.


def test_what_a_key_reads_is_reduced_to_findings_and_trend() -> None:
    stored = [recovery.envelope("acme/web", "proof.a"), recovery.envelope("acme/web", "proof.b")]

    view = recovery.tenant_view(stored, {"HIGH": 2})

    assert view == _view(
        ("proof/acme-web", "proof.a", "HIGH"), ("proof/acme-web", "proof.b", "HIGH")
    )
    with pytest.raises(TypeError):
        recovery.tenant_view({}, {})


def test_adding_an_envelope_adds_its_finding_and_counts_it() -> None:
    before = _view(("proof/acme-web", "proof.a", "HIGH"))

    after = recovery.with_envelope(before, recovery.envelope("acme/web", "proof.b"))

    assert after == _view(
        ("proof/acme-web", "proof.a", "HIGH"), ("proof/acme-web", "proof.b", "HIGH")
    )
    assert before == _view(("proof/acme-web", "proof.a", "HIGH"))


def test_an_identical_snapshot_holds() -> None:
    views = {"acme/web": _view(("proof/acme-web", "proof.a", "HIGH"))}

    assert recovery.snapshot_problems(views, json.loads(json.dumps(views))) == []


@pytest.mark.parametrize(
    ("actual", "problem"),
    [
        ({"acme/web": _view(trend={})}, "acme/web: missing"),
        (
            {
                "acme/web": _view(
                    ("proof/acme-web", "proof.a", "HIGH"), ("proof/acme-web", "proof.a", "HIGH")
                )
            },
            "acme/web: not expected",
        ),
        (
            {"acme/web": _view(("proof/acme-web", "proof.a", "HIGH"), trend={"HIGH": 2})},
            "acme/web: trend",
        ),
        ({}, "acme/web: nothing read back"),
        (
            {
                "acme/web": _view(("proof/acme-web", "proof.a", "HIGH")),
                "globex/api": _view(trend={}),
            },
            "globex/api: not expected",
        ),
    ],
    ids=["missing-finding", "counted-twice", "trend-changed", "tenant-missing", "extra-tenant"],
)
def test_a_snapshot_that_differs_is_a_problem(actual: dict[str, Any], problem: str) -> None:
    expected = {"acme/web": _view(("proof/acme-web", "proof.a", "HIGH"))}

    problems = recovery.snapshot_problems(expected, actual)

    assert any(p.startswith(problem) for p in problems), problems


def test_a_finding_stored_twice_and_read_back_once_is_missing() -> None:
    twice = ("proof/acme-web", "proof.a", "HIGH")
    expected = {"acme/web": _view(twice, twice)}
    actual = {"acme/web": _view(twice, trend={"HIGH": 2})}

    assert recovery.snapshot_problems(expected, actual) == [
        "acme/web: missing ['proof/acme-web', 'proof.a', 'HIGH', 'app/settings.py:3']"
    ]


def test_each_key_reading_only_its_own_source_holds() -> None:
    views = {
        "acme/web": _view(("proof/acme-web", "proof.a", "HIGH")),
        "globex/api": _view(("proof/globex-api", "proof.a", "MEDIUM")),
    }

    assert recovery.isolation_problems(views, recovery.SOURCES) == []


def test_a_key_reading_another_tenants_source_is_a_problem() -> None:
    views = {
        "acme/web": _view(
            ("proof/acme-web", "proof.a", "HIGH"), ("proof/globex-api", "proof.a", "MEDIUM")
        ),
        "globex/api": _view(trend={}),
    }

    assert recovery.isolation_problems(views, recovery.SOURCES) == [
        "acme/web reads proof/globex-api, which is not its own",
        "globex/api reads none of its own submissions",
    ]


def test_every_synthetic_envelope_carries_the_channels_the_collector_requires() -> None:
    document = recovery.envelope("globex/api", "proof.a")

    assert document["schema_version"] == recovery.ENVELOPE_VERSION
    assert {"findings", "unverified", "errors", "summary"} <= document.keys()
    assert document["summary"]["max_severity"] == document["findings"][0]["severity"] == "MEDIUM"


def test_the_record_says_the_proof_is_not_an_offline_claim() -> None:
    assert recovery.NOT_OFFLINE.startswith("offline:")


def test_a_proof_that_stops_early_writes_a_record_that_does_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def held(*_: object) -> Step:
        return Step(name="the checkout matches", command="git diff", expected_exit=0)

    def stops(*_: object) -> None:
        raise RuntimeError("docker went away")

    monkeypatch.setattr(recovery, "same_as_tag", held)
    monkeypatch.setattr(recovery, "_migrations", stops)
    written = tmp_path / "recovery.json"

    with pytest.raises(RuntimeError, match="docker went away"):
        recovery.recovery(
            version="1.0.0", old_version="0.41.0", repository=tmp_path, work=tmp_path / "w",
            record_path=written,
        )  # fmt: skip

    document = json.loads(written.read_text(encoding="utf-8"))
    assert document["verdict"] == "failed"
    assert document["steps"][-1]["problems"] == ["stopped: RuntimeError('docker went away')"]

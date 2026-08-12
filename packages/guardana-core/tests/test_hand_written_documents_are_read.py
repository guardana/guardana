"""Three documents Guardana only ever reads, and never writes.

A contract is a team's threat model, a pack manifest is an author's compatibility
declaration, and a generic observation file is another harness's output. Nothing in
Guardana produces any of them, so there is no serializer to compare a reader
against — which removes the first half of a round trip and leaves the half that
found the last two defects intact.

**A key whose deletion changes nothing is a key nothing reads**, and on a
hand-written document that is worse than on a generated one: the author typed it,
believed it took effect, and nothing anywhere says it did not. `provides:` in a pack
manifest is checked against what actually registers for exactly this reason; these
gates ask the same question of every other key in all three files.

The accepted keys are read off the loaders rather than listed here, so a key added
to one and forgotten in a fixture fails instead of going unexercised.
"""

import json
from pathlib import Path
from typing import Any

import yaml
from _roundtrip import Document, unread_keys
from guardana.core.contract.assertion import AssertionKind
from guardana.core.contract.errors import ContractError
from guardana.core.contract.load import (
    _ALLOWED_ASSERTION_KEYS,
    _ALLOWED_CONTRACT_KEYS,
    contract_from_dict,
)
from guardana.core.pack.load import _ALLOWED_KEYS, _ALLOWED_PROVIDES_KEYS, load_manifest
from guardana.core.pack.model import PACK_SCHEMA_VERSION, PackError
from guardana.core.trace._parse import TraceLoadError
from guardana.core.trace.observations import (
    OBSERVATIONS_SCHEMA_VERSION,
    OBSERVATIONS_VERSION_KEY,
    read_observations,
)

# --- a security contract ------------------------------------------------------


def _contract() -> Document:
    """A contract carrying every key the loader accepts, on every assertion kind."""
    return {
        "schema_version": 1,
        "name": "checkout",
        "applies_to": {"ai_system": "checkout-agent"},
        "assertions": [
            {
                "id": "one-tenant-per-run",
                "type": str(AssertionKind.TENANT_BOUNDARY),
                "title": "A checkout run serves exactly one customer",
                "severity": "critical",
                "sources": ["retrieval"],
            },
            {
                "id": "refunds-need-a-human",
                "type": str(AssertionKind.APPROVAL_REQUIRED),
                "title": "Money only moves after a person says so",
                "severity": "critical",
                "actions": ["payment.refund"],
                "sinks": ["payment"],
                "approvers": ["human:*"],
            },
            {
                "id": "payments-hop-moves-money-only",
                "type": str(AssertionKind.ALLOWED_SCOPES),
                "title": "The payments hop may move money and nothing else",
                # Not `high`: that is the loader's default for an omitted severity, so
                # a fixture stating it could not tell a read field from an unread one.
                "severity": "medium",
                "boundaries": ["https://pay.example/*"],
                "allow": ["payments.read"],
            },
            {
                "id": "no-credential-on-the-open-web",
                "type": str(AssertionKind.CREDENTIAL_BOUNDARY),
                "title": "Nothing we send to the public internet carries a credential",
                "severity": "critical",
                "boundaries": ["http://*"],
            },
            {
                "id": "no-shell-no-code",
                "type": str(AssertionKind.FORBIDDEN_SINK),
                "title": "A checkout agent has no business running code",
                "severity": "critical",
                "sinks": ["shell"],
                "actions": ["exec"],
                "statuses": ["executed"],
            },
        ],
    }


def test_the_contract_fixture_carries_every_key_the_loader_accepts() -> None:
    """Read off the loader, so a key added there and forgotten here fails rather than idles."""
    document: dict[str, Any] = dict(_contract())
    by_kind = {str(assertion["type"]): set(assertion) for assertion in document["assertions"]}

    missing = sorted(_ALLOWED_CONTRACT_KEYS - set(document)) + sorted(
        f"{kind}.{key}"
        for kind, allowed in _ALLOWED_ASSERTION_KEYS.items()
        for key in allowed - by_kind.get(str(kind), set())
    )

    assert not missing, (
        f"contract keys the loader accepts and this fixture never exercises: {missing}"
    )


def test_no_key_of_a_contract_can_be_deleted_without_the_loader_noticing() -> None:
    ignored = unread_keys(
        _contract(),
        lambda doc: contract_from_dict(doc, source="contract.yaml"),
        root="contract",
        refusal=ContractError,
    )

    assert not ignored, (
        "keys a hand-written contract carries that change nothing about the "
        "invariants it compiles to — the author typed them and nothing says they "
        "had no effect:\n  " + "\n  ".join(ignored)
    )


# --- a pack manifest ----------------------------------------------------------


def _pack() -> Document:
    """A manifest carrying every key the loader accepts."""
    return {
        "schema_version": PACK_SCHEMA_VERSION,
        "name": "acme-guardana-rules",
        "description": "Acme's private checks",
        "extension_api": ">=1,<2",
        "provides": {
            "rules": ["acme.agent.customer_data"],
            "evaluators": ["acme.strict_refusal"],
            "targets": ["acme.warehouse"],
            "taxonomies": ["ACME-CONTROLS"],
        },
    }


def test_the_pack_fixture_carries_every_key_the_loader_accepts() -> None:
    document: dict[str, Any] = dict(_pack())

    missing = sorted(_ALLOWED_KEYS - set(document)) + sorted(
        f"provides.{key}" for key in _ALLOWED_PROVIDES_KEYS - set(document["provides"])
    )

    assert not missing, (
        f"pack manifest keys the loader accepts and this fixture never uses: {missing}"
    )


def test_no_key_of_a_pack_manifest_can_be_deleted_without_the_loader_noticing(
    tmp_path: Path,
) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "guardana-pack.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        # `source` names the file the manifest came from, and the file is rewritten
        # per mutation. Dropped from the comparison so the temporary path cannot make
        # two otherwise-identical manifests differ.
        return dataclass_without_source(load_manifest(path))

    ignored = unread_keys(_pack(), read, root="pack", refusal=PackError)

    assert not ignored, (
        "keys a pack manifest carries that make no difference to the manifest that "
        "is read back:\n  " + "\n  ".join(ignored)
    )


def dataclass_without_source(manifest: object) -> tuple[object, ...]:
    """Everything about a manifest except where it was read from."""
    return tuple(
        getattr(manifest, name)
        for name in type(manifest).__dataclass_fields__  # type: ignore[attr-defined]
        if name != "source"
    )


# --- a generic observation document -------------------------------------------


def _observations() -> Document:
    """The documented shape an internal harness writes, with every field occupied."""
    return {
        OBSERVATIONS_VERSION_KEY: OBSERVATIONS_SCHEMA_VERSION,
        "producer": {
            "name": "acme-harness",
            "version": "2.4",
            "recorded_at": "2026-08-11T09:00:00Z",
        },
        "target": "http://model.invalid/v1",
        "observations": [
            {
                "id": "obs-1",
                "title": "the agent disclosed another tenant's order",
                "outcome": "failed",
                "severity": "HIGH",
                "category": "tenant-isolation",
                "detail": "order 5512 belongs to a different customer",
                # Deliberately not the document-level target above: a claim's own
                # target falls back to the document's, so two identical values could
                # not tell the fallback from the field being read.
                "target": "http://model.invalid/v1/chat",
            },
            {
                # No target of its own, so the document-level one above is what this
                # claim ends up carrying. Without a claim that needs the fallback, the
                # document-level key could be deleted with nothing changing — which is
                # indistinguishable from a key nobody reads.
                "id": "obs-2",
                "title": "the agent quoted its system prompt",
                "outcome": "errored",
                "severity": "MEDIUM",
                "category": "prompt-leak",
                "detail": "the harness could not reach the judge",
            },
        ],
    }


def test_no_key_of_an_observation_document_can_be_deleted_without_the_reader_noticing(
    tmp_path: Path,
) -> None:
    def read(document: Document) -> object:
        path = tmp_path / "observations.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        read_back = read_observations(path)
        provenance = read_back.provenance
        # Where the file was found and which dialect it turned out to be are answers
        # about the *reading*, re-derived per mutation. The producer's own identity is
        # not: a claim nobody can trace back to who made it is precisely what importing
        # one instead of retyping it was supposed to buy.
        return (
            read_back.observations,
            read_back.passed,
            read_back.unreadable,
            provenance.producer,
            provenance.producer_version,
            provenance.recorded_at,
        )

    ignored = unread_keys(_observations(), read, root="observations", refusal=TraceLoadError)

    assert not ignored, (
        "keys another tool's observation document carries that this reader ignores, "
        "so a claim arrives with less context than it was written with:\n  " + "\n  ".join(ignored)
    )

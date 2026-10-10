"""SECURITY-INSIGHTS.yml stays valid against the OpenSSF v2 spec essentials.

The spec's machine-readable schema is CUE (spec/schema.cue), which this
repository does not run; this test pins the fields the scanners and the
issue require (reporting process, release artifacts, contact) plus the
format rules the CUE schema enforces (semver, YYYY-MM-DD dates, URL and
email shapes), so drift fails loudly here instead of in a scanner.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
DOC = yaml.safe_load((_ROOT / "security-insights.yml").read_text(encoding="utf-8"))

_URL = re.compile(r"^https?://[^\s]+$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SEMVER = re.compile(r"^[1-9]+\.[0-9]+\.[0-9]+$")


def test_header_schema_version_and_url() -> None:
    assert _SEMVER.match(DOC["header"]["schema-version"])
    assert _DATE.match(DOC["header"]["last-updated"])
    assert DOC["header"]["url"].endswith("/security-insights.yml")


def test_vulnerability_reporting_matches_security_md() -> None:
    reporting = DOC["project"]["vulnerability-reporting"]
    assert reporting["reports-accepted"] is True
    contact = reporting["contact"]
    assert contact["primary"] is True
    assert _EMAIL.match(contact["email"])
    policy = reporting["policy"]
    assert policy.endswith("/SECURITY.md")
    security_md = (_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert contact["email"] in security_md


def test_release_artifacts_described() -> None:
    release = DOC["repository"]["release"]
    assert release["automated-pipeline"] is True
    predicates = {a["predicate-uri"] for a in release["attestations"]}
    assert any("SPDX" in p or "spdx" in p for p in predicates)
    assert any("slsa.dev" in p for p in predicates)
    for attestation in release["attestations"]:
        assert _URL.match(attestation["location"])
    uris = [d["uri"] for d in release["distribution-points"]]
    assert any(u.startswith("pkg:pypi/") for u in uris)
    assert any("github.com" in u and "releases" in u for u in uris)


def test_license_and_contact() -> None:
    assert DOC["repository"]["license"]["expression"] == "Apache-2.0"
    assert _URL.match(DOC["repository"]["license"]["url"])
    core = DOC["repository"]["core-team"]
    assert any(c.get("primary") and _EMAIL.match(c.get("email", "")) for c in core)

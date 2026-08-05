import json
from collections.abc import Callable
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from guardana.core.redaction import EvidenceRedactor
from guardana.core.report.result import ScanResult
from guardana.core.report.serialize import finding_to_dict

_TIMEOUT_SECONDS = 30

ENVELOPE_SCHEMA_VERSION = 5
"""Version of the JSON envelope POSTed to a collector.

The collector is a separate service on its own release cadence, so the envelope
is versioned: a collector that doesn't understand a version rejects it outright
rather than silently misreading a renamed field.

v5 says *why* each rule was skipped, not just that it was: a collector that saw
`rules_skipped: ["guardana.agent.tool_argument_scope"]` could not tell a rule
that never applied from one the provider could not support, and showed a fleet
with a coverage hole as fully checked.
v4 names the rules that ran (`summary.rules_executed`) instead of only counting
them: a collector that saw `rules_run: 12` could not tell a clean agent from one
whose profile excluded the rules that would have found something, and showed
both as green.
v3 added the `errors` channel (checks that could not run at all): a collector
that showed an agent as clean while its checks were crashing would be the same
false all-clear v2 fixed, one layer further out.
v2 added the `unverified` channel (checks that ran but could not reach a
verdict). v1 dropped them, so a model whose CRITICAL checks could not be graded
was forwarded as `findings: []` — a false all-clear at the collector boundary.
"""


INGEST_PATH = "/findings"
"""Where a collector accepts an envelope.

Appended when the reporter is given a bare collector URL, which is what every
documented example writes: `--reporter server://https://collector.example.com`
names a *collector*, not a route, and making a user know the route would leak the
collector's shape into every pipeline that talks to it.

Aimed at the bare URL, the reporter used to POST to `/`, which no collector serves.
The submission came back `404`, the CLI printed a warning, and the scan still
exited `0` — so a whole fleet could report nothing while a dashboard showed stale
data as current. A URL that already carries a path is left alone, because somebody
behind a reverse proxy may legitimately point at one.
"""


def _ingest_url(parts: SplitResult) -> str:
    """Resolve a reporter URL to the route a collector actually accepts."""
    if parts.path not in ("", "/"):
        return parts.geturl()
    return urlunsplit((parts.scheme, parts.netloc, INGEST_PATH, parts.query, parts.fragment))


class Reporter(Protocol):
    """Where findings go after a scan. The seam the optional collector plugs into."""

    def submit(self, result: ScanResult, *, source: str) -> None:
        """Forward one scan result, tagged with where it came from."""
        ...


def _serialize(result: ScanResult, *, source: str) -> bytes:
    max_sev = result.max_severity()
    payload = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "source": source,
        "findings": [finding_to_dict(f) for f in result.findings],
        # Never dropped: a check that ran but could not grade is not a pass. The
        # collector must see it, or a dashboard renders a false all-clear on a
        # model whose CRITICAL checks silently failed to run.
        "unverified": [finding_to_dict(f) for f in result.unverified],
        "errors": [
            {"source": e.source, "stage": e.stage, "reason": e.reason} for e in result.errors
        ],
        "summary": {
            "rules_run": result.rules_run_count,
            "rules_executed": list(result.rules_run),
            "rules_skipped": [
                {"rule_id": s.rule_id, "reason": str(s.reason), "missing": list(s.missing)}
                for s in result.rules_skipped
            ],
            "max_severity": max_sev.name if max_sev else None,
            "unverified": len(result.unverified),
            "errors": len(result.errors),
        },
    }
    return json.dumps(payload).encode("utf-8")


def _urllib_transport(url: str, payload: bytes, *, api_key: str | None) -> None:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    # S310 x2: the scheme is validated to be http/https in HttpReporter.__init__.
    request = Request(url, data=payload, headers=headers, method="POST")  # noqa: S310
    with urlopen(request, timeout=_TIMEOUT_SECONDS):  # noqa: S310
        pass


class HttpReporter:
    """Forwards findings to a `guardana-server` collector. Core never imports the server."""

    def __init__(
        self,
        url: str,
        *,
        api_key: str | None = None,
        transport: Callable[[str, bytes], None] | None = None,
        redactor: EvidenceRedactor | None = None,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(
                f"unsupported reporter URL scheme {parts.scheme!r}: expected http or https"
            )
        self._url = _ingest_url(parts)
        self._api_key = api_key
        self._transport = transport if transport is not None else self._default_transport
        # Applied here rather than by the caller: this is the path that leaves the
        # machine, and it must not depend on whoever wired the reporter up.
        self._redactor = redactor if redactor is not None else EvidenceRedactor()

    def _default_transport(self, url: str, payload: bytes) -> None:
        _urllib_transport(url, payload, api_key=self._api_key)

    def submit(self, result: ScanResult, *, source: str) -> None:
        """POST the normalized envelope to the collector."""
        payload = _serialize(self._redactor.redact_result(result), source=source)
        self._transport(self._url, payload)

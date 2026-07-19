import json
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from guardana.core.report.result import ScanResult
from guardana.core.report.serialize import finding_to_dict

_TIMEOUT_SECONDS = 30

ENVELOPE_SCHEMA_VERSION = 2
"""Version of the JSON envelope POSTed to a collector.

The collector is a separate service on its own release cadence, so the envelope
is versioned: a collector that doesn't understand a version rejects it outright
rather than silently misreading a renamed field.

v2 added the `unverified` channel (checks that ran but could not reach a
verdict). v1 dropped them, so a model whose CRITICAL checks could not be graded
was forwarded as `findings: []` — a false all-clear at the collector boundary.
"""


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
        "summary": {
            "rules_run": result.rules_run,
            "rules_skipped": list(result.rules_skipped),
            "max_severity": max_sev.name if max_sev else None,
            "unverified": len(result.unverified),
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
    ) -> None:
        scheme = urlsplit(url).scheme
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported reporter URL scheme {scheme!r}: expected http or https")
        self._url = url
        self._api_key = api_key
        self._transport = transport if transport is not None else self._default_transport

    def _default_transport(self, url: str, payload: bytes) -> None:
        _urllib_transport(url, payload, api_key=self._api_key)

    def submit(self, result: ScanResult, *, source: str) -> None:
        """POST the normalized envelope to the collector."""
        payload = _serialize(result, source=source)
        self._transport(self._url, payload)

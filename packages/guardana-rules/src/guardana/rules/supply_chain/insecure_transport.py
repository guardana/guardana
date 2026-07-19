import ast
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_LLM03
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# Bare call names that fetch a model, dataset, or file over the network. A
# plaintext `http://` URL only matters as an argument to one of these — an
# `http://` string elsewhere (an XML namespace, a label) is not a download.
# Matched by bare name because these are near-always aliased (`requests.get`,
# `httpx.get`, `urllib.request.urlopen`).
_FETCH_CALLS = frozenset(
    {
        "get",
        "post",
        "request",
        "urlopen",
        "urlretrieve",
        "Request",
        "from_pretrained",
        "hf_hub_download",
        "snapshot_download",
        "load_dataset",
    }
)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})  # noqa: S104 — matched, not bound


def _bare_call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _tls_verification_disabled(node: ast.Call) -> bool:
    return any(
        kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
        for kw in node.keywords
    )


def _string_args(node: ast.Call) -> Iterator[str]:
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            yield arg.value
    for kw in node.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            yield kw.value.value


def _plaintext_host(url: str) -> str | None:
    """Return the host of an exposed `http://` URL, or None if it is https/local.

    The scheme is matched case-insensitively — `HTTP://` and `Http://` are exactly
    as plaintext as `http://`, and an attacker (or a sloppy config) will use them.
    """
    scheme, sep, rest = url.partition("://")
    if not sep or scheme.lower() != "http":
        return None
    host = rest.split("/", 1)[0].split(":", 1)[0]
    return None if host.lower() in _LOCAL_HOSTS else host


class InsecureTransportRule(Rule):
    """Flags disabled TLS verification, and model/data fetched over plaintext HTTP."""

    meta = RuleMeta(
        id="guardana.supply_chain.insecure_transport",
        title="Insecure transport for a model or dataset fetch",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file for TLS-off calls and plaintext-HTTP fetches."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".py",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        source = read_text_bounded(path)
        if source is None:
            return
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield from self._call_findings(node, path)

    def _call_findings(self, node: ast.Call, path: Path) -> Iterator[Finding]:
        if _tls_verification_disabled(node):
            # A firm finding: disabling certificate checks is an unambiguous MITM
            # exposure, so it carries no lead verdict — it is certain.
            yield self._finding(
                path,
                node.lineno,
                Severity.HIGH,
                "verify=False disables TLS certificate checks (MITM risk)",
            )
        if _bare_call_name(node) in _FETCH_CALLS:
            for host in filter(None, map(_plaintext_host, _string_args(node))):
                yield self._finding(
                    path,
                    node.lineno,
                    Severity.MEDIUM,
                    f"plaintext http:// fetch from {host} (weights can be swapped in transit)",
                    lead=True,
                )

    def _finding(
        self, path: Path, lineno: int, severity: Severity, summary: str, *, lead: bool = False
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=f"{path}:{lineno}",
            evidence=Evidence(summary=summary, detail=f"{path.name}:{lineno}"),
            verdict=lead_verdict(summary) if lead else None,
        )

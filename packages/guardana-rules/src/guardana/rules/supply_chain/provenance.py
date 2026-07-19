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

_RULE_ID = "guardana.supply_chain.provenance"
_DOWNLOAD_CALLS = frozenset({"from_pretrained", "hf_hub_download"})
_CARD_NAMES = frozenset({"readme.md", "model_card.md"})
_RISKY_LICENSE_MARKERS = ("AGPL", "non-commercial", "no redistribution")


def _bare_call_name(node: ast.Call) -> str:
    """Return the called function's own name, receiver ignored (`x.load` → `load`)."""
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _has_revision_kw(node: ast.Call) -> bool:
    return any(kw.arg == "revision" for kw in node.keywords)


def _unpinned_downloads(tree: ast.AST) -> Iterator[int]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _bare_call_name(node) in _DOWNLOAD_CALLS and not _has_revision_kw(node):
            yield node.lineno


def _license_lead(text: str) -> str | None:
    for marker in _RISKY_LICENSE_MARKERS:
        if marker.lower() in text.lower():
            return marker
    return None


class ProvenanceRule(Rule):
    """Flags an unpinned model download, or a licence in the model card worth a second look."""

    meta = RuleMeta(
        id=_RULE_ID,
        title="Model provenance: unpinned download or risky license lead",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan `.py` files for downloads, and model cards for licence markers."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".py",)):
            yield from self._scan_downloads(path)
        for path in target.iter_files((".md",)):
            if path.name.lower() in _CARD_NAMES:
                yield from self._scan_license(path)

    def _scan_downloads(self, path: Path) -> Iterator[Finding]:
        source = read_text_bounded(path)
        if source is None:
            return
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        for lineno in _unpinned_downloads(tree):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=f"{path}:{lineno}",
                evidence=Evidence(
                    summary="unpinned model download (add revision=<commit-sha>)",
                    detail=f"{path.name}:{lineno}",
                ),
                verdict=lead_verdict("unpinned model download; a provenance lead, not a certainty"),
            )

    def _scan_license(self, path: Path) -> Iterator[Finding]:
        text = read_text_bounded(path, errors="ignore")
        if text is None:
            return
        marker = _license_lead(text)
        if marker is None:
            return
        yield Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title="Risky license marker in model card",
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"risky license marker in model card ({marker})",
                detail=f"file={path.name}",
            ),
            verdict=lead_verdict(
                f"risky license marker ({marker}); worth a second look, not a verdict"
            ),
        )

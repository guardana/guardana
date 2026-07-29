import re
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as _defused_et  # noqa: N813 — the library's own module name
from defusedxml.common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from guardana.core.formats import FormatError, read_safetensors_header
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_ASI05, OWASP_LLM03, OWASP_LLM05
from guardana.rules.supply_chain._reading import read_bytes_bounded

_RULE_ID = "guardana.supply_chain.model_format"

_XXE_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_XXE_ENTITY = re.compile(rb"<!ENTITY", re.IGNORECASE)


def _scan_pmml(path: Path, data: bytes) -> Iterator[Finding]:
    doctype = _XXE_DOCTYPE.search(data)
    entity = _XXE_ENTITY.search(data)
    if doctype is not None or entity is not None:
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.HIGH,
            title="XML model file declares DOCTYPE/ENTITY (XXE)",
            taxonomy=(
                OWASP_LLM03,
                OWASP_LLM05,
                NIST_SUPPLY_CHAIN,
                OWASP_ASI05,
            ),
            target_ref=str(path),
            evidence=Evidence(
                summary="DOCTYPE or ENTITY declaration found; vulnerable parsers may leak files",
                detail=f"file={path.name}",
            ),
        )
        return
    # Belt-and-braces: defusedxml with forbid_dtd=True explicitly rejects
    # DTD/entity-bearing documents even when our lightweight byte-scan above
    # missed a variant. Combined with the regex pre-filter above, this ensures
    # genuine XXE defense via parser + regex (not regex-only).
    try:
        _defused_et.fromstring(data, forbid_dtd=True)
    except (DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden) as exc:
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.HIGH,
            title="XML model file rejected by defused parser (XXE)",
            taxonomy=(OWASP_LLM03, OWASP_LLM05, NIST_SUPPLY_CHAIN),
            target_ref=str(path),
            evidence=Evidence(
                summary=f"defusedxml with forbid_dtd=True refused to parse: {exc}",
                detail=f"file={path.name}",
            ),
        )
    except ParseError:  # not XML (or truncated by the bounded read) — not this rule's concern
        return


def _scan_safetensors(path: Path) -> Iterator[Finding]:
    # safetensors has no code-execution surface: the header is a length-prefixed
    # JSON dict of tensor metadata and the payload is raw bytes. Only the
    # container's shape is checked here — a well-formed file is inert and must
    # yield nothing. (`hidden_instructions` scans the one text channel it does
    # have, `__metadata__`.)
    try:
        read_safetensors_header(path)
    except FormatError as exc:
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.INFO,
            title="Malformed safetensors header",
            taxonomy=(NIST_SUPPLY_CHAIN,),
            target_ref=str(path),
            evidence=Evidence(
                summary=f"structurally corrupt safetensors container: {exc}",
                detail=f"file={path.name}",
            ),
        )


# Content detectors get a bounded prefix of the file (an XML prolog lives near
# the start; the bound keeps a crafted multi-GB file from stalling the scan).
# Whole-file detectors manage their own reading because the interesting region
# can legitimately exceed that bound.
_CONTENT_DETECTORS: dict[str, Callable[[Path, bytes], Iterator[Finding]]] = {
    ".pmml": _scan_pmml,
    ".xml": _scan_pmml,
}

_WHOLE_FILE_DETECTORS: dict[str, Callable[[Path], Iterator[Finding]]] = {
    ".safetensors": _scan_safetensors,
}


class ModelFormatRule(Rule):
    """Flags risky constructs in non-pickle model formats (PMML/XML, safetensors).

    Format-specific depth lives in the rule that owns the format —
    `keras_lambda` for Keras, `chat_template` for GGUF — so one artifact
    never yields two findings about the same fact.
    """

    meta = RuleMeta(
        id=_RULE_ID,
        title="Risky construct in a non-pickle model file format",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, OWASP_LLM05, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every model file whose suffix has a detector."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((*_CONTENT_DETECTORS, *_WHOLE_FILE_DETECTORS)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        whole_file_detector = _WHOLE_FILE_DETECTORS.get(path.suffix)
        if whole_file_detector is not None:
            yield from whole_file_detector(path)
            return
        prefix = read_bytes_bounded(path)
        if prefix is None:
            return
        yield from _CONTENT_DETECTORS[path.suffix](path, prefix[0])

import re
from collections.abc import Callable, Generator, Iterable, Iterator
from pathlib import Path
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as _defused_et  # noqa: N813 — the library's own module name
from defusedxml.common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from guardana.core.formats import FormatError, read_safetensors_header
from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
)
from guardana.core.testing import build_safetensors
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import (
    LFS_POINTER_REASON,
    MAX_SCAN_BYTES,
    is_lfs_pointer,
    read_bytes_bounded,
    read_model,
)

_RULE_ID = "guardana.supply_chain.model_format"

_PMML_SUFFIX = ".pmml"
_XXE_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_XXE_ENTITY = re.compile(rb"<!ENTITY", re.IGNORECASE)


def _scan_pmml(path: Path, data: bytes) -> Generator[Finding, None, bool]:
    """Grade a PMML/XML file and return whether it was read as XML at all."""
    doctype = _XXE_DOCTYPE.search(data)
    entity = _XXE_ENTITY.search(data)
    if doctype is not None or entity is not None:
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.HIGH,
            title="XML model file declares DOCTYPE/ENTITY (XXE)",
            taxonomy=(
                OWASP_LLM03_2025,
                OWASP_LLM04_2026,
                OWASP_LLM05_2025,
                OWASP_LLM10_2026,
                NIST_SUPPLY_CHAIN,
                OWASP_ASI05_2026,
            ),
            target_ref=str(path),
            evidence=Evidence(
                summary="DOCTYPE or ENTITY declaration found; vulnerable parsers may leak files",
                detail=f"file={path.name}",
            ),
        )
        return True
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
            taxonomy=(
                OWASP_LLM03_2025,
                OWASP_LLM04_2026,
                OWASP_LLM05_2025,
                OWASP_LLM10_2026,
                NIST_SUPPLY_CHAIN,
            ),
            target_ref=str(path),
            evidence=Evidence(
                summary=f"defusedxml with forbid_dtd=True refused to parse: {exc}",
                detail=f"file={path.name}",
            ),
        )
    except ParseError:
        # Not XML, or cut by the bounded read: nothing here was read as a model, so the
        # file is not examined, and an observed `.pmml` stays a coverage shortfall.
        return False
    return True


def _scan_safetensors(path: Path, ctx: RuleContext) -> Iterator[Finding]:
    """Check a safetensors container's header; one that cannot be read is not cleared.

    safetensors has no code-execution surface: the header is a length-prefixed JSON
    dict of tensor metadata and the payload is raw bytes, so a well-formed file is
    inert and yields nothing (`hidden_instructions` scans its one text channel,
    `__metadata__`). A malformed header is no verdict about the file either: what a
    loader makes of it was never read here.
    """
    try:
        read_model(read_safetensors_header, path)
    except FormatError as exc:
        ctx.shortfall(unread_component(_RULE_ID, path, str(exc)))
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.LOW,
            title="safetensors file not scanned",
            taxonomy=(NIST_SUPPLY_CHAIN,),
            target_ref=str(path),
            evidence=Evidence(
                summary=f"safetensors file not scanned: {exc}", detail=f"file={path.name}"
            ),
            verdict=unscanned_verdict("the file could not be read, so nothing was cleared"),
        )


def _unscanned(path: Path, reason: str, ctx: RuleContext) -> Finding:
    # Only PMML is a model component the inventory lists; an oversized `.xml` is any
    # document, and naming it as an unread model would hold up every run beside it.
    if path.suffix.lower() == _PMML_SUFFIX:
        ctx.shortfall(unread_component(_RULE_ID, path, reason))
    return Finding(
        rule_id=_RULE_ID,
        severity=Severity.LOW,
        title="XML model file not scanned",
        taxonomy=(OWASP_LLM03_2025, OWASP_LLM04_2026, NIST_SUPPLY_CHAIN),
        target_ref=str(path),
        evidence=Evidence(
            summary=f"XML model file not scanned: {reason}", detail=f"file={path.name}"
        ),
        verdict=unscanned_verdict("the document could not be read whole, so nothing was cleared"),
    )


# Content detectors get a bounded prefix of the file (an XML prolog lives near
# the start; the bound keeps a crafted multi-GB file from stalling the scan).
# Whole-file detectors manage their own reading because the interesting region
# can legitimately exceed that bound.
_CONTENT_DETECTORS: dict[str, Callable[[Path, bytes], Generator[Finding, None, bool]]] = {
    _PMML_SUFFIX: _scan_pmml,
    ".xml": _scan_pmml,
}

_WHOLE_FILE_DETECTORS: dict[str, Callable[[Path, RuleContext], Iterator[Finding]]] = {
    ".safetensors": _scan_safetensors,
}


_XXE_SAMPLE = (
    '<?xml version="1.0"?>\n<!DOCTYPE PMML [<!ENTITY ext SYSTEM "file:///etc/hostname">]>\n'
    '<PMML version="4.4"><Header description="&ext;"/></PMML>\n'
)


class ModelFormatRule(ArtifactRule):
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
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            NIST_SUPPLY_CHAIN,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a PMML file declaring an entity, a safetensors file and one with a cut header."""
        return materialise(
            (
                _samples.sample(
                    "a PMML model declaring an external entity",
                    FixtureOutcome.FINDING,
                    {"model.pmml": _XXE_SAMPLE},
                ),
                _samples.sample(
                    "a well-formed safetensors file",
                    FixtureOutcome.CLEAN,
                    {"model.safetensors": build_safetensors()},
                ),
                _samples.sample(
                    "a safetensors file whose header length is cut short",
                    FixtureOutcome.INCONCLUSIVE,
                    {"model.safetensors": b"\x01\x00"},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every model file whose suffix has a detector."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((*_CONTENT_DETECTORS, *_WHOLE_FILE_DETECTORS)):
            if (yield from self._scan(path, ctx)):
                ctx.examined(path)

    def _scan(self, path: Path, ctx: RuleContext) -> Generator[Finding, None, bool]:
        """Scan one file and return whether it was read, or reported as unread by name."""
        whole_file_detector = _WHOLE_FILE_DETECTORS.get(path.suffix.lower())
        if whole_file_detector is not None:
            yield from whole_file_detector(path, ctx)
            return True
        prefix = read_bytes_bounded(path)
        if prefix is None:
            return False
        data, truncated = prefix
        if path.suffix.lower() == _PMML_SUFFIX and is_lfs_pointer(data):
            yield _unscanned(path, LFS_POINTER_REASON, ctx)
            return True
        examined = yield from _CONTENT_DETECTORS[path.suffix.lower()](path, data)
        if truncated:
            # A parser reads the whole document, and a prolog of comments can push a
            # DOCTYPE past the bound.
            yield _unscanned(
                path, f"the file is larger than the {MAX_SCAN_BYTES}-byte read bound", ctx
            )
            return path.suffix.lower() == _PMML_SUFFIX
        return examined

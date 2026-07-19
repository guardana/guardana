import json
import re
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as _defused_et  # noqa: N813 — the library's own module name
from defusedxml.common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import NIST_SUPPLY_CHAIN, OWASP_LLM03, OWASP_LLM05
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES

_RULE_ID = "guardana.supply_chain.model_format"

# CVE-2024-34359: llama-cpp-python rendered a GGUF's embedded chat_template
# with a Jinja2 Environment that had no sandboxing, so a template carrying
# attribute-access gadgets (dunder chains, `os`/`subprocess`) achieves
# arbitrary code execution the moment the template is rendered.
#
# `_CHAT_TEMPLATE` locates candidate regions with a plain substring scan (no
# backtracking), then `_SSTI_SINK` checks only a bounded fixed-size slice
# after each occurrence. This is linear in file size, unlike a single regex
# with a variable-length gap (`.{0,N}?`), which is re-scanned from every
# `chat_template` occurrence and degrades toward quadratic on adversarial input.
_CHAT_TEMPLATE = re.compile(rb"chat_template", re.IGNORECASE)
_SSTI_SINK = re.compile(
    rb"__\w+__|__import__|__globals__|\bos\.|\bsubprocess\b|\bpopen\b",
    re.IGNORECASE,
)
_SSTI_GAP = 4096

# Keras/H5 model configs are JSON; a "Lambda" layer's `class_name` wraps an
# arbitrary Python callable (often a base64-marshalled code object) that
# runs on model load — there is no safe way to sandbox it.
_KERAS_LAMBDA = re.compile(rb'"class_name"\s*:\s*"Lambda"')

_XXE_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_XXE_ENTITY = re.compile(rb"<!ENTITY", re.IGNORECASE)

_SAFETENSORS_HEADER_LEN = 8

# The declared header length is attacker-controlled (it's the first 8 bytes
# of the file). A legitimate safetensors header for a model with tens of
# thousands of tensors can exceed the 1 MiB content-scan bound (a 20k-tensor
# header is ~1.5 MiB of JSON), so the safetensors detector must read its own
# declared length rather than reusing the bounded content-scan buffer. This
# cap still bounds the read so a crafted file claiming an absurd (e.g.
# exabyte-scale) header can't force a huge allocation/read.
_MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024


def _scan_gguf(path: Path, data: bytes) -> Iterator[Finding]:
    for template_match in _CHAT_TEMPLATE.finditer(data):
        window_start = template_match.end()
        window = data[window_start : window_start + _SSTI_GAP]
        sink_match = _SSTI_SINK.search(window)
        if sink_match is None:
            continue
        excerpt = data[template_match.start() : window_start + sink_match.end()][:120]
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.HIGH,
            title="GGUF chat_template carries a Jinja2 SSTI sink",
            taxonomy=(OWASP_LLM03, OWASP_LLM05, NIST_SUPPLY_CHAIN),
            target_ref=str(path),
            evidence=Evidence(
                summary=(
                    "embedded chat_template contains an unsandboxed Jinja2 "
                    "attribute-access/exec gadget (CVE-2024-34359)"
                ),
                detail=f"file={path.name} match={excerpt!r}",
            ),
        )
        return


def _scan_keras(path: Path, data: bytes) -> Iterator[Finding]:
    match = _KERAS_LAMBDA.search(data)
    if match is None:
        return
    yield Finding(
        rule_id=_RULE_ID,
        severity=Severity.HIGH,
        title="Keras Lambda layer (arbitrary code on load)",
        taxonomy=(OWASP_LLM03, OWASP_LLM05, NIST_SUPPLY_CHAIN),
        target_ref=str(path),
        evidence=Evidence(
            summary="model config declares a Lambda layer, which executes arbitrary Python on load",
            detail=f"file={path.name}",
        ),
    )


def _scan_pmml(path: Path, data: bytes) -> Iterator[Finding]:
    doctype = _XXE_DOCTYPE.search(data)
    entity = _XXE_ENTITY.search(data)
    if doctype is not None or entity is not None:
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.HIGH,
            title="XML model file declares DOCTYPE/ENTITY (XXE)",
            taxonomy=(OWASP_LLM03, OWASP_LLM05, NIST_SUPPLY_CHAIN),
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
    # safetensors has no code-execution surface: the header is a length-
    # prefixed JSON dict of tensor metadata, and the payload is raw bytes.
    # We only sanity-check the container shape; a well-formed file is inert
    # and must yield nothing.
    #
    # The header can legitimately be larger than the 1 MiB content-scan
    # bound (a 20k-tensor model's JSON header is ~1.5 MiB), which is why this
    # is a whole-file detector reading its own declared length.
    try:
        file_size = path.stat().st_size
        with path.open("rb") as fh:
            length_prefix = fh.read(_SAFETENSORS_HEADER_LEN)
            if len(length_prefix) < _SAFETENSORS_HEADER_LEN:
                yield _malformed_safetensors(path, "file shorter than the header-length prefix")
                return
            header_len = int.from_bytes(length_prefix, "little")
            header_end = _SAFETENSORS_HEADER_LEN + header_len
            if header_len > _MAX_SAFETENSORS_HEADER or header_end > file_size:
                yield _malformed_safetensors(path, "declared header length exceeds file size")
                return
            header_bytes = fh.read(header_len)
    except OSError:
        return
    try:
        json.loads(header_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        yield _malformed_safetensors(path, "header bytes are not valid JSON")


def _malformed_safetensors(path: Path, reason: str) -> Finding:
    return Finding(
        rule_id=_RULE_ID,
        severity=Severity.INFO,
        title="Malformed safetensors header",
        taxonomy=(NIST_SUPPLY_CHAIN,),
        target_ref=str(path),
        evidence=Evidence(
            summary=f"structurally corrupt safetensors container: {reason}",
            detail=f"file={path.name}",
        ),
    )


# Content detectors get a bounded prefix of the file (GGUF metadata, Keras
# configs, and XML prologs all live near the start; the bound keeps a crafted
# multi-GB file from stalling the scan). Whole-file detectors manage their own
# reading because the interesting region can legitimately exceed that bound.
_CONTENT_DETECTORS: dict[str, Callable[[Path, bytes], Iterator[Finding]]] = {
    ".gguf": _scan_gguf,
    ".keras": _scan_keras,
    ".h5": _scan_keras,
    ".pmml": _scan_pmml,
    ".xml": _scan_pmml,
}

_WHOLE_FILE_DETECTORS: dict[str, Callable[[Path], Iterator[Finding]]] = {
    ".safetensors": _scan_safetensors,
}


class ModelFormatRule(Rule):
    """Flags risky constructs in non-pickle model formats (GGUF, Keras, PMML, safetensors)."""

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
        try:
            with path.open("rb") as fh:
                data = fh.read(MAX_SCAN_BYTES)
        except OSError:
            return
        yield from _CONTENT_DETECTORS[path.suffix](path, data)

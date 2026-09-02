import json
import re
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
    OWASP_ML06_2023,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_bytes_bounded

# A Keras `Lambda` layer wraps an arbitrary Python callable that runs on
# `load_model` — a code-execution primitive, no inference needed. `safe_mode` is
# bypassable (CVE-2025-1550, and CVE-2025-9905 shows load_model ignores it for
# `.h5`), so the layer's mere presence is the signal.
_LAMBDA = "Lambda"
# If a Lambda's serialized body references one of these, it is almost certainly
# malicious rather than a benign in-graph tensor op — Keras 3.9's own fix draws
# the same line by whitelisting Keras-internal modules only.
_DANGEROUS_MODULES = ("os", "subprocess", "sys", "socket", "shutil", "pty", "importlib")
# The model config is JSON wherever it is stored, and a Lambda layer declares
# itself with this exact key/value pair. Matching the bare word "Lambda" instead
# reported any layer a user happened to *name* "Lambda" as code execution.
_CLASS_MARKER = re.compile(rb'"class_name"\s*:\s*"Lambda"')
_MAX_CONFIG_BYTES = 16 * 1024 * 1024
_UNSCANNED_TITLE = "Keras model not scanned"


def _iter_lambda_configs(node: object) -> Iterator[object]:
    """Yield the `config` of every object in the tree whose `class_name` is Lambda."""
    if isinstance(node, dict):
        if node.get("class_name") == _LAMBDA:
            yield node.get("config")
        for value in node.values():
            yield from _iter_lambda_configs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_lambda_configs(item)


def _dangerous_module(config: object) -> str | None:
    """Return a dangerous module name referenced in a Lambda's serialized body, if any."""
    blob = json.dumps(config)
    for module in _DANGEROUS_MODULES:
        if f"'{module}'" in blob or f'"{module}"' in blob or f"import {module}" in blob:
            return module
    return None


class KerasLambdaRule(ArtifactRule):
    """Flag a Keras `Lambda` layer — arbitrary Python that runs when the model loads."""

    meta = RuleMeta(
        id="guardana.supply_chain.keras_lambda",
        title="Keras Lambda layer (arbitrary code on model load)",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            OWASP_ML06_2023,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Parse `.keras` archives structurally; scan legacy `.h5`/`.hdf5` for the class marker."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".keras",)):
            yield from self._scan_keras(path)
        for path in target.iter_files((".h5", ".hdf5")):
            yield from self._byte_scan(path, fallback_reason=None)

    def _scan_keras(self, path: Path) -> Iterator[Finding]:
        config = _read_keras_config(path)
        if config is None:
            # Real `.keras` files are zip archives. A file that is not one is
            # malformed, so fall back to the byte marker — a payload inside a
            # deliberately broken archive must not become invisible.
            yield from self._byte_scan(path, fallback_reason="not a readable .keras archive")
            return
        for lambda_config in _iter_lambda_configs(config):
            module = _dangerous_module(lambda_config)
            summary = "Keras Lambda layer runs arbitrary code on load"
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)

    def _byte_scan(self, path: Path, *, fallback_reason: str | None) -> Iterator[Finding]:
        prefix = read_bytes_bounded(path, _MAX_CONFIG_BYTES)
        if prefix is None:
            yield self._unscanned(path, "file could not be read")
            return
        data, truncated = prefix
        if _CLASS_MARKER.search(data) is not None:
            # Firm, not a lead: the config declares the layer, and `load_model`
            # ignores `safe_mode` for the legacy format (CVE-2025-9905), so this
            # will execute.
            yield self._finding(path, "model config declares a Lambda layer, which runs on load")
        elif fallback_reason is not None:
            yield self._unscanned(path, fallback_reason)
        elif truncated:
            yield self._unscanned(path, f"only the first {_MAX_CONFIG_BYTES} bytes were read")

    def _finding(self, path: Path, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=f"file={path.name}"),
        )

    def _unscanned(self, path: Path, reason: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"Keras model not scanned for Lambda layers: {reason}",
                detail=f"file={path.name}",
            ),
            verdict=lead_verdict("the model config could not be read, so nothing was cleared"),
        )


def _read_keras_config(path: Path) -> object | None:
    """Read and parse `config.json` from a `.keras` archive; None if unreadable."""
    try:
        with zipfile.ZipFile(path) as archive:
            if "config.json" not in archive.namelist():
                return None
            with archive.open("config.json") as member:
                raw = member.read(_MAX_CONFIG_BYTES)
        parsed: object = json.loads(raw)
    except (zipfile.BadZipFile, OSError, ValueError):
        return None
    else:
        return parsed

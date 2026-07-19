import json
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0018, NIST_SUPPLY_CHAIN, OWASP_LLM05, OWASP_ML06
from guardana.rules.supply_chain._leads import lead_verdict

# A Keras `Lambda` layer wraps an arbitrary Python callable that runs on
# `load_model` — a code-execution primitive, no inference needed. `safe_mode` is
# bypassable (CVE-2025-1550, and CVE-2025-9905 shows load_model ignores it for
# `.h5`), so the layer's mere presence is the signal.
_LAMBDA = "Lambda"
# If a Lambda's serialized body references one of these, it is almost certainly
# malicious rather than a benign in-graph tensor op — Keras 3.9's own fix draws
# the same line by whitelisting Keras-internal modules only.
_DANGEROUS_MODULES = ("os", "subprocess", "sys", "socket", "shutil", "pty", "importlib")
_H5_MARKER = b'"Lambda"'
_MAX_CONFIG_BYTES = 16 * 1024 * 1024


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


class KerasLambdaRule(Rule):
    """Flag a Keras `Lambda` layer — arbitrary Python that runs when the model loads."""

    meta = RuleMeta(
        id="guardana.supply_chain.keras_lambda",
        title="Keras Lambda layer (arbitrary code on model load)",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM05, OWASP_ML06, ATLAS_T0018, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Parse `.keras` archives structurally; bytes-scan legacy `.h5`/`.hdf5`."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".keras",)):
            yield from self._scan_keras(path)
        for path in target.iter_files((".h5", ".hdf5")):
            yield from self._scan_h5(path)

    def _scan_keras(self, path: Path) -> Iterator[Finding]:
        config = _read_keras_config(path)
        if config is None:
            return
        for lambda_config in _iter_lambda_configs(config):
            module = _dangerous_module(lambda_config)
            summary = "Keras Lambda layer runs arbitrary code on load"
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(summary=summary, detail=f"file={path.name}"),
            )

    def _scan_h5(self, path: Path) -> Iterator[Finding]:
        try:
            with path.open("rb") as handle:
                data = handle.read(_MAX_CONFIG_BYTES)
        except OSError:
            return
        if _H5_MARKER not in data:
            return
        yield Finding(
            rule_id=self.meta.id,
            severity=Severity.MEDIUM,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary="legacy HDF5 model references a Lambda layer (arbitrary code on load)",
                detail=f"file={path.name}",
            ),
            verdict=lead_verdict("HDF5 Lambda marker found by bytes-scan; a lead, not a certainty"),
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

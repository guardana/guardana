import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0018, NIST_SUPPLY_CHAIN, OWASP_LLM03
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# A Hugging Face config that carries `auto_map` (or `custom_pipelines`) is wired to
# import and run Python that ships in the model repo when it is loaded with
# `trust_remote_code=True`. `remote_code` catches the *call site* in source; this
# catches the *artifact* — the downloaded config that requests the execution — a
# file `remote_code`'s `.py`-only scan never sees.
_CODE_POINTER_KEYS = ("auto_map", "custom_pipelines")
_CONFIG_NAME_SUFFIX = "config.json"


def _is_config(path: Path) -> bool:
    return path.name.endswith(_CONFIG_NAME_SUFFIX)


def _module_targets(pointer: object) -> Iterator[str]:
    """Yield each `module.Qualname` string a code pointer references.

    `auto_map` values are `"modeling_x.ModelClass"` or a `[config, model]` pair;
    every leaf string names a module whose code runs on load.
    """
    if isinstance(pointer, str):
        yield pointer
    elif isinstance(pointer, dict):
        for value in pointer.values():
            yield from _module_targets(value)
    elif isinstance(pointer, list):
        for item in pointer:
            yield from _module_targets(item)


def _local_module_present(reference: str, directory: Path) -> bool:
    """Whether the `.py` module a pointer references ships next to the config."""
    module = reference.rsplit(".", 1)[0] if "." in reference else reference
    filename = module.rsplit(".", 1)[-1]  # a dotted package path -> its leaf file
    return (directory / f"{filename}.py").is_file()


class RemoteCodeConfigRule(Rule):
    """Flags a model config that points at custom Python run on `trust_remote_code=True` load."""

    meta = RuleMeta(
        id="guardana.supply_chain.remote_code_config",
        title="Model config requests custom-code execution on load",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03, ATLAS_T0018, NIST_SUPPLY_CHAIN),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `*config.json` for an `auto_map`/`custom_pipelines` code pointer."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".json",)):
            if _is_config(path):
                yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        raw = read_text_bounded(path, errors="ignore")
        if raw is None:
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        for key in _CODE_POINTER_KEYS:
            if key in doc:
                yield self._finding(path, key, doc[key])

    def _finding(self, path: Path, key: str, pointer: object) -> Finding:
        references = list(_module_targets(pointer))
        code_present = any(_local_module_present(ref, path.parent) for ref in references)
        summary = f"'{key}' points at custom code run on trust_remote_code=True load"
        # Code shipped alongside is a firm finding — it *will* run. A pointer with
        # no local module is still the RCE-config, but the code is fetched
        # elsewhere, so it is a lead, not a certainty.
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity if code_present else Severity.MEDIUM,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=summary + (" (module ships alongside)" if code_present else ""),
                detail=f"file={path.name}; references={', '.join(references) or '(none)'}",
            ),
            verdict=None if code_present else lead_verdict(summary),
        )

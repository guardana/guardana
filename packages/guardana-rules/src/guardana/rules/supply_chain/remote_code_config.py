import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0018, NIST_SUPPLY_CHAIN, OWASP_ASI05, OWASP_LLM03
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# A Hugging Face config that carries `auto_map` (or `custom_pipelines`) is wired to
# import and run Python that ships in the model repo when it is loaded with
# `trust_remote_code=True`. `remote_code` catches the *call site* in source; this
# catches the *artifact* — the downloaded config that requests the execution — a
# file `remote_code`'s `.py`-only scan never sees.
_CODE_POINTER_KEYS = ("auto_map", "custom_pipelines")
_CONFIG_NAME_SUFFIX = "config.json"

# CVE-2026-4372: transformers applied config entries to internal objects through a
# generic `setattr`, so a private field in a downloaded `config.json` could name a
# Hub repository, which the kernel loader then downloaded and imported. The path
# never consults `trust_remote_code`, so `trust_remote_code=False` — the setting
# users treat as the safe mode — does not stop it. Fixed in transformers 5.3.0.
#
# Detection is by *key name*, never by value shape: `_name_or_path` carries an
# `owner/repo` string in a large share of real configs, so a shape-only rule would
# flag almost every model on the Hub.
_INTERNAL_KERNEL_KEY = "_attn_implementation_internal"
_PUBLIC_KERNEL_KEYS = ("attn_implementation", "_attn_implementation")
_KERNEL_REFERENCE = re.compile(r"^[A-Za-z0-9][\w.-]*/[A-Za-z0-9][\w.-]*$")


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
    """Flags a model config that asks for code to be run when the model loads.

    Two shapes, one artifact: `auto_map`/`custom_pipelines` point at Python that
    runs under `trust_remote_code=True`, while a kernel reference runs *whatever
    the flag is set to* — the config is the request, and the `.py` scan never
    sees it.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.remote_code_config",
        title="Model config requests custom-code execution on load",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05,
        ),
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
        for key in (_INTERNAL_KERNEL_KEY, *_PUBLIC_KERNEL_KEYS):
            reference = doc.get(key)
            if isinstance(reference, str) and _KERNEL_REFERENCE.match(reference):
                yield self._kernel_finding(path, key, reference)

    def _kernel_finding(self, path: Path, key: str, reference: str) -> Finding:
        """Build the finding for a config entry naming a Hub kernel repository.

        Through the private field this is the CVE — code runs on a load the user
        believes is sandboxed. Through the documented field it is an opt-in, so it
        is reported the way `trust_remote_code=True` is: a lead, not a compromise.
        """
        internal = key == _INTERNAL_KERNEL_KEY
        summary = (
            f"'{key}' names the Hub kernel repository '{reference}', "
            "which transformers downloads and imports on load"
        )
        if internal:
            summary += " — a private field, so trust_remote_code=False does not stop it "
            summary += "(CVE-2026-4372)"
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.CRITICAL if internal else Severity.MEDIUM,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=summary,
                detail=f"file={path.name}; kernel={reference}; fixed in transformers 5.3.0",
            ),
            verdict=None if internal else lead_verdict(summary),
        )

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

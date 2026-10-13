import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._leads import lead_verdict, unscanned_verdict
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES, read_text_prefix

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
_INTERNAL_KERNEL_KEYS = ("_attn_implementation_internal", "_attn_implementation")
_PUBLIC_KERNEL_KEY = "attn_implementation"
_KERNEL_KEYS = (*_INTERNAL_KERNEL_KEYS, _PUBLIC_KERNEL_KEY)
# The pattern transformers' `is_kernel` matches: `org/repo`, optionally `@revision`
# and `:function`, with any prefix such as `paged|` before the owner.
_KERNEL_REFERENCE = re.compile(r"^[^/:]+/[^/:]+(?:@[^/:]+)?(?::[^/:]+)?$")


def _is_config(path: Path) -> bool:
    return path.name.lower().endswith(_CONFIG_NAME_SUFFIX)


def _kernel_references(doc: dict[str, object]) -> Iterator[tuple[str, str, str]]:
    """Yield `(key, label, reference)` for each kernel reference the config sets.

    The attribute setter takes a dict keyed by sub-config name (`""` for the config
    itself), and a composite config that builds its sub-configs after its own init
    keeps the field each sub-config carries, so nested configs are read as well.
    """
    pending: list[tuple[str, dict[str, object]]] = [("", doc)]
    while pending:
        prefix, config = pending.pop()
        for key, value in config.items():
            label = f"{prefix}{key}"
            if key in _KERNEL_KEYS:
                entries = value.items() if isinstance(value, dict) else [(None, value)]
                for sub, reference in entries:
                    if isinstance(reference, str) and _KERNEL_REFERENCE.match(reference):
                        yield key, label if sub is None else f'{label}["{sub}"]', reference
            elif isinstance(value, dict):
                pending.append((f"{label}.", value))


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


_AUTO_MAP = {"model_type": "custom", "auto_map": {"AutoModel": "modeling_custom.CustomModel"}}


class RemoteCodeConfigRule(ArtifactRule):
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
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a config pointing at shipped code, a plain one and one past the read bound."""
        return materialise(
            (
                _samples.sample(
                    "a config whose auto_map points at a module shipped beside it",
                    FixtureOutcome.FINDING,
                    {
                        "config.json": json.dumps(_AUTO_MAP),
                        "modeling_custom.py": "class CustomModel:\n    pass\n",
                    },
                ),
                _samples.sample(
                    "a config naming only a built-in architecture",
                    FixtureOutcome.CLEAN,
                    {"config.json": json.dumps({"model_type": "bert", "hidden_size": 768})},
                ),
                _samples.sample(
                    "a config padded past the read bound, its auto_map after the padding",
                    FixtureOutcome.INCONCLUSIVE,
                    {"config.json": _samples.past_the_scan_bound(json.dumps(_AUTO_MAP))},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `*config.json` for a code pointer or a Hub kernel reference."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".json",)):
            if _is_config(path):
                yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        prefix = read_text_prefix(path, errors="ignore")
        if prefix is None:
            yield self._unscanned(path, "the file could not be read")
            return
        raw, truncated = prefix
        if truncated:
            # A loader reads the whole file, so a key past the bound still applies.
            yield self._unscanned(
                path, f"the file is larger than the {MAX_SCAN_BYTES}-byte read bound"
            )
            return
        try:
            doc = json.loads(raw)
        except (ValueError, RecursionError):
            # A loader cannot parse it either, so it configures nothing; `tsconfig.json`
            # with comments is the common case.
            return
        if not isinstance(doc, dict):
            return
        for key in _CODE_POINTER_KEYS:
            if key in doc:
                yield self._finding(path, key, doc[key])
        for key, label, reference in _kernel_references(doc):
            yield self._kernel_finding(path, key, label, reference)

    def _kernel_finding(self, path: Path, key: str, label: str, reference: str) -> Finding:
        """Build the finding for a config entry naming a Hub kernel repository.

        Through a private field this is the CVE — code runs on a load the user
        believes is sandboxed. Through the documented field it is an opt-in, so it
        is reported the way `trust_remote_code=True` is: a lead, not a compromise.
        """
        internal = key in _INTERNAL_KERNEL_KEYS
        summary = (
            f"'{label}' names the Hub kernel repository '{reference}', "
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

    def _unscanned(self, path: Path, reason: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title="Model config not scanned",
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"model config not scanned: {reason}", detail=f"file={path.name}"
            ),
            verdict=unscanned_verdict("the config could not be read whole, so nothing was cleared"),
        )

import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.formats import FormatError, read_gguf_metadata
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
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
)
from guardana.core.testing import build_gguf
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._jinja_gadgets import Gadget, jinja_gadgets
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import (
    MAX_SCAN_BYTES,
    read_bytes_bounded,
    read_model,
    read_text_prefix,
)

_RULE_ID = "guardana.supply_chain.chat_template"
_UNSCANNED_TITLE = "Chat template not scanned"
_PAST_THE_BOUND = f"the file is larger than the {MAX_SCAN_BYTES}-byte read bound"

# The same template ships in up to four places for one model, and a scanner that
# knows only one of them reports the other three clean: inside GGUF metadata, in
# `tokenizer_config.json`, and — since transformers 4.47 saves it this way by
# default — as a standalone `chat_template.jinja`. A GGUF file also carries named
# templates (`tokenizer.chat_template.tool_use`), which llama.cpp loads as readily.
_GGUF_TEMPLATE_KEY = "tokenizer.chat_template"
_CONFIG_NAMES = frozenset({"tokenizer_config.json", "chat_template.json", "processor_config.json"})
_CONFIG_KEY = "chat_template"
_TEMPLATE_STEM = "chat_template"
_TEMPLATE_SUFFIXES = (".jinja", ".j2")


_GADGET = "{{ lipsum.__globals__['os'].popen('id').read() }}"
_PLAIN_TEMPLATE = "{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}\n{% endfor %}"


class ChatTemplateRule(ArtifactRule):
    """Flags Jinja code-execution gadgets in a model's chat template.

    The template is Jinja source that ships inside the model and is rendered the
    moment the model is used, so a gadget in it is code execution on the host that
    loads the model — no inference required, and no `trust_remote_code` involved.
    """

    meta = RuleMeta(
        id=_RULE_ID,
        title="Chat template carries a code-execution gadget",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a GGUF template with a gadget, a plain one and a GGUF file cut short."""
        return materialise(
            (
                _samples.sample(
                    "a GGUF chat template reaching os through lipsum.__globals__",
                    FixtureOutcome.FINDING,
                    {"model.gguf": build_gguf({_GGUF_TEMPLATE_KEY: _GADGET})},
                ),
                _samples.sample(
                    "a GGUF chat template that only formats messages",
                    FixtureOutcome.CLEAN,
                    {"model.gguf": build_gguf({_GGUF_TEMPLATE_KEY: _PLAIN_TEMPLATE})},
                ),
                _samples.sample(
                    "a GGUF file cut off inside its template",
                    FixtureOutcome.INCONCLUSIVE,
                    {"model.gguf": build_gguf({_GGUF_TEMPLATE_KEY: _GADGET})[:-8]},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every carrier of a chat template: GGUF metadata, tokenizer config, `.jinja`."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".gguf",)):
            yield from self._scan_gguf(path, ctx)
            ctx.examined(path)
        for path in target.iter_files(_TEMPLATE_SUFFIXES):
            if path.stem.lower().startswith(_TEMPLATE_STEM):
                yield from self._scan_template_file(path, ctx)
        for path in target.iter_files((".json",)):
            if path.name.lower() in _CONFIG_NAMES:
                yield from self._scan_config(path, ctx)

    def _scan_gguf(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        try:
            metadata = read_model(read_gguf_metadata, path)
        except FormatError as exc:
            yield self._unscanned(path, str(exc), ctx)
            return
        # A model with no template is not an open question — the file was read and
        # understood. Only an unreadable file is.
        for key in sorted(metadata.entries):
            if key != _GGUF_TEMPLATE_KEY and not key.startswith(f"{_GGUF_TEMPLATE_KEY}."):
                continue
            template = metadata.text(key)
            if template is not None:
                yield from self._graded(path, key, template)

    def _scan_template_file(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        prefix = read_bytes_bounded(path)
        if prefix is None:
            yield self._unscanned(path, "file could not be read", ctx)
            return
        raw, truncated = prefix
        yield from self._graded(path, path.name, raw.decode("utf-8", errors="ignore"))
        # Padding a template past the read bound to push a gadget out of view is the
        # obvious evasion once a scanner is known, and a gadget found in the part that
        # was read says nothing about a worse one after it.
        if truncated:
            yield self._unscanned(path, _PAST_THE_BOUND, ctx)

    def _scan_config(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        prefix = read_text_prefix(path, errors="ignore")
        if prefix is not None and prefix[1]:
            yield self._unscanned(path, _PAST_THE_BOUND, ctx)
            return
        document = None if prefix is None else _json_object(prefix[0])
        if document is None:
            yield self._unscanned(path, "not a readable JSON object", ctx)
            return
        if _CONFIG_KEY not in document:
            return
        templates = list(_config_templates(document[_CONFIG_KEY]))
        if not templates:
            yield self._unscanned(
                path, f"'{_CONFIG_KEY}' is present in a shape we cannot read", ctx
            )
            return
        for label, template in templates:
            yield from self._graded(path, label, template)

    def _graded(self, path: Path, label: str, template: str) -> Iterator[Finding]:
        gadgets = list(jinja_gadgets(template))
        if not gadgets:
            return
        yield Finding(
            rule_id=_RULE_ID,
            severity=Severity.CRITICAL if gadgets[0].critical else Severity.HIGH,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=_summary(gadgets),
                detail=(
                    f"file={path.name} source={label} offset={gadgets[0].offset} "
                    f"match={gadgets[0].excerpt!r}"
                ),
            ),
        )

    def _unscanned(self, path: Path, reason: str, ctx: RuleContext) -> Finding:
        ctx.shortfall(unread_component(_RULE_ID, path, reason))
        return Finding(
            rule_id=_RULE_ID,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"chat template not scanned: {reason}",
                detail=f"file={path.name}",
            ),
            verdict=unscanned_verdict("the template could not be read, so nothing was cleared"),
        )


def _json_object(raw: str) -> dict[str, object] | None:
    try:
        document = json.loads(raw)
    except ValueError:
        return None
    return document if isinstance(document, dict) else None


def _summary(gadgets: list[Gadget]) -> str:
    kinds = ", ".join(gadget.kind for gadget in gadgets)
    return f"chat template carries a Jinja gadget ({kinds}) — code runs when the template renders"


def _config_templates(value: object) -> Iterator[tuple[str, str]]:
    """Yield `(label, template)` for the string form and the named-list form.

    `transformers` accepts either a bare string or a list of `{name, template}`
    objects; a scanner that understands only the string form reports a poisoned
    named template as clean.
    """
    if isinstance(value, str):
        yield _CONFIG_KEY, value
    elif isinstance(value, list):
        for entry in value:
            if isinstance(entry, dict) and isinstance(entry.get("template"), str):
                yield f"{_CONFIG_KEY}[{entry.get('name', '?')}]", entry["template"]

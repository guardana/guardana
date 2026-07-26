import json
import os
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, EndpointTarget
from guardana.core.testing import RefusingTransport, build_gguf
from guardana.rules.supply_chain.chat_template import ChatTemplateRule
from guardana.rules.supply_chain.model_format import ModelFormatRule

_KEY = "tokenizer.chat_template"
_PAYLOAD = "{{ lipsum.__globals__['os'].popen('id').read() }}"

# A faithful modern chat template: the constructs real ones actually use —
# `namespace(...)`, `tojson`, `strftime_now`, `raise_exception`, loop metadata,
# whitespace control. None of them may fire the rule.
_REAL_TEMPLATE = """
{%- set ns = namespace(found=false) %}
{{- bos_token }}
{%- if tools %}
    {{- "You may call these tools:\\n" }}
    {{- tools | tojson(indent=2) }}
{%- endif %}
{%- for message in messages %}
    {%- if message['role'] == 'system' %}
        {%- set ns.found = true %}
    {%- endif %}
    {%- if message['role'] not in ['user', 'assistant', 'system', 'tool'] %}
        {{- raise_exception('Unknown role: ' + message['role']) }}
    {%- endif %}
    {{- '<|im_start|>' + message['role'] + '\\n' + message['content'] | trim + '<|im_end|>\\n' }}
    {%- if loop.last and add_generation_prompt %}
        {{- '<|im_start|>assistant\\n' }}
    {%- endif %}
{%- endfor %}
{{- "Today is " + strftime_now("%Y-%m-%d") }}
"""


def _run(root: Path) -> list[object]:
    return list(ChatTemplateRule().run(ArtifactTarget(root), RuleContext()))


def _severities(root: Path) -> list[str]:
    return [f.severity.name for f in ChatTemplateRule().run(ArtifactTarget(root), RuleContext())]


def test_flags_a_gadget_in_a_gguf_chat_template(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(build_gguf({_KEY: _PAYLOAD}))
    assert _severities(tmp_path) == [Severity.CRITICAL.name]


def test_flags_a_gadget_appended_after_a_full_length_real_template(tmp_path: Path) -> None:
    # The regression that motivated the rule: the shipping bytes-scan only looked
    # 4 KiB past the literal `chat_template`, so a gadget appended to the end of a
    # real 8 KiB template scanned clean. The whole value is graded now.
    template = (_REAL_TEMPLATE * 12) + _PAYLOAD
    assert len(template) > 8 * 1024
    (tmp_path / "m.gguf").write_bytes(build_gguf({_KEY: template}))
    assert _severities(tmp_path) == [Severity.CRITICAL.name]


def test_stays_silent_on_a_vocabulary_that_merely_contains_dunder_tokens(tmp_path: Path) -> None:
    # The mirror-image regression: a code model's vocabulary carries `__init__`
    # and friends. Scanning a byte window rather than the template value turned
    # that into a HIGH finding on a model with no chat template at all.
    (tmp_path / "vocab.gguf").write_bytes(
        build_gguf(
            {
                "tokenizer.ggml.model": "chat_template is mentioned here",
                "tokenizer.ggml.tokens": ("__init__", "__name__", "__globals__"),
            }
        )
    )
    assert _run(tmp_path) == []


def test_stays_silent_on_a_real_template(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(build_gguf({_KEY: _REAL_TEMPLATE}))
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"chat_template": _REAL_TEMPLATE}))
    (tmp_path / "chat_template.jinja").write_text(_REAL_TEMPLATE)
    assert _run(tmp_path) == []


def test_flags_a_gadget_in_tokenizer_config(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"chat_template": _PAYLOAD}))
    assert _severities(tmp_path) == [Severity.CRITICAL.name]


def test_flags_a_gadget_in_the_named_template_list_form(tmp_path: Path) -> None:
    # transformers also accepts a list of named templates; a scanner that only
    # understands the string form reports the file clean.
    document = {
        "chat_template": [
            {"name": "default", "template": _REAL_TEMPLATE},
            {"name": "rag", "template": _PAYLOAD},
        ]
    }
    (tmp_path / "tokenizer_config.json").write_text(json.dumps(document))
    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert "rag" in findings[0].evidence.detail


def test_flags_the_attr_filter_sandbox_escape(tmp_path: Path) -> None:
    # CVE-2025-27516: `|attr` reaches str.format and escapes the sandboxed
    # environment transformers renders chat templates in. No dunder in sight.
    (tmp_path / "chat_template.jinja").write_text(
        "{{ ''|attr('format')('{0.__class__}', messages) }}"
    )
    assert _severities(tmp_path) == [Severity.CRITICAL.name]


def test_flags_a_standalone_chat_template_file(tmp_path: Path) -> None:
    (tmp_path / "chat_template.jinja").write_text("{{ cycler.__init__.__globals__ }}")
    assert _severities(tmp_path) == [Severity.CRITICAL.name]


def test_template_inclusion_is_high_not_critical(tmp_path: Path) -> None:
    (tmp_path / "chat_template.jinja").write_text("{% include 'other.jinja' %}\nHello")
    assert _severities(tmp_path) == [Severity.HIGH.name]


def test_an_unrelated_jinja_file_is_not_a_chat_template(tmp_path: Path) -> None:
    # A web template using `{% extends %}` is not this rule's business; scanning
    # every `.jinja` in a repo would be general template security, not AI risk.
    (tmp_path / "page.jinja").write_text("{% extends 'base.jinja' %}")
    assert _run(tmp_path) == []


def test_an_unreadable_gguf_is_reported_as_unscanned(tmp_path: Path) -> None:
    (tmp_path / "broken.gguf").write_bytes(b"GGUF\x03\x00\x00\x00 truncated")
    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.LOW]
    assert findings[0].verdict is not None
    assert "not scanned" in findings[0].evidence.summary


def test_an_unparseable_tokenizer_config_is_reported_as_unscanned(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text("{ not json")
    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.LOW]


def test_a_gguf_without_a_chat_template_is_clean(tmp_path: Path) -> None:
    # Silence is correct here and only here: the file was read and understood,
    # and it carries no template. That is different from "could not be read".
    (tmp_path / "base.gguf").write_bytes(build_gguf({"general.architecture": "llama"}))
    assert _run(tmp_path) == []


def test_a_config_whose_template_is_an_unreadable_shape_is_not_cleared(tmp_path: Path) -> None:
    # The key is there, so the model does have a template — we just cannot read
    # the shape it is written in. That is an open question, not an all-clear.
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"chat_template": 42}))
    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.LOW]
    assert "cannot read" in findings[0].evidence.summary


def test_a_named_list_of_unreadable_entries_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"chat_template": [1, 2]}))
    assert _severities(tmp_path) == [Severity.LOW.name]


def test_a_config_that_is_not_a_json_object_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text("[1, 2, 3]")
    assert _severities(tmp_path) == [Severity.LOW.name]


def test_a_config_without_a_template_is_clean(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"model_max_length": 4096}))
    assert _run(tmp_path) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_an_unreadable_template_file_is_not_cleared(tmp_path: Path) -> None:
    # A FIFO named like a template: reading it would block forever, so it is
    # skipped — but skipped loudly.
    os.mkfifo(tmp_path / "chat_template.jinja")
    assert _severities(tmp_path) == [Severity.LOW.name]


def test_a_template_padded_past_the_read_bound_is_not_cleared(tmp_path: Path) -> None:
    # Padding the file so the gadget falls outside the read bound is the obvious
    # evasion once a scanner is known. A partial read must not read as clean.
    (tmp_path / "chat_template.jinja").write_text("{{ 'x' }}\n" + " " * (16 * 1024 * 1024))
    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.LOW]
    assert "read bound" in findings[0].evidence.summary


def test_an_endpoint_target_is_not_this_rules_business() -> None:
    endpoint = EndpointTarget("http://x", "m", transport=RefusingTransport())
    assert list(ChatTemplateRule().run(endpoint, RuleContext())) == []


def test_model_format_no_longer_reports_on_gguf(tmp_path: Path) -> None:
    # Ownership moved: two rules firing on one template would give the user two
    # findings with different severities for a single fact.
    (tmp_path / "m.gguf").write_bytes(build_gguf({_KEY: _PAYLOAD}))
    assert list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext())) == []

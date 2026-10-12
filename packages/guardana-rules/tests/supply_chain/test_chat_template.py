import json
import os
from pathlib import Path

import pytest
from guardana.core.report import Finding, ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, EndpointTarget
from guardana.core.testing import RefusingTransport, build_gguf
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES
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


def _unread(root: Path) -> list[str]:
    """The files the rule names as unread components when run over `root`."""
    ctx = RuleContext()
    list(ChatTemplateRule().run(ArtifactTarget(root), ctx))
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.chat_template could not read it: ")
    ]


def _run(root: Path) -> list[Finding]:
    return list(ChatTemplateRule().run(ArtifactTarget(root), RuleContext()))


def _severities(root: Path) -> list[str]:
    return [f.severity.name for f in ChatTemplateRule().run(ArtifactTarget(root), RuleContext())]


def test_flags_a_gadget_in_a_gguf_chat_template(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(build_gguf({_KEY: _PAYLOAD}))
    assert _severities(tmp_path) == [Severity.CRITICAL.name]


def test_flags_a_gadget_in_a_named_gguf_chat_template(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(
        build_gguf({_KEY: _REAL_TEMPLATE, f"{_KEY}.tool_use": _PAYLOAD})
    )

    findings = _run(tmp_path)

    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert f"source={_KEY}.tool_use " in findings[0].evidence.detail


def test_a_clean_named_gguf_chat_template_is_clean(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(
        build_gguf({_KEY: _REAL_TEMPLATE, f"{_KEY}.tool_use": _REAL_TEMPLATE})
    )

    assert _run(tmp_path) == []


def test_a_key_that_only_shares_the_prefix_is_not_a_template(tmp_path: Path) -> None:
    (tmp_path / "m.gguf").write_bytes(build_gguf({f"{_KEY}s": _PAYLOAD}))

    assert _run(tmp_path) == []


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


def test_every_additional_chat_template_is_read(tmp_path: Path) -> None:
    """transformers loads each `additional_chat_templates/*.jinja`, `default` ahead of the rest."""
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"chat_template": "{{ x }}"}))
    extra = tmp_path / "additional_chat_templates"
    extra.mkdir()
    (extra / "default.jinja").write_text(_PAYLOAD)
    (extra / "tool_use.jinja").write_text("{{ cycler.__init__.__globals__ }}")
    (extra / "rag.jinja").write_text(_REAL_TEMPLATE)

    findings = _run(tmp_path)

    assert sorted(Path(f.target_ref).name for f in findings) == ["default.jinja", "tool_use.jinja"]
    assert {f.severity for f in findings} == {Severity.CRITICAL}


def test_an_unreadable_additional_chat_template_is_not_cleared(tmp_path: Path) -> None:
    extra = tmp_path / "additional_chat_templates"
    extra.mkdir()
    (extra / "default.jinja").write_text("{{ 'x' }}\n" + " " * (MAX_SCAN_BYTES + 1))

    assert _unread(tmp_path) == [str(extra / "default.jinja")]


def test_a_jinja_file_beside_a_template_directory_of_another_name_is_not_read(
    tmp_path: Path,
) -> None:
    pages = tmp_path / "templates"
    pages.mkdir()
    (pages / "default.jinja").write_text("{% include 'base.jinja' %}")

    assert _run(tmp_path) == []


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
    assert _unread(tmp_path) == [str(tmp_path / "broken.gguf")]


def test_an_unparseable_tokenizer_config_is_reported_as_unscanned(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text("{ not json")
    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity for f in findings] == [Severity.LOW]
    assert _unread(tmp_path) == [str(tmp_path / "tokenizer_config.json")]


def test_a_gguf_without_a_chat_template_is_clean(tmp_path: Path) -> None:
    # Silence is correct here and only here: the file was read and understood,
    # and it carries no template. That is different from "could not be read".
    (tmp_path / "base.gguf").write_bytes(build_gguf({"general.architecture": "llama"}))
    assert _run(tmp_path) == []
    assert _unread(tmp_path) == []


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


@pytest.mark.parametrize(
    "entry",
    [42, {"name": "tools"}, {"name": "tools", "template": 7}, "bare string"],
    ids=["number", "no-template", "template-not-a-string", "string"],
)
def test_a_readable_template_does_not_hide_an_unreadable_sibling(
    tmp_path: Path, entry: object
) -> None:
    document = {"chat_template": [{"name": "default", "template": "plain"}, entry]}
    (tmp_path / "tokenizer_config.json").write_text(json.dumps(document))

    findings = _run(tmp_path)

    assert [f.severity for f in findings] == [Severity.LOW]
    assert "entry 1" in findings[0].evidence.summary
    assert _unread(tmp_path) == [str(tmp_path / "tokenizer_config.json")]


def test_a_gadget_and_every_unreadable_entry_beside_it_are_both_reported(tmp_path: Path) -> None:
    document = {"chat_template": [42, {"name": "rag", "template": _PAYLOAD}, None]}
    (tmp_path / "tokenizer_config.json").write_text(json.dumps(document))

    findings = _run(tmp_path)

    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]
    assert "entries 0, 2" in findings[1].evidence.summary


def test_a_config_that_is_not_a_json_object_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text("[1, 2, 3]")
    assert _severities(tmp_path) == [Severity.LOW.name]


def test_a_config_nested_too_deep_to_parse_is_not_cleared(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text("[" * 200_000)

    assert _unread(tmp_path) == [str(tmp_path / "tokenizer_config.json")]


def test_a_config_without_a_template_is_clean(tmp_path: Path) -> None:
    (tmp_path / "tokenizer_config.json").write_text(json.dumps({"model_max_length": 4096}))
    assert _run(tmp_path) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_an_unreadable_template_file_is_not_cleared(tmp_path: Path) -> None:
    # A FIFO named like a template: reading it would block forever, so it is
    # skipped — but skipped loudly.
    os.mkfifo(tmp_path / "chat_template.jinja")
    assert _severities(tmp_path) == [Severity.LOW.name]
    assert _unread(tmp_path) == [str(tmp_path / "chat_template.jinja")]


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


def test_a_gadget_before_the_read_bound_does_not_hide_the_unread_rest(tmp_path: Path) -> None:
    (tmp_path / "chat_template.jinja").write_text("{% include 'x' %}\n" + " " * MAX_SCAN_BYTES)

    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity for f in findings] == [Severity.HIGH, Severity.LOW]
    assert findings[1].title == "Chat template not scanned"
    assert _unread(tmp_path) == [str(tmp_path / "chat_template.jinja")]


def test_a_tokenizer_config_past_the_read_bound_says_so(tmp_path: Path) -> None:
    document = {"pad": "x" * MAX_SCAN_BYTES, "chat_template": _PAYLOAD}
    (tmp_path / "tokenizer_config.json").write_text(json.dumps(document))

    findings = list(ChatTemplateRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity for f in findings] == [Severity.LOW]
    assert "read bound" in findings[0].evidence.summary

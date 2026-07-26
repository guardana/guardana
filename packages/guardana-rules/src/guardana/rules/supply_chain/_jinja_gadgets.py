"""Detection of Jinja code-execution gadgets in a model's chat template.

A chat template is Jinja source that ships *inside a model artifact* and is
rendered the moment the model is used. Renderers disagree on how carefully:
`transformers` uses a sandbox, `llama-cpp-python` did not (CVE-2024-34359), and
SGLang's rerank path still did in 2026 (CVE-2026-5760) — and the sandbox itself
has been escaped (CVE-2025-27516). So the template's *content* is the signal,
independent of who renders it.

The vocabulary below is deliberately narrow. A chat template arranges messages:
it never reaches for a dunder, never needs the `attr` filter, and never pulls in
another template. Each pattern here is a construct that has no honest use in one.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass

_EXCERPT_RADIUS = 48
_EXCERPT_LIMIT = 120

# Anything that reaches Python's object model. Matched generically rather than by
# an allowlist of names, so `__reduce__`, `__getattribute__` and tomorrow's gadget
# are caught with today's code.
_DUNDER = re.compile(r"__\w+__")
# CVE-2025-27516: `|attr('format')` reaches str.format and escapes the sandboxed
# environment that transformers renders chat templates in.
_ATTR_FILTER = re.compile(r"\|\s*attr\s*\(")
# Jinja globals that exist only as gadget entry points in this context. Note that
# `namespace` and `self` are deliberately absent: real templates use `namespace()`
# for loop-carried state, and flagging it would be false-positive theatre.
_JINJA_GLOBAL = re.compile(r"\b(?:lipsum|cycler|joiner)\b")
_CODE_SINK = re.compile(
    r"\bos\.\w|\bsubprocess\b|\bpopen\s*\(|\bsystem\s*\(|\beval\s*\(|\bexec\s*\("
    r"|\b__import__\b|\bimport_module\b"
)
# Pulls in another template. Chat templates are standalone strings rendered with
# no loader configured, so an inclusion is either broken or an attempt to fetch
# instructions from somewhere the reviewer is not looking.
_INCLUSION = re.compile(r"{%-?\s*(?:include|extends|import|from)\b")

_CRITICAL_GADGETS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dunder-chain", _DUNDER),
    ("attr-filter", _ATTR_FILTER),
    ("jinja-global", _JINJA_GLOBAL),
    ("code-sink", _CODE_SINK),
)
_SUSPECT_GADGETS: tuple[tuple[str, re.Pattern[str]], ...] = (("template-inclusion", _INCLUSION),)


@dataclass(frozen=True)
class Gadget:
    """One code-execution construct found in a template."""

    kind: str
    excerpt: str
    offset: int
    critical: bool


def jinja_gadgets(template: str) -> Iterator[Gadget]:
    """Yield each distinct gadget construct in `template`, most severe first.

    One `Gadget` per construct kind, not per occurrence: a payload repeating
    `__globals__` four times is one finding's worth of evidence, not four.
    """
    for critical, table in ((True, _CRITICAL_GADGETS), (False, _SUSPECT_GADGETS)):
        for kind, pattern in table:
            match = pattern.search(template)
            if match is not None:
                yield Gadget(
                    kind=kind,
                    excerpt=_excerpt(template, match.start(), match.end()),
                    offset=match.start(),
                    critical=critical,
                )


def _excerpt(template: str, start: int, end: int) -> str:
    window = template[max(0, start - _EXCERPT_RADIUS) : end + _EXCERPT_RADIUS]
    return " ".join(window.split())[:_EXCERPT_LIMIT]

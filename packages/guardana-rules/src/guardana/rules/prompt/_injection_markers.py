"""Shared detectors for smuggled instructions — the core of indirect prompt injection.

Any file whose text is later fed to a model as trusted context (an MCP tool
manifest, an agent rules file, a model card, a README) can carry instructions a
human reviewer never sees: invisible Unicode, or an override phrase buried in
prose. These detectors are shared so every rule that scans such text agrees on
what "hidden instruction" means, instead of each re-inventing the vocabulary.
"""

import re
import unicodedata

# An instruction that tries to override the surrounding context. Greppable phrases
# that are far more common in an injection than in honest documentation.
OVERRIDE_PHRASE = re.compile(
    r"ignore\s+(all\s+|the\s+)?previous"
    r"|disregard\s+(the\s+)?(above|previous|prior)"
    r"|previous\s+instructions?\s+(are\s+)?(outdated|void|no longer)"
    r"|do\s+not\s+(tell|mention|inform|reveal)"
    r"|forget\s+(everything|all|your)"
    r"|<important>",
    re.IGNORECASE,
)


def has_hidden_char(text: str) -> bool:
    """Report whether the text carries an invisible control/format char (a smuggling vector).

    A blanket "Unicode category C" test — right for a short MCP tool description,
    where any control char is anomalous.
    """
    return any(unicodedata.category(ch)[0] == "C" and ch not in "\t\n\r" for ch in text)


# The narrow set of invisible characters actually used to smuggle instructions,
# spelled as escapes (the literals are themselves control characters a linter
# rightly refuses in source): the bidirectional overrides/isolates (the
# Trojan-Source set), the zero-width space, and the word joiner. Deliberately
# excluded, because each has heavy legitimate use that would make this noisy: the
# emoji joiner U+200D, the Persian/Indic non-joiner U+200C, the byte-order mark
# U+FEFF, and the bidi marks U+200E / U+200F.
_SMUGGLING_CHARS = frozenset(
    chr(cp)
    for cp in (
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,  # bidi embedding / override / pop
        0x2066,
        0x2067,
        0x2068,
        0x2069,  # bidi isolates
        0x200B,
        0x2060,  # zero-width space, word joiner
    )
)
# The Unicode Tags block: an entire invisible copy of ASCII, the channel used to
# smuggle a readable instruction past a human straight into an LLM's context.
_TAG_BLOCK = range(0xE0000, 0xE0080)


def has_smuggled_char(text: str) -> bool:
    """Report whether the text carries an instruction-smuggling invisible character.

    Calibrated for prose files (READMEs, model cards, agent rule files): the bidi
    controls, the zero-width space/word joiner, and the Unicode Tags block. Emoji
    joiners, non-joiners, and byte-order marks are not flagged, so it stays quiet
    on honest documentation — a blanket "category C" test would not.
    """
    return any(ch in _SMUGGLING_CHARS or ord(ch) in _TAG_BLOCK for ch in text)

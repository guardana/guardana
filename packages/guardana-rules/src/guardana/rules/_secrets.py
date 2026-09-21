"""Secret-shape patterns and redaction shared by the two secret-scanning rules.

Precision over recall: every pattern is prefix-anchored or structurally
unambiguous — no bare-entropy matching. A false positive here is worse than
a missed secret (no theater).
"""

import heapq
import re
from collections.abc import Iterator
from pathlib import Path

# A provider prefix carries no signal in the middle of a word: a corpus token
# such as `risk-clinicalpredictionmodel` holds `sk-` followed by enough letters
# to satisfy the key body, and a vocabulary built from a large corpus always
# holds some. Every prefix shape below therefore starts at a word boundary.
_WORD_START = r"(?<![A-Za-z0-9_])"


def _prefix_shape(source: str) -> re.Pattern[str]:
    """Compile a prefix-anchored secret shape that may only start a word."""
    return re.compile(_WORD_START + source)


# The `sk-…` family: OpenAI's current default (`sk-proj-`), service accounts
# (`sk-svcacct-`), Anthropic (`sk-ant-api03-`), and the legacy bare form. The
# optional prefix group carries the `-` these keys use; the body itself is
# alphanumeric, so it stays `[A-Za-z0-9]` — allowing `-`/`_` there would flag any
# long kebab/snake identifier as a secret (a false positive precision forbids).
_LLM_API_KEY = _prefix_shape(r"sk-(?:proj-|svcacct-|ant-api\d+-)?[A-Za-z0-9]{20,}")

_COMMON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key ID", _prefix_shape(r"AKIA[0-9A-Z]{16}")),
    # ghp_ (PAT), gho_ (OAuth), ghu_/ghs_ (user/server-to-server), ghr_ (refresh).
    ("GitHub token", _prefix_shape(r"gh[oprsu]_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained token", _prefix_shape(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("Slack token", _prefix_shape(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", _prefix_shape(r"AIza[0-9A-Za-z_\-]{35}")),
    ("LLM provider API key", _LLM_API_KEY),
)

# The PEM header covers the labels OpenSSH, OpenSSL, and GnuPG actually emit.
_PRIVATE_KEY_LABEL = r"(?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?"

# The private-key pattern deliberately differs per scan surface: a bare header
# in a repository file is routinely a truncated documentation example, so the
# file scan demands a real key body; a live endpoint reply is often truncated
# mid-leak, so there even the header alone is signal.
_PRIVATE_KEY_WITH_BODY = (
    "private key header",
    re.compile(rf"-----BEGIN {_PRIVATE_KEY_LABEL}-----\s*(?:[A-Za-z0-9+/=\s]{{100,}})-----END"),
)
_PRIVATE_KEY_HEADER = (
    "private key header",
    re.compile(rf"-----BEGIN {_PRIVATE_KEY_LABEL}-----"),
)

FILE_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    _PRIVATE_KEY_WITH_BODY,
    *_COMMON_PATTERNS,
)
REPLY_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    _PRIVATE_KEY_HEADER,
    *_COMMON_PATTERNS,
)

# Well-known public example values — documentation fixtures, never real
# secrets. Applied to both scan surfaces: quoting AWS's canonical example
# key is citation, not leakage. Every entry must be matchable by some pattern
# above (a test enforces this), so the AWS *secret*-key example — which no
# pattern emits — is not listed here.
ALLOWLIST: frozenset[str] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
    }
)

# One pattern hit: where it starts, where it ends, what it looks like, what it says.
SecretMatch = tuple[int, int, str, str]


def _tagged(label: str, pattern: re.Pattern[str], text: str) -> Iterator[SecretMatch]:
    """Tag one pattern's hits with its own label.

    A function rather than a nested generator expression: a comprehension shares one
    binding across every generator it builds, so the labels would all read as the
    last pattern's by the time the merge consumed them — a GitHub token reported as
    a provider API key, which is a finding that names the wrong secret.
    """
    return ((m.start(), m.end(), label, m.group(0)) for m in pattern.finditer(text))


def find_secret_matches(
    text: str, patterns: tuple[tuple[str, re.Pattern[str]], ...]
) -> Iterator[SecretMatch]:
    """Yield every pattern hit outside the allowlist, ordered by position in the text.

    The per-pattern scans are merged lazily rather than collected, so a file holds
    one pending match per pattern however many hits it contains.
    """
    streams = [_tagged(label, pattern, text) for label, pattern in patterns]
    for match in heapq.merge(*streams):
        if match[3] not in ALLOWLIST:
            yield match


REDACT_PREFIX_LEN = 6


def redact(secret: str) -> str:
    """Keep only a short identifying prefix — evidence must never carry the secret."""
    return f"{secret[:REDACT_PREFIX_LEN]}…"


# Text-like config/source suffixes both secret-scanning rules cover. Deliberately
# excludes markdown/docs and binaries/model formats — a served model is fronted by
# a Node/Go/Java gateway as often as a Python one, so web/systems source is in.

TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".py",
        ".pyi",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".txt",
        ".sh",
        ".bash",
        ".zsh",
        ".properties",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rb",
        ".java",
        ".kt",
        ".rs",
        ".php",
        ".cs",
        ".tf",
        ".tfvars",
        ".gradle",
        ".xml",
        ".vue",
        ".svelte",
    }
)

# `Path.suffix` never matches a file literally named ".env" or ".env.local"
# (it treats the whole name as the stem for dotfiles), so those are matched by name.
_ENV_DOTFILE = re.compile(r"^\.env(\..+)?$")


def is_scannable_text(path: Path) -> bool:
    """Whether a path is a text-like source/config file worth a secret scan."""
    return path.suffix in TEXT_SUFFIXES or bool(_ENV_DOTFILE.match(path.name))

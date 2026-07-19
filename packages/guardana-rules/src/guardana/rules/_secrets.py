"""Secret-shape patterns and redaction shared by the two secret-scanning rules.

Precision over recall: every pattern is prefix-anchored or structurally
unambiguous — no bare-entropy matching. A false positive here is worse than
a missed secret (no theater).
"""

import re

# The `sk-…` family: OpenAI's current default (`sk-proj-`), service accounts
# (`sk-svcacct-`), Anthropic (`sk-ant-api03-`), and the legacy bare form. The
# optional prefix group carries the `-` these keys use; the body itself is
# alphanumeric, so it stays `[A-Za-z0-9]` — allowing `-`/`_` there would flag any
# long kebab/snake identifier as a secret (a false positive precision forbids).
_LLM_API_KEY = re.compile(r"sk-(?:proj-|svcacct-|ant-api\d+-)?[A-Za-z0-9]{20,}")

_COMMON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    # ghp_ (PAT), gho_ (OAuth), ghu_/ghs_ (user/server-to-server), ghr_ (refresh).
    ("GitHub token", re.compile(r"gh[oprsu]_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
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

REDACT_PREFIX_LEN = 6


def redact(secret: str) -> str:
    """Keep only a short identifying prefix — evidence must never carry the secret."""
    return f"{secret[:REDACT_PREFIX_LEN]}…"

"""A repository that looks like somebody's, with every file labelled.

The dogfood scan proves Guardana finds nothing in Guardana. That is worth having and it
says nothing about noise: this repository does not look like the ones people point a
scanner at, so a rule that fires on a documentation example, a test fixture or an
environment-variable lookup would pass it untouched. An organisation that excludes a
noisy scanner has an organisation-level fail-open, so the false-alarm rate is a security
property here and it is measured like one.

Every file carries a label and none of the three is a guess:

- **`Planted`** names the rule that must fire on it. A plant nobody finds is coverage
  that quietly went away between releases.
- **`Decoy`** says why it looks like a finding and is not. Several are near-misses on
  purpose — a docstring warning against `trust_remote_code=True`, a documentation page
  showing the shape of a provider key, a plaintext URL nothing fetches — because the
  easy negatives are the ones a rule was already never going to fire on.
- **`Missed`** is a hole this build does not see, written down rather than left out.
  Building this ground found one, and a gap nobody records is a gap that reads as
  coverage; the test asserting it is *still* missed is what makes closing it visible.

**Nothing here contains a real credential or a literal a scanner matches**, which is why
the payloads are assembled rather than written out: the same reason
`test_trace_rules.py` builds its key as `"sk-proj-" + "A" * 24`. A fixture that tripped
the dogfood scan would be a fixture nobody could keep.
"""

import json
from dataclasses import dataclass
from pathlib import Path

_FAKE_KEY = "sk-proj-" + "9dPqL2mNxR7vT4wY8bK1cF6h"
"""Assembled, so this file carries no literal the secret rule matches."""

_DANGEROUS_PICKLE = (
    b"\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05"
    + b"posix"
    + b"\x94\x8c\x06"
    + b"system"
    + b"\x94\x93\x94\x8c\x07id > /tmp\x94\x85\x94R\x94."
)
"""A pickle whose load calls out to the shell, assembled the same way and never loaded."""

_SAFE_PICKLE = (
    b"\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04size\x94K\x02\x8c"
    b"\x05vocab\x94]\x94(\x8c\x01a\x94\x8c\x01b\x94es."
)
"""The same file type carrying a dictionary: a tokenizer, and nothing to execute."""


@dataclass(frozen=True, slots=True)
class Planted:
    """A file that must produce a finding, and which rule has to produce it."""

    path: str
    rule_id: str
    why: str
    content: bytes


@dataclass(frozen=True, slots=True)
class Missed:
    """A file that should produce a finding and does not, with the reason it does not.

    Recorded rather than quietly excluded. A scanner's real coverage is what it finds,
    not what its rule list implies, and the difference belongs somewhere a reader can
    see it — beside the plants, in the same list, under its own name.
    """

    path: str
    rule_id: str
    why: str
    content: bytes


@dataclass(frozen=True, slots=True)
class Decoy:
    """A file that must produce no finding, and why it looks like one."""

    path: str
    why: str
    content: bytes


def _text(body: str) -> bytes:
    return body.encode("utf-8")


PLANTED: tuple[Planted, ...] = (
    Planted(
        path="app/config.py",
        rule_id="guardana.supply_chain.hardcoded_secret",
        why="a provider key assigned to a module-level constant, in the shape a provider issues",
        content=_text(
            f'"""Runtime configuration."""\n\nOPENAI_API_KEY = "{_FAKE_KEY}"\nMODEL = "gpt-4o"\n'
        ),
    ),
    Planted(
        path="app/loader.py",
        rule_id="guardana.supply_chain.remote_code",
        why="`trust_remote_code=True` runs code from whoever published the model repository",
        content=_text(
            "from transformers import AutoModel\n\n\n"
            "def load(name: str):\n"
            "    return AutoModel.from_pretrained(name, trust_remote_code=True)\n"
        ),
    ),
    Planted(
        path="app/loader.py",
        rule_id="guardana.supply_chain.provenance",
        why="the same call names no revision, so the bytes it fetches can change under the team",
        content=b"",
    ),
    Planted(
        path="app/sync.py",
        rule_id="guardana.supply_chain.insecure_transport",
        why="a model index fetched over plaintext, which anybody on the path can rewrite",
        content=_text(
            "import httpx\n\n\n"
            "def pull_index():\n"
            '    return httpx.get("http://models.internal.example/index.json")\n'
        ),
    ),
    Planted(
        path="models/embed.pkl",
        rule_id="guardana.supply_chain.pickle_opcode",
        why="loading the weights would run a shell command",
        content=_DANGEROUS_PICKLE,
    ),
    Planted(
        path="models/tokenizer_config.json",
        rule_id="guardana.supply_chain.chat_template",
        why="the chat template walks a dunder chain to a code sink when it renders",
        content=json.dumps(
            {
                "chat_template": (
                    "{% for m in messages %}{{ m.content }}{% endfor %}"
                    "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
                ),
                "model_max_length": 4096,
            }
        ).encode("utf-8"),
    ),
    Planted(
        path="notebooks/explore.ipynb",
        rule_id="guardana.supply_chain.notebook_payload",
        why="a cell decodes a base64 blob and executes it",
        content=json.dumps(
            {
                "cells": [
                    {
                        "cell_type": "code",
                        "execution_count": 1,
                        "metadata": {},
                        "outputs": [],
                        "source": [
                            "import os\n",
                            "exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n",
                        ],
                    }
                ],
                "metadata": {},
                "nbformat": 4,
                "nbformat_minor": 5,
            }
        ).encode("utf-8"),
    ),
)

MISSED: tuple[Missed, ...] = (
    Missed(
        path="app/mirror.py",
        rule_id="guardana.supply_chain.insecure_transport",
        why=(
            "the plaintext URL reaches the fetch through a module constant, and the rule "
            "reads the literal at the call site. It says so about a bare string — an "
            "`http://` label is not a download — and following one assignment into a call "
            "is a different piece of analysis, with its own way of being wrong"
        ),
        content=_text(
            "import httpx\n\n"
            'MIRROR = "http://models.internal.example/index.json"\n\n\n'
            "def pull_index():\n"
            "    return httpx.get(MIRROR)\n"
        ),
    ),
)

DECOYS: tuple[Decoy, ...] = (
    Decoy(
        path="app/settings.py",
        why="a credential read from the environment is a credential nobody committed",
        content=_text(
            '"""Settings read from the environment, which is where a credential belongs."""\n\n'
            "import os\n\n"
            'api_key = os.environ["SUPPORT_API_KEY"]\n'
            'database_url = os.environ.get("DATABASE_URL", "postgresql://localhost/support")\n'
        ),
    ),
    Decoy(
        path="app/safe_loader.py",
        why=(
            "its docstring names `trust_remote_code=True` to warn against it, and the call "
            "passes False with a pinned revision — prose about a flag is not the flag"
        ),
        content=_text(
            "from transformers import AutoModel\n\n\n"
            "def load(name: str, revision: str):\n"
            '    """Load a pinned model.\n\n'
            "    `trust_remote_code=True` is never used here: the flag runs arbitrary code\n"
            "    from the model repository at load time.\n"
            '    """\n'
            "    return AutoModel.from_pretrained(\n"
            "        name, revision=revision, trust_remote_code=False\n"
            "    )\n"
        ),
    ),
    Decoy(
        path="app/legacy.py",
        why=(
            "a plaintext URL in a constant that nothing fetches — an `http://` string is a "
            "label until something downloads through it"
        ),
        content=_text('BILLING_LEGACY = "http://billing.internal.example/v1"\n'),
    ),
    Decoy(
        path="app/client.py",
        why="every call goes over TLS, which is what the transport rule is looking for",
        content=_text(
            "import httpx\n\n"
            'BILLING = "https://billing.internal.example/v1"\n\n\n'
            "def call(path: str) -> httpx.Response:\n"
            '    return httpx.get(f"{BILLING}{path}", timeout=10)\n'
        ),
    ),
    Decoy(
        path="app/version.py",
        why="a commit sha and a uuid are high-entropy strings and neither is a credential",
        content=_text(
            'BUILD_COMMIT = "4f2b8c1e9a7d3f6b0c5e8a2d4f7b1c9e3a6d0f5b"\n'
            'BUILD_ID = "9f8e7d6c-5b4a-4392-8172-0a1b2c3d4e5f"\n'
        ),
    ),
    Decoy(
        path="app/redacted.json",
        why="a placeholder where a token goes is the opposite of a leaked token",
        content=_text(
            '{"provider": "internal", "token": "<redacted>", '
            '"endpoint": "https://api.internal.example"}\n'
        ),
    ),
    Decoy(
        path="docs/setup.md",
        why="AWS's own documented example key — quoting it is citation, not disclosure",
        content=_text(
            "# Setup\n\nThe AWS docs use the example key `AKIAIOSFODNN7EXAMPLE` with secret\n"
            "`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`; never commit a real one.\n"
        ),
    ),
    Decoy(
        path="docs/troubleshooting.md",
        why=(
            "documentation showing the shape of a provider key and warning against a "
            "dangerous flag — the page a team writes to prevent both findings"
        ),
        content=_text(
            "# Troubleshooting\n\n"
            f"A provider key looks like `{_FAKE_KEY}`; ours is in the secret manager.\n\n"
            "Do **not** pass `trust_remote_code=True` to work around a loading error.\n"
        ),
    ),
    Decoy(
        path=".env.example",
        why="a template of variable names with placeholder values, committed on purpose",
        content=_text("SUPPORT_API_KEY=changeme\nDATABASE_URL=postgresql://user:password@db/app\n"),
    ),
    Decoy(
        path="tests/conftest.py",
        why="an obviously fabricated key in a test fixture, which is how tests are written",
        content=_text(
            "import pytest\n\n\n"
            "@pytest.fixture\n"
            "def fake_key() -> str:\n"
            '    return "sk-test-" + "0" * 32\n'
        ),
    ),
    Decoy(
        path="models/tokenizer.pkl",
        why="the same file extension as the planted one, carrying a dictionary and no callable",
        content=_SAFE_PICKLE,
    ),
    Decoy(
        path="scripts/fetch.sh",
        why="a download over TLS in a shell script",
        content=_text(
            "#!/bin/sh\n"
            "curl -fsSL https://models.internal.example/embed.safetensors -o embed.safetensors\n"
        ),
    ),
    Decoy(
        path="assets/logo.py",
        why="a base64 data URI is a long high-entropy string and it is a one-pixel image",
        content=_text(
            'LOGO = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ'
            'AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="\n'
        ),
    ),
    Decoy(
        path="requirements.txt",
        why="ordinary pinned dependencies, none of them yanked, typosquatted or invented",
        content=_text("httpx==0.27.0\ntransformers==4.44.2\nnumpy==1.26.4\n"),
    ),
    Decoy(
        path="requirements-dev.txt",
        why="the same, for the development set",
        content=_text("requests==2.32.3\npytest==8.3.2\nruff==0.6.2\n"),
    ),
)


Marked = Planted | Missed | Decoy
"""Any labelled file: the three labels differ in what they claim, not in what they are."""


def build(root: Path) -> Path:
    """Materialise the proving ground under `root` and hand back its path.

    Built here rather than checked in, so review reads one labelled list instead of a
    directory of files whose purpose has to be inferred — and so no payload sits in the
    repository waiting to be mistaken for a real one.
    """
    marked_files: tuple[Marked, ...] = (*PLANTED, *MISSED, *DECOYS)
    for marked in marked_files:
        if not marked.content:
            continue
        path = root / marked.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(marked.content)
    return root

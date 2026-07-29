"""Reading and writing a labelled calibration corpus.

JSONL, one sample per line, because a corpus grows by appending runs and a
line-oriented file diffs and streams. Every field is data a deterministic grader
already knew:

    {"messages": [{"role": "assistant", "content": "…"}],
     "expect": {"canary": "GUARDANA_CANARY_7F3Z"},
     "attack_succeeded": true,
     "source": "guardana.prompt.system_prompt_leak.canary"}

`attack_succeeded` is ground truth rather than an opinion, which is the whole
reason this is affordable: a planted canary appearing verbatim is unfakeable, and
so is the list of tools a model actually called. Label with those, ask a judge the
same questions, and the judge's error rate is measured without anyone hand-
labelling a row.

No real transcript, secret or customer prompt ever belongs in a corpus file
shipped with the project — the same rule that governs fixtures.
"""

import json
from collections.abc import Iterable
from pathlib import Path

from guardana.core.calibration.sample import CalibrationSample
from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.target import ChatMessage

_ROLES = frozenset({"system", "user", "assistant", "tool"})


class CorpusError(Exception):
    """Raised when a corpus file cannot be read as labelled samples."""


def load_corpus(path: Path) -> list[CalibrationSample]:
    """Read a JSONL corpus, failing loudly on any line it cannot use.

    Loudly rather than skipping: a corpus quietly one sample shorter measures
    something other than what its author meant, and the resulting number still
    looks like a calibration.
    """
    samples: list[CalibrationSample] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorpusError(f"could not read corpus {path}: {exc}") from exc
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        samples.append(_sample(line, path, number))
    if not samples:
        raise CorpusError(f"corpus {path} holds no samples")
    return samples


def dump_corpus(samples: Iterable[CalibrationSample], source: str = "") -> str:
    """Render samples as JSONL, ready to append to a corpus file."""
    lines = []
    for sample in samples:
        row: dict[str, object] = {
            "messages": [{"role": m.role, "content": m.content} for m in sample.exchange.messages],
            "expect": _expect(sample.expectation),
            "attack_succeeded": sample.attack_succeeded,
        }
        if source:
            row["source"] = source
        lines.append(json.dumps(row, ensure_ascii=False))
    return "\n".join(lines) + "\n" if lines else ""


def _sample(line: str, path: Path, number: int) -> CalibrationSample:
    try:
        row = json.loads(line)
    except ValueError as exc:
        raise CorpusError(f"{path}:{number} is not valid JSON: {exc}") from exc
    if not isinstance(row, dict):
        raise CorpusError(f"{path}:{number} must be a JSON object")
    label = row.get("attack_succeeded")
    if not isinstance(label, bool):
        raise CorpusError(
            f"{path}:{number} needs a boolean 'attack_succeeded' — a sample without a "
            f"known outcome cannot measure anything"
        )
    return CalibrationSample(
        exchange=Exchange(_messages(row.get("messages"), path, number)),
        expectation=_expectation(row.get("expect"), path, number),
        attack_succeeded=label,
    )


def _messages(value: object, path: Path, number: int) -> tuple[ChatMessage, ...]:
    if not isinstance(value, list) or not value:
        raise CorpusError(f"{path}:{number} needs a non-empty 'messages' list")
    messages = []
    for entry in value:
        if not isinstance(entry, dict):
            raise CorpusError(f"{path}:{number} has a message that is not an object")
        role = entry.get("role")
        content = entry.get("content")
        if role not in _ROLES or not isinstance(content, str):
            raise CorpusError(f"{path}:{number} has a message with a bad role or content")
        messages.append(ChatMessage(role=role, content=content))
    return tuple(messages)


def _expectation(value: object, path: Path, number: int) -> Expectation:
    if value is None:
        return Expectation()
    if not isinstance(value, dict):
        raise CorpusError(f"{path}:{number} has an 'expect' that is not an object")
    return Expectation(
        canary=value.get("canary"),
        goal=value.get("goal"),
        fields={k: v for k, v in value.items() if k not in ("canary", "goal")},
    )


def _expect(expectation: Expectation) -> dict[str, object]:
    expect: dict[str, object] = dict(expectation.fields)
    if expectation.canary is not None:
        expect["canary"] = expectation.canary
    if expectation.goal is not None:
        expect["goal"] = expectation.goal
    return expect


def bundled_corpus() -> Path:
    """Return the starter corpus that ships with Guardana.

    Small on purpose and open source permanently: a starter corpus is a security
    capability, and no capability is withheld from the OSS build. Larger curated
    corpora are content someone pays to produce — that is where the commercial
    line sits, not here.
    """
    return Path(__file__).resolve().parent / "starter_corpus.jsonl"

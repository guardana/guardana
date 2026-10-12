import io
import json
import os
import re
import struct
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO

from guardana.core.formats import find_hdf5_signature
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
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
    OWASP_ML06_2023,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._leads import unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import (
    LFS_POINTER_REASON,
    is_lfs_pointer,
    open_regular,
    read_bytes_bounded,
)
from guardana.rules.supply_chain._zip import (
    ARCHIVE_MAX_ENTRIES,
    ZIP_DIRECTORY_MAX_BYTES,
    ZIP_ERRORS,
    listing_refusal,
)

# A Keras `Lambda` layer wraps an arbitrary Python callable that runs on
# `load_model` — a code-execution primitive, no inference needed. `safe_mode` is
# bypassable (CVE-2025-1550, and CVE-2025-9905 shows load_model ignores it for
# `.h5`), so the layer's mere presence is the signal.
_LAMBDA = "Lambda"
# If a Lambda's serialized body references one of these, it is almost certainly
# malicious rather than a benign in-graph tensor op — Keras 3.9's own fix draws
# the same line by whitelisting Keras-internal modules only.
_DANGEROUS_MODULES = ("os", "subprocess", "sys", "socket", "shutil", "pty", "importlib")
_MAX_CONFIG_BYTES = 16 * 1024 * 1024
# The module hint on a byte-level match is best-effort: the finding never depends
# on it, so its decoding is bounded per marker and in total parsed characters.
_ATTEMPTS_PER_MARKER = 16
_DECODE_BUDGET_FACTOR = 2
_DECODER = json.JSONDecoder()
_UNSCANNED_TITLE = "Keras model not scanned"
_HDF5_SUFFIXES = (".h5", ".hdf5")
# tf_keras loads any HDF5 file as a model whatever it is called, so these names,
# which other formats share, are read when their bytes are an HDF5 file.
_HDF5_SNIFFED_SUFFIXES = (".bin", ".model", ".hdf", ".weights", ".tf")
# An unzipped Keras model is a directory holding `config.json`; one beside either
# of Keras' own files is read, while a lone `config.json` belongs to anything.
_DIRECTORY_CONFIG = "config.json"
_DIRECTORY_SIBLINGS = ("metadata.json", "model.weights.h5")


def _json_spelling(word: str) -> bytes:
    """Build a pattern matching every spelling inside a JSON string that decodes to `word`."""
    alternatives = []
    for char in word:
        hex_digits = b"".join(
            b"[" + digit.encode() + digit.upper().encode() + b"]"
            if digit.isalpha()
            else digit.encode()
            for digit in f"{ord(char):04x}"
        )
        alternatives.append(b"(?:" + re.escape(char.encode()) + rb"|\\u" + hex_digits + b")")
    return b"".join(alternatives)


_JSON_STRING_CHAR = rb'(?:[^"\\]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))'

# A Lambda layer declares itself with this key/value pair; matching the bare word
# "Lambda" reported any layer a user happened to *name* "Lambda". Keras resolves a
# dotted class name through its export registry (`layers.Lambda` under module
# `keras`), and reads the config with `json.loads`, so the pattern accepts any
# dotted prefix and every spelling that decoder turns into the pair: any character
# as a unicode escape, JSON whitespace around the colon.
_CLASS_MARKER = re.compile(
    b'"'
    + _json_spelling("class_name")
    + b'"[ \t\n\r]*:[ \t\n\r]*"(?:'
    + _JSON_STRING_CHAR
    + b"*"
    + _json_spelling(".")
    + b")?"
    + _json_spelling(_LAMBDA)
    + b'"'
)
_CLASS_MARKER_TEXT = re.compile(_CLASS_MARKER.pattern.decode("ascii"))


def _is_lambda_class(class_name: object) -> bool:
    """Whether a `class_name` names the Lambda layer, bare or by a dotted export path."""
    return isinstance(class_name, str) and (
        class_name == _LAMBDA or class_name.endswith("." + _LAMBDA)
    )


# Not None: a config whose JSON is `null` was read, and is no model either.
_UNREADABLE = object()


def _iter_lambda_configs(node: object) -> Iterator[object]:
    """Yield the `config` of every object in the tree whose `class_name` is Lambda."""
    if isinstance(node, dict):
        if _is_lambda_class(node.get("class_name")):
            yield node.get("config")
        for value in node.values():
            yield from _iter_lambda_configs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_lambda_configs(item)


def _dangerous_module(config: object) -> str | None:
    """Return a dangerous module name referenced in a Lambda's serialized body, if any."""
    blob = json.dumps(config)
    for module in _DANGEROUS_MODULES:
        if f"'{module}'" in blob or f'"{module}"' in blob or f"import {module}" in blob:
            return module
    return None


def _decode_from(text: str, start: int) -> tuple[object | None, int]:
    """Decode the object opening at `start`; return it, or None, and the characters spent.

    A failed attempt is charged up to where the decoder stopped, or to the end of the
    text when the decoder does not say, so the charge never undercounts the work.
    """
    try:
        value, end = _DECODER.raw_decode(text, start)
    except json.JSONDecodeError as exc:
        return None, exc.pos - start + 1
    except (ValueError, RecursionError):
        return None, len(text) - start
    return value, end - start


def _last_brace(text: str, low: int, high: int) -> int:
    """Return the offset of the last `{` in `text[low:high]`, or -1 if there is none."""
    return text.rfind("{", low, high)


def _module_in_marked_layers(data: bytes) -> str | None:
    """Return a dangerous module a marked Lambda layer references, if one decodes.

    Walks back from each class marker to the nearest `{` whose object decodes and
    holds a Lambda, the layer itself, so its body is read the way Keras reads it.
    No search reaches below the previous marker and the decoder parses a bounded
    multiple of the text, so the work stays linear in the bytes read.
    """
    text = data.decode("utf-8", errors="replace")
    budget = _DECODE_BUDGET_FACTOR * len(text)
    floor = 0
    for marker in _CLASS_MARKER_TEXT.finditer(text):
        brace = marker.start()
        for _ in range(_ATTEMPTS_PER_MARKER):
            brace = _last_brace(text, floor, brace)
            if brace < 0 or budget <= 0:
                break
            layer, spent = _decode_from(text, brace)
            budget -= spent
            if layer is None:
                continue
            try:
                configs = list(_iter_lambda_configs(layer))
                module = next(filter(None, map(_dangerous_module, configs)), None)
            except RecursionError:
                break
            if module is not None:
                return module
            if configs:
                break
        if budget <= 0:
            break
        floor = marker.start()
    return None


class KerasLambdaRule(ArtifactRule):
    """Flag a Keras `Lambda` layer — arbitrary Python that runs when the model loads."""

    meta = RuleMeta(
        id="guardana.supply_chain.keras_lambda",
        title="Keras Lambda layer (arbitrary code on model load)",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            OWASP_ML06_2023,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.INVARIANT,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a `.keras` model with a Lambda layer, one without and one that is no archive."""
        return materialise(
            (
                _samples.sample(
                    "a .keras model declaring a Lambda layer",
                    FixtureOutcome.FINDING,
                    {
                        "model.keras": _samples.keras_archive(
                            [
                                {
                                    "class_name": "Lambda",
                                    "config": {"name": "fn", "function": "lambda x: x"},
                                }
                            ]
                        )
                    },
                ),
                _samples.sample(
                    "a .keras model of Dense layers only",
                    FixtureOutcome.CLEAN,
                    {
                        "model.keras": _samples.keras_archive(
                            [{"class_name": "Dense", "config": {"name": "dense", "units": 1}}]
                        )
                    },
                ),
                _samples.sample(
                    "a .keras file that is not a readable archive",
                    FixtureOutcome.INCONCLUSIVE,
                    {"model.keras": b"not a zip archive"},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Parse Keras configs structurally; scan HDF5 models for the class marker."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".keras",)):
            yield from self._scan_keras(path, ctx)
            ctx.examined(path)
        for path in _directory_configs(target):
            config = _read_json_file(path)
            yield from self._scan_config(path, config, ctx, "not a readable Keras config")
            ctx.examined(path)
        for path in target.iter_files(_HDF5_SUFFIXES):
            yield from self._byte_scan(path, ctx, fallback_reason=None)
            ctx.examined(path)
        for path in target.iter_files(_HDF5_SNIFFED_SUFFIXES):
            if _holds_hdf5_signature(path):
                yield from self._byte_scan(path, ctx, fallback_reason=None)
                ctx.examined(path)

    def _scan_keras(self, path: Path, ctx: RuleContext) -> Iterator[Finding]:
        refusal, config = _checked_keras_config(path)
        if refusal is not None:
            # Listing an archive that declares this much costs more than any model does,
            # so it is never opened; its first bytes are still searched for the marker.
            yield from self._byte_scan(path, ctx, fallback_reason=refusal)
            return
        # Real `.keras` files are zip archives. A file that is not one is malformed, so
        # the byte marker is searched instead: a payload inside a deliberately broken
        # archive must not become invisible.
        yield from self._scan_config(path, config, ctx, "not a readable .keras archive")

    def _scan_config(
        self, path: Path, config: object, ctx: RuleContext, unreadable: str
    ) -> Iterator[Finding]:
        if config is _UNREADABLE:
            yield from self._byte_scan(path, ctx, fallback_reason=unreadable)
            return
        try:
            modules = [_dangerous_module(found) for found in _iter_lambda_configs(config)]
        except RecursionError:
            reason = "its model config is nested too deeply to walk"
            yield from self._byte_scan(path, ctx, fallback_reason=reason)
            return
        for module in modules:
            summary = "Keras Lambda layer runs arbitrary code on load"
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)
        if not modules and not isinstance(config, dict):
            # Keras writes the model as one object; any other root holds no layer to clear.
            yield self._unscanned(path, "the model config is not a JSON object", ctx)

    def _byte_scan(
        self, path: Path, ctx: RuleContext, *, fallback_reason: str | None
    ) -> Iterator[Finding]:
        prefix = read_bytes_bounded(path, _MAX_CONFIG_BYTES)
        if prefix is None:
            yield self._unscanned(path, "file could not be read", ctx)
            return
        data, truncated = prefix
        if _CLASS_MARKER.search(data) is not None:
            # Firm, not a lead: the config declares the layer, and `load_model`
            # ignores `safe_mode` for the legacy format (CVE-2025-9905), so this
            # will execute.
            summary = "model config declares a Lambda layer, which runs on load"
            module = _module_in_marked_layers(data)
            if module is not None:
                summary += f"; references the {module!r} module (near-certain malicious)"
            yield self._finding(path, summary)
        elif not truncated and is_lfs_pointer(data):
            yield self._unscanned(path, LFS_POINTER_REASON, ctx)
        elif fallback_reason is not None:
            yield self._unscanned(path, fallback_reason, ctx)
        elif truncated:
            yield self._unscanned(path, f"only the first {_MAX_CONFIG_BYTES} bytes were read", ctx)

    def _finding(self, path: Path, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=f"file={path.name}"),
        )

    def _unscanned(self, path: Path, reason: str, ctx: RuleContext) -> Finding:
        ctx.shortfall(unread_component(self.meta.id, path, reason))
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"Keras model not scanned for Lambda layers: {reason}",
                detail=f"file={path.name}",
            ),
            verdict=unscanned_verdict("the model config could not be read, so nothing was cleared"),
        )


def _directory_configs(target: FileReader) -> list[Path]:
    """Return each `config.json` the listing holds beside a file only Keras writes, any case."""
    listed = {(path.parent, path.name.lower()) for path in target.iter_files((".json", ".h5"))}
    return [
        path
        for path in target.iter_files((".json",))
        if path.name.lower() == _DIRECTORY_CONFIG
        and any((path.parent, sibling) in listed for sibling in _DIRECTORY_SIBLINGS)
    ]


def _holds_hdf5_signature(path: Path) -> bool:
    """Whether the HDF5 library would open `path`, wherever its userblock puts the signature.

    A signature past the read bound still counts: the byte scan then reports the file
    as read only in part instead of passing over it.
    """
    try:
        if not path.is_file():
            return False
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            return find_hdf5_signature(handle, size) is not None
    except OSError:
        return False


def _read_json_file(path: Path) -> object:
    """Read and parse a JSON file within the read bound; `_UNREADABLE` if unreadable or cut."""
    prefix = read_bytes_bounded(path, _MAX_CONFIG_BYTES)
    if prefix is None or prefix[1]:
        return _UNREADABLE
    try:
        parsed: object = json.loads(prefix[0])
    except (ValueError, RecursionError):
        return _UNREADABLE
    return parsed


def _checked_keras_config(path: Path) -> tuple[str | None, object]:
    """Why a `.keras` archive must not be listed, else its parsed `config.json`.

    Both come from one open handle, so the archive `zipfile` lists is the one the bounds
    were checked on. The config is `_UNREADABLE` when the archive was refused, is not a
    regular file or cannot be read.
    """
    try:
        with io.BufferedReader(open_regular(path)) as handle:
            refusal = listing_refusal(
                handle, max_entries=ARCHIVE_MAX_ENTRIES, max_directory_bytes=ZIP_DIRECTORY_MAX_BYTES
            )
            if refusal is not None:
                return refusal, _UNREADABLE
            return None, _read_keras_config(handle)
    except (OSError, ValueError, OverflowError, struct.error):
        return None, _UNREADABLE


def _read_keras_config(handle: BinaryIO) -> object:
    """Read and parse `config.json` from a `.keras` archive; `_UNREADABLE` if it cannot be."""
    try:
        with zipfile.ZipFile(handle) as archive:
            if "config.json" not in archive.namelist():
                return _UNREADABLE
            with archive.open("config.json") as member:
                raw = member.read(_MAX_CONFIG_BYTES)
        parsed: object = json.loads(raw)
    except (*ZIP_ERRORS, RecursionError):
        return _UNREADABLE
    else:
        return parsed

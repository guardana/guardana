---
title: "Reading model formats"
nav_order: 270
summary: "the public GGUF / safetensors / ONNX readers, and their bounded, fail-closed contract"
status: stable
---

# Reading model formats — `guardana.core.formats`

A rule that inspects a model file needs to read a binary format before it can
say anything about it. Doing that by hand is where scanners get quietly wrong:
a byte-window scan around a keyword both misses payloads that sit further away
and invents findings from unrelated neighbouring bytes. Guardana ships the
parsing so your rule can ship the judgement.

These readers are **public API**. They are what a third-party rule pack is meant
to build on.

```python
from guardana.core.formats import FormatError, read_gguf_metadata

try:
    metadata = read_gguf_metadata(path)
except FormatError as exc:
    ...                                   # report "not scanned" — never silence
template = metadata.text("tokenizer.chat_template")
```

## The contract

Every reader in the package makes the same four promises.

| Promise | What it means for you |
|---|---|
| **Offline** | It reads the one file it was given. No network, ever. |
| **Bounded** | Sizes claimed *inside* a file are checked against `Limits` before anything is allocated. A header claiming 2⁶⁴ entries costs a `FormatError`, not the scan. |
| **Deterministic** | Same bytes, same result, on every platform and locale. |
| **Fail-closed** | Anything it cannot parse raises `FormatError`. A reader never returns "empty" to mean "clean". |

And one non-promise, which is the point: **a reader returns data, never a
verdict.** It has no opinion about whether what it found is dangerous. That is
your rule's job, and keeping the line there is what lets you add coverage for a
new threat without touching the engine.

Non-regular files are refused rather than opened. A FIFO or device node opens
happily and then blocks on `read` until a writer appears, so a crafted directory
could otherwise stall a whole scan just by naming one `model.gguf`.

## What ships

### GGUF — `read_gguf_metadata(path, *, limits=DEFAULT_LIMITS) -> GgufMetadata`

Reads the header and the metadata key/value block; tensor data is never touched.

```python
@dataclass(frozen=True)
class GgufMetadata:
    version: int
    tensor_count: int
    entries: Mapping[str, GgufValue]      # str | int | float | bool | tuple[...]

    def text(self, key: str) -> str | None
```

`text()` is the safe accessor: it returns `None` when the key is absent *or* is
not a string, so a rule never has to type-check an entry itself.

### safetensors — `read_safetensors_header(path, *, limits=DEFAULT_LIMITS) -> SafetensorsHeader`

```python
@dataclass(frozen=True)
class SafetensorsHeader:
    header_size: int
    tensors: Mapping[str, Mapping[str, object]]
    metadata: Mapping[str, str]           # the __metadata__ block, separated out
```

`metadata` is the format's one attacker-writable *text* channel, so it is
separated from the tensor index rather than left mixed in with it. A non-string
value is serialised rather than dropped — a writer smuggling a structure in
there is exactly what a scanner needs to see.

### ONNX — `read_onnx_summary(path, *, limits=DEFAULT_LIMITS) -> OnnxSummary`

```python
@dataclass(frozen=True)
class OnnxSummary:
    producer: str
    opset_domains: tuple[str, ...]
    node_domains: tuple[str, ...]
    metadata_props: Mapping[str, str]
    external_data_paths: tuple[str, ...]
    truncated: bool
```

The graph is walked straight off disk by a dependency-free streaming protobuf
reader that seeks past tensor payloads, so summarising a multi-gigabyte model
reads kilobytes. The walk covers every graph the model carries: the main graph
and its sparse initializers, tensors and subgraphs held in node attributes
(Constant values, If/Loop/Scan bodies), model-local functions and training
graphs. `node_domains` and `external_data_paths` collect from all of them.
`STANDARD_ONNX_DOMAINS` is exported alongside it: anything else in
`node_domains` means the runtime must register a native operator library before
the model will run.

`truncated` is the honest half of the bound — it says the walk did not finish:
the field budget ran out, subgraphs were nested deeper than 32 levels, or the
metadata passed `Limits.max_header_bytes`. The
`guardana.supply_chain.onnx_graph` rule gives a file one field per two bytes of
its size, never fewer than 1,000,000 and never more than 8,000,000, so a graph
below the cap is walked in full. **A partial walk has not cleared the model,
whatever it found**: a lead in the fields it reached says nothing about a worse
one past the budget. A rule reports the findings it has and says the walk was
partial:

```python
yield from self._graded(path, summary)
if summary.truncated:
    yield self._unscanned(path, "the model was too large or nested too deeply to walk in full", ctx)
```

`_unscanned` there yields the inconclusive finding and reports the file as an
unexamined component; see [writing a rule on top](#writing-a-rule-on-top).

### Limits

```python
@dataclass(frozen=True)
class Limits:
    max_header_bytes: int = 64 * 1024 * 1024
    max_entries: int = 100_000
    max_string_bytes: int = 8 * 1024 * 1024
    max_array_items: int = 2_000_000
```

Defaults are sized off real models — a 20k-tensor safetensors index is ~1.5 MiB
of JSON, a 256k-token GGUF vocabulary a few MiB — so honest files stay far
inside them. Pass your own `Limits` to tighten them for a constrained runner.

## Writing a rule on top

Every rule on a model format has one shape. Read the file, turn `FormatError`
into a visible finding, grade what you got.

A file the rule could not read, or read only in part, gets two reports. The finding
carries an `inconclusive` verdict, so it lands on the unverified channel. The
`unexamined_component` shortfall names the file, so the run is `indeterminate` under
every policy rather than only under `fail_on_inconclusive`. The built-in model rules
do both, and a rule that reads the format calls `ctx.examined(path)` either way, so
the format-level pass does not name the file again
([`guardana scan`](usage-scan.md#model-files-no-rule-reads)).

Here is that shape in `ApprovedModelRule`, from
`examples/custom_rule/src/acme_rules/approved_model.py` — a complete third-party
rule, tested, whose entire body is policy:

```python
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Check the provenance metadata of every GGUF model under the target."""
        if not isinstance(target, FileReader):
            raise RuleError(f"{self.meta.id} needs a file target, got {type(target).__name__}")
        for path in target.iter_files((".gguf",)):
            ctx.examined(path)
            try:
                metadata = read_gguf_metadata(path)
            except FormatError as exc:
                yield self._unscanned(path, f"provenance unreadable: {exc}", ctx)
                continue
            organization = metadata.text(_ORGANIZATION_KEY)
            if organization is None or organization.lower() not in _APPROVED_ORGANIZATIONS:
                name = metadata.text(_NAME_KEY) or path.name
                yield self._finding(path, f"'{name}' declares organization {organization!r}")

    def _unscanned(self, path: Path, reason: str, ctx: RuleContext) -> Finding:
        # Unreadable provenance is a decline, not an accusation: reporting the model
        # as unapproved would invent evidence. The shortfall keeps the run from
        # passing under every policy, not only under `fail_on_inconclusive`.
        ctx.shortfall(
            CoverageShortfall(
                ShortfallKind.UNEXAMINED_COMPONENT,
                name=str(path),
                detail=f"{self.meta.id} could not read it: {reason}",
            )
        )
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=reason, detail=f"file={path.name}"),
            verdict=Verdict("inconclusive", 0.0, reason, self.meta.id),
        )
```

## Testing your rule

`guardana.core.testing` builds crafted artifacts so a malicious fixture is a
dict literal in a test rather than a binary in your repository.

```python
from guardana.core.testing import build_gguf, build_onnx, build_safetensors

# positive: it fires
payload = "{{ lipsum.__globals__['os'].popen('id').read() }}"
(tmp_path / "m.gguf").write_bytes(build_gguf({"tokenizer.chat_template": payload}))

# negative: it stays silent
(tmp_path / "clean.safetensors").write_bytes(build_safetensors(metadata={"format": "pt"}))

# an ONNX model that reads outside its own directory
(tmp_path / "m.onnx").write_bytes(
    build_onnx(nodes=(("Conv", ""),), external_paths=("../../etc/passwd",))
)
```

A positive *and* a negative fixture is required for every rule Guardana ships,
and the same bar is what we ask of a plugin. Add a third: a file your reader
cannot parse, asserting that your rule reports it rather than passing it.

## Adding a format

There is no registry to sign up with — a reader is a module with a function.
If you write one for a format Guardana does not cover (TFLite, OpenVINO,
GGML v1), the contract above is the whole specification, and a pull request is
welcome. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## See also

- [`writing-rules.md`](writing-rules.md) — the `Rule` contract and YAML authoring
- [`architecture.md`](architecture.md) — where `formats` sits in the engine
- [`how-it-works.md`](how-it-works.md) — the product, end to end

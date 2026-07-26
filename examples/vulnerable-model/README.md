# vulnerable-model — intentionally insecure demo inputs

**These files are deliberately dangerous. Do not run them.** They exist so
you can see Guardana find real problems in one command:

```bash
uv run guardana scan examples/vulnerable-model
```

- `model.pt` — a pickle whose `__reduce__` calls `os.system` (arbitrary code on load)
- `load_model.py` — calls `torch.load` without `weights_only=True`
- `train.py` — imports a package that does not exist (slopsquat lead)
- `chat_template.jinja` — a chat template ending in a Jinja gadget: rendering it
  runs a shell command, with no inference and no `trust_remote_code` involved.
  The gadget sits *after* a full, ordinary-looking template, which is exactly
  where a byte-window scan stops looking (CVE-2024-34359, CVE-2026-5760)
- `config.json` — `_attn_implementation_internal` naming a Hub repository, which
  transformers downloads and imports on load. Note the `_name_or_path` beside it:
  the same `owner/repo` shape, entirely innocent, which is why this is matched by
  key name and not by what the value looks like (CVE-2026-4372)
- `requirements.txt` — a compromised `ultralytics` release, plus the loader
  versions that would arm the two findings above
- `model.gguf` — the same gadget, this time inside GGUF metadata and appended to
  the end of an 8 KiB template. Nothing about the first 8 KiB looks wrong
- `model.onnx` — a graph needing a custom operator library (native code at
  inference) whose `external_data` points at `../../../etc/passwd`
- `model.safetensors` — a well-formed, code-free model whose `__metadata__`
  carries an instruction written in invisible Unicode Tag characters

Guardana reports CRITICAL, HIGH and MEDIUM findings and exits non-zero — the
same signal a CI gate reads. Read the `requirements.txt` findings next to the
`config.json` and `chat_template.jinja` ones: the loaders pinned there are
exactly what would execute the two artifacts.

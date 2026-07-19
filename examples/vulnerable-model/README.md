# vulnerable-model — intentionally insecure demo inputs

**These files are deliberately dangerous. Do not run them.** They exist so
you can see Guardana find real problems in one command:

```bash
uv run guardana scan examples/vulnerable-model
```

- `model.pt` — a pickle whose `__reduce__` calls `os.system` (arbitrary code on load)
- `load_model.py` — calls `torch.load` without `weights_only=True`
- `train.py` — imports a package that does not exist (slopsquat lead)

Guardana reports a CRITICAL, a HIGH, and a MEDIUM finding and exits non-zero —
the same signal a CI gate reads.

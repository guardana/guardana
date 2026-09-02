---
title: "guardana rules"
nav_order: 175
summary: "`guardana rules`: list every discovered rule, grouped by the layer it secures"
status: stable
---

# `guardana rules` — what is discovered, before anything runs

List all discovered rules, grouped by the layer they secure — build-time
(static, artifact — dev machine, CI, training server) versus runtime (dynamic,
endpoint — live probe and monitor).

```bash
guardana rules
```

Pass `--rules <dir>` to include your own YAML rules in the listing — the same
flag `scan`/`probe` take — so you can confirm a rule pack parses and is picked
up without launching a full probe. A file that fails to load is warned about,
never silently dropped.

## Flags

`rules` discovers plugins the same way `scan`/`probe` do, so it takes the same
plugin-trust flags:

| Flag | Default | Meaning |
|---|---|---|
| `--plugins [all\|builtins\|allowlist\|disabled]` | `all` | Which installed plugins to load — same meaning as on `probe` |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist` |

## See also

- [`usage-taxonomy.md`](usage-taxonomy.md) — the framework catalogues a rule's mapping names
- [`writing-rules.md`](writing-rules.md) — author a rule as YAML or as a Python plugin

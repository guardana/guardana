---
title: "guardana rules"
nav_order: 175
summary: "`guardana rules`: list every discovered rule, grouped by the layer it secures"
status: stable
---

# `guardana rules` — what is discovered, before anything runs

`guardana rules` lists discovered build-time and runtime rules when you need to check what is available.

```bash
guardana rules
```

Pass `--rules <dir>` to include YAML rules, as with `scan` and `probe`. Files that fail to load produce a warning.

## Flags

`rules` discovers plugins the same way `scan`/`probe` do, so it takes the same
plugin-trust flags:

| Flag | Default | Meaning |
|---|---|---|
| `--surface [all\|build\|runtime]` | `all` | Filter by security layer: list every rule, or only build-time or runtime ones |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `builtins`, or the profile's `plugins:` | Which installed plugins to load — same meaning as on `probe` |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist` |
| `--profile PATH` | none | A `guardana.yaml` whose `plugins:` decides which installed plugins load — see [`profiles.md`](profiles.md#plugin-trust-plugins) |

## See also

- [`usage-taxonomy.md`](usage-taxonomy.md) — the framework catalogues a rule's mapping names
- [`writing-rules.md`](writing-rules.md) — author a rule as YAML or as a Python plugin

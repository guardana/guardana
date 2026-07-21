# Installing Guardana

Guardana requires **Python 3.11+**.

## Install from source (recommended today)

Guardana is currently GitHub-first: clone the workspace and run it with
[`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/guardana/guardana
cd guardana
uv sync                  # resolves the full workspace (5 packages) + dev tooling
uv run guardana --version
uv run guardana scan examples/vulnerable-model   # exits 1: finds the planted issues
```

(Inside this checkout, `guardana scan .` also exits `1` — by design:
`examples/vulnerable-model/` is deliberately malicious so there is always
something real to find. In your own projects, `guardana scan .` is the
normal invocation.)

`uv sync` installs `guardana-core`, `guardana-rules`, `guardana-cli`,
`guardana-report`, and `guardana-server` from the workspace defined in the
root `pyproject.toml`, plus `ruff`, `mypy`, and `pytest`. Run every command
with `uv run guardana ...` from inside the checkout. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md) for the full contributor setup and
test/lint gates.

## Install from PyPI

All five packages are on PyPI (Apache-2.0). For most users the CLI is all you
need:

```bash
uvx --from guardana-cli guardana scan .   # zero-install run
uv add guardana-cli                       # or add it to a project
pip install guardana-cli                  # or plain pip
```

The console script is `guardana`; its distribution is `guardana-cli`, which pulls
in `guardana-core` / `guardana-rules` / `guardana-report`, so `uvx` needs
`--from guardana-cli` to find the script by name. The optional collector is a
separate install: `pip install guardana-server`.

To run an unreleased revision with zero install, point `uvx` at the git repo:

```bash
uvx --from git+https://github.com/guardana/guardana#subdirectory=packages/guardana-cli guardana scan .
```

## The optional collector

`guardana-server` (the collector) is a separate, optionally-deployed
service — it is never required to use `scan`/`probe`/`monitor`. Install and
run it only if you want a central place to receive findings from many
agents; see [`architecture.md`](architecture.md#the-coreserver-boundary).

## Installing a third-party rule package

Third-party rule/evaluator packages are ordinary Python distributions —
install them like any dependency:

```bash
uv add acme-guardana-rules   # example; see examples/custom_rule/
```

Guardana discovers their rules automatically the next time it runs, via the
`guardana.rules` entry point (see [`extending.md`](extending.md)). Because
this executes the installed package's code, only install rule packages you
trust — or run with `--no-plugins` to disable all code-plugin discovery; see
[`SECURITY.md`](../SECURITY.md).

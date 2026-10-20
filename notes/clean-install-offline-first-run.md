---
title: "Clean-install offline first run (#138)"
date: 2026-10-20
summary: "The offline first-run proof passed all 12 cells across Linux, macOS and Windows, each with 14 of 14 steps."
---
The maintainer ran this proof with Guardana 1.0.0rc5 from PyPI, using proof scripts at commit `91196fd6`. The [workflow run](https://github.com/guardana/guardana/actions/runs/39424046832) records the results.

## Installation and platforms

The workflow, `.github/workflows/proofs.yml`, was dispatched with the version. The checkout supplied only the proof scripts in `scripts/proofs/`. Every package came from pypi.org.

The twelve cells covered Python 3.11 and 3.13, each with pip and uv, on three platforms:

- Linux: a `python:3.11-slim` or `python:3.13-slim` container on an ubuntu-24.04 runner, with Debian userspace.
- macOS 15 on arm64.
- Windows Server 2025.

The installation followed `docs/install.md` for a candidate release. With pip:

```console
$ python -m venv .venv
$ .venv/bin/python -m pip install --pre guardana-cli==1.0.0rc5
```

With uv:

```console
$ uv init --bare
$ uv add --prerelease allow guardana-cli==1.0.0rc5
```

Both installers named pypi.org. Each installer's own report showed that every file came from files.pythonhosted.org, with a sha256.

## Network cut

The network was cut after installation. Linux ran the proof in a second container with `--network none`. macOS ran it under `sandbox-exec`, denying every network operation to the process tree.

Windows used firewall rules to block outbound traffic from `python.exe`, both the base and environment executables, and `guardana.exe`. Another executable would not be blocked.

Before the cut, a canary reached pypi.org:443 and a literal address. Both connections were refused after the cut.

## Following the starter README

The proof followed the README written by the starter command. Each command was checked against the exit code and output lines stated in that README.

```console
$ guardana init --starter first-run
$ guardana scan model --format json --output before.json
```

The first scan exited with code 1. Its saved run, `before.json`, holds a CRITICAL `guardana.supply_chain.pickle_opcode` finding in `model/weights.pkl`.

The README then replaces the pickle file with the safe model file:

```console
$ rm model/weights.pkl
$ cp safe/weights.safetensors model/
$ guardana scan model --format json --output after.json
```

The second scan exited with code 0. Its saved report, `after.json`, observed `model/weights.safetensors`.

```console
$ guardana diff before.json after.json
$ guardana doctor
$ guardana rule test --rules checks 'starter.*'
```

The README specifies exit 1 for the diff, showing that the finding left the scan, and exit 0 for doctor. The rule test exited with code 0 and reported:

```text
1 rule(s); 3 fixture(s) passed, 0 failed, 0 could not run. 0 rule(s) not fully sampled.
```

The proof then made the README's edit to `checks/codename.yaml`, adding a second codename and a fourth sample, and repeated the test:

```console
$ guardana rule test --rules checks 'starter.*'
```

It exited with code 0 and reported:

```text
1 rule(s); 4 fixture(s) passed, 0 failed, 0 could not run. 0 rule(s) not fully sampled.
```

## Results and Windows limitations

```text
Linux:   4 of 4 cells passed; 14 of 14 steps each
macOS:   4 of 4 cells passed; 14 of 14 steps each
Windows: 4 of 4 cells passed; 14 of 14 steps each
```

On Windows, with output going to a pipe in the ANSI code page, cp1252, `guardana diff` and `guardana doctor` no longer end with exit 5. Since 1.0.0rc4 Guardana writes UTF-8 when the output stream cannot carry a character. Every Windows step now exits with the code the starter README states. The comparison holds with a recorded known difference: `guardana diff before.json after.json` exits `1` as the README states, but names the file `model\weights.pkl` where the README shows `weights.pkl`. The other steps passed with the network cut. The workflow requires the Windows cells to pass.

Runs written on Windows record `model\weights.pkl`, where Linux and macOS record `model/weights.pkl`. A finding's fingerprint follows that path, so baselines do not carry between Windows and the other platforms. This known difference is tracked in #167.

## Saved evidence

Each cell has a JSON record containing every step's command, exit code and a short output excerpt. These records and the two saved scan runs are uploaded as artifacts of the workflow run. Artifacts are kept for 90 days.

## What this proof does not show

This proof does not show how people new to Guardana experience a first run. That is the first-run study in `docs/studies`, which needs real participants. It does not show adoption.

On Windows, it does not show that an executable other than the blocked `python.exe` and `guardana.exe` stays offline. On Linux, it does not show an Ubuntu userspace: the containers use Debian userspace.

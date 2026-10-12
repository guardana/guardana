---
title: "Conformance kit"
nav_order: 58
summary: "what a pack runs in its own tests to prove its rules, targets, formats and reporters keep Guardana's contracts, and what each check does not prove"
status: beta
---

# Conformance kit — prove your pack keeps the contract

A pack's tests can use the same checks Guardana uses on its own extensions. Each check below
ships in `guardana-core`, so a pack's test suite does not copy it. A check that passes proves
what its row says. It proves nothing else.

| Check | What it proves | What it does not prove |
|---|---|---|
| [`guardana rule test`](usage-rule-test.md), `guardana.core.rule.verify.verify_rule` | each rule classifies its own `finding`, `clean` and `inconclusive` samples as declared; a rule missing one of the three is reported as a gap, never as passed | that a prompt carries an attack against a real model, or that the samples resemble your targets |
| `guardana.testing.assert_target_conforms` | a target implements every capability it declares and declares every capability it implements, has a `ref`, and finds its files in any suffix case | that it reads the right data or reaches the right address; over an empty root it has no file to sample |
| `ScriptedMcpServer`, `ScriptedA2aAgent` | a rule runs against a server or agent that enforces authorization and one that does not, through the same interfaces a live one uses | that a real server implementation behaves like the double |
| `files_target` (with `source_read_limit=` for a file the target leaves unread), a `Trace` in a `TraceTarget`, the scripted transports | a rule's fixtures built in code: a file tree, a recorded execution, a model's replies | anything about the model or the files your team actually ships |
| `guardana.testing.assert_renderer_conforms` | a format's name can be selected, and `render` returns text for every sample run, through the boundary `--format` uses | that the text is correct or complete, or that it states the verdict |
| `guardana.testing.assert_reporter_conforms` | `prepare` sends nothing, the deliverer has the right shape, and each destination yields its own status for every sample run, through the boundary `--reporter` uses; given the `receiver()` it delivers to, each `delivered` arrived there as exactly one request | what the request carries, whether it ignores proxy variables, or a connection made by a subprocess or a C extension during `prepare`; without `receiver=`, that anything was sent at all |

The kit has no evaluator check: an evaluator is exercised through the fixtures of the rules
that use it.

## Rules, targets and fixtures

[`guardana rule test`](usage-rule-test.md) runs every fixture a rule declares;
`verify_rule(rule)` does the same from Python and returns the gaps it found.
[`extending.md`](extending.md#testing-your-extension) lists every double in
`guardana.core.testing` and shows `assert_target_conforms`. A file the target could not read
makes a sample `inconclusive`, as a run reports it, so a fixture over an unreadable file never
counts as clean.

## Outputs

`guardana.core.testing.sample_verifications()` runs the engine five times and returns each
run: a passed scan, a failed scan, a scan of an empty tree, a probe stopped by its request
budget and a scan in which no rule ran. The output checks run your format or reporter over
all five. A format tested only against a passing run has never seen the runs it most needs
to describe.

```python
import base64

from guardana.core.testing import receiver
from guardana.testing import assert_renderer_conforms, assert_reporter_conforms

from acme_outputs import provide_table, provide_webhook


def test_the_table_keeps_the_output_contract():
    assert_renderer_conforms(provide_table(), name="acme-table")


def test_the_webhook_keeps_the_output_contract(monkeypatch):
    key = base64.b64encode(b"a key for this test only").decode()
    monkeypatch.setenv("ACME_WEBHOOK_SECRET", f"whsec_{key}")
    with receiver() as served:
        assert_reporter_conforms(
            provide_webhook(),
            delivered=served.accepting,
            rejected=served.refusing,
            unreachable=served.closed,
            name="acme-webhook",
            receiver=served,
        )
```

`name` is the entry point's name, and `spec.name` must equal it. If `name` is omitted, the
spec's own name is checked. A name must match `[a-z][a-z0-9-]*`, be at most 40 characters long,
and not be reserved for its kind ([installed outputs](outputs.md#write-your-own)).

**`assert_renderer_conforms(spec)`** calls `render` through `guardana.core.output.render`, so
the format sees what `--format` hands it, redacted a second time. It fails when `render`
raises or returns anything but text holding more than whitespace for any sample.

**`assert_reporter_conforms(spec, *, delivered, rejected, unreachable)`** takes three locators,
written as they would follow `<name>://`. They point at a destination that accepts, one that
answers and refuses, and one that does not answer. For every sample and every locator, it
checks:

- `prepare` makes no connection and no name lookup. `socket.socket.connect`, `connect_ex`,
  `socket.create_connection` and `socket.getaddrinfo` are refused while it runs, and an
  attempt fails the check even when `prepare` catches the error. A subprocess or a C
  extension that opens its own connection is not covered.
- `destination` is a `str` and `sent_secrets()` is a tuple of `str`.
- delivered through `guardana.core.output.deliver`, the run comes back with that locator's
  status: `delivered`, `rejected` or `unreachable`. `unknown` always fails, with its detail:
  the reporter raised, overran 30 seconds, or said `delivered` with no attempt or with a
  status outside 2xx.
- with `receiver=`, the `receiver()` the `delivered` locator points at, each run the reporter
  called `delivered` reached its accepting URL as exactly one request. A reporter that says
  `delivered` and sends nothing, or sends a run twice, fails. A `delivered` locator that does
  not point at that receiver fails too, since nothing can be counted.

**`guardana.core.testing.receiver()`** serves the three destinations for an HTTP reporter on
`127.0.0.1`, for the length of a `with` block. `accepting` answers `200` with
`{"status":"ok","duplicate":false,"stored":0}`, the collector's acknowledgement, `refusing`
answers `403`, and `closed` is a port nothing listens on.
`received` lists every request the first two answered. A reporter may append its own path to
either URL. A reporter that retries waits out its backoff on `closed` once per sample, so
`examples/output_pack` hands the check a `prepare` whose sleep returns at once.

Both checks raise `OutputContractError`, an `AssertionError`, naming every problem they found,
so one failing run lists everything to fix.

The kit does not check that a reporter ignores `HTTP_PROXY` and `HTTPS_PROXY`, as
[installed outputs](outputs.md#write-your-own) asks. Test that yourself: `examples/output_pack`
sets every proxy variable to a refusing address and still expects the delivery.

---
title: "MCP has two eras"
nav_order: 40
summary: "two revisions of MCP, and settling which one a server speaks before asking it anything"
status: accepted
---

# MCP has two eras, and a client that knows only one grades neither

**Status:** accepted, implemented — ships in the next release · **Written:** 2026-08-10 · **Step four**

## The problem, stated precisely

Guardana pins MCP `2025-11-25` and opens every conversation with `initialize`.
The specification revised on 2026-07-28 removed that handshake. A server built to
the current specification answers `initialize` with an error, so `probe --mcp`
against it does not reach the manifest, does not reach the authorization surface,
and reports six checks it could not run.

That failure is loud, which is the one thing in its favour. It is still the item
that goes first, because everything this project says about MCP — six invariants,
a manifest pin, a threat model with the server as a separate actor — is said
about a protocol revision that is now the *older* of two.

[The changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
is not drift at the margins:

| Removed or replaced | What the client used to do |
|---|---|
| `initialize` / `notifications/initialized` | opened every conversation |
| protocol sessions, `Mcp-Session-Id` | carried a session on each request; graded how it was minted |
| server-initiated requests (`roots/list`, `sampling/createMessage`, `elicitation/create`) | never sent, but the transport had to be ready to receive them |
| `ping`, `logging/setLevel`, `notifications/roots/list_changed` | unused |
| the GET stream, `resources/subscribe`, `Last-Event-ID` | unused |

and what arrived is a different shape, not a renamed one: every request carries
its own protocol version and client capabilities in `_meta`, servers **MUST**
implement `server/discover`, every result carries a required `resultType`, and
`tools/list` now carries `ttlMs` and `cacheScope`.

## The decision: speak both eras, and settle which one before anything else

There is no version of this that picks a side. A tool that only speaks
`2026-07-28` cannot examine the servers in production today; one that only speaks
`2025-11-25` cannot examine the ones being written now. Both eras stay reachable,
and the run records which one it actually spoke.

The specification's own terms are used verbatim, because inventing a synonym for a
word the spec defines is how two readers end up meaning different things:

- **modern** — version, identity and capabilities travel as per-request metadata
  (`2026-07-28` and later).
- **legacy** — the conversation opens with an `initialize` handshake
  (`2025-11-25` and earlier).
- **dual-era** — a server that answers both.

### The era is settled by `server/discover`, on both transports

`server/discover` is a method that did not exist before `2026-07-28`, so it is
the only question whose *answer* identifies the era rather than merely being
consistent with one. The three outcomes are the specification's:

| The probe returns | Conclusion |
|---|---|
| a result carrying `supportedVersions` | modern; choose a mutually supported version |
| `UnsupportedProtocolVersionError` (`-32022`) with `data.supported` | modern; choose from the list it named |
| anything else, or nothing | legacy; fall back to `initialize` |

The [stdio binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio#backward-compatibility)
prescribes exactly this and forbids keying the fallback to one error code, since a
legacy server answers an unknown method with whatever its SDK chose. The
[HTTP binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#backward-compatibility)
permits a cheaper route — send a modern request and read the body of a `400` —
and **that route is rejected here**, deliberately, at a cost of one request
against a legacy server.

The reason is a false claim, not a preference. The specification warns that some
legacy servers do not check that a request arrived after `initialize` and will
process an era-ambiguous method anyway. `tools/list` is era-ambiguous. A probe
that opened with it would receive a tool list from a legacy server and record
`mcp: 2026-07-28` in the run manifest — a coverage claim about a revision that
server has never heard of, written into the document a later `diff` compares
against. One request is cheaper than a manifest that lies.

The probe is bought once per target per run and shared, like every other
observation here, so the cost grows with the target and not with the rule count.

### Every mismatch is an outcome, never a pass

If the client and the server share no version, there is no conversation to have.
That is reported three ways and none of them is silence:

- the authorization observations record it as the reason the server could not be
  reached, so every invariant rule reports `inconclusive` naming both version
  lists;
- `list_tools()` raises, so the manifest rules are recorded as skipped with the
  same sentence, which `fail_on_skipped` turns into an indeterminate run;
- `protocols()` reports nothing, so the coverage fingerprint does not claim a
  revision was reached.

## What the client sends, and what it deliberately does not

A modern request carries three `_meta` fields, of which the specification requires
two:

```json
{
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": {"name": "guardana", "version": "…"},
  "io.modelcontextprotocol/clientCapabilities": {}
}
```

On HTTP the version is mirrored into `MCP-Protocol-Version` and the method into
`Mcp-Method`; a mismatch between header and body is a `HeaderMismatch` (`-32020`),
so they are written from one value rather than two. `Mcp-Name` is required only
for `tools/call`, `resources/read` and `prompts/get`, none of which Guardana ever
sends.

**`clientCapabilities` is empty, and that is a safety property rather than an
omission.** Under Multi Round-Trip Requests a server asks for sampling,
elicitation or roots by returning them in `inputRequests` — and it **MUST NOT**
ask for a capability the client did not declare. A client declaring none cannot
be asked to run a model completion or to prompt a human on the server's behalf.
This is the same posture the engine already takes toward stdio: the scanner does
not acquire abilities it has no reason to hold.

An `input_required` result is therefore a non-conforming answer to every request
Guardana makes, and it is raised rather than read. That matters more than it
sounds: an `InputRequiredResult` has no `tools` key, and the reader that turns a
reply into a manifest would otherwise have produced an empty tool list — a server
asking a question, recorded as a server offering nothing.

`resultType` is handled per the specification: absent means `"complete"`, because
that is what an older server sends; an unrecognised value is invalid and is
raised rather than guessed past.

## The session rules, made revision-aware

A conforming `2026-07-28` server has no session, and `guardana.mcp.session_binding`
grades sessions. Today it reports `inconclusive — the server issues no session id`
against exactly the server that got it right, which under a policy that fails on
indeterminate checks breaks the build of the team that upgraded.

**Decision: on a server that offers no legacy revision, the rule is silent.** Not
skipped, not inconclusive — silent, which in this codebase means *the invariant
holds*. It does hold, and it holds for a stronger reason than usual: the client
sends no session id, the server mints none, and the mechanism the rule grades was
removed from the protocol. There is no unasked question hiding in that silence.

**Rejected: report it as inconclusive so the reason stays visible.** The reason
does stay visible, in the right place — `coverage.protocols` in the run manifest
records the negotiated revision, and `diff` already reports a change in it as
*reach changed* rather than as the system changing. An inconclusive verdict is
for a question that could not be answered. This one was answered.

**Rejected: skip the rule by capability.** The 0.14 mechanism — an unrecorded
evidence dimension becomes an undeclared capability, and the runner skips with a
reason — is the right answer when a producer chose not to record something. Here
nothing is missing. A skip would make `fail_on_skipped` fail a conforming server,
which is the accusation this whole section exists to avoid.

### The hole that answer would have left, and how it is closed

A **dual-era** server is the interesting case, and the one a naive reading loses.
It answers `server/discover`, so the era settles as modern, so sessions are
vacuous — except that the same server still hands a session to every legacy
client it serves, and if those ids are a counter, that is a live defect the
modern conversation cannot see.

So the test is not *which era did we negotiate* but *does this server still offer
a legacy revision*. `supportedVersions` says so directly. When it does, the
session observations are bought over the legacy era — the same requests as
today — and the rule grades them exactly as before. Silence is reserved for a
server that offers modern versions only.

`guardana.trace.session_as_identity` needs no change, and the argument is worth
writing down rather than leaving to be re-derived. It grades a recorded identity,
not a protocol: a step that changed something while presenting a session and no
credential is a defect under every revision, and under `2026-07-28` it is a
defect involving something the protocol no longer even provides. The rule cannot
accuse a conforming server, because a conforming server produces no session for
the trace to record.

## Two new checks the revision creates

Both are graded from documents and declarations the run already buys. Neither
sends a request that was not already going out.

### `guardana.mcp.issuer_identification`

> MCP clients **MUST** apply the validation in RFC 9207 Section 2.4 before
> transmitting the authorization code to any token endpoint.

The client half of that is Guardana's own obligation and not a check. The
*server* half is: an authorization server that returns `iss` **MUST** advertise
`authorization_response_iss_parameter_supported: true` in its metadata, and one
that advertises nothing gives a client no way to detect that it is talking to the
wrong authorization server at all. Mix-up is the attack; `iss` is the only
defence the protocol offers against it, and its availability is a published field
in a document `probe --mcp` already fetches.

Reported `medium`. It is a `SHOULD` on the authorization server, which argues for
less, and it disables a client `MUST`, which argues for more; the attack also
needs a second, attacker-influenced authorization server in the picture, which is
why it is not `high`. The specification says a future revision is expected to
raise the server-side requirement to `MUST`, and this rule is what will already
be measuring when it does.

### `guardana.mcp.cache_scope`

`cacheScope: "public"` means *any shared gateway or caching proxy may store this
and serve it to any user*. A server that declares it on a tool listing it refused
to an unauthenticated caller has declared two incompatible things about the same
document, and the specification's own security note describes the outcome: the
result of an authenticated call may be served outside the authorization context
that fetched it.

The rule grades **what the server declares**, and only that. It does not attempt
to show what an intermediary did, because a scanner that proved this by finding a
cache would be reporting somebody else's infrastructure.

Three boundaries, each chosen so that silence stays honest:

- **A legacy server is silent.** The fields do not exist in that revision, so
  nothing was declared to anyone. Same argument as the session rules.
- **A missing `cacheScope` is silent.** Only `"public"` authorises sharing, and
  an absent field is not an instruction to share with anyone. A client may still
  hold the answer for itself — which is the same privacy position as holding it for
  the length of one run. The specification does require the fields on a modern
  server, but a conformance gap that creates no exposure is not this rule's
  finding.
- **A server open to anonymous callers is silent.** A public declaration on a
  document anyone may fetch is correct, and reporting it would put a finding on
  every unauthenticated development server there is — the same trap
  `token_audience` avoids for the same reason.

## What is deliberately not built

| Left out | Reason |
|---|---|
| Sending an MRTR retry (`inputResponses`, `requestState`) | Guardana declares no client capabilities, so a conforming server can never ask it for input. Building the retry would mean declaring a capability in order to exercise the code that handles it |
| `subscriptions/listen` | a long-lived stream is a listener, and a scanner that holds one has a different safety posture and a request meter that cannot bound it. The rug-pull check wants a *schedule*, which is `monitor --mcp`, still deferred |
| The tasks extension (`io.modelcontextprotocol/tasks`) | an extension is opt-in on both sides; nothing Guardana sends can be answered with a task handle unless it declares support, and declaring support to test it is the same mistake as above |
| `x-mcp-header` mirroring | it applies to `tools/call`, which Guardana does not send. Calling a tool to grade its header mirroring would execute the tool |
| Grading `ttlMs` as a freshness policy | how long a manifest may be cached is an operational choice, not a security invariant. `cacheScope` is graded because it names *who may hold it*, which is |
| Deprecated-feature findings (Roots, Sampling, Logging, DCR, HTTP+SSE) | the specification keeps them legal for twelve months. Reporting a supported feature as a defect is a false red, and Dynamic Client Registration is called out by name because it remains the only registration route some authorization servers offer |

## Related

- [`mcp-authorization-depth.md`](mcp-authorization-depth.md) — the six invariants,
  the honesty boundary they are placed against, and the four distinctions
  (identity is three claims; delegation has a direction and a boundary; consent is
  per client; a session is not an identity) that this revision leaves intact
- [`trace-domain-model.md`](trace-domain-model.md) — why a session in a trace does
  not make the identity dimension instrumented
- [`../usage-probe.md`](../usage-probe.md) — how to run it

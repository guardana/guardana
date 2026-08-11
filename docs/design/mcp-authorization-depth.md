---
title: "MCP authorization depth"
nav_order: 50
summary: "what a live MCP server's authorization surface can be asked with one credential"
status: accepted
---

# MCP in depth: what a client can prove about a server it does not run

**Status:** accepted, implemented — ships in the next release · **Written:** 2026-08-09 · **Step two**

## The problem, stated precisely

Guardana has spoken to a live MCP server since 0.5, and what it says to one is
`initialize` followed by `tools/list`. That reads the manifest — the text an
agent's model is handed as trusted context — and compares it against a pin. It is
a real check and it catches a real attack, and it is also the *only* thing
Guardana knows how to ask.

Everything an MCP deployment gets wrong in production sits one layer below the
manifest. A server accepts a token minted for a different service. A session id
is a counter. A proxy forwards the client's credential to an API that reads it as
its own. The scopes on offer are `*`. None of that is visible in a tool
description, and none of it is covered by anything Guardana ships.

Two things make this the right work to do now rather than later:

- **The controls are settled.** OAuth 2.1, PKCE, audience-bound tokens, no token
  passthrough. These are `MUST`s in a published specification, not a research
  position, and they did not move between the two most recent revisions.
- **The target already exists.** `McpServerTarget` connects, negotiates and
  reports what it negotiated. This is depth on something Guardana has, not a new
  kind of thing to build.

It also has to happen before the domain model, because identity, delegation,
consent and approval are exactly the fields `Trace` will freeze at 1.0, and
principle 14 says the model lands after the domain is met rather than before.
Meeting them here is the point.

**What this is not:** a scanner that counts CVEs against MCP server versions.
That is a listed non-goal, it ages badly, and it is well served elsewhere. Every
finding below is *this invariant does not hold on the server in front of you*.

## The honesty boundary, decided first

The most important decision in this document is not which checks to write. It is
which claims a client is entitled to make, because an MCP client sees one side of
a two-sided protocol and most of the interesting failures happen on the other.

Three categories, and every check below is placed in one of them explicitly.

**Observable.** The server's answer settles the question. A server that returns a
tool list to a request carrying no credential requires no credential; there is
nothing further to establish.

**Observable in one direction only.** The failure is provable, the success is
not. Presenting a token this server cannot have issued and getting a `200` proves
the token was not validated. Getting a `401` proves only that *this* token was
rejected — it says nothing about a correctly signed token minted for a different
audience, which is the attack. So the rule's title carries the narrow claim it
actually tests, and its silence means only that the narrow claim held.

**Not observable.** Token passthrough happens between the MCP server and an
upstream API. A client watching the server's replies cannot see it, and no
sequence of requests makes it visible. A check here would be a guess wearing a
verdict's clothes, so there is no check here — there is a documented gap.

The rule this produces, and it governs the whole file: **a check that lands in
the second category never reports a pass; it reports nothing found and says what
it looked at.** A check with no observable form is deferred in writing rather
than approximated.

### The trap this avoids, named

A server that requires no authentication at all will reject nothing, because
there is nothing to reject. Run the audience check against it and it answers
every request happily — which is not evidence of missing audience validation,
because there is no audience to validate against.

Read carelessly, that produces a critical finding on every unauthenticated
development server. Read carelessly the other way — "it answered, so it must be
fine" — it produces a pass on a server nobody authenticated. The correct answer
is neither: when the unauthenticated probe already succeeded, the audience check
is **inconclusive**, and the missing-authentication rule is the one that speaks.

## The decision: the target observes, the rule judges

`McpServerTarget` gains one new observation method. It performs the probes once
per run, caches them, and returns plain data. The rules read that data and decide
what it means.

```python
class McpServerTarget(Target):
    def list_tools(self) -> tuple[McpTool, ...]: ...          # today
    def authorization(self) -> McpAuthorizationView: ...      # new, cached
```

Two reasons, both structural.

**Cost grows with the target, not the rule count** (principle 2). Six rules
asking six times would send six handshakes. One cached observation is one
handshake, and adding a seventh rule that reads it costs nothing.

**Protocol knowledge belongs in a target; judgement belongs in a rule.** How to
find a Protected Resource Metadata document is a fact about MCP, the same kind of
fact as how to phrase an Ollama chat request — and `EndpointTarget` has held that
kind of knowledge since 0.1. Whether a `scopes_supported` list is too broad is a
security opinion, and opinions live in rules where a profile can exclude them and
a taxonomy mapping can answer for them.

`McpAuthorizationView` is a record of observations, never of conclusions: the
status and headers of an unauthenticated request, the metadata documents as
fetched, the session ids collected, the status of the request that carried a
foreign token. No field on it is named after a vulnerability.

### The capability, and why stdio must skip rather than pass

The authorization specification says, in as many words, that implementations
using an stdio transport **SHOULD NOT** follow it and should take credentials
from the environment instead. An stdio server has no HTTP status, no
`WWW-Authenticate` header and no session id, and grading one against rules
written for OAuth would be grading a bicycle on its emissions.

So a new capability, `INSPECT_AUTHORIZATION`, is declared **only by an MCP target
speaking streamable HTTP**. Against an stdio server the six rules below are
skipped by the runner, each carrying its reason, and `fail_on.fail_on_skipped`
turns that coverage hole into an indeterminate result for anyone who wants it
that way. What must not happen is the alternative: six rules finding nothing on a
target they could not examine, and a report that reads clean.

## The six invariants

Each one names the requirement it tests, what makes it fire, and — the part that
matters more — what makes it decline to answer.

### 1. `guardana.mcp.unauthenticated_access`

*The server answers a tool listing presented with no credential.*

Authorization is `OPTIONAL` in MCP, so this is not a specification violation on
its own; it is a fact about a deployment, and it is the fact every other check
here depends on. Severity follows reachability: a server on a loopback address is
reported at `low` with that stated, because an unauthenticated server on
`127.0.0.1` is how everybody develops, and crying `high` at it teaches people to
ignore the rule. A server on a routable address that hands its tool manifest to
an anonymous caller is `high`.

Declines to answer: never. This one is always observable.

### 2. `guardana.mcp.authorization_discovery`

*A protected server does not publish an authorization surface a conforming client
can use.*

Four `MUST`s from the specification, checked in order:

- MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata
  ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)), and **MUST**
  publish it either through `resource_metadata` in the `WWW-Authenticate` header
  of a `401` or at the well-known URI.
- The metadata document **MUST** include `authorization_servers` with at least
  one entry.
- The document's `resource` **MUST** be the canonical URI of this server. A
  document naming somebody else's resource makes audience binding decorative:
  clients will request tokens for the wrong audience, correctly.
- The authorization server's metadata **MUST** advertise
  `code_challenge_methods_supported`; the specification says a client that does
  not find it **MUST refuse to proceed**, so a deployment missing it is one no
  conforming client can use.

Declines to answer: when the server needed no credential (rule 1 fired), there is
no protected resource and this rule reports nothing. When a metadata document
could not be fetched — a timeout, a body that is not JSON — the finding is
`inconclusive` naming the address, never a clean surface.

### 3. `guardana.mcp.token_audience`

*The server answers a request bearing a token it could not have issued.*

> MCP servers **MUST** validate that access tokens were issued specifically for
> them as the intended audience […] MCP servers **MUST** only accept tokens
> specifically intended for themselves and **MUST** reject tokens that do not
> include them in the audience claim.

Guardana presents a token that is unmistakably not a credential: an unsigned JWT
whose audience and issuer both name `https://guardana.invalid/`, whose subject is
`guardana-probe`, and whose signature segment says so in words. If the server
answers a `tools/list` with it, it validated nothing.

This is the one-directional case named above, and the rule is titled for what it
proves. Silence means the server rejected *this* token. It is not a certificate
of audience validation, the documentation says so, and no report will imply
otherwise.

Declines to answer: `inconclusive` when the unauthenticated probe already
succeeded, because a server that accepts everything cannot demonstrate anything
about tokens.

### 4. `guardana.mcp.session_binding`

*The session id is predictable, or the session is accepted as authentication.*

> MCP servers that implement authorization **MUST** verify all inbound requests.
> MCP Servers **MUST NOT** use sessions for authentication. […] MCP servers
> **MUST** use secure, non-deterministic session IDs.

Two observations, one rule, because they are two halves of one property — who
this connection belongs to.

*Predictability* is measured over a handful of handshakes: ids that increment,
ids that share a long common prefix and differ in a counter, ids short enough to
enumerate. Nothing here is a randomness test — a scanner claiming to measure
entropy from four samples would be inventing a number — it looks for structure,
and it says which structure it found.

*Session as authentication* needs a credential, and it is the reason
`--mcp-token-env` exists. Establish a session with the operator's credential,
then send one request carrying the session id and **not** the credential. A
server that answers is authenticating by session, which the specification
forbids in a sentence.

Declines to answer: without a credential the second half is `inconclusive` and
says which flag would settle it. On a server that issues no session id at all,
both halves report nothing and the evidence says the server is stateless.

### 5. `guardana.mcp.scope_breadth`

*The advertised scopes cannot express least privilege.*

The specification's own list of common mistakes includes publishing every
possible scope in `scopes_supported` and using wildcard or omnibus scopes — `*`,
`all`, `full-access`. A token minted against those has a blast radius equal to
the whole server, and revoking it costs the user every workflow at once. Also
checked: a `401` that carries no `scope` parameter, which the specification
`SHOULD`s and which is what lets a client ask for less than everything.

Declines to answer: no metadata, nothing to read, nothing reported.

### 6. `guardana.mcp.discovery_target`

*The server points its client at an address a client must not follow.*

Discovery is the one place in MCP where the server hands the client a URL and the
client fetches it. The specification devotes a section to what that enables:
cloud metadata endpoints at `169.254.169.254`, internal services on loopback
ports, `javascript:` and `file:` schemes where a URL is opened rather than
fetched, plain `http://` for an authorization server that **MUST** be HTTPS.

This rule is the one that also protects Guardana. The check and the guard are the
same code path: the target refuses to fetch a discovery URL that is not
`https://` (or loopback `http://`), that resolves into a private, loopback or
link-local range, or that carries a scheme a client must reject — and the refusal
*is* the finding. A scanner that followed the URL to prove it was dangerous would
be the confused deputy it is looking for.

## The catalogue: OWASP MCP Top 10 as data

OWASP publishes an [MCP Top 10](https://owasp.org/www-project-mcp-top-10/),
currently at **v0.1, Phase 3 — Beta Release and Pilot Testing**, with the next
revision expected in October 2026. Its entries carry the edition in their own
identifiers — `MCP01:2025` — which is exactly the identity model step one landed,
so it registers as a seventh catalogue file and nothing in the engine changes:

```yaml
scheme: OWASP-MCP
edition: "2025"
version: "0.1"
title: OWASP MCP Top 10 (beta)
source: https://owasp.org/www-project-mcp-top-10/
```

A beta document is one that moves, and `version` plus the catalogue digest is how
a run says which revision it was mapped against. When v0.2 renames an entry — and
MCP06 has already been rendered two ways in two places OWASP publishes — it is a
new catalogue file, not an edit, because the old digest is pinned in saved runs.

`test_every_catalogue_carries_a_digest_over_its_content` pins the installed set,
so it grows from six frameworks to seven. That edit is the point of the test:
adding a framework is a decision somebody makes on purpose.

### Rejected: a crosswalk from MCP entries to LLM and ASI entries

Tempting, because `MCP03 Tool Poisoning` and `ASI04 Agentic Supply Chain` clearly
overlap. Rejected on two grounds. The mechanism is spelled `supersedes` and means
*this edition relative to an earlier edition of the same scheme*; pointing it at
another framework would overload one field with two meanings. And the
relationship between two frameworks' categories is a mapping opinion that changes
per rule — the honest expression of it already exists and is used everywhere
else: a rule carries both references.

## The manifest pin grows to the whole declaration

Today's pin digests each tool's `description`. A server can therefore change a
tool's `inputSchema` — add a parameter, widen an enum, rewrite a property
description that the model reads as instruction — and the pin stays green. Schema
drift beyond the pinned manifest is on the roadmap for exactly this reason.

`McpTool` gains the rest of the declaration (`title`, `inputSchema`,
`outputSchema`, `annotations`), the digest covers all of it, and the marker scan
that today reads descriptions reads property descriptions too — a hidden
instruction is a hidden instruction wherever the model will read it.

**Pin schema v1 → v2, and a v1 pin keeps working while saying what it covers.**
This is principle 11 and principle 10 meeting in one file. A v1 pin holds
description digests only; a v2 build that read it and reported "no drift" would be
claiming coverage the document cannot support. So a v1 pin compares descriptions,
and every run that uses one carries a note saying schemas are not covered and
which command re-approves it. Refusing to read v1 at all was the alternative and
is worse: it breaks a working setup at upgrade time, which teaches people to pin
the old version.

## Cost: the meter counts what actually went out

One MCP session makes two JSON-RPC calls, `initialize` and `tools/list`. The
meter records one. Measured, not inferred:

```
JSON-RPC calls actually made: ['initialize', 'tools/list']
requests the meter reports: 1
```

`McpServerTarget` also never overrode `apply_budgets`, so the base class refuses
any ceiling — which means `probe --mcp --max-requests 5` does not overspend
today, it refuses to start. That is the fail-closed direction and it was fine
while a run cost two calls that nobody would budget.

It stops being fine here. The observations above add an unauthenticated probe, up
to three metadata fetches, a foreign-token probe and several handshakes, and a
ceiling has to mean something. So metering moves into the transport seam: every
JSON-RPC call and every metadata fetch reserves before it is sent and records
after it returns, `apply_budgets` is implemented, and `--max-requests 5` sends
five requests and never six. The same defect and the same fix as
`probe --max-requests 5` sending ten, which 0.12 corrected on the chat path.

## Credentials, redaction, and what Guardana never does

`--mcp-token-env NAME` reads the credential from the environment, never from the
command line, for the reason `--api-key-env` already exists: an argument is in
every process list on the machine. Only `Authorization: Bearer` is supported,
because that is what the specification requires of a conforming client; a server
using a bespoke header is not doing MCP authorization, and supporting it is a
separate decision rather than a convenience.

The credential is a secret and goes nowhere near a report. Evidence records
whether a credential was presented and what the server answered — never the
value, at any privacy level, on the same seam that removes secrets from every
other channel.

**Guardana never calls a tool on an MCP server.** Every observation in this
document is made with `initialize`, `tools/list`, and unauthenticated `GET`s of
metadata documents. Calling a tool is a side effect on somebody's system —
possibly a write, possibly a payment — and no verification result is worth
finding that out by experiment.

## Rejected options

**Taking the official MCP SDK.** It would supply the authorization flow whole.
Rejected for the reason the client is hand-rolled in the first place: a security
scanner's dependency tree is part of its own attack surface, and principle 6 puts
a new dependency in front of a justification rather than a green CI. What the
checks need is a handful of HTTP requests and a JSON parser.

**Completing an OAuth flow to obtain a real token.** It would turn the
one-directional audience check into a two-directional one. It requires a browser,
a user, a consent screen and a redirect listener, all inside a tool that runs in
CI with no human present — and the token it produced would be a real credential
in a scanner's memory. The one-directional check plus a stated limit is worth
more than a flow nobody can run unattended.

**Registering a client on the advertised authorization server** to test
`redirect_uri` validation and the confused-deputy preconditions. It is the only
way to test them, and it is a *write to a third party's system* performed by a
tool whose whole proposition is that it is safe to point at production.

**A rule per specification `MUST`.** Fourteen rules, most firing together on the
same misconfiguration, each needing its own triage decision. The six above are
grouped by the question an operator answers, not by the sentence in the document.

## Deliberately deferred, with the reason

Each of these is in scope for step two on the roadmap and is not built. Each is
deferred because the honest version of it cannot be produced, not because it is
large — and each leaves a stated gap rather than a silent one.

| Deferred | Why |
|---|---|
| **Token passthrough to an upstream API** | It happens between the server and a service Guardana is not talking to. No sequence of client requests makes it observable. Accepting a foreign-audience token is its precondition and *is* checked; the passthrough itself needs the trace work |
| **Confused deputy, in full** | The preconditions — a static client id toward a third party, per-client consent storage — live on the server's back side. The only client-side proof requires registering a client on somebody's authorization server, which is a write to a third party. The observable slice (PKCE, discovery targets, scope breadth) is built |
| **Sampling misuse** | A server that abuses `sampling/createMessage` issues a request *to the client*, over a stream the client holds open and answers. Guardana's client sends a request and reads a reply. Changing that is a transport-contract change third-party transports implement — the same reason `finish_reason` was deferred out of step one, and worth doing beside the trace work rather than as a passenger here |
| **Multi-user data isolation** | Proving user A's session cannot reach user B's data needs two credentials *and* knowledge of which data belongs to whom. Guardana has neither and cannot ask for the second. The one-credential half — a session accepted as authentication — is a specification `MUST NOT` and is built |
| **Shadow servers (`MCP09`)** | Finding MCP servers nobody registered is a discovery problem on a network, not a verification problem on a target. Guardana verifies what it is pointed at |

## What this teaches the domain model

Principle 14 says `Trace` lands before 1.0 freezes anything, and step two comes
first so the model is shaped by fields that were met rather than imagined. Four
of them showed up here, and each arrived with a distinction that a naive schema
would have flattened:

- **Identity is not one field.** There is the credential the client presented,
  the audience the token names, and the resource the server claims to be. The
  interesting failures are precisely where those three disagree.
- **Delegation has a direction and a boundary.** The token a server receives and
  the token it uses upstream are different tokens, and a model with one
  `credential` field per call cannot represent the failure where they are the
  same one.
- **Consent is per client, not per user.** The confused-deputy attack works
  because a consent decision recorded against a user was read as a decision about
  a client.
- **A session is not an identity**, and a model that lets a session id stand in
  for one bakes in the thing the specification forbids.

## Related

- [`taxonomy-editions.md`](taxonomy-editions.md) — the identity model the MCP
  catalogue registers under, and why its edition is part of its name.
- [`../usage-probe.md`](../usage-probe.md) — how an operator runs this.
- [`../safe-testing.md`](../safe-testing.md) — impact levels, and why nothing
  here calls a tool.
- `ROADMAP.md`, *Step two — MCP, in depth*.

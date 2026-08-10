# `guardana probe` — one-shot dynamic checks against a live endpoint

Runs every **endpoint**-kind rule once against a live chat endpoint:
direct prompt injection, jailbreak attempts (single-turn and multi-turn
scenarios), indirect (RAG) injection, system-prompt leakage (via a planted
canary), output-secret leakage, excessive tool-use agency (when the endpoint
supports tool calling), and unbounded output (denial-of-wallet). Each dynamic
finding carries a `Verdict` — `outcome`, `confidence`, `rationale`,
`evaluator_id` — from the rule's configured Evaluator.

By default the endpoint is OpenAI-compatible (`POST /v1/chat/completions` —
Ollama's `/v1`, vLLM, llamafile, LM Studio, and friends). `--provider ollama`
speaks Ollama's native `/api/chat` instead, and `--provider tgi` speaks
Hugging Face TGI's `/generate`.

```bash
guardana probe --url <base-url> --model <name> [OPTIONS]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--url TEXT` | — | Base URL of the OpenAI-compatible endpoint. Required unless `--mcp` names an MCP server instead |
| `--model TEXT` | — | Model name to send in each request. Required unless `--mcp` names an MCP server instead |
| `--api-key-env TEXT` | none | Name of an environment variable holding the bearer API key |
| `--provider [openai\|ollama\|tgi]` | `openai` | Endpoint wire protocol: OpenAI-compatible (default), Ollama's native `/api/chat`, or HF TGI's `/generate` |
| `--adapter PATH` | none | Adapter file mapping a **guarded product endpoint**'s custom request/response schema — see [Probing a guarded endpoint](#probing-a-guarded-endpoint). Overrides `--provider`. |
| `--system-prompt-file PATH` | none | File containing the system prompt already deployed in front of the model, so non-canary rules probe the real configuration |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file |
| `--preset [ci\|pre-training\|monitor]` | none | Named policy preset (mutually exclusive with `--profile`) — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--format [human\|json\|sarif\|junit]` | `human` | Output format |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable. Combined with the profile's `rules.paths` — see [`writing-rules.md`](writing-rules.md). A malformed rule file is a warning, never an abort. |
| `--concurrency INTEGER` | `4` | How many rules may query the model at once. The probe is almost entirely spent waiting on the model, so overlapping rules is the biggest speed-up available; results stay in rule order, so two runs match. Rate limits (429) are retried with backoff — lower this if an endpoint keeps refusing. |
| `--reporter TEXT` | none | Forward findings to a collector, e.g. `server://https://collector.example.com` |
| `--mcp TEXT` | none | Examine an **MCP server** instead of a chat model — see [Probing an MCP server](#probing-an-mcp-server) |
| `--mcp-token-env TEXT` | none | Name of an environment variable holding a bearer token for the MCP server |
| `--mcp-pin PATH` | none | Approved MCP manifest to compare the live one against |
| `--write-mcp-pin PATH` | none | Write the server's current manifest as approved, and exit without reporting |
| `--allow-exec` | off | Permit `--mcp` to **start** an stdio server, which executes the code under examination |

## Probing an MCP server

`--mcp` points `probe` at a Model Context Protocol server rather than a chat
endpoint. There is no model to talk to, so every chat rule is skipped by
capability and says so; what runs instead is the manifest check and the eight
authorization checks.

```bash
export MCP_TOKEN=…
guardana probe \
  --mcp https://mcp.example.com/mcp \
  --mcp-token-env MCP_TOKEN
```

**Guardana never calls a tool on your server.** Every observation is made with
`server/discover`, `tools/list`, the `initialize` handshake where the server still
expects one, and unauthenticated `GET`s of the two discovery documents. Calling a
tool is a side effect on somebody's system — possibly a write, possibly a payment
— and no verification result is worth finding that out by experiment.

**Guardana declares no client capabilities**, which is a safety property rather
than an omission. Under the `2026-07-28` Multi Round-Trip Requests pattern a server
asks for sampling, elicitation or a root listing by returning them in a result, and
it **MUST NOT** ask for a capability the client did not declare. A client declaring
none cannot be asked to run a model completion or to prompt a human on the server's
behalf; a server that asks anyway gets an error, never an answer.

### Two revisions of the protocol, and which one your server speaks

The specification revised on 2026-07-28 removed the `initialize` handshake and
protocol-level sessions, and made every request carry its own version. Guardana
speaks both that revision and `2025-11-25`, and settles which one applies before
asking a server anything else:

```
$ guardana probe --mcp https://mcp.example.com/mcp --format json | jq .run.coverage.protocols
{ "mcp": "2026-07-28" }
```

The probe is one `server/discover` call — the method the newer revision requires
and the older one has never heard of, which makes its *answer* identify the era.
Guardana deliberately does not use the cheaper route the HTTP binding allows
(send an ordinary request, read the body of a `400`): some servers built to the
older revision will answer `tools/list` without a handshake, and a client that
opened with one would take their manifest and record `2026-07-28` in the run
manifest — a coverage claim about a revision that server has never heard of.

Three consequences worth knowing:

- **The negotiated revision is in the run manifest**, so [`guardana diff`](usage-diff.md)
  reports a server that moved between revisions as *the reach changed*, not as the
  system behaving differently.
- **`guardana.mcp.session_binding` is silent on a server with no sessions.** A
  conforming `2026-07-28` server mints none, so there is nothing to guess and
  nothing to authenticate with. A server that still offers an older revision
  alongside the new one is graded over that older one, because it is still handing
  sessions to every client that asks for them.
- **No revision in common is an outcome, never a pass.** The authorization checks
  report `inconclusive` naming both version lists, and the manifest checks are
  skipped with the same sentence — which `fail_on.fail_on_skipped` turns into an
  indeterminate run.

**The token never leaves the origin you named.** MCP is the one protocol here
where the server picks an address and the client fetches it, so every redirect hop
is checked against the same guard as the first request — and a hop to a different
scheme, host or port arrives with no `Authorization` and no `Mcp-Session-Id`. The
alternative is a server under test answering `302` and being handed the credential
of whoever is scanning it, which is the confused deputy these checks exist to look
for. A redirect *within* one origin keeps the header, because a server pointing at
its own path is ordinary.

### The manifest, and pinning it

A tool declaration is fed to the agent's model as trusted context, so an
instruction hidden in one is indirect prompt injection with an audience of one.
Guardana scans the whole declaration — description, title, input and output
schema, annotations — because a property description is read by the model exactly
like the tool description.

Drift is only detectable against something you approved:

```bash
guardana probe --mcp https://mcp.example.com/mcp \
  --write-mcp-pin mcp.pin.json          # approve today's manifest
guardana probe --mcp https://mcp.example.com/mcp \
  --mcp-pin mcp.pin.json                # compare against it
```

The pin stores a digest per tool rather than the prose, so the file records *that*
the manifest was approved and cannot be edited into agreement. Without `--mcp-pin`
drift is reported `inconclusive`, never as a clean server.

Pins written before this release are `schema_version 1` and cover **descriptions
only**. They still load and still compare, and every run that uses one carries a
note saying which drift it cannot see — re-approve with `--write-mcp-pin` to cover
schemas too.

### The authorization surface

Eight checks, each testing an invariant the MCP specification states, and each
saying plainly when it could not reach a verdict:

| Rule | What it establishes |
|---|---|
| `guardana.mcp.unauthenticated_access` | The server answers a tool listing with no credential. `low` on a loopback or private address, `high` elsewhere |
| `guardana.mcp.authorization_discovery` | A protected server publishes Protected Resource Metadata (RFC 9728) naming an authorization server, identifies *this* origin as its resource, and points at an authorization server that advertises PKCE |
| `guardana.mcp.token_audience` | The server refuses a bearer token it could not have issued |
| `guardana.mcp.session_binding` | Session ids are not a counter, are not shared, and do not authenticate a request on their own |
| `guardana.mcp.scope_breadth` | The advertised scopes can express least privilege, and the challenge names the scope a request needs |
| `guardana.mcp.discovery_target` | Every discovery address the server advertises is one a client may follow |
| `guardana.mcp.issuer_identification` | The authorization server advertises `authorization_response_iss_parameter_supported`, without which a client cannot detect an authorization-server mix-up (RFC 9207) |
| `guardana.mcp.cache_scope` | A tool listing the server gates behind a credential is not also declared `cacheScope: "public"`, which would invite any shared gateway to serve it to a caller the server would have refused |

**Two of them need `--mcp-token-env` to say anything**, and say so rather than
going quiet: whether a session authenticates on its own cannot be tested without a
credential to remove. A run without one reports those as `inconclusive` and names
the flag.

**What a silent `token_audience` does and does not mean.** Guardana presents a
token nobody could mistake for a credential — `alg: none`, an audience and issuer
naming a reserved domain that never resolves, and a signature segment that says
`guardana-probe-not-a-valid-signature` in words. A server that answers a tool
listing while holding it validated nothing, and that is a finding. A server that
rejects it has rejected *that token*; proving it validates audiences would need a
correctly signed token minted for another service, which no scanner can honestly
obtain. Against a server that requires no credential at all the check reports
`inconclusive`, because a server that accepts everything demonstrates nothing.

**Dynamic Client Registration is not reported as a defect.** `2026-07-28`
deprecates it in favour of Client ID Metadata Documents and keeps it legal for at
least twelve months, and it remains the only registration route some authorization
servers offer. Reporting a supported feature as a defect is a false red.

**stdio servers are not graded on this.** The specification says an stdio
implementation should take credentials from the environment instead of following
the authorization spec, so an stdio target does not declare the capability and all
eight rules are **skipped** with their reason recorded. `fail_on.fail_on_skipped`
turns that coverage hole into an indeterminate result; what never happens is six
rules reporting nothing about a server they could not examine.

**The credential never reaches a report.** It is read from the environment rather
than an argument — an argument is in every process list on the machine — and
evidence records whether one was presented and what the server answered, never its
value, at any privacy level.

### Cost

An MCP probe sends around a dozen requests: one `server/discover` to settle the
revision, a listing without a credential (preceded by a handshake where the server
still expects one), up to five discovery fetches, a listing with the forged token,
and a handful of handshakes to sample session ids. Every one is
counted, so `--max-requests` bounds it, and a run that hits the ceiling exits `6`
with an `indeterminate` gate rather than reporting the checks it never reached as
clean.

Ask before you spend, with [`guardana plan`](usage-plan.md):

```bash
guardana plan probe --mcp https://mcp.example.com/mcp
```

That contacts nothing. The ceiling it reports is higher than any run spends —
each rule declares what it would cost *alone*, because a plan cannot know which
one runs first and buys the shared observation — so treat it as the upper bound
it is.

## Probing a guarded endpoint

`--provider` speaks the raw model wire (OpenAI/Ollama/TGI). But the thing you most
want to test is often your **guarded product endpoint** — the model *plus* the API
gateway, auth, and guardrails in front of it — and that has its own request and
response schema. `--adapter <file>` maps it, so the probe drives the whole surface
instead of bypassing it to the bare model.

```yaml
# wellness-adapter.yaml
url: https://api.example.com/v1/wellness/chat   # optional; defaults to --url
headers:
  X-Api-Key: ${WELLNESS_API_KEY}                # ${ENV} is expanded; unset = error
  Content-Type: application/json
body:                                           # your endpoint's request shape;
  message: "{{prompt}}"                         # {{prompt}} is where the probe goes
  user_id_hash: "guardana-probe"
  stream: false
response_path: data.reply                       # dotted path to the reply text
```

```bash
guardana probe --url https://api.example.com --model wellness --adapter wellness-adapter.yaml
```

For a **multi-turn** scenario (gradual jailbreak, indirect injection), give the
body a `{{messages}}` slot to receive the full transcript as a `[{role, content}]`
list, if your endpoint speaks multi-turn:

```yaml
body:
  messages: "{{messages}}"     # the whole conversation, not just the last turn
```

Without a `{{messages}}` slot, every turn is folded into `{{prompt}}` as a labelled
transcript — so a scenario's escalation reaches the endpoint instead of collapsing
to the final message.

The mapping is **fail-closed**: a `body` with no `{{prompt}}` or `{{messages}}`
slot is rejected at load (the probe would otherwise send the same static request
for every check and pass everything), and a `response_path` that does not resolve
to a string is an error, never a blank reply graded as clean. A planted system
prompt with no `{{system}}` slot is folded into the prompt rather than dropped, so
a canary/leak check is never silently disarmed. Programmatically, the same mapping
is `guardana.core.target.HttpAdapterTransport` / `AdapterConfig`.

## How canary rules work

Rules that need `plant_system_prompt` (the system-prompt-leak canary rule and
the indirect-injection scenario) run in their **own** probe pass, each against a dedicated endpoint
target whose system prompt is your `--system-prompt-file` contents (if any)
plus a Guardana-generated line embedding a **fresh random canary token**
minted for that run — the static canary value in the rule's YAML only marks
the rule as canary-capable and is never used for detection, so a model can't
have been trained around it. All other
endpoint rules run together in a single pass against your endpoint as
configured. This means one `probe` invocation may issue multiple batches of
requests — this is expected and is what lets an unmodifiable canary
co-exist with your real system prompt.

## Example invocation and output

```console
$ guardana probe --url http://localhost:11434 --model llama3 --api-key-env OLLAMA_API_KEY
✖ [CRITICAL] guardana.prompt.system_prompt_leak.canary — System prompt leakage via canary marker
    Planted canary marker found in response.  (http://localhost:11434#llama3)
✖ [HIGH] guardana.prompt.injection.ignore_previous — Prompt injection via instruction override
    No refusal marker found; response likely complied.  (http://localhost:11434#llama3)

2 finding(s); 8 rule(s) run, 0 skipped.
```

Every dynamic finding's evidence pairs with a verdict: run
`--format json` to see `outcome`, `confidence`, and `rationale` per finding.

A check that ran but could not reach a verdict — an unreachable judge, an
empty model reply — is reported separately as `? [UNVERIFIED]` (the
`unverified` key in JSON), never silently counted as a pass; set
`fail_on_inconclusive: true` in your profile to make it fail the gate.

## Rules graded by an LLM judge

The `llm_judge` and `guard` evaluators need a model of their own, wired from
an `evaluators:` block in `guardana.yaml` — see
[`profiles.md`](profiles.md#config-wired-evaluators-llm_judge-and-guard). With
no block configured, a rule that names one of them is **skipped visibly** in
the run summary rather than silently passed.

## Exit codes

Same policy gate as `scan` (see [`profiles.md`](profiles.md)): exits `1` if
any finding at or above `fail_on.severity` also meets `fail_on.min_confidence`,
else `0`.

## Forwarding to a collector

```bash
guardana probe --url http://localhost:11434 --model llama3 --reporter server://https://collector.example.com
```

## Trying it without a live model

`probe` needs a running OpenAI-compatible endpoint — if `--url` is
unreachable, the command reports a clear connection error and exits
non-zero rather than hanging. The fastest way to get one locally:

```bash
ollama serve &
ollama pull llama3
guardana probe --url http://localhost:11434 --model llama3
```

Any other OpenAI-compatible local server (vLLM, HF-TGI, LM Studio, etc.)
works the same way — just point `--url`/`--model` at it.

## Saving a run for comparison

`--output <path>` writes the report to a file instead of stdout. With
`--format json` that file is a versioned document `guardana diff` reads back, so
you can ask whether the next run is worse than this one — see
[`usage-diff.md`](usage-diff.md).

```bash
guardana probe --url … --model …  --format json --output run.json
```

Prefer it to a shell redirect: PowerShell redirects write UTF-16, and the reader
on the other end cannot parse that.

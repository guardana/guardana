"""Targets for the frameworks people build agents with, rather than raw endpoints.

A team using LangChain does not have an OpenAI-compatible URL to point `probe` at —
they have an object in a Python process, wrapped in whatever retries, system prompt
and middleware their framework adds. Verifying the endpoint underneath it verifies
something nobody deployed.

Three rules hold for every adapter here, and they are the reason this package exists
separately from `guardana.core.target`:

**The framework is never imported.** Each adapter is duck-typed against the small
part of the framework's surface it needs, so `guardana-core` gains no dependency and
a version bump in somebody's agent stack cannot break the security tool that checks
it. An object that does not fit is refused at construction, with a sentence saying
what was expected.

**Nothing new is invented.** An adapter is a `ChatTransport` behind an
`EndpointTarget`, so metering, budgets, safety ceilings and every rule keep working
unchanged and no framework gets its own dialect of "secure".

**Silence is never a pass.** A reply this cannot read is an `EndpointError`, never an
empty string — an empty reply grades exactly like a well-behaved model.

The framework names live here rather than in `guardana.core.*` on purpose: the engine
does not know vendors, and a name that moves with somebody else's release calendar
does not belong in it.
"""

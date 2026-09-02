"""Find out what a target actually supports, by asking it as cheaply as possible.

"OpenAI-compatible" is a claim about a URL shape, not about behaviour. A gateway
may accept a `tools` array and ignore it; a proxy may strip the system message; a
local server may return no usage block at all. Every one of those turns a rule
into a check that ran and proved nothing — and the only way to know is to try.

So this sends a handful of tiny requests, one per question, and reports what came
back. Each probe answers exactly one thing, and a probe that fails is recorded as
`unsupported` with the error rather than silently folded into the others.
"""

from dataclasses import dataclass, field
from enum import StrEnum

from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.target.endpoint import (
    ChatMessage,
    EndpointError,
    ToolCallingTransport,
    ToolSpec,
    UsageReportingTransport,
)

_PROBE = "Reply with the single word: ok"
_SYSTEM_MARKER = "GUARDANA_SYSTEM_PROBE"
_SYSTEM_PROBE = f"You must reply with exactly this word and nothing else: {_SYSTEM_MARKER}"
_TOOL = ToolSpec(name="guardana_probe_tool", description="Call this tool with no arguments.")


class Support(StrEnum):
    """Whether a target supports one capability."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    """The probe could not be run, so nothing was learned.

    Never collapsed into `unsupported`: "it does not do this" and "we could not
    find out" lead to different actions, and only one of them is a reason to stop
    expecting the coverage.
    """


@dataclass(frozen=True, slots=True)
class CapabilityFinding:
    """What one probe established, and what it cost."""

    capability: str
    support: Support
    detail: str
    requests: int = 0


@dataclass(frozen=True, slots=True)
class TargetReport:
    """What a target turned out to support, and which rules that leaves unrunnable."""

    ref: str
    kind: TargetKind
    declared: tuple[str, ...]
    findings: tuple[CapabilityFinding, ...] = ()
    unsupported_rules: tuple[str, ...] = field(default_factory=tuple)

    @property
    def requests(self) -> int:
        """How many requests the inspection itself cost."""
        return sum(f.requests for f in self.findings)

    @property
    def verified(self) -> frozenset[str]:
        """Capabilities a probe actually confirmed, as opposed to ones merely declared."""
        return frozenset(f.capability for f in self.findings if f.support is Support.SUPPORTED)

    @property
    def contradicts_declaration(self) -> tuple[str, ...]:
        """Capabilities the target declared and no probe confirmed.

        The reason to run this at all. A target that advertises tool calling and
        does not honour it makes every agency rule a check that ran and proved
        nothing — which reads as a clean bill of health.

        `UNKNOWN` counts here, not only `UNSUPPORTED`. A gateway that accepts a
        tools array and returns no tool call is indistinguishable from a model
        that declined, and both leave the declared capability unproven — which is
        the thing a reader has to act on. Listing only outright refusals would
        hide the more common and more dangerous case.
        """
        return tuple(
            sorted(
                f.capability
                for f in self.findings
                if f.support is not Support.SUPPORTED and f.capability in self.declared
            )
        )


def _probe_chat(target: EndpointTarget) -> CapabilityFinding:
    try:
        reply = target.chat([ChatMessage(role="user", content=_PROBE)])
    except EndpointError as exc:
        return CapabilityFinding(
            str(Capability.CHAT), Support.UNSUPPORTED, f"chat request failed: {exc}", 1
        )
    if not reply.strip():
        return CapabilityFinding(
            str(Capability.CHAT),
            Support.UNSUPPORTED,
            "the endpoint answered with empty text, which no rule can grade",
            1,
        )
    return CapabilityFinding(str(Capability.CHAT), Support.SUPPORTED, "replied with text", 1)


def _probe_system_prompt(base: EndpointTarget, planted: EndpointTarget) -> CapabilityFinding:
    """Check the system message survives the hop, by asking the model to echo a marker.

    A proxy that drops the system message is the case this exists for: every
    canary rule then plants a marker nobody sees, finds no leak, and reports a
    confident pass for a model that may leak everything.
    """
    name = str(Capability.PLANT_SYSTEM_PROMPT)
    try:
        reply = planted.chat([ChatMessage(role="user", content="Reply now.")])
    except EndpointError as exc:
        return CapabilityFinding(name, Support.UNKNOWN, f"probe failed: {exc}", 1)
    if _SYSTEM_MARKER in reply:
        return CapabilityFinding(name, Support.SUPPORTED, "the system message reached the model", 1)
    return CapabilityFinding(
        name,
        Support.UNKNOWN,
        "the model did not echo the marker: it may have declined to follow the "
        "instruction, or the system message may have been dropped in transit — "
        "canary rules cannot be trusted here until this is resolved",
        1,
    )


def _probe_tools(target: EndpointTarget) -> CapabilityFinding:
    name = str(Capability.CALL_TOOLS)
    if not isinstance(target.transport, ToolCallingTransport):
        return CapabilityFinding(
            name, Support.UNSUPPORTED, "this transport does not implement tool calling", 0
        )
    try:
        reply = target.offer_tools(
            [ChatMessage(role="user", content="Call the probe tool.")], [_TOOL]
        )
    except EndpointError as exc:
        return CapabilityFinding(name, Support.UNSUPPORTED, f"tool request rejected: {exc}", 1)
    if reply.tool_calls:
        return CapabilityFinding(name, Support.SUPPORTED, "the model returned a tool call", 1)
    return CapabilityFinding(
        name,
        Support.UNKNOWN,
        "the endpoint accepted the tools array but returned no tool call: the model "
        "may have declined, or the gateway may be ignoring tools entirely",
        1,
    )


def _probe_usage(target: EndpointTarget) -> CapabilityFinding:
    """Report whether token counts come back — which decides if a token budget can hold."""
    usage = target.usage()
    if not isinstance(target.transport, UsageReportingTransport):
        return CapabilityFinding(
            "usage_metadata",
            Support.UNSUPPORTED,
            "this transport cannot report token counts, so a token budget cannot be enforced",
            0,
        )
    if usage.input_tokens is None:
        return CapabilityFinding(
            "usage_metadata",
            Support.UNSUPPORTED,
            "the endpoint returned no token counts on the probes above",
            0,
        )
    return CapabilityFinding(
        "usage_metadata", Support.SUPPORTED, "the endpoint reports token counts", 0
    )


def inspect_endpoint(target: EndpointTarget, planted: EndpointTarget) -> TargetReport:
    """Probe one endpoint and report what it supports.

    `planted` is the same endpoint with a system prompt set — built by the caller,
    because constructing a target is the command's job and this module does not
    know how the connection was configured.

    Costs three requests. That is stated rather than hidden: an inspection is
    cheap next to a probe, and a team paying per token is entitled to know the
    price of every command.
    """
    findings = [_probe_chat(target)]
    findings.append(_probe_system_prompt(target, planted))
    findings.append(_probe_tools(target))
    findings.append(_probe_usage(target))
    return TargetReport(
        ref=target.ref,
        kind=target.kind,
        declared=tuple(sorted(str(c) for c in target.capabilities())),
        findings=tuple(findings),
    )


def unrunnable_rules(report: TargetReport, rules: object) -> tuple[str, ...]:
    """Which of `rules` this target cannot support, judged on what was verified.

    Judged on verified capabilities rather than declared ones: a target that
    advertises tool calling and does not honour it would otherwise pass this check
    and fail every agency rule silently at run time.
    """
    verified = report.verified
    unrunnable: list[str] = []
    for rule in getattr(rules, "rules", lambda: ())():
        meta = rule.meta
        if meta.target_kind is not TargetKind.ENDPOINT:
            continue
        if {str(c) for c in meta.required_capabilities} - verified:
            unrunnable.append(meta.id)
    return tuple(sorted(unrunnable))


def endpoint_rule_count(rules: object) -> int:
    """How many endpoint rules `rules` holds — the population `unrunnable_rules` judges.

    Needed to tell "every rule could run" from "no rule was there to judge": an
    empty `unrunnable_rules()` result reads as the first only when this is nonzero.
    A registry emptied by a restrictive plugin trust mode returns zero here, which
    is the signal a renderer needs to report an absence of evidence rather than a
    clean result.
    """
    return sum(
        1
        for rule in getattr(rules, "rules", lambda: ())()
        if rule.meta.target_kind is TargetKind.ENDPOINT
    )


def declared_capabilities(target: Target) -> tuple[str, ...]:
    """Return what a target says it supports, without asking it anything."""
    return tuple(sorted(str(c) for c in target.capabilities()))

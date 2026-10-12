"""Installed outputs: a format for `--format` and a reporter for `--reporter`, from another package.

An output is one entry point in `guardana.renderers` or `guardana.reporters`, and its
entry-point name is the output's name, so a collision and a trust refusal are decided
from metadata before anything is imported. An output is imported only when a run
selects it. Both kinds receive a `Verification` through `outbound`, which holds no more
than the saved run holds. A reporter receives the saved run's manifest with every text
field redacted again and its target ref at `redacted` mode, and no kept exchange.
"""

import re
import threading
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, TypeVar

from guardana.core.entrypoints import (
    OUTPUT_GROUPS,
    RENDERER_GROUP,
    REPORTER_GROUP,
    InstalledEntryPoint,
    installed_entry_points,
)
from guardana.core.origin import Origin
from guardana.core.plugins import PluginTrust, normalize_distribution
from guardana.core.recording import RecordedExchange, Recording
from guardana.core.redaction import EvidenceRedactor, at_redacted_mode
from guardana.core.report.check_error import bounded_reason
from guardana.core.verify import Verification

OUTPUT_API_VERSION = 1
"""The version of `RendererSpec`, `ReporterSpec`, `ReporterRequest`, `Deliverer` and `Delivery`."""

SUPPORTED_OUTPUT_API_VERSIONS = frozenset({OUTPUT_API_VERSION})
"""The output API versions this build can run."""

RESERVED_RENDERER_NAMES = frozenset({"human", "json", "sarif", "junit"})
"""Format names the built-in renderers use; no installed format can take one."""

RESERVED_REPORTER_NAMES = frozenset({"server", "http", "https"})
"""Reporter names the built-in collector forms use; no installed reporter can take one."""

RESERVED_PREFIX = "guardana"
"""Every output name starting with this is reserved, for either kind."""

OUTPUT_NAME_PATTERN = re.compile(r"[a-z][a-z0-9-]*")
"""What an output name must match in full."""

MAX_OUTPUT_NAME_LENGTH = 40

DELIVERY_DEADLINE_SECONDS = 30.0
"""How long `deliver` waits for a reporter before the delivery is `unknown`."""

_HTTP_OK = 200
_HTTP_REDIRECT = 300

_C0_DEL_C1 = re.compile("[\x00-\x1f\x7f-\x9f]")
_URL_AUTHORITY = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)")
_SECOND_PASS = EvidenceRedactor()


def is_output_name(name: str) -> bool:
    """Whether `name` has the shape of an output name: `[a-z][a-z0-9-]*`, at most 40 characters."""
    return len(name) <= MAX_OUTPUT_NAME_LENGTH and OUTPUT_NAME_PATTERN.fullmatch(name) is not None


def is_reserved_renderer_name(name: str) -> bool:
    """Whether `name` belongs to a built-in format or to Guardana's reserved namespace."""
    return name in RESERVED_RENDERER_NAMES or name.startswith(RESERVED_PREFIX)


def is_reserved_reporter_name(name: str) -> bool:
    """Whether `name` belongs to a built-in reporter form or to Guardana's reserved namespace."""
    return name in RESERVED_REPORTER_NAMES or name.startswith(RESERVED_PREFIX)


@dataclass(frozen=True, slots=True)
class RendererSpec:
    """What a `guardana.renderers` provider returns: a format that turns a run into text."""

    name: str
    """The format's name; equal to the entry point's name."""

    summary: str
    """One line saying what the format writes."""

    render: Callable[[Verification], str]


@dataclass(frozen=True, slots=True)
class ReporterRequest:
    """What a reporter is prepared with."""

    locator: str
    """What followed `<name>://` on the command line."""


class DeliveryStatus(StrEnum):
    """What became of one delivery."""

    DELIVERED = "delivered"
    """The receiver acknowledged it: at least one attempt, and any HTTP status a 2xx."""

    REJECTED = "rejected"
    """The receiver answered and did not accept it."""

    UNREACHABLE = "unreachable"
    """No answer from the receiver."""

    NOT_SENT = "not_sent"
    """Decided before sending; nothing left the machine."""

    UNKNOWN = "unknown"
    """The reporter failed; whether anything left the machine is unknown."""


@dataclass(frozen=True, slots=True)
class Delivery:
    """A reporter's account of one delivery."""

    status: DeliveryStatus
    detail: str = ""
    attempts: int = 0
    http_status: int | None = None


class Deliverer(Protocol):
    """What `ReporterSpec.prepare` returns: one destination, ready to receive one run."""

    destination: str
    """The destination's display form, fixed by `prepare`."""

    def sent_secrets(self) -> tuple[str, ...]:
        """Return every value this deliverer sends that must be withheld from a printed line."""

    def deliver(self, verification: Verification) -> Delivery:
        """Send one run and say what became of it."""


@dataclass(frozen=True, slots=True)
class ReporterSpec:
    """What a `guardana.reporters` provider returns: a reporter, prepared per run."""

    name: str
    """The reporter's name; equal to the entry point's name."""

    summary: str
    """One line saying where the reporter delivers."""

    prepare: Callable[[ReporterRequest], Deliverer]
    """Validate the request and return a deliverer; sends nothing."""


class OutputSelectionKind(StrEnum):
    """Why an output could not be selected."""

    UNKNOWN = "unknown"
    RESERVED = "reserved"
    COLLISION = "collision"
    REFUSED = "refused"
    BROKEN = "broken"
    UNSUPPORTED = "unsupported"


class OutputSelectionError(Exception):
    """An output that cannot be selected, refused before the run sends anything.

    `distributions` names the distributions involved, as spelled in their metadata: the
    one trust refused, or every one in a collision.
    """

    def __init__(
        self,
        kind: OutputSelectionKind,
        name: str,
        message: str,
        distributions: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.name = name
        self.message = message
        self.distributions = distributions


class OutputError(Exception):
    """A selected format that failed to render; nothing it returned may be written."""

    def __init__(self, name: str, origin: Origin, reason: str) -> None:
        super().__init__(reason)
        self.name = name
        self.origin = origin
        self.reason = reason


class BoundaryError(Exception):
    """The output boundary's own redaction raised, so the output was not called.

    A defect in Guardana, not in the output. `name` is the output's name and `reason`
    the type of what the redaction raised; the exception itself is chained as the cause.
    """

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"the redaction for {name} failed: {reason}")
        self.name = name
        self.reason = reason


@dataclass(frozen=True, slots=True)
class SelectedRenderer:
    """An installed format, imported and checked, ready to render."""

    name: str
    spec: RendererSpec
    origin: Origin


@dataclass(frozen=True, slots=True)
class PreparedReporter:
    """An installed reporter, imported and prepared for one destination, ready to deliver.

    `destination` is the deliverer's display form already sanitised, reduced to
    `scheme://host[:port]` when it is a URL, and `secrets` what its `sent_secrets()`
    returned when it was prepared; both are fixed at selection.
    """

    name: str
    spec: ReporterSpec
    deliverer: Deliverer
    origin: Origin
    destination: str
    secrets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OutputDiscovery:
    """Every installed output the pack commands can account for, imported under one trust.

    An entry point whose name is reserved or invalid can never be selected, so it is
    neither imported nor listed here.
    """

    renderers: Mapping[str, Origin]
    reporters: Mapping[str, Origin]
    refused: tuple[InstalledEntryPoint, ...]
    failed: tuple[tuple[InstalledEntryPoint, str], ...]
    """Each entry point whose provider raised or returned something other than its spec."""

    collisions: Mapping[str, tuple[str, ...]]
    """`renderer:<name>` or `reporter:<name>`, to each distribution that installs it."""


@dataclass(frozen=True, slots=True)
class OutputCollision:
    """One selectable output name that more than one distinct install provides."""

    group: str
    name: str
    entry_points: tuple[InstalledEntryPoint, ...]

    @property
    def distributions(self) -> tuple[str, ...]:
        """Each install's distribution and version, sorted, as a message names them."""
        return tuple(sorted(_describe(ep) for ep in self.entry_points))


_Spec = TypeVar("_Spec", RendererSpec, ReporterSpec)


@dataclass(frozen=True, slots=True)
class _Kind:
    """What tells a renderer selection from a reporter selection."""

    group: str
    key: str
    noun: str
    built_in: str
    is_reserved: Callable[[str], bool]


_RENDERER = _Kind(
    group=RENDERER_GROUP,
    key="renderer",
    noun="format",
    built_in="human, json, sarif, junit",
    is_reserved=is_reserved_renderer_name,
)
_REPORTER = _Kind(
    group=REPORTER_GROUP,
    key="reporter",
    noun="reporter",
    built_in="server://URL or an http(s) collector URL",
    is_reserved=is_reserved_reporter_name,
)


def sanitise_reason(text: str, secrets: Iterable[str] = ()) -> str:
    """Make text from plugin or collector code safe to print: one line, secrets gone, bounded.

    Every C0, DEL and C1 control character and every Unicode format character (bidi
    controls, zero-width marks) is dropped first, so none can split a secret out of the
    patterns' sight; then each of `secrets` is withheld, the default redactor runs, and
    the length is bounded.
    """
    known = tuple(secrets)
    withheld = (*known, *(_printable(value) for value in known))
    return bounded_reason(EvidenceRedactor(secrets=withheld).redact_text(_printable(text)))


def _printable(text: str) -> str:
    """Drop every C0, DEL and C1 control character and every Unicode format character."""
    text = _C0_DEL_C1.sub("", text)
    if text.isascii():
        return text
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


def _describe(entry_point: InstalledEntryPoint) -> str:
    """Name the distribution behind an entry point, as an error message says it."""
    if entry_point.distribution is None:
        return "an unnamed distribution"
    if entry_point.version is None:
        return entry_point.distribution
    return f"{entry_point.distribution} {entry_point.version}"


def _origin(entry_point: InstalledEntryPoint) -> Origin:
    return Origin(distribution=entry_point.distribution, version=entry_point.version)


def _identity(entry_point: InstalledEntryPoint) -> tuple[object, ...]:
    """Return what makes two same-named entry points one install; an unnamed one is distinct."""
    distribution: object = (
        object()
        if entry_point.distribution is None
        else normalize_distribution(entry_point.distribution)
    )
    return (distribution, entry_point.value, entry_point.version)


def _distinct(entry_points: Iterable[InstalledEntryPoint]) -> tuple[InstalledEntryPoint, ...]:
    """Keep one entry point per distinct install, in the order listed."""
    seen: set[tuple[object, ...]] = set()
    kept: list[InstalledEntryPoint] = []
    for entry_point in entry_points:
        identity = _identity(entry_point)
        if identity not in seen:
            seen.add(identity)
            kept.append(entry_point)
    return tuple(kept)


def _by_name(
    entry_points: Iterable[InstalledEntryPoint],
) -> dict[str, tuple[InstalledEntryPoint, ...]]:
    grouped: dict[str, list[InstalledEntryPoint]] = {}
    for entry_point in entry_points:
        grouped.setdefault(entry_point.name, []).append(entry_point)
    return {name: _distinct(found) for name, found in grouped.items()}


def _named(entry_points: Iterable[InstalledEntryPoint]) -> tuple[str, ...]:
    """Return the distribution names involved, as spelled, each once and in order."""
    return tuple(
        dict.fromkeys(ep.distribution for ep in entry_points if ep.distribution is not None)
    )


_KINDS = {RENDERER_GROUP: _RENDERER, REPORTER_GROUP: _REPORTER}


def unselectable_reason(group: str, name: str) -> str | None:
    """Say why an output entry point named `name` in `group` can never be selected, or None.

    `group` must be one of `OUTPUT_GROUPS`. A reserved name is reported before an invalid one.
    """
    if group not in _KINDS:
        msg = f"{group} is not an output entry-point group"
        raise ValueError(msg)
    if _KINDS[group].is_reserved(name):
        return "reserved name"
    if not is_output_name(name):
        return "invalid name"
    return None


def output_collisions(entry_points: Iterable[InstalledEntryPoint]) -> tuple[OutputCollision, ...]:
    """Find every selectable output name that more than one distinct install provides.

    Entry points outside `OUTPUT_GROUPS` and names that can never be selected are ignored;
    selection refuses each collision found here without importing any of its entry points.
    """
    by_group: dict[str, list[InstalledEntryPoint]] = {}
    for entry_point in entry_points:
        if entry_point.group in _KINDS:
            by_group.setdefault(entry_point.group, []).append(entry_point)
    return tuple(
        OutputCollision(group, name, found)
        for group in OUTPUT_GROUPS
        for name, found in _by_name(by_group.get(group, ())).items()
        if len(found) > 1 and unselectable_reason(group, name) is None
    )


def _collision_message(kind: _Kind, name: str, found: tuple[InstalledEntryPoint, ...]) -> str:
    which = ", ".join(OutputCollision(kind.group, name, found).distributions)
    nobody = "neither" if len(found) == 2 else "none"  # noqa: PLR2004 — the grammar of two
    return (
        f"the {kind.noun} {name} is installed by {len(found)} distributions ({which}), "
        f"so {nobody} is used"
    )


def _installed_listing(
    kind: _Kind, trust: PluginTrust, entry_points: tuple[InstalledEntryPoint, ...]
) -> str:
    states: list[str] = []
    for name, found in sorted(_by_name(entry_points).items()):
        if unselectable_reason(kind.group, name) is not None:
            continue
        if len(found) > 1:
            state = "collision"
        else:
            state = "admitted" if trust.allows(found[0].distribution) else "refused"
        states.append(f"{name} ({state})")
    return ", ".join(states) or "none"


def _resolve(kind: _Kind, name: str, trust: PluginTrust) -> InstalledEntryPoint:
    """Run steps 1 to 4 of selection from metadata alone: one admitted entry point, or refuse."""
    if kind.is_reserved(name):
        raise OutputSelectionError(
            OutputSelectionKind.RESERVED,
            name,
            f"{name} is a built-in {kind.noun} name, so no installed {kind.noun} can use it",
        )
    installed = installed_entry_points(groups=(kind.group,))
    found = _distinct(ep for ep in installed if ep.name == name) if is_output_name(name) else ()
    if not found:
        raise OutputSelectionError(
            OutputSelectionKind.UNKNOWN,
            name,
            f"the {kind.noun} {name} is not installed; built-in: {kind.built_in}; "
            f"installed: {_installed_listing(kind, trust, installed)}",
        )
    if len(found) > 1:
        raise OutputSelectionError(
            OutputSelectionKind.COLLISION,
            name,
            _collision_message(kind, name, found),
            _named(found),
        )
    (entry_point,) = found
    if not trust.allows(entry_point.distribution):
        raise OutputSelectionError(
            OutputSelectionKind.REFUSED,
            name,
            f"the {kind.noun} {name} comes from {_describe(entry_point)}, which plugin trust "
            f"{trust.describe()} does not admit",
            _named(found),
        )
    return entry_point


def _failure(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _provide(entry_point: InstalledEntryPoint, spec_type: type[_Spec]) -> _Spec:
    """Import an entry point and call its provider; raise `_BrokenError` naming what is wrong.

    Any exception but `KeyboardInterrupt` is turned into the reason, `SystemExit` included:
    a provider must not end the command.
    """
    try:
        provider = entry_point.load()
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise _BrokenError(_failure(exc)) from exc
    if not callable(provider):
        raise _BrokenError(f"{entry_point.value} is not callable")
    try:
        spec = provider()
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise _BrokenError(_failure(exc)) from exc
    if not isinstance(spec, spec_type):
        raise _BrokenError(
            f"the provider returned {type(spec).__name__}, not a {spec_type.__name__}"
        )
    if spec.name != entry_point.name:
        raise _BrokenError(
            f"the provider's {spec_type.__name__} is named {spec.name!r}, not {entry_point.name!r}"
        )
    hook = spec.render if isinstance(spec, RendererSpec) else spec.prepare
    if not isinstance(spec.summary, str) or not callable(hook):
        raise _BrokenError(
            f"the provider returned a {spec_type.__name__} with a field of the wrong type"
        )
    return spec


class _BrokenError(Exception):
    """A provider or a prepare step that failed, with the unsanitised reason."""


def _broken(
    kind: _Kind, name: str, entry_point: InstalledEntryPoint, step: str, reason: str
) -> OutputSelectionError:
    return OutputSelectionError(
        OutputSelectionKind.BROKEN,
        name,
        f"the {kind.noun} {name} from {_describe(entry_point)} could not be {step}: "
        f"{sanitise_reason(reason)}",
        _named((entry_point,)),
    )


def select_renderer(name: str, trust: PluginTrust) -> SelectedRenderer:
    """Select the installed format `name` under `trust`, importing only its entry point.

    Raises `OutputSelectionError` for a reserved, unknown, colliding, refused or broken
    format; nothing is imported unless metadata alone admits exactly one install.
    """
    entry_point = _resolve(_RENDERER, name, trust)
    try:
        spec = _provide(entry_point, RendererSpec)
    except _BrokenError as exc:
        raise _broken(_RENDERER, name, entry_point, "loaded", str(exc)) from exc
    return SelectedRenderer(name=name, spec=spec, origin=_origin(entry_point))


def select_reporter(name: str, locator: str, trust: PluginTrust) -> PreparedReporter:
    """Select the installed reporter `name` under `trust` and prepare it for `locator`.

    Raises `OutputSelectionError` as `select_renderer` does, and `broken` when `prepare`
    fails or returns something that is not a deliverer. `prepare` sends nothing.
    """
    entry_point = _resolve(_REPORTER, name, trust)
    try:
        spec = _provide(entry_point, ReporterSpec)
    except _BrokenError as exc:
        raise _broken(_REPORTER, name, entry_point, "loaded", str(exc)) from exc
    try:
        deliverer, destination, secrets = _prepared(spec, locator)
    except _BrokenError as exc:
        raise _broken(_REPORTER, name, entry_point, "prepared", str(exc)) from exc
    return PreparedReporter(
        name=name,
        spec=spec,
        deliverer=deliverer,
        origin=_origin(entry_point),
        destination=_display_destination(sanitise_reason(destination, secrets)),
        secrets=secrets,
    )


def _display_destination(sanitised: str) -> str:
    """Reduce a URL to `scheme://host[:port]`; keep any other destination as it is.

    A webhook URL often carries its credential in the userinfo, path or query, which a
    printed line must never show.
    """
    match = _URL_AUTHORITY.match(sanitised)
    if match is None:
        return sanitised
    scheme, authority = match.groups()
    host = authority.rpartition("@")[2]
    if not host or host.startswith(":"):
        return sanitised
    return f"{scheme}://{host}"


def _prepared(spec: ReporterSpec, locator: str) -> tuple[Deliverer, str, tuple[str, ...]]:
    """Call `prepare` and check what it returned; raise `_BrokenError` naming what is wrong."""
    try:
        deliverer = spec.prepare(ReporterRequest(locator=locator))
        deliver = getattr(deliverer, "deliver", None)
        destination = getattr(deliverer, "destination", None)
        sent_secrets = getattr(deliverer, "sent_secrets", None)
        values = sent_secrets() if callable(sent_secrets) else None
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise _BrokenError(_failure(exc)) from exc
    if not callable(deliver) or not callable(sent_secrets) or not isinstance(destination, str):
        raise _BrokenError(
            "prepare returned no deliverer: it needs a callable deliver, a str destination "
            "and a callable sent_secrets"
        )
    return deliverer, destination, _secrets(values)


def _secrets(values: object) -> tuple[str, ...]:
    """Check what `sent_secrets()` returned: strings, and nothing else."""
    if isinstance(values, str) or not isinstance(values, (tuple, list)):
        raise _BrokenError("sent_secrets() returned something other than a tuple of str")
    if not all(isinstance(value, str) for value in values):
        raise _BrokenError("sent_secrets() returned something other than a tuple of str")
    return tuple(values)


def outbound(verification: Verification, *, leaves_machine: bool) -> Verification:
    """Return what an output may see of `verification`: no more than the saved run holds.

    The result gets the default redactor's second pass, as the built-in renderers and the
    collector give it. Stop and judge messages are dropped: they are never saved. A format
    gets the manifest as saved and the kept exchanges redacted again by span. When the
    output `leaves_machine`, it gets the manifest through `EvidenceRedactor.redact_spans_in`,
    which raises `TypeError` on a value it does not know, the target ref at `redacted`
    mode, and no kept exchange.
    """
    manifest = verification.manifest
    exchanges: Recording | None
    if leaves_machine:
        manifest = _SECOND_PASS.redact_spans_in(manifest)
        ref = at_redacted_mode(_SECOND_PASS.policy).redact_text(manifest.target.ref)
        manifest = replace(manifest, target=replace(manifest.target, ref=ref))
        exchanges = None
    else:
        exchanges = _redacted_recording(verification.exchanges)
    return replace(
        verification,
        result=_SECOND_PASS.redact_result(verification.result),
        manifest=manifest,
        stop_messages=(),
        judge_stops=(),
        exchanges=exchanges,
    )


def _redacted_recording(recording: Recording | None) -> Recording | None:
    if recording is None:
        return None
    return replace(recording, exchanges=tuple(_redacted(e) for e in recording.exchanges))


def _redacted(exchange: RecordedExchange) -> RecordedExchange:
    """Redact one kept exchange by span again, the way the keeper redacted it."""
    spans = _SECOND_PASS.redact_spans
    reply = None if exchange.reply is None else spans(exchange.reply)
    return replace(
        exchange,
        input=tuple(
            replace(
                message,
                content=spans(message.content),
                tool_calls=tuple(
                    replace(call, arguments=spans(call.arguments)) for call in message.tool_calls
                ),
            )
            for message in exchange.input
        ),
        reply=reply,
        altered=exchange.altered or reply != exchange.reply,
        meta={name: value for name, value in exchange.meta.items() if spans(value) == value},
    )


def render(selected: SelectedRenderer, verification: Verification) -> str:
    """Render `verification` with an installed format, through `outbound`.

    Raises `BoundaryError` when the boundary fails, before the format is called, and
    `OutputError` when the format raises anything but `KeyboardInterrupt` or returns
    something that is not text or no text at all.
    """
    try:
        seen = outbound(verification, leaves_machine=False)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise BoundaryError(selected.name, type(exc).__name__) from exc
    try:
        rendered = selected.spec.render(seen)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise OutputError(selected.name, selected.origin, sanitise_reason(_failure(exc))) from exc
    if not isinstance(rendered, str):
        raise OutputError(
            selected.name, selected.origin, f"it returned {type(rendered).__name__}, not text"
        )
    if not rendered:
        raise OutputError(selected.name, selected.origin, "it returned no text")
    return rendered


def deliver(
    prepared: PreparedReporter,
    verification: Verification,
    *,
    deadline: float = DELIVERY_DEADLINE_SECONDS,
) -> Delivery:
    """Deliver `verification` with an installed reporter, through `outbound`, within `deadline`.

    Raises `BoundaryError` when the boundary fails, before the reporter is called. Never
    raises for the reporter's sake: a reporter that raises, overruns the deadline,
    returns an invalid delivery, or returns `delivered` with no attempt or with an HTTP
    status outside 2xx is `unknown`. The deadline covers the delivery and the
    `sent_secrets` hook read after it. A `KeyboardInterrupt` propagates. The detail
    is sanitised.
    """
    try:
        sent = outbound(verification, leaves_machine=True)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise BoundaryError(prepared.name, type(exc).__name__) from exc
    ran = _run_deliverer(prepared, sent, deadline)
    if ran is None:
        return Delivery(DeliveryStatus.UNKNOWN, detail=f"did not finish within {deadline:g} s")
    outcome, raised, secrets = ran
    if raised:
        known = prepared.secrets if secrets is None else secrets
        return Delivery(DeliveryStatus.UNKNOWN, detail=sanitise_reason(_failure(raised[0]), known))
    if secrets is None:
        return Delivery(DeliveryStatus.UNKNOWN, detail="sent_secrets() failed after the delivery")
    delivery = _valid(outcome[0] if outcome else None)
    refused = _refusal(delivery)
    if delivery is None or refused is not None:
        return Delivery(DeliveryStatus.UNKNOWN, detail=refused or "returned an invalid delivery")
    return replace(delivery, detail=sanitise_reason(delivery.detail, secrets))


def _run_deliverer(
    prepared: PreparedReporter, sent: Verification, deadline: float
) -> tuple[list[object], list[Exception | SystemExit], tuple[str, ...] | None] | None:
    """Run the delivery and then its `sent_secrets` hook on one daemon thread, in one deadline.

    Returns what `deliver` returned or raised and the secrets known afterwards, or None
    when the thread is still running at `deadline`.
    """
    outcome: list[object] = []
    raised: list[Exception | SystemExit] = []
    secrets: list[tuple[str, ...] | None] = []
    interrupted: list[KeyboardInterrupt] = []

    def attempt() -> None:
        try:
            try:
                outcome.append(prepared.deliverer.deliver(sent))
            except (Exception, SystemExit) as exc:
                raised.append(exc)
            secrets.append(_current_secrets(prepared))
        except KeyboardInterrupt as exc:
            interrupted.append(exc)

    worker = threading.Thread(target=attempt, name=f"guardana-deliver-{prepared.name}", daemon=True)
    worker.start()
    # Joined from the calling thread, so an interrupt while waiting propagates from here.
    worker.join(deadline)
    if worker.is_alive():
        return None
    if interrupted:
        raise interrupted[0]
    return outcome, raised, secrets[0] if secrets else None


def _current_secrets(prepared: PreparedReporter) -> tuple[str, ...] | None:
    """Return every secret known at selection and now, or None when the deliverer cannot say."""
    try:
        return (*prepared.secrets, *_secrets(prepared.deliverer.sent_secrets()))
    except (Exception, SystemExit):
        return None


def _valid(value: object) -> Delivery | None:
    """Return `value` when it is a well-formed `Delivery`, else None."""
    try:
        if not isinstance(value, Delivery):
            return None
        attempts = value.attempts
        http_status = value.http_status
        well_formed = (
            isinstance(value.status, DeliveryStatus)
            and isinstance(value.detail, str)
            and isinstance(attempts, int)
            and not isinstance(attempts, bool)
            and attempts >= 0
            and (
                http_status is None
                or (isinstance(http_status, int) and not isinstance(http_status, bool))
            )
        )
    except (Exception, SystemExit):
        return None
    return value if well_formed else None


def _refusal(delivery: Delivery | None) -> str | None:
    """Say why a well-formed delivery cannot stand, or None when it can.

    `delivered` needs at least one attempt and, when it names an HTTP status, a 2xx one.
    """
    if delivery is None or delivery.status is not DeliveryStatus.DELIVERED:
        return None
    status = delivery.http_status
    if delivery.attempts > 0 and (status is None or _HTTP_OK <= status < _HTTP_REDIRECT):
        return None
    return "returned delivered without an acknowledgement"


def format_delivery_line(name: str, destination: str, delivery: Delivery) -> str:
    """Return the delivery line printed for a selected reporter, in its documented grammar.

    `delivery: <status> — <name> to <destination>[ (HTTP <code>, <n> attempt|attempts)][: <detail>]`
    """
    facts: list[str] = []
    if delivery.http_status is not None:
        facts.append(f"HTTP {delivery.http_status}")
    if delivery.attempts:
        facts.append(f"{delivery.attempts} attempt{'' if delivery.attempts == 1 else 's'}")
    line = f"delivery: {delivery.status} — {name} to {destination}"
    if facts:
        line += f" ({', '.join(facts)})"
    if delivery.detail:
        line += f": {delivery.detail}"
    return line


def _provide_renderer(entry_point: InstalledEntryPoint) -> RendererSpec:
    return _provide(entry_point, RendererSpec)


def _provide_reporter(entry_point: InstalledEntryPoint) -> ReporterSpec:
    return _provide(entry_point, ReporterSpec)


def discover_outputs(trust: PluginTrust) -> OutputDiscovery:
    """Import every admitted, non-colliding output provider, and account for every other.

    Only the pack commands call this; a run imports an output only when it selects it.
    """
    renderers: dict[str, Origin] = {}
    reporters: dict[str, Origin] = {}
    refused: list[InstalledEntryPoint] = []
    failed: list[tuple[InstalledEntryPoint, str]] = []
    collisions: dict[str, tuple[str, ...]] = {}
    installed = installed_entry_points(groups=OUTPUT_GROUPS)
    colliding = {(c.group, c.name): c for c in output_collisions(installed)}
    kinds: tuple[tuple[_Kind, Callable[[InstalledEntryPoint], object], dict[str, Origin]], ...] = (
        (_RENDERER, _provide_renderer, renderers),
        (_REPORTER, _provide_reporter, reporters),
    )
    for kind, provide, found_into in kinds:
        group = tuple(ep for ep in installed if ep.group == kind.group)
        for name, found in _by_name(group).items():
            if unselectable_reason(kind.group, name) is not None:
                continue
            collision = colliding.get((kind.group, name))
            if collision is not None:
                collisions[f"{kind.key}:{name}"] = collision.distributions
                continue
            (entry_point,) = found
            if not trust.allows(entry_point.distribution):
                refused.append(entry_point)
                continue
            try:
                provide(entry_point)
            except _BrokenError as exc:
                failed.append((entry_point, sanitise_reason(str(exc))))
                continue
            found_into[name] = _origin(entry_point)
    return OutputDiscovery(
        renderers=renderers,
        reporters=reporters,
        refused=tuple(refused),
        failed=tuple(failed),
        collisions=collisions,
    )


__all__ = [
    "DELIVERY_DEADLINE_SECONDS",
    "MAX_OUTPUT_NAME_LENGTH",
    "OUTPUT_API_VERSION",
    "OUTPUT_NAME_PATTERN",
    "RESERVED_PREFIX",
    "RESERVED_RENDERER_NAMES",
    "RESERVED_REPORTER_NAMES",
    "SUPPORTED_OUTPUT_API_VERSIONS",
    "BoundaryError",
    "Deliverer",
    "Delivery",
    "DeliveryStatus",
    "OutputCollision",
    "OutputDiscovery",
    "OutputError",
    "OutputSelectionError",
    "OutputSelectionKind",
    "PreparedReporter",
    "RendererSpec",
    "ReporterRequest",
    "ReporterSpec",
    "SelectedRenderer",
    "deliver",
    "discover_outputs",
    "format_delivery_line",
    "is_output_name",
    "is_reserved_renderer_name",
    "is_reserved_reporter_name",
    "outbound",
    "output_collisions",
    "render",
    "sanitise_reason",
    "select_renderer",
    "select_reporter",
    "unselectable_reason",
]

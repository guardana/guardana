"""Build the evaluators a profile configures under `evaluators:` and register them.

The judge's differentiating value is that it grades "did the attack succeed" — but
it needs a model to ask, and nothing built one from config until here. Both the
judge and the optional guard model are ordinary endpoints, so they can point at a
local OpenAI-compatible server for fully offline grading. Absent config leaves an
evaluator unregistered, and a rule that names it then records a `RuleLoadError`
(`unknown evaluator`) error in the run — never a silent pass.

A judge block is read as a `Connection` (`endpoint` is its URL), so it takes a
provider and an adapter as the endpoint commands do, and a key variable that is unset
or empty is refused before a judge is asked anything.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit

from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.calibration.store import RecordedCalibration
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.evaluator.llm_judge import (
    DEFAULT_PROMPT_VERSION,
    PROMPT_TEMPLATES,
    JudgeCalibration,
    LlmJudgeEvaluator,
)
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.fingerprint import digest_of
from guardana.core.manifest.usage import JudgeUsage
from guardana.core.profile import Profile
from guardana.core.profile.errors import ProfileError
from guardana.core.profile.loader import check_evaluator_blocks
from guardana.core.redaction import MessageQuoting, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.target import (
    ChatMessage,
    EndpointError,
    EndpointTarget,
    EndpointUnreachable,
    private_url_parts,
)
from guardana.core.target.connection import (
    Connection,
    ConnectionConfigError,
    ResolvedConnection,
    Spelling,
    resolve_connection,
)
from guardana.core.target.failure import http_status_problem

_DEFAULT_PORTS = {"https": 443, "http": 80}
_USABLE_SCHEMES = frozenset({"http", "https"})


class EndpointBuilder(Protocol):
    """Make the endpoint a judge is asked through."""

    def __call__(self, url: str, model: str, api_key: str | None) -> EndpointTarget:
        """Return an endpoint for `model` at `url`, authenticated with `api_key` if any."""
        raise NotImplementedError


@runtime_checkable
class ConnectionBuilder(Protocol):
    """An `EndpointBuilder` that can also honour a judge block's provider and adapter."""

    def __call__(self, url: str, model: str, api_key: str | None) -> EndpointTarget:
        """Return an endpoint for `model` at `url` on the default provider."""
        raise NotImplementedError

    def connect(self, connection: ResolvedConnection) -> EndpointTarget:
        """Return the endpoint `connection` describes, on its provider or adapter."""
        raise NotImplementedError


class _NetworkEndpoints:
    """Judge endpoints on the providers' real network transports."""

    def __call__(self, url: str, model: str, api_key: str | None) -> EndpointTarget:
        """Build a judge endpoint on the default provider's network transport."""
        return EndpointTarget(url, model, api_key=api_key)

    def connect(self, connection: ResolvedConnection) -> EndpointTarget:
        """Build a judge endpoint on the transport `connection` resolved to."""
        return connection.endpoint()


default_endpoint_builder: ConnectionBuilder = _NetworkEndpoints()
"""Build a judge endpoint on the provider's real network transport."""


def safe_url(url: str) -> str:
    """Return `url` with its userinfo, query and fragment removed, for a message a reader sees.

    A configured endpoint can carry a credential in any of those three places.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


class JudgeUnavailableError(EndpointError):
    """A grading call failed at a config-built judge's endpoint, not at the target's.

    An `EndpointError`, so the runner ends the run as it does for any unreachable
    endpoint; the message names the `evaluators:` block and the judge's URL, without
    credentials, so the CLI never blames the target for it.
    """

    def __init__(self, block: str, endpoint: str, problem: str) -> None:
        self.block = block
        self.endpoint = endpoint
        super().__init__(problem)


def unusable_url(url: str) -> str | None:
    """Say why the built-in transports cannot use `url` as a base URL, or None when they can.

    The reason never repeats the URL: a value that is not an http(s) URL can hold
    its credential where no scrubber looks for one.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "is not a URL"
    if parts.scheme not in _USABLE_SCHEMES:
        return "must be an http or https URL"
    try:
        _ = parts.port
    except ValueError:
        # A password holding `/`, `?` or `#` ends the host early and lands here too.
        return "has a port that is not a number from 0 to 65535"
    carried = private_url_parts(url)
    if carried:
        # The transports append their API path to the base URL, so a query or a
        # fragment ends up before it, and urllib fails on userinfo instead of
        # sending it; nothing that could have worked is refused here.
        return (
            f"carries {_listed(carried)}, which the built-in endpoint transports cannot "
            f"send; a key belongs in an environment variable, never in the URL"
        )
    return None


def _listed(names: tuple[str, ...]) -> str:
    """Spell part names as prose: `a query`, `userinfo and a query`."""
    spelled = [name if name == "userinfo" else f"a {name}" for name in names]
    if len(spelled) == 1:
        return spelled[0]
    return f"{', '.join(spelled[:-1])} and {spelled[-1]}"


class JudgeMeter:
    """One `evaluators:` block's judge endpoint: its own tally, and whether it stopped a run.

    Every failure of a call leaves naming the block and the judge's URL without
    credentials: the runner reports a transport failure as the run's endpoint being
    down and a spent budget as a spent budget, so an unnamed one reads as the target's.

    Safe to share across threads: the tally is the endpoint's thread-safe meter, and the
    stop is written once, with the message a reader is shown.

    What the judge's endpoint said is quoted through `quoting`, the run's own privacy
    policy and the secrets the judge sends; without one, it is quoted under the default
    policy.
    """

    def __init__(
        self,
        block: str,
        target: EndpointTarget,
        endpoint: str,
        serves: tuple[str, ...],
        *,
        quoting: MessageQuoting | None = None,
    ) -> None:
        self.block = block
        self.name = f"evaluators.{block}"
        self.evaluators = serves
        """The ids of the evaluators whose grading calls this meter counts."""
        self.endpoint = safe_url(endpoint)
        self._raw = (endpoint, endpoint.rstrip("/").removesuffix("/v1"))
        self._target = target
        self._quoting = quoting if quoting is not None else MessageQuoting.of(RedactionPolicy())
        self.stopped: str | None = None
        """Why this judge's ceiling stopped the run, or None when it never did."""

    def apply(self, budgets: Budgets) -> None:
        """Bound this judge by `budgets`, refusing a ceiling its transport cannot enforce."""
        try:
            self._target.apply_budgets(budgets)
        except BudgetExhausted as exc:
            raise BudgetExhausted(f"{self.name} ({self.endpoint}): {self._scrubbed(exc)}") from exc

    def ask(self, prompt: str) -> str:
        """Send one grading prompt to the judge and return its reply."""
        try:
            return self._target.chat([ChatMessage(role="user", content=prompt)])
        except BudgetExhausted as exc:
            self.stopped = f"{self.name} ({self.endpoint}) stopped the run: {self._scrubbed(exc)}"
            raise BudgetExhausted(self.stopped) from exc
        except HTTPError as exc:
            raise self._unavailable(self._rejection(exc.code)) from exc
        except OSError as exc:
            # `URLError` is the connect failure; a timeout or a reset while the reply is
            # read arrives as a bare `OSError`.
            reason = exc.reason if isinstance(exc, URLError) else exc
            raise self._unavailable(
                f"could not reach endpoint {self.endpoint} ({self.name}): {self._quoted(reason)}"
            ) from exc
        except EndpointUnreachable as exc:
            raise self._unavailable(
                f"could not reach endpoint {self.endpoint} ({self.name}): {self._quoted(exc)}"
            ) from exc
        except EndpointError as exc:
            raise self._unavailable(
                f"endpoint {self.endpoint} ({self.name}) sent a reply guardana cannot use: "
                f"{self._quoted(exc)}"
            ) from exc

    def usage(self) -> JudgeUsage:
        """Return what this judge has spent so far, a null token sum meaning none reported."""
        spent = self._target.usage()
        return JudgeUsage(
            requests=spent.requests,
            input_tokens=spent.input_tokens,
            output_tokens=spent.output_tokens,
            requests_missing_token_counts=spent.requests_missing_token_counts,
            budget_exhausted=self.stopped is not None,
        )

    def _unavailable(self, problem: str) -> JudgeUnavailableError:
        return JudgeUnavailableError(self.block, self.endpoint, problem)

    def _quoted(self, problem: object) -> str:
        """Quote what the judge's endpoint said under the run's policy, without its secrets."""
        return self._quoting.detail(self._scrubbed(problem))

    def _scrubbed(self, problem: object) -> str:
        text = str(problem)
        for raw in self._raw:
            if raw:
                text = text.replace(raw, self.endpoint)
        return text

    def _rejection(self, status: int) -> str:
        return http_status_problem(
            status,
            where=f"endpoint {self.endpoint} ({self.name})",
            sender="the judge",
            rate_limited_remedy="wait for its quota to reset",
            rejected_remedy=f"check {self.name}.api_key_env and the key it names",
        )


@dataclass(frozen=True, slots=True)
class JudgeMeters:
    """The meters of every judge built from config, for a command to read once per run.

    Read outside the scan result on purpose: every pass of a probe shares these meters,
    and a snapshot carried per pass would be summed once per pass when results merge.
    """

    meters: tuple[JudgeMeter, ...] = ()

    def usage(self) -> dict[str, JudgeUsage] | None:
        """Return each judge's spend by block, or None when no judge was configured."""
        if not self.meters:
            return None
        return {meter.block: meter.usage() for meter in self.meters}

    def stops(self) -> tuple[str, ...]:
        """Say which judge ceilings stopped the run, in the words a reader is shown."""
        return tuple(meter.stopped for meter in self.meters if meter.stopped is not None)


def wire_config_evaluators(
    registry: Registry,
    profile: Profile,
    budgets: Budgets | None = None,
    *,
    build: EndpointBuilder = default_endpoint_builder,
    sending: bool = True,
) -> JudgeMeters:
    """Register every evaluator that must be built from `guardana.yaml` config.

    `llm_judge` and `reference_judge` share one judge model, built from
    `evaluators.llm_judge`; `guard` is an optional safety classifier. Call after
    discovery so they join the evaluator set the runner resolves every rule against.

    `budgets` bounds every judge and guard call on a meter of the model's own, so a
    judge-graded run stops at the ceiling like its target instead of spending past it.
    `None` leaves them unbounded. A token ceiling the judge's transport cannot enforce
    raises `BudgetExhausted` here, before anything is sent.

    Returns the judges' meters, fresh on every call, so the caller can record what
    grading spent beside what the target spent, and each meter names the evaluators it
    counts for. `build` makes each judge's endpoint, so a command can route it through
    the transport its tests substitute; a builder that is not a `ConnectionBuilder`
    cannot honour a block's `provider` or `adapter`, and such a block is refused.

    `sending` False wires judges that will never be asked, as a plan does: no key
    variable is read and no adapter header is expanded. An unknown block or key, and
    every connection the endpoint commands refuse, raise `ProfileError`.
    """
    check_evaluator_blocks(profile.evaluator_config)
    wiring = _Wiring(
        build,
        sending=sending,
        beside=profile.source.parent if profile.source is not None else None,
        privacy=profile.privacy,
    )
    meters: list[JudgeMeter] = []
    judge_cfg = profile.evaluator_config.get("llm_judge")
    if judge_cfg is not None:
        judge, meter, identity = _endpoint_call(
            judge_cfg,
            "llm_judge",
            budgets,
            (LlmJudgeEvaluator.id, ReferenceJudgeEvaluator.id),
            wiring,
        )
        for evaluator in _build_judges(judge_cfg, judge, identity):
            registry.register_evaluator(evaluator)
        meters.append(meter)
    guard_cfg = profile.evaluator_config.get("guard")
    if guard_cfg is not None:
        guard, meter, identity = _endpoint_call(
            guard_cfg, "guard", budgets, (GuardEvaluator.id,), wiring
        )
        registry.register_evaluator(GuardEvaluator(guard, judge_identity=identity))
        meters.append(meter)
    return JudgeMeters(tuple(meters))


@dataclass(frozen=True, slots=True)
class _Wiring:
    """How every judge endpoint of one wiring is built."""

    build: EndpointBuilder
    sending: bool
    beside: Path | None
    """The profile's directory, which a relative adapter path is read beside."""

    privacy: RedactionPolicy
    """The run's policy, which every message quoting a judge's endpoint follows."""


def _build_judges(
    cfg: Mapping[str, object], judge: Callable[[str], str], endpoint_identity: str
) -> tuple[LlmJudgeEvaluator, ReferenceJudgeEvaluator]:
    """Build the security judge and the reference judge on one judge model and one meter."""
    version = cfg.get("prompt_version", DEFAULT_PROMPT_VERSION)
    if not isinstance(version, str):
        raise ProfileError("evaluators.llm_judge.prompt_version must be a string")
    min_agreement = cfg.get("min_agreement", 1)
    # `bool` is an `int` subclass, so `min_agreement: true` would slip through — reject it.
    if not isinstance(min_agreement, int) or isinstance(min_agreement, bool):
        raise ProfileError("evaluators.llm_judge.min_agreement must be an integer")
    identity = f"{endpoint_identity}; samples={min_agreement}"
    try:
        # `prompt_version` names the security judge's rubric; the reference judge keeps
        # its own, so neither can inherit a calibration measured for the other.
        return (
            LlmJudgeEvaluator(
                judge, version, min_agreement, _calibration(cfg), judge_identity=identity
            ),
            ReferenceJudgeEvaluator(judge, min_agreement=min_agreement, judge_identity=identity),
        )
    except ValueError as exc:  # unknown prompt_version or min_agreement < 1 — config typos
        raise ProfileError(f"evaluators.llm_judge: {exc}") from exc


def _calibration(cfg: Mapping[str, object]) -> JudgeCalibration | None:
    """Read a measured accuracy from config, if the operator recorded one.

    Deliberately numbers rather than a corpus path: measuring costs one judge call
    per sample, and a scan is the wrong moment to spend that. Run
    `guardana calibrate`, then record what it measured — an explicit, auditable
    act rather than something that quietly happens on every run.
    """
    raw = cfg.get("calibration")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ProfileError("evaluators.llm_judge.calibration must be a mapping")
    accuracy = raw.get("accuracy")
    samples = raw.get("samples")
    evaluator_id = raw.get("evaluator_id")
    if not isinstance(accuracy, int | float) or isinstance(accuracy, bool):
        raise ProfileError("evaluators.llm_judge.calibration.accuracy must be a number")
    if not isinstance(samples, int) or isinstance(samples, bool):
        raise ProfileError("evaluators.llm_judge.calibration.samples must be an integer")
    if not isinstance(evaluator_id, str) or not evaluator_id:
        raise ProfileError(
            "evaluators.llm_judge.calibration.evaluator_id must name the judge that was "
            "measured, e.g. llm_judge@2026.1 — a changed rubric must not inherit an "
            "older measurement"
        )
    try:
        return JudgeCalibration(
            evaluator_id=evaluator_id, accuracy=float(accuracy), samples=samples
        )
    except ValueError as exc:
        raise ProfileError(f"evaluators.llm_judge.calibration: {exc}") from exc


def calibrations_for_another_prompt_version(
    profile: Profile, calibrations: Mapping[str, RecordedCalibration]
) -> tuple[str, ...]:
    """Say which configured calibration was measured under another `llm_judge` prompt version.

    A calibration applies only to the judge id its verdicts carried, and the prompt version
    is part of that id, so such a calibration neither caps confidence nor corrects a rate.
    Each sentence names the pin that keeps it. A version the wiring refuses names nothing,
    since that run never starts.
    """
    cfg = profile.evaluator_config.get("llm_judge")
    if cfg is None:
        return ()
    version = cfg.get("prompt_version", DEFAULT_PROMPT_VERSION)
    if not isinstance(version, str) or version not in PROMPT_TEMPLATES:
        return ()
    in_force = f"{LlmJudgeEvaluator.id}@{version}"
    named: list[tuple[str, str]] = []
    inline = cfg.get("calibration")
    if isinstance(inline, Mapping) and isinstance(inline.get("evaluator_id"), str):
        named.append(("evaluators.llm_judge.calibration", str(inline["evaluator_id"])))
    named.extend(
        (f"the calibration recorded for {recorded.evaluator}", recorded.assessor)
        for recorded in calibrations.values()
        if recorded.assessor is not None
    )
    said: list[str] = []
    for where, measured_for in named:
        judge, versioned, measured_version = measured_for.partition("@")
        if judge != LlmJudgeEvaluator.id or not versioned or measured_for == in_force:
            continue
        keep = (
            f'set evaluators.llm_judge.prompt_version: "{measured_version}" to keep it, '
            f"or measure the judge again with guardana calibrate"
            if measured_version in PROMPT_TEMPLATES
            else "measure the judge again with guardana calibrate"
        )
        said.append(
            f"{where} was measured for {measured_for}, and this run grades with {in_force}, "
            f"so it does not apply; {keep}"
        )
    return tuple(said)


def _endpoint_call(
    cfg: Mapping[str, object],
    what: str,
    budgets: Budgets | None,
    serves: tuple[str, ...],
    wiring: _Wiring,
) -> tuple[Callable[[str], str], JudgeMeter, str]:
    """Build a `prompt -> reply` callable from an endpoint config block, bounded when asked.

    `serves` names the evaluators that will grade through it, so its meter can say whose
    calls it counts. The judge's identity is returned beside it.
    """
    endpoint = _require_str(cfg, "endpoint", what)
    model = _require_str(cfg, "model", what)
    carried = private_url_parts(endpoint)
    if urlsplit(endpoint).scheme in ("http", "https") and carried:
        raise ProfileError(
            f"evaluators.{what}.endpoint carries a part a credential hides in "
            f"({', '.join(carried)}), which a judge endpoint cannot send; name the variable "
            f"holding its key in evaluators.{what}.api_key_env instead"
        )
    problem = unusable_url(endpoint)
    if problem is not None:
        raise ProfileError(f"evaluators.{what}.endpoint {problem}")
    connection = Connection(
        endpoint,
        model,
        provider=_optional_str(cfg, "provider", what),
        api_key_env=_optional_str(cfg, "api_key_env", what),
        adapter=_adapter_path(cfg, what, wiring.beside),
    )
    builder = wiring.build
    if not isinstance(builder, ConnectionBuilder) and (
        connection.provider is not None or connection.adapter is not None
    ):
        raise ProfileError(
            f"evaluators.{what} sets provider or adapter, which the judge endpoint builder "
            f"this run was given cannot honour; drop them, or build judges with the "
            f"default builder"
        )
    try:
        resolved = resolve_connection(
            connection, sending=wiring.sending, spelling=Spelling.judge(what), for_judge=True
        )
    except ConnectionConfigError as exc:
        raise ProfileError(str(exc)) from exc
    try:
        if isinstance(builder, ConnectionBuilder):
            target = builder.connect(resolved)
        else:
            target = builder(endpoint, model, resolved.api_key)
    except EndpointError:
        # Neither the builder's message nor the URL is repeated: a value that did not
        # parse as a URL can hold its credential where no scrubber looks for one.
        raise ProfileError(
            f"evaluators.{what}.endpoint must be an http or https URL with a host"
        ) from None
    meter = JudgeMeter(
        what,
        target,
        endpoint,
        serves,
        quoting=MessageQuoting.of(wiring.privacy, resolved.secret_values),
    )
    if budgets is not None:
        meter.apply(budgets)
    return meter.ask, meter, _identity(cfg, what, resolved)


def _identity(cfg: Mapping[str, object], what: str, resolved: ResolvedConnection) -> str:
    """State which model at which endpoint grades, so a calibration can be matched to it.

    The endpoint is digested after canonicalisation, never written out: a URL can carry
    credentials in its userinfo or query, and two spellings of one server must not read
    as two judges. A provider and an adapter are named only when the block sets them,
    so the identity of a block that sets neither does not move.
    """
    model = _require_str(cfg, "model", what)
    parts = urlsplit(_require_str(cfg, "endpoint", what))
    try:
        port = parts.port
    except ValueError as exc:
        raise ProfileError(f"evaluators.{what}.endpoint has an unreadable port: {exc}") from exc
    scheme = parts.scheme.lower()
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    if port is None:
        raise ProfileError(f"evaluators.{what}.endpoint must state a port, or use http or https")
    host = (parts.hostname or "").lower()
    canonical = f"{scheme}://{host}:{port}{parts.path.rstrip('/')}"
    endpoint = digest_of(canonical).split(":", 1)[-1][:12]
    identity = f"model={model}; endpoint={endpoint}"
    if cfg.get("provider") is not None:
        identity += f"; provider={resolved.provider}"
    if resolved.adapter_digest is not None:
        identity += f"; adapter={resolved.adapter_digest.split(':', 1)[-1][:12]}"
    return identity


def _require_str(cfg: Mapping[str, object], key: str, what: str) -> str:
    value = cfg.get(key)
    if not isinstance(value, str) or not value:
        raise ProfileError(f"evaluators.{what}.{key} must be a non-empty string")
    return value


def _optional_str(cfg: Mapping[str, object], key: str, what: str) -> str | None:
    value = cfg.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ProfileError(f"evaluators.{what}.{key} must be a non-empty string")
    return value


def _adapter_path(cfg: Mapping[str, object], what: str, beside: Path | None) -> Path | None:
    """Return the block's adapter file; a relative one is read beside the profile."""
    written = _optional_str(cfg, "adapter", what)
    if written is None:
        return None
    path = Path(written)
    if beside is None or path.is_absolute():
        return path
    return beside / path

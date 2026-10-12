"""Run Guardana from Python the way the CLI runs it, and get typed results for every outcome.

`Verifier` holds what a run is configured with — the plugin trust, the profile, local and
in-code rules and evaluators, calibrations — and `Verifier.scan` or `Verifier.run`
returns a `Verification`: the redacted result, the saved-run manifest, the gate's
verdict and the exit code the CLI would use. A run that fails, stays indeterminate, or is
stopped by its budget or by its target failing part-way is returned like one that passed;
only a run that could not be carried out raises, with a `VerificationError`.

`guardana scan` and `guardana probe` call this module, so a run from Python and a run
from the command line compose the same steps in the same order.
"""

import hashlib
import json
import threading
import uuid
import weakref
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import URLError

from guardana.core.budget import BudgetExhausted
from guardana.core.calibration.store import CalibrationStoreError, RecordedCalibration
from guardana.core.evaluator.base import Evaluator
from guardana.core.evaluator.config import (
    EndpointBuilder,
    JudgeMeters,
    JudgeUnavailableError,
    default_endpoint_builder,
    wire_config_evaluators,
)
from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.fixtures import Fixtures
from guardana.core.gate import GateOutcome, OpenQuestion, exit_code_for, gate_outcome
from guardana.core.gate import open_questions as _open_questions
from guardana.core.keeping import ExchangeKeeper
from guardana.core.manifest.build import (
    ConnectionFacts,
    build_run_manifest,
    load_profile_calibrations,
    target_identity,
)
from guardana.core.manifest.identity import DeploymentRef, RunSource, TargetIdentity
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import (
    ExchangesRecord,
    FixturesRecord,
    RecordingOriginRecord,
    RecordingRecord,
)
from guardana.core.manifest.usage import JudgeUsage
from guardana.core.plugins import PluginTrust
from guardana.core.probe import run_target_probe
from guardana.core.profile import Policy, Profile, ProfileError, default_profile
from guardana.core.recording import (
    Recording,
    RecordingError,
    RecordingOrigin,
    read_recording,
    render_recording,
)
from guardana.core.redaction import EvidenceRedactor, MessageQuoting
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.report.baseline import Baseline, apply_baseline
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.location import relativize, relativize_findings
from guardana.core.report.serialize import run_to_dict
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.rule import Rule
from guardana.core.runner import (
    DEFAULT_ENDPOINT_CONCURRENCY,
    Runner,
    applicability_refusal,
    refuse_unmatched_includes,
    select_rules,
    target_failures,
)
from guardana.core.subject import SubjectKind
from guardana.core.target import (
    ArtifactTarget,
    Capability,
    EndpointError,
    SeededData,
    SeededTarget,
    Target,
    TargetKind,
    examined_by_rules_only,
)
from guardana.core.target.adapter import HttpAdapterTransport
from guardana.core.target.endpoint import EndpointTarget, secrets_sent_by
from guardana.core.target.failure import FailureRemedies, describe_failure
from guardana.core.target.recorded import RecordedTarget


class VerificationError(Exception):
    """A run that could not be carried out, so there is no result to return."""


class TargetUnavailableError(VerificationError):
    """The target failed in a way the run could not record, so there is no result to keep.

    A target that fails while a rule sends to it stops the run instead, and the stopped
    `Verification` is returned with what it graded so far.
    """


class JudgeUnreachableError(VerificationError):
    """A judge configured under `evaluators:` could not be reached during the run."""


class UnenforceableBudgetError(VerificationError):
    """The profile sets a budget this target or judge cannot enforce, refused before sending."""


class CalibrationError(VerificationError):
    """A calibration file the run was pointed at cannot be read."""


class UnsupportedTargetError(VerificationError):
    """A target this facade does not run, refused rather than run without what it needs."""


class RecordingRefusedError(VerificationError):
    """A recording that cannot be graded as asked: unreadable, or kept at other trials."""


class TargetReusedError(VerificationError):
    """A target that already ran, so its usage, budgets or cached reads would describe two runs."""


_KEPT_NAME = "guardana-probe"
"""The name a probe's sidecar recording carries; its version is the run id."""

_NAMED_AT_MOST = 3
"""How many differing rules a refusal names before it says there are more."""

_CANARY_PROBE = "GUARDANA_CANARY_PLANNING"
"""A stand-in token, only to ask a rule whether it plants a canary."""

_RAN: "weakref.WeakValueDictionary[int, Target]" = weakref.WeakValueDictionary()
"""Every live target this module has run, by identity; a target is refused the second time."""
_RAN_LOCK = threading.Lock()


@dataclass(frozen=True, slots=True)
class Verification:
    """One run as typed data: what it found, how it describes itself, and what it concluded.

    `result` is redacted under the profile's privacy policy and has its baseline applied;
    `manifest` is the run's saved-run description. Both are the halves of the document
    `guardana scan --format json --output` writes, which `document()` returns.
    """

    result: ScanResult
    manifest: RunManifest
    gate: GateOutcome
    judge_usage: Mapping[str, JudgeUsage] | None = None
    """What each judge configured under `evaluators:` spent, or None when none was."""

    judge_stops: tuple[str, ...] = ()
    """Each judge whose own ceiling stopped the run, in the words the CLI prints."""

    exchanges: Recording | None = None
    """The chat exchanges the run kept under `privacy.keep_exchanges`, redacted, or None.

    `manifest.exchanges` records the digest of `render_recording(exchanges)`, which is what
    `save()` writes beside the run.
    """

    stop_messages: tuple[str, ...] = ()
    """What the target did when it stopped the run, in the words the CLI prints; never saved.

    Taken before redaction, which under `metadata_only` withholds every recorded reason:
    these messages were built within the run's privacy policy already, so the saved run
    stays redacted while the operator still learns the cause.
    """

    @property
    def exit_code(self) -> int:
        """The exit code `guardana` gives this result: 0, 1, 2, 4 (its target stopped it) or 6."""
        return exit_code_for(self.gate, self.result.stopped_by)

    @property
    def passed(self) -> bool:
        """Whether the gate passed. Anything else — a failure, an open question — is False."""
        return self.gate is GateOutcome.PASS

    @property
    def open_questions(self) -> tuple[OpenQuestion, ...]:
        """Every fact in the result that leaves part of the run's question unanswered."""
        return _open_questions(self.result)

    def document(self) -> dict[str, object]:
        """Return the saved-run document, in the current run schema, as a JSON-ready dict."""
        return run_to_dict(self.result, self.manifest)

    def save(self, path: Path) -> None:
        """Write the saved-run document to `path`, as `--format json --output` does.

        Kept exchanges go to `exchanges_path(path)` beside it, replacing a link there rather
        than writing through it; a file there from an earlier run is removed when this one
        kept none, so it never reads as this run's.
        """
        path.write_text(json.dumps(self.document(), indent=2) + "\n", encoding="utf-8")
        sidecar = exchanges_path(path)
        if self.exchanges is not None:
            if sidecar.is_symlink():
                sidecar.unlink()
            sidecar.write_bytes(render_recording(self.exchanges).encode("utf-8"))
        elif sidecar.exists():
            sidecar.unlink()


def load_verification(path: Path) -> Verification:
    """Read a saved run of any schema back as a `Verification`, its verdict as recorded.

    The gate is the one the run recorded, never re-derived; exchanges are not read. A run
    that records no gate, as a migrated schema-1 run does, raises `ReportLoadError`.
    """
    report = load_report(path)
    gate = report.manifest.result_summary.gate
    if gate is None:
        raise ReportLoadError(f"{path} records no gate, so its verdict cannot be read")
    return Verification(result=report.result, manifest=report.manifest, gate=gate)


def exchanges_path(run: Path) -> Path:
    """Where the exchanges a run kept are written beside it: `run.json` → `run.exchanges.jsonl`."""
    stem = run.stem if run.suffix == ".json" else run.name
    return run.with_name(f"{stem}.exchanges.jsonl")


@dataclass(frozen=True, slots=True)
class Verifier:
    """What a run is configured with; one `Verifier` can run several targets in turn.

    `trust` is required: which installed distributions may run code in this process is
    a decision, never a default. `profile` defaults to `default_profile()`, which
    redacts evidence. `rule_paths` load local YAML rules beside the profile's own
    `rules.paths`; `rules` and `evaluators` register objects built in code.
    `calibrations` default to the files the profile names. `concurrency` bounds an
    endpoint run, as `probe --concurrency` does. `secrets` are values the target sends
    to authenticate beside those it declares itself (`SendsSecrets`); both are withheld
    from every failure, finding and kept exchange the run records. `remedies` is what a
    recorded failure advises.

    `registry` is for a caller that assembled its own: nothing is discovered or loaded
    into it, so it cannot be combined with `rule_paths`, `rules` or `evaluators`, and
    the profile's `rules.paths` are not loaded either; the caller loads them on it. The
    trust it was discovered under is the one in force and the one the run records.
    Each run works on a copy that gets the profile's trials and the judges configured
    under `evaluators:`, so the registry itself is never changed.
    """

    trust: PluginTrust
    profile: Profile = field(default_factory=default_profile)
    rule_paths: Sequence[Path] = ()
    rules: Sequence[Rule] = ()
    evaluators: Sequence[Evaluator] = ()
    calibrations: Mapping[str, RecordedCalibration] | None = None
    concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY
    registry: Registry | None = None
    judge_endpoint: EndpointBuilder = default_endpoint_builder
    """How the endpoint of each judge under `evaluators:` is built from its url, model and key.

    Only the default builder honours a judge block's `provider` or `adapter`; with
    a builder of your own, such a block raises `ProfileError` before anything is sent,
    rather than building that judge on the OpenAI wire.
    """

    demanded_rules: frozenset[str] = frozenset()
    """Rules the run must complete; one that does not is a coverage shortfall, with no switch.

    Empty by default. A recipe demands every rule its lock pins, so a recording that answers
    none of a locked rule's questions cannot leave the run green.
    """

    subject_kind: SubjectKind | None = None
    """What answered, as the caller declares it, written into the exchanges a run keeps.

    None by default, which declares nothing; `guardana recipe run` passes its recipe's kind.
    """

    fixtures: FixturesRecord | None = None
    """The fixtures file the run was given, written into its manifest as declared.

    None by default. A caller that builds its target from fixtures passes
    `Fixtures.record()`, so the saved run says which seeded data it asked about and `diff`
    refuses to read a change of fixtures as a change of the system. A target that declares
    `Capability.SEEDED_DATA` records its own fixtures when this is None, and is refused when
    this names others.

    Fixtures demand their checks: every registered rule that needs seeded data, except
    one that says it has nothing to check on the target. One not completed is a
    `demanded_check` shortfall, and so is a registry with no such rule, so a run cannot
    record seeded data and verify none of it.
    """

    secrets: tuple[str, ...] = field(default=(), repr=False)
    """Values the target sends to authenticate beside those it declares; none is saved."""

    remedies: FailureRemedies = field(default_factory=FailureRemedies)
    """What a recorded failure advises for a refused credential and for a rate limit."""

    _prepared: list[Registry] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        """Refuse arguments a registry given whole would silently leave out."""
        if self.registry is not None and (self.rule_paths or self.rules or self.evaluators):
            raise ValueError(
                "a Verifier given a registry loads nothing into it: register the rules, "
                "evaluators and rule directories on that registry instead"
            )

    def _registry(self) -> Registry:
        if self.registry is not None:
            return self.registry
        if not self._prepared:
            registry = Registry.discover(self.trust)
            for rule in self.rules:
                registry.register_rule(rule)
            for evaluator in self.evaluators:
                registry.register_evaluator(evaluator)
            registry.load_yaml_rule_dirs(
                [Path(path) for path in self.profile.rule_paths] + list(self.rule_paths)
            )
            self._prepared.append(registry)
        return self._prepared[0]

    def scan(
        self,
        path: Path,
        *,
        relative_to: Path | None = None,
        baseline: Baseline | None = None,
        source: RunSource | None = None,
        deployment: DeploymentRef | None = None,
    ) -> Verification:
        """Scan a file or directory with the artifact rules, as `guardana scan PATH` does.

        `relative_to` rewrites file paths in findings, observations and the listing
        relative to that directory, as the CLI does against its working directory; left
        out, they stay as given. A path that does not exist raises `FileNotFoundError`:
        a scan of a typo would find nothing and pass.
        """
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist, so there is nothing to scan")
        target = ArtifactTarget(path, excludes=self.profile.path_excludes)
        reference = target.ref if relative_to is None else relativize(target.ref, relative_to)
        return self._verify(
            target,
            reference=reference,
            relative_to=relative_to,
            baseline=baseline,
            source=source,
            deployment=deployment,
        )

    def run(
        self,
        target: Target,
        *,
        relative_to: Path | None = None,
        baseline: Baseline | None = None,
        source: RunSource | None = None,
        deployment: DeploymentRef | None = None,
    ) -> Verification:
        """Run every applicable rule against `target` and return what the run concluded.

        An endpoint target gets one pass per canary rule with a fresh canary planted,
        when it can plant one. A trace target is refused with `UnsupportedTargetError`:
        its unreadable records and its contracts are read by `guardana analyze-trace`.
        `relative_to` rewrites file paths in what the run found, never the target's own
        reference, which a third-party target owns. The caller owns the target, and
        closes it. A target runs once: a second run, or one started while the first is
        under way, raises `TargetReusedError`, because its meter and whatever it cached
        would describe both runs. A run refused before anything was sent, over its
        calibrations, a budget or its profile, leaves the target free; a target that
        cannot be weakly referenced is checked by its meter alone. A `rules.include`
        pattern that matches no registered rule raises `ProfileError` before any rule runs.
        """
        return self._verify(
            target,
            reference=target.ref,
            relative_to=relative_to,
            baseline=baseline,
            source=source,
            deployment=deployment,
        )

    def grade(
        self,
        path: Path,
        *,
        source: RunSource | None = None,
        deployment: DeploymentRef | None = None,
    ) -> Verification:
        """Grade the answers a recording holds, as `guardana grade RECORDING` does; nothing is sent.

        The recording is the execution: its digest becomes `target.document` and its own
        description the manifest's `recording`. Rules run against a `RecordedTarget`, so a
        question the recording does not answer, or a reply redaction altered, is never a
        pass. A recording that cannot be read, or that a probe kept at different trials per
        case than this profile runs, raises `RecordingRefusedError` before anything runs.
        """
        try:
            recording = read_recording(path)
        except RecordingError as exc:
            raise RecordingRefusedError(str(exc)) from exc
        return self.run(RecordedTarget(recording), source=source, deployment=deployment)

    def _verify(  # noqa: PLR0913 — the finish step's inputs, keyword-only
        self,
        target: Target,
        *,
        reference: str,
        relative_to: Path | None,
        baseline: Baseline | None,
        source: RunSource | None,
        deployment: DeploymentRef | None,
    ) -> Verification:
        if target.kind is TargetKind.TRACE:
            raise UnsupportedTargetError(
                f"{target.ref} is a trace; run `guardana analyze-trace`, which reads its "
                f"unreadable records and its contracts"
            )
        fixtures = self._fixtures_of(target)
        keeping = self._keeps(target)
        withheld = self._withheld(target)
        spent = target.usage()
        if spent is not None and spent.requests:
            raise TargetReusedError(
                f"{target.ref} already sent {spent.requests} request(s); build a fresh target "
                f"for each run so its usage and budgets describe this run alone"
            )
        _claim(target)
        keeper = None
        try:
            calibrations = self._calibrations()
            registry = self._registry().copied()
            refuse_unmatched_includes(self.profile, registry)
            registry.apply_trials(self.profile.trials)
            if isinstance(target, RecordedTarget):
                refuse_other_trials(target.recording, registry)
            endpoint = target.kind is TargetKind.ENDPOINT
            judges = self._judges(registry) if endpoint else JudgeMeters()
            if keeping is not None:
                keeper = ExchangeKeeper()
                keeping.keep_exchanges(keeper)
            planned = self._kept_plan(registry, target) if keeper is not None else None
            started_at = datetime.now(UTC)
            result, identity = self._execute(
                target, registry, calibrations, endpoint=endpoint, withheld=withheld
            )
        except (CalibrationError, UnenforceableBudgetError, RecordingRefusedError, ProfileError):
            # Each is refused before the first request, which leaves the target unused.
            if keeping is not None:
                keeping.stop_keeping()
            _release(target)
            raise
        withheld = self._learned(target, withheld)
        return self._finish(
            registry,
            result,
            target,
            identity=identity if reference == target.ref else target_identity(target, reference),
            reference=reference,
            relative_to=relative_to,
            baseline=baseline,
            started_at=started_at,
            concurrency=self.concurrency if endpoint else 1,
            calibrations=calibrations,
            judges=judges,
            source=source,
            deployment=deployment,
            kept=None if keeper is None or planned is None else (keeper, planned),
            fixtures=fixtures,
            demanded=self.demanded_rules | demanded_by_fixtures(registry, target, fixtures),
            unchecked=unchecked_fixtures(registry, target, fixtures),
            withheld=withheld,
        )

    def _withheld(self, target: Target) -> tuple[str, ...]:
        """Return every value the run withholds: the caller's and those the target declares.

        Asked before anything is sent: a target that cannot say what it sends would
        have its credentials saved in what the run records, so it is refused instead.
        """
        try:
            declared = secrets_sent_by(target)
        except Exception as exc:
            raise UnsupportedTargetError(
                f"{target.ref} could not say which values it sends to authenticate "
                f"({type(exc).__name__}), so the run could not keep them out of what it saves"
            ) from exc
        return (*self.secrets, *declared)

    def _learned(self, target: Target, before: tuple[str, ...]) -> tuple[str, ...]:
        """Return what the run withholds once it has run: a target learns values while it sends.

        A session id or task id the server handed out is one of them, and a server may
        echo it into an error, so the target is asked again before anything is written.
        """
        return tuple(dict.fromkeys((*before, *self._withheld(target))))

    def _fixtures_of(self, target: Target) -> FixturesRecord | None:
        """Return the fixtures the run records, refusing a record that names other fixtures."""
        held = _seeded_fixtures(target)
        if held is None:
            return self.fixtures
        seeded = held.record()
        if self.fixtures is not None and self.fixtures.digest != seeded.digest:
            raise UnsupportedTargetError(
                f"the run was given fixtures {self.fixtures.name} ({self.fixtures.digest}) and "
                f"{target.ref} was seeded from {seeded.name} ({seeded.digest}); the run would "
                f"record fixtures it did not ask about"
            )
        return seeded

    def _keeps(self, target: Target) -> EndpointTarget | SeededTarget | None:
        """Return the endpoint whose exchanges this run keeps, refusing one that cannot keep them.

        Only an endpoint run has chat exchanges, and a recording is already what it answers
        from. The built-in endpoint, and any target built on it, keeps them through its
        per-rule views; any other endpoint target would keep nothing while the run said it
        kept everything, so it is refused before anything is sent.
        """
        if (
            not self.profile.privacy.keep_exchanges
            or target.kind is not TargetKind.ENDPOINT
            or isinstance(target, RecordedTarget)
        ):
            return None
        if not isinstance(target, EndpointTarget | SeededTarget):
            raise UnsupportedTargetError(
                f"privacy.keep_exchanges keeps the chat exchanges of the built-in endpoint "
                f"target and of targets built on it; {target.ref} is a "
                f"{type(target).__name__}, which keeps none"
            )
        return target

    def _kept_plan(self, registry: Registry, target: Target) -> dict[str, int]:
        """Return each rule the plain pass plans, with its trials per case.

        A rule that plants a canary runs in a planted pass whose exchanges are never kept,
        so it is left out: a regrade cannot plant one either. So is a rule that asks as a
        tenant: tenant endpoints keep nothing, and a regrade has no tenant to ask as.
        """
        chosen, _ = select_rules(registry, self.profile, target)
        return {
            rule.meta.id: rule.trials_per_case
            for rule in chosen
            if rule.with_canary(_CANARY_PROBE) is None
            and Capability.SEEDED_DATA not in rule.meta.required_capabilities
        }

    def _calibrations(self) -> Mapping[str, RecordedCalibration]:
        if self.calibrations is not None:
            return self.calibrations
        try:
            return load_profile_calibrations(self.profile)
        except CalibrationStoreError as exc:
            raise CalibrationError(str(exc)) from exc

    def _judges(self, registry: Registry) -> JudgeMeters:
        try:
            return wire_config_evaluators(
                registry, self.profile, self.profile.budgets, build=self.judge_endpoint
            )
        except BudgetExhausted as exc:
            raise UnenforceableBudgetError(str(exc)) from exc

    def _execute(
        self,
        target: Target,
        registry: Registry,
        calibrations: Mapping[str, RecordedCalibration],
        *,
        endpoint: bool,
        withheld: tuple[str, ...],
    ) -> tuple[ScanResult, TargetIdentity]:
        records = {key: value.as_record() for key, value in calibrations.items()}
        try:
            if endpoint and not examined_by_rules_only(target):
                probed = run_target_probe(
                    registry,
                    self.profile,
                    target,
                    concurrency=self.concurrency,
                    calibrations=records,
                    secrets=self.secrets,
                    remedies=self.remedies,
                )
                return probed.result, probed.identity
            runner = Runner(
                registry=registry,
                profile=self.profile,
                concurrency=self.concurrency if endpoint else 1,
                calibrations=records,
                secrets=self.secrets,
                remedies=self.remedies,
            )
            return runner.run(target), target_identity(target, target.ref)
        except BudgetExhausted as exc:
            raise UnenforceableBudgetError(str(exc)) from exc
        except JudgeUnavailableError as exc:
            raise JudgeUnreachableError(str(exc)) from exc
        except (URLError, EndpointError) as exc:
            raise TargetUnavailableError(self._unreachable(exc, target, withheld)) from exc
        except OSError as exc:
            if not endpoint:
                raise
            raise TargetUnavailableError(self._unreachable(exc, target, withheld)) from exc

    def _unreachable(self, exc: BaseException, target: Target, withheld: tuple[str, ...]) -> str:
        """Say why `target` could not be reached, without a value the run withholds, bounded."""
        quoting = MessageQuoting.of(self.profile.privacy, self._learned(target, withheld))
        return describe_failure(exc, target.ref, quoting, self.remedies)

    def _finish(  # noqa: PLR0913 — one value per persisted execution fact
        self,
        registry: Registry,
        result: ScanResult,
        target: Target,
        *,
        identity: TargetIdentity,
        reference: str,
        relative_to: Path | None,
        baseline: Baseline | None,
        started_at: datetime,
        concurrency: int,
        calibrations: Mapping[str, RecordedCalibration],
        judges: JudgeMeters,
        source: RunSource | None,
        deployment: DeploymentRef | None,
        kept: tuple[ExchangeKeeper, dict[str, int]] | None = None,
        fixtures: FixturesRecord | None = None,
        demanded: frozenset[str] = frozenset(),
        unchecked: tuple[CoverageShortfall, ...] = (),
        withheld: tuple[str, ...] = (),
    ) -> Verification:
        """Relativize, redact, apply the baseline, gate and describe — in that order.

        Redaction comes before the baseline because a waiver's fingerprint is taken from
        the redacted evidence; the gate reads the waived result; the manifest records
        the gate.
        """
        stop_messages = target_failures(result)
        if relative_to is not None:
            result = relativize_findings(result, relative_to)
        redactor = EvidenceRedactor(self.profile.privacy, secrets=withheld)
        result = redactor.redact_result(result)
        if baseline is not None:
            result = apply_baseline(result, baseline.active())
        result = replace(
            result,
            coverage_shortfall=(
                *result.coverage_shortfall,
                *unfinished_demands(demanded, result, self.profile.policy),
                *unchecked,
            ),
        )
        gate = gate_outcome(result, self.profile.policy)
        run_id = str(uuid.uuid4())
        exchanges = (
            None
            if kept is None
            else self._kept_recording(
                kept,
                redactor,
                run_id=run_id,
                subject=reference,
                started_at=started_at,
                gate=gate,
                result=result,
            )
        )
        manifest = build_run_manifest(
            registry,
            self.profile,
            result,
            target_kind=target.kind,
            target_ref=reference,
            target=target,
            gate=gate,
            started_at=started_at,
            identity=identity,
            concurrency=concurrency,
            deployment=deployment,
            source=source,
            calibrations=calibrations,
            judge_usage=judges.usage(),
            exchanges=None if exchanges is None else _exchanges_record(exchanges),
            recording=_recording_record(target.recording)
            if isinstance(target, RecordedTarget)
            else None,
            run_id=run_id,
            connection=_connection_facts(target),
        )
        if fixtures is not None:
            manifest = replace(manifest, fixtures=fixtures)
        return Verification(
            result=result,
            manifest=manifest,
            gate=gate,
            judge_usage=judges.usage(),
            judge_stops=judges.stops(),
            exchanges=exchanges,
            stop_messages=stop_messages,
        )

    def _kept_recording(  # noqa: PLR0913 — the facts the sidecar's origin states
        self,
        kept: tuple[ExchangeKeeper, dict[str, int]],
        redactor: EvidenceRedactor,
        *,
        run_id: str,
        subject: str,
        started_at: datetime,
        gate: GateOutcome,
        result: ScanResult,
    ) -> Recording | None:
        """Turn what the keeper collected into the sidecar recording, or None when it holds nothing.

        A recording with no exchange is refused by every reader, so a run that kept none
        writes no sidecar and records no `exchanges`.
        """
        keeper, planned = kept
        recorded = keeper.recorded(redactor)
        if not recorded:
            return None
        recording = Recording(
            name=_KEPT_NAME,
            version=run_id,
            verbatim=True,
            subject=subject,
            origin=RecordingOrigin(
                run_id=run_id,
                target=subject,
                started_at=started_at.isoformat(),
                stopped_by=None if result.stopped_by is None else str(result.stopped_by),
                gate=str(gate),
                trials=planned,
                rules=tuple(sorted(planned)),
            ),
            exchanges=recorded,
            digest=None,
            subject_kind=self.subject_kind,
        )
        data = render_recording(recording).encode("utf-8")
        digest = DocumentDigest(
            digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
            kind=DigestKind.CONTENT,
            bytes=len(data),
        )
        return replace(recording, digest=digest)


def refuse_other_trials(recording: Recording, registry: Registry) -> None:
    """Refuse grading a probe's exchanges at other trials per case than it kept.

    Raises `RecordingRefusedError`; `guardana plan grade` asks the same question, so a plan
    never promises a grade this refuses.

    Fewer trials would leave a kept reply, possibly the failing one, ungraded; more would
    ask for replies the probe never received.
    """
    if recording.origin is None:
        return
    rules = {rule.meta.id: rule for rule in registry.rules()}
    differing = [
        f"{rule_id} kept {kept}, this run grades {rules[rule_id].trials_per_case}"
        for rule_id, kept in sorted(recording.origin.trials.items())
        if rule_id in rules and rules[rule_id].trials_per_case != kept
    ]
    if differing:
        raise RecordingRefusedError(
            f"the recording kept other trials per case than this run grades "
            f"({'; '.join(differing[:_NAMED_AT_MOST])}"
            f"{'…' if len(differing) > _NAMED_AT_MOST else ''}); grade it with "
            f"the trials the probe ran"
        )


def unfinished_demands(
    demanded: Collection[str], result: ScanResult, policy: Policy
) -> tuple[CoverageShortfall, ...]:
    """Return one shortfall for each demanded rule the run did not complete, saying why.

    `policy` is the run's own, so a rule it never selected is named as such rather than
    as one that started and did not finish.
    """
    skipped = {skip.rule_id: skip for skip in result.rules_skipped}
    errored = {error.source: error for error in result.errors}
    completed = set(result.rules_run)
    gaps: list[CoverageShortfall] = []
    for rule_id in sorted(set(demanded) - completed):
        if rule_id in skipped:
            why = f"was skipped ({skipped[rule_id].reason}): {skipped[rule_id].detail}"
        elif rule_id in errored:
            why = f"did not finish: {errored[rule_id].reason}"
        elif not policy.matches(rule_id):
            why = "is not selected by the profile"
        else:
            why = "never ran to completion"
        gaps.append(
            CoverageShortfall(
                kind=ShortfallKind.DEMANDED_CHECK,
                name=rule_id,
                detail=f"{rule_id} is required by this run and {why}",
            )
        )
    return tuple(gaps)


def demanded_by_fixtures(
    registry: Registry, target: Target, fixtures: FixturesRecord | None
) -> frozenset[str]:
    """Return the rules a run given fixtures must complete; none for a run given no fixtures.

    Every registered rule that needs `Capability.SEEDED_DATA` is demanded, whatever the
    profile selects, unless it says it has nothing to check on `target`. A run that
    records fixtures and was not handed a seeded target demands them too, and they then
    cannot run, so the run cannot pass on fixtures it never asked about.
    """
    if fixtures is None and not _declares_seeded_data(target):
        return frozenset()
    return frozenset(
        rule.meta.id
        for rule in registry.rules()
        if Capability.SEEDED_DATA in rule.meta.required_capabilities
        and applicability_refusal(rule, target) is None
    )


def _declares_seeded_data(target: Target) -> bool:
    """Whether `target` says it holds seeded data, whoever built it."""
    return Capability.SEEDED_DATA in target.capabilities()


def _seeded_fixtures(target: Target) -> Fixtures | None:
    """Return the fixtures a target seeded with data holds, or None for any other target."""
    if isinstance(target, SeededData) and _declares_seeded_data(target):
        return target.fixtures
    return None


def unchecked_fixtures(
    registry: Registry, target: Target, fixtures: FixturesRecord | None
) -> tuple[CoverageShortfall, ...]:
    """Return a shortfall when a run is given fixtures and no registered rule checks them."""
    given = fixtures is not None or _declares_seeded_data(target)
    if not given or demanded_by_fixtures(registry, target, fixtures):
        return ()
    return (
        CoverageShortfall(
            kind=ShortfallKind.DEMANDED_CHECK,
            name=str(Capability.SEEDED_DATA),
            detail=(
                "the run was given fixtures and no registered rule checks seeded data, so "
                "none of it was verified"
            ),
        ),
    )


def _connection_facts(target: Target) -> ConnectionFacts | None:
    """Describe how an endpoint run reached its model; None for any other target.

    Read off the target the caller passed, before a canary is planted on a view of it; a
    seeded target is described by the run's own endpoint, which is never a tenant.
    """
    if isinstance(target, SeededTarget):
        target = target.endpoint
    if not isinstance(target, EndpointTarget):
        return None
    transport = target.transport
    prompt = target.system_prompt
    return ConnectionFacts(
        provider=target.provider,
        adapter_digest=transport.source_digest
        if isinstance(transport, HttpAdapterTransport)
        else None,
        system_prompt_digest=None
        if prompt is None
        else DocumentDigest.of(prompt.encode("utf-8"), DigestKind.CONTENT).digest,
    )


def _recording_record(recording: Recording) -> RecordingRecord:
    """Describe the recording a graded run answered from, as the recording declares itself."""
    origin = recording.origin
    return RecordingRecord(
        name=recording.name,
        version=recording.version,
        subject=recording.subject,
        verbatim=recording.verbatim,
        origin=None
        if origin is None
        else RecordingOriginRecord(
            run_id=origin.run_id,
            target=origin.target,
            started_at=origin.started_at,
            stopped_by=origin.stopped_by,
            gate=origin.gate,
        ),
    )


def _exchanges_record(recording: Recording) -> ExchangesRecord:
    """Describe a kept recording in the manifest: its digest, its size, how many were altered."""
    if recording.digest is None:
        raise ValueError("a kept recording is digested before the manifest records it")
    return ExchangesRecord(
        digest=recording.digest.digest,
        count=len(recording.exchanges),
        altered=sum(1 for exchange in recording.exchanges if recording.reply_altered(exchange)),
    )


def _claim(target: Target) -> None:
    """Claim `target` for one run, refusing one that ran or is running here.

    A target that cannot be weakly referenced is not tracked; its meter is still checked.
    """
    with _RAN_LOCK:
        if _RAN.get(id(target)) is target:
            raise TargetReusedError(
                f"{target.ref} already ran; build a fresh target for each run so what it "
                f"lists and reads describes this run alone"
            )
        try:
            _RAN[id(target)] = target
        except TypeError:
            return


def _release(target: Target) -> None:
    """Give back a claim on a target that was refused before it sent anything."""
    with _RAN_LOCK:
        if _RAN.get(id(target)) is target:
            del _RAN[id(target)]


__all__ = [
    "CalibrationError",
    "EndpointBuilder",
    "JudgeUnreachableError",
    "RecordingRefusedError",
    "TargetReusedError",
    "TargetUnavailableError",
    "UnenforceableBudgetError",
    "UnsupportedTargetError",
    "Verification",
    "VerificationError",
    "Verifier",
    "exchanges_path",
    "load_verification",
]

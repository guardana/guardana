from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import NotOffered, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    McpAuthorizationView,
    TargetKind,
    TaskAnswer,
    TaskOffer,
    Tasks,
)
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025, OWASP_MCP10_2025
from guardana.rules.mcp import _samples
from guardana.rules.mcp._base import McpAuthorizationRule
from guardana.rules.mcp._ids import id_structure

_COUNTING = ("task-1", "task-2", "task-3")


class McpTaskIdentityRule(McpAuthorizationRule):
    """MCP tasks shown to a caller who presented no credential, or guarded only by their ids.

    > Receivers that support context binding […] MUST NOT list tasks belonging to other
    > requestors. If context-binding is unavailable, receivers MUST generate
    > cryptographically secure task IDs.

    Only `tools/call` creates a task, in either revision, and Guardana calls no tool, so
    this reads what a caller presenting nothing is shown by one `tasks/list`. A fresh
    anonymous session owns no task, so any task it is shown is somebody else's. On a
    server that serves tools to anyone there is no authorization context to bind a task
    to, and the id is all that guards it: ids that repeat, count up or are short enough
    to enumerate are a second finding there. On a server that gates its tools they are
    not, because the context binds the task whatever its id looks like.

    A refused anonymous listing is the conforming answer. An empty one on a gated server
    is conforming only beside a task it hides: one more listing presenting the operator's
    credential has to show at least one, or the binding is inconclusive, as it is without
    a credential (`--mcp-token-env`). On an open server an empty listing leaves the ids
    ungraded and says so. A
    server that declares no tasks and answers `tasks/list` as an unknown method has none
    to grade, which the run records as not offered. The listing is one page, and an
    empty one naming a further page is inconclusive; ids are read in memory and never
    written, and evidence holds only counts.
    """

    meta = RuleMeta(
        id="guardana.mcp.task_identity",
        title="MCP server shows tasks to a caller who presented no credential",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP07_2025, OWASP_MCP10_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    claim = "what its task listing shows a caller without a credential was not established"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous probe, the legacy probe and two sessions.

        Over a dual-era server that settled on the modern era: discovery, the anonymous
        listing, the legacy probe, then an anonymous handshake, its notification and the
        task listing, and the same three again presenting the operator's credential. Over
        the handshake era the anonymous three, the listing and the conversation's
        handshake, its notification and the operator's listing stay below that.
        """
        return 9

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample an open listing, two gated ones, two empty ones and a server without tasks."""
        return materialise(
            (
                _samples.sample(
                    "an open server listing counting task ids to anyone",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(
                        _samples.open_server(tasks=_COUNTING, task_declaration="listing")
                    ),
                ),
                _samples.sample(
                    "a gated server listing each caller only its own tasks",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.gated_server(
                            tasks=_COUNTING,
                            tasks_owner_bound=True,
                            tasks_unguarded=True,
                            task_declaration="listing",
                        ),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "a gated server refusing its task listing to a caller without a credential",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.gated_server(
                            tasks=_COUNTING, tasks_owner_bound=True, task_declaration="listing"
                        ),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "an open server with no task stored",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.open_server(tasks=(), task_declaration="listing")
                    ),
                ),
                _samples.sample(
                    "a gated server listing nobody a task, the operator included",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.gated_server(
                            tasks=(),
                            tasks_owner_bound=True,
                            tasks_unguarded=True,
                            task_declaration="listing",
                        ),
                        credential=_samples.CREDENTIAL,
                    ),
                ),
                _samples.sample(
                    "a server declaring no tasks",
                    FixtureOutcome.NOT_OFFERED,
                    lambda: _samples.target(_samples.open_server()),
                ),
            )
        )

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Grade the anonymous listing; decide before reporting whether tasks are offered at all."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        tasks = view.tasks
        if tasks.error is not None:
            yield self.unverified(view, f"{self.claim}: {tasks.error}")
            return
        if tasks.answer is TaskAnswer.ANSWERED:
            yield from self._answered(view, tasks)
            return
        if tasks.answer is TaskAnswer.REFUSED:
            return
        if tasks.answer is TaskAnswer.UNKNOWN_METHOD:
            yield from self._unknown_method(view, tasks)
            return
        yield self.unverified(view, f"tasks/list was answered with {tasks.detail}, so {self.claim}")

    def _answered(self, view: McpAuthorizationView, tasks: Tasks) -> Iterator[Finding]:
        open_server = view.anonymous.open_to_anyone
        if tasks.count == 0:
            if tasks.more:
                yield self.unverified(
                    view,
                    "the first page of the listing shows no task to a caller without a "
                    "credential and names a further page, which guardana does not read, so "
                    "what that caller is shown is unknown",
                )
                return
            if open_server:
                yield self.unverified(
                    view,
                    "no task is visible to a caller without a credential, so whether task "
                    "ids can be guessed — the only guard a server without authentication "
                    "has — cannot be graded",
                )
                return
            yield from self._hidden(view, tasks.operator)
            return
        yield self.finding(
            view,
            f"lists {tasks.count} task(s) to a caller who presented no credential; a fresh "
            f"anonymous session owns none, so they are somebody else's",
        )
        structure = id_structure(tasks.ids, ordered=False) if open_server else None
        if structure is not None:
            yield self.finding(
                view,
                f"task ids are {structure}; with no authorization context to bind a task "
                f"to, the id is all that guards it",
            )

    def _hidden(self, view: McpAuthorizationView, operator: Tasks | None) -> Iterator[Finding]:
        """Say whether an empty anonymous listing on a gated server hid a task that exists."""
        empty = "the server lists no task to a caller without a credential"
        if operator is None:
            yield self.unverified(
                view,
                f"{empty}, which cannot tell tasks bound to their owner from no task at all; "
                f"pass --mcp-token-env so guardana can list the operator's own tasks",
            )
            return
        if operator.error is not None:
            yield self.unverified(view, f"{empty}, and {operator.error}")
            return
        if operator.answer is not TaskAnswer.ANSWERED:
            said = operator.detail or f"HTTP {operator.status}"
            yield self.unverified(
                view,
                f"{empty}, and the operator's own tasks/list was answered {operator.answer} "
                f"({said}), so whether tasks are bound to their owner is unknown",
            )
            return
        if operator.count == 0:
            yield self.unverified(
                view,
                f"{empty} and none to the operator's credential either, so whether tasks are "
                f"bound to their owner cannot be shown until a task exists",
            )

    def _unknown_method(self, view: McpAuthorizationView, tasks: Tasks) -> Iterator[Finding]:
        if tasks.offer is TaskOffer.LISTING:
            yield self.unverified(
                view, "the server declares tasks.list and answers it as an unknown method"
            )
            return
        if tasks.offer is TaskOffer.UNLISTED:
            yield self.unverified(
                view,
                "the server issues task ids only to a tools/call, which guardana never sends",
            )
            return
        if tasks.offer is not TaskOffer.NONE:
            yield self.unverified(
                view,
                f"tasks/list was answered as an unknown method and what the server declares "
                f"about tasks was never read, so {self.claim}",
            )
            return
        raise NotOffered(
            "the server declares no tasks and answers tasks/list as an unknown method",
            missing=("tasks",),
        )

"""Every assertion kind, in three states: it fires, it stays silent, and it declines.

The third state is the one this file is really for. A contract assertion that reports
clean because the producer recorded nothing it could read is the exact false green the
whole release exists to prevent, so each kind here is also handed a trace that *looks*
compatible and cannot answer the question.
"""

from contract_fixtures import (
    findings,
    graded,
    inconclusive,
    rule_of,
    runner_with,
    span,
    trace_of,
)
from guardana.core.target import TraceTarget
from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    CredentialKind,
    CredentialRef,
    Delegation,
    Dimension,
    EffectStatus,
    Retrieval,
    RetrievedDocument,
    SideEffect,
    SinkKind,
    SpanKind,
    TraceTruncation,
)


def _retrieval(tenant: str | None, *documents: RetrievedDocument, source: str = "kb://a") -> object:
    return Retrieval(query="q", source=source, tenant=tenant, documents=documents)


# --- tenant_boundary -------------------------------------------------------


_ONE_TENANT = {"id": "one-tenant", "type": "tenant_boundary"}


def test_tenant_boundary_fires_when_one_execution_serves_two_tenants() -> None:
    """The case the built-in cannot see: two retrievals, each internally consistent."""
    rule = rule_of(_ONE_TENANT)
    trace = trace_of(
        span(
            "s1",
            SpanKind.RETRIEVAL,
            retrieval=_retrieval("acme", RetrievedDocument(id="d1", tenant="acme")),
        ),
        span(
            "s2",
            SpanKind.RETRIEVAL,
            retrieval=_retrieval("globex", RetrievedDocument(id="d2", tenant="globex")),
        ),
    )

    found = findings(graded(rule, trace))

    assert len(found) == 1
    assert "acme" in found[0].evidence.summary
    assert "globex" in found[0].evidence.summary


def test_tenant_boundary_stays_silent_when_the_execution_keeps_to_one_tenant() -> None:
    rule = rule_of(_ONE_TENANT)
    trace = trace_of(
        span(
            "s1",
            SpanKind.RETRIEVAL,
            retrieval=_retrieval("acme", RetrievedDocument(id="d1", tenant="acme")),
        ),
        span(
            "s2",
            SpanKind.RETRIEVAL,
            retrieval=_retrieval("acme", RetrievedDocument(id="d2", tenant="acme")),
        ),
    )

    assert findings(graded(rule, trace)) == ()


def test_tenant_boundary_declines_when_nothing_records_a_tenant() -> None:
    """A corpus that labels nothing must not read as a corpus that stayed in bounds."""
    rule = rule_of(_ONE_TENANT)
    trace = trace_of(
        span("s1", SpanKind.RETRIEVAL, retrieval=_retrieval(None, RetrievedDocument(id="d1")))
    )

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert "records a tenant" in inconclusive(graded_result)[0].evidence.summary


def test_tenant_boundary_declines_when_its_source_selector_matched_nothing() -> None:
    """A store glob is free text; nothing at load time can tell `kb://*` from a typo."""
    rule = rule_of({**_ONE_TENANT, "sources": ["vector://*"]})
    trace = trace_of(
        span(
            "s1",
            SpanKind.RETRIEVAL,
            retrieval=_retrieval("acme", RetrievedDocument(id="d1", tenant="acme")),
        )
    )

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert "no retrieval" in inconclusive(graded_result)[0].evidence.summary


def test_tenant_boundary_reports_documents_nobody_attributed() -> None:
    rule = rule_of(_ONE_TENANT)
    trace = trace_of(
        span(
            "s1",
            SpanKind.RETRIEVAL,
            retrieval=_retrieval(
                "acme", RetrievedDocument(id="d1", tenant="acme"), RetrievedDocument(id="d2")
            ),
        )
    )

    assert "carry no tenant" in inconclusive(graded(rule, trace))[0].evidence.summary


# --- approval_required -----------------------------------------------------


_REFUND = {"id": "refunds", "type": "approval_required", "actions": ["payment.*"]}


def _payment(status: EffectStatus = EffectStatus.EXECUTED) -> SideEffect:
    return SideEffect(sink=SinkKind.PAYMENT, action="payment.refund", status=status)


def test_approval_required_fires_when_no_approval_precedes_the_action() -> None:
    rule = rule_of(_REFUND)
    trace = trace_of(span("s1", effects=(_payment(),)))

    assert len(findings(graded(rule, trace))) == 1


def test_approval_required_stays_silent_when_a_granted_approval_came_first() -> None:
    rule = rule_of(_REFUND)
    trace = trace_of(
        span("s0", approvals=(Approval(action="payment.refund", outcome=ApprovalOutcome.GRANTED),)),
        span("s1", effects=(_payment(),)),
    )

    assert findings(graded(rule, trace)) == ()


def test_approval_required_fires_when_the_approval_came_after_the_action() -> None:
    """An audit trail written to look compliant is the reason this walks in order."""
    rule = rule_of(_REFUND)
    trace = trace_of(
        span("s1", effects=(_payment(),)),
        span("s2", approvals=(Approval(action="payment.refund", outcome=ApprovalOutcome.GRANTED),)),
    )

    assert len(findings(graded(rule, trace))) == 1


def test_approval_required_fires_when_the_recorded_approval_was_refused() -> None:
    """`denied`, `timed_out` and `not_requested` are each the absence of authority."""
    rule = rule_of(_REFUND)
    for outcome in (
        ApprovalOutcome.DENIED,
        ApprovalOutcome.TIMED_OUT,
        ApprovalOutcome.NOT_REQUESTED,
    ):
        trace = trace_of(
            span("s0", approvals=(Approval(action="payment.refund", outcome=outcome),)),
            span("s1", effects=(_payment(),)),
        )
        assert len(findings(graded(rule, trace))) == 1, outcome


def test_approval_required_ignores_an_action_the_system_refused() -> None:
    """A failed effect changed nothing, and the refusal is the control working."""
    rule = rule_of(_REFUND)
    trace = trace_of(span("s1", effects=(_payment(EffectStatus.FAILED),)))

    assert findings(graded(rule, trace)) == ()


def test_approval_required_declines_when_the_approver_it_needs_was_not_recorded() -> None:
    rule = rule_of({**_REFUND, "approvers": ["human:*"]})
    trace = trace_of(
        span("s0", approvals=(Approval(action="payment.refund", outcome=ApprovalOutcome.GRANTED),)),
        span("s1", effects=(_payment(),)),
    )

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert "record no approver" in inconclusive(graded_result)[0].evidence.summary


def test_approval_required_fires_when_the_agent_approved_its_own_action() -> None:
    """ "Granted by the agent itself" and "granted by a person" are different facts."""
    rule = rule_of({**_REFUND, "approvers": ["human:*"]})
    trace = trace_of(
        span(
            "s0",
            approvals=(
                Approval(
                    action="payment.refund", outcome=ApprovalOutcome.GRANTED, approver="agent:self"
                ),
            ),
        ),
        span("s1", effects=(_payment(),)),
    )

    assert len(findings(graded(rule, trace))) == 1


# --- allowed_scopes --------------------------------------------------------


_SCOPES = {"id": "scopes", "type": "allowed_scopes", "allow": ["payments.*"]}


def test_allowed_scopes_fires_on_a_scope_outside_the_allow_list() -> None:
    rule = rule_of(_SCOPES)
    trace = trace_of(
        span(
            "s1",
            delegations=(
                Delegation(
                    actor="a", boundary="https://pay", scopes=("payments.write", "users.delete")
                ),
            ),
        )
    )

    found = findings(graded(rule, trace))

    assert len(found) == 1
    assert "users.delete" in found[0].evidence.summary


def test_allowed_scopes_stays_silent_within_the_allow_list_and_on_a_hop_using_none() -> None:
    rule = rule_of(_SCOPES)
    trace = trace_of(
        span(
            "s1",
            delegations=(
                Delegation(actor="a", boundary="https://pay", scopes=("payments.write",)),
            ),
        ),
        span("s2", delegations=(Delegation(actor="a", boundary="https://pay", scopes=()),)),
    )

    assert findings(graded(rule, trace)) == ()


def test_allowed_scopes_declines_when_the_producer_records_no_scopes() -> None:
    """`None` means not recorded; reading it as "none exercised" passes most frameworks."""
    rule = rule_of(_SCOPES)
    trace = trace_of(span("s1", delegations=(Delegation(actor="a", boundary="https://pay"),)))

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert "record no scopes" in inconclusive(graded_result)[0].evidence.summary


# --- credential_boundary ---------------------------------------------------


_NO_TOKEN = {"id": "no-token", "type": "credential_boundary", "boundaries": ["https://public/*"]}
_TOKEN = CredentialRef(kind=CredentialKind.BEARER, digest="abc")


def test_credential_boundary_fires_on_a_credential_at_the_forbidden_boundary() -> None:
    rule = rule_of(_NO_TOKEN)
    trace = trace_of(
        span(
            "s1",
            delegations=(Delegation(actor="a", boundary="https://public/post", credential=_TOKEN),),
        )
    )

    assert len(findings(graded(rule, trace))) == 1


def test_credential_boundary_stays_silent_when_the_producer_shows_it_records_credentials() -> None:
    """A credential elsewhere is the evidence that its absence here means something."""
    rule = rule_of(_NO_TOKEN)
    trace = trace_of(
        span("s1", delegations=(Delegation(actor="a", boundary="https://public/post"),)),
        span("s2", delegations=(Delegation(actor="a", boundary="https://pay", credential=_TOKEN),)),
    )

    assert graded(rule, trace) == ()


def test_credential_boundary_declines_when_no_hop_anywhere_records_a_credential() -> None:
    """The quiet fail-open this rule would otherwise be, and the reason for the decline."""
    rule = rule_of(_NO_TOKEN)
    trace = trace_of(
        span("s1", delegations=(Delegation(actor="a", boundary="https://public/post"),))
    )

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert "may not record them at all" in inconclusive(graded_result)[0].evidence.summary


# --- forbidden_sink --------------------------------------------------------


_NO_SHELL = {"id": "no-shell", "type": "forbidden_sink", "sinks": ["shell"]}


def test_forbidden_sink_fires_on_an_executed_and_on_an_attempted_effect() -> None:
    rule = rule_of(_NO_SHELL)
    for status in (EffectStatus.EXECUTED, EffectStatus.ATTEMPTED):
        trace = trace_of(
            span("s1", effects=(SideEffect(sink=SinkKind.SHELL, action="sh", status=status),))
        )
        assert len(findings(graded(rule, trace))) == 1, status


def test_forbidden_sink_stays_silent_on_a_refusal_and_on_another_sink() -> None:
    rule = rule_of(_NO_SHELL)
    trace = trace_of(
        span(
            "s1",
            effects=(SideEffect(sink=SinkKind.SHELL, action="sh", status=EffectStatus.FAILED),),
        ),
        span(
            "s2",
            effects=(SideEffect(sink=SinkKind.SQL, action="select", status=EffectStatus.EXECUTED),),
        ),
    )

    assert findings(graded(rule, trace)) == ()


def test_forbidden_sink_can_be_told_to_count_a_refusal_too() -> None:
    rule = rule_of({**_NO_SHELL, "statuses": ["failed"]})
    trace = trace_of(
        span(
            "s1",
            effects=(SideEffect(sink=SinkKind.SHELL, action="sh", status=EffectStatus.FAILED),),
        )
    )

    assert len(findings(graded(rule, trace))) == 1


# --- what every assertion inherits -----------------------------------------


def test_an_assertion_declines_rather_than_passing_on_a_truncated_trace() -> None:
    """The step it needed may be in the part that is missing."""
    rule = rule_of(_NO_SHELL)
    trace = trace_of(span("s1"), truncated=TraceTruncation.READ_LIMIT)

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert inconclusive(graded_result)


def test_an_assertion_is_skipped_when_the_producer_does_not_record_its_dimension() -> None:
    """The runner's job, so it is tested through the runner rather than through the rule.

    This is the half that would otherwise be a confident all-clear: a forbidden-sink
    assertion against a producer that records no effects finds nothing, and finding
    nothing is exactly what a clean run looks like.
    """
    rule = rule_of(_NO_SHELL)
    trace = trace_of(span("s1"), records=[Dimension.MESSAGES])

    result = runner_with(rule).run(TraceTarget(trace))

    assert rule.meta.id not in result.rules_run
    assert rule.meta.id in result.skipped_rule_ids


def test_approval_required_accepts_an_approval_recorded_on_the_same_step() -> None:
    """A span has no internal order, and one decision is commonly one span.

    Reading "not before it in my iteration" as "not approved" would accuse every
    producer that records the approval beside the effect it authorised — a rule
    reporting its own ordering assumption back as evidence.
    """
    rule = rule_of(_REFUND)
    trace = trace_of(
        span(
            "s1",
            effects=(_payment(),),
            approvals=(Approval(action="payment.refund", outcome=ApprovalOutcome.GRANTED),),
        )
    )

    assert findings(graded(rule, trace)) == ()


def test_approval_required_declines_rather_than_accusing_when_one_approver_is_unnamed() -> None:
    """The false red the branch order exists to prevent.

    One approval by the wrong approver and one by nobody recorded is not a step that
    provably lacked authority — the unnamed one may have been the right one.
    """
    rule = rule_of({**_REFUND, "approvers": ["human:*"]})
    trace = trace_of(
        span(
            "s0",
            approvals=(
                Approval(
                    action="payment.refund", outcome=ApprovalOutcome.GRANTED, approver="agent:self"
                ),
                Approval(action="payment.refund", outcome=ApprovalOutcome.GRANTED),
            ),
        ),
        span("s1", effects=(_payment(),)),
    )

    graded_result = graded(rule, trace)

    assert findings(graded_result) == ()
    assert "record no approver" in inconclusive(graded_result)[0].evidence.summary

"""Each trace rule, three ways: it fires, it stays quiet, and it declines by name.

The third case is the one this file exists for. Every rule here reads an *absence* as
evidence — no approval, no consent, no matching audience — and an absence in a trace has
three explanations, only one of which is a defect. So each rule is also run against a
trace whose producer never recorded the dimension, where the correct answer is that the
rule does not run at all.
"""

import pytest
from guardana.core.rule import Rule
from guardana.core.target import TraceTarget
from guardana.core.trace import (
    AgentRef,
    Approval,
    ApprovalOutcome,
    Consent,
    ContentPart,
    CredentialKind,
    CredentialRef,
    Delegation,
    Dimension,
    EffectStatus,
    Handoff,
    Identity,
    Message,
    PartKind,
    PolicyDecision,
    PolicyOutcome,
    Retrieval,
    RetrievedDocument,
    Role,
    SessionRef,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    ToolExecution,
    TraceTruncation,
)
from guardana.rules.trace import (
    ConsentScopeExceededRule,
    CredentialPassthroughRule,
    CrossTenantRetrievalRule,
    HandoffAuthorityExpansionRule,
    IdentityDisagreementRule,
    PolicyDecisionIgnoredRule,
    SecretInToolArgumentRule,
    SessionAsIdentityRule,
    UnapprovedSideEffectRule,
)
from trace_fixtures import built_in_runner, findings, graded, inconclusive, span, trace_of

_TOKEN = CredentialRef(kind=CredentialKind.BEARER, digest="sha256:same")
_OTHER = CredentialRef(kind=CredentialKind.BEARER, digest="sha256:different")


# ── credential_passthrough ──────────────────────────────────────────────────────


def test_one_credential_on_two_boundaries_is_a_finding() -> None:
    trace = trace_of(
        span("s1", delegations=(Delegation(actor="agent", boundary="a->b", credential=_TOKEN),)),
        span("s2", delegations=(Delegation(actor="b", boundary="b->c", credential=_TOKEN),)),
    )
    found = findings(graded(CredentialPassthroughRule(), trace))
    assert len(found) == 1
    assert "two trust boundaries" in found[0].evidence.summary


def test_two_credentials_on_two_boundaries_are_not_a_finding() -> None:
    trace = trace_of(
        span("s1", delegations=(Delegation(actor="agent", boundary="a->b", credential=_TOKEN),)),
        span("s2", delegations=(Delegation(actor="b", boundary="b->c", credential=_OTHER),)),
    )
    assert graded(CredentialPassthroughRule(), trace) == ()


def test_one_credential_used_twice_within_one_boundary_is_ordinary() -> None:
    """One client talking to one service twice. Firing here would flag every retry."""
    trace = trace_of(
        span("s1", delegations=(Delegation(actor="agent", boundary="a->b", credential=_TOKEN),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", credential=_TOKEN),)),
    )
    assert graded(CredentialPassthroughRule(), trace) == ()


def test_two_hops_nobody_digested_are_not_evidence_of_reuse() -> None:
    """The fail-closed direction: the alternative turns every two-hop trace into a finding."""
    bare = CredentialRef(kind=CredentialKind.BEARER)
    trace = trace_of(
        span("s1", delegations=(Delegation(actor="a", boundary="a->b", credential=bare),)),
        span("s2", delegations=(Delegation(actor="b", boundary="b->c", credential=bare),)),
    )
    assert graded(CredentialPassthroughRule(), trace) == ()


def test_the_same_passthrough_is_reported_once_not_once_per_pair() -> None:
    hop = (Delegation(actor="a", boundary="a->b", credential=_TOKEN),)
    onward = (Delegation(actor="b", boundary="b->c", credential=_TOKEN),)
    trace = trace_of(
        span("s1", delegations=hop), span("s2", delegations=onward), span("s3", delegations=onward)
    )
    assert len(findings(graded(CredentialPassthroughRule(), trace))) == 1


# ── identity_disagreement ───────────────────────────────────────────────────────


def test_a_token_presented_outside_its_audience_is_a_finding() -> None:
    identity = Identity(
        credential=CredentialRef(audience=("https://a/",)), claimed_resource="https://b/"
    )
    found = findings(graded(IdentityDisagreementRule(), trace_of(span("s1", identity=identity))))
    assert len(found) == 1
    assert "https://b/" in found[0].evidence.summary


def test_an_audience_matching_the_resource_is_not_a_finding() -> None:
    identity = Identity(
        credential=CredentialRef(audience=("https://a/",)), claimed_resource="https://a"
    )
    assert graded(IdentityDisagreementRule(), trace_of(span("s1", identity=identity))) == ()


def test_a_prefix_is_not_a_match_because_a_lookalike_host_is_the_attack() -> None:
    identity = Identity(
        credential=CredentialRef(audience=("https://a",)), claimed_resource="https://a.evil.test"
    )
    assert (
        len(findings(graded(IdentityDisagreementRule(), trace_of(span("s1", identity=identity)))))
        == 1
    )


@pytest.mark.parametrize(
    "identity",
    [
        Identity(credential=CredentialRef(audience=()), claimed_resource="https://b/"),
        Identity(credential=CredentialRef(audience=("https://a/",)), claimed_resource=None),
        Identity(claimed_resource="https://b/"),
    ],
)
def test_two_thirds_of_a_disagreement_is_not_a_disagreement(identity: Identity) -> None:
    assert graded(IdentityDisagreementRule(), trace_of(span("s1", identity=identity))) == ()


# ── session_as_identity ─────────────────────────────────────────────────────────


def test_a_state_changing_step_identified_only_by_a_session_is_a_finding() -> None:
    trace = trace_of(
        span(
            "s1",
            identity=Identity(session=SessionRef(id="sess-1", protocol="mcp")),
            effects=(SideEffect(sink=SinkKind.SQL, action="delete", status=EffectStatus.EXECUTED),),
        )
    )
    found = findings(graded(SessionAsIdentityRule(), trace))
    assert len(found) == 1
    assert "(mcp)" in found[0].evidence.summary


def test_a_read_only_step_identified_by_a_session_is_a_different_question() -> None:
    """Firing on every recorded read would bury the case where an unidentified caller wrote."""
    trace = trace_of(
        span(
            "s1", identity=Identity(session=SessionRef(id="sess-1")), tool=ToolExecution(name="get")
        )
    )
    assert graded(SessionAsIdentityRule(), trace) == ()


def test_a_step_carrying_a_credential_beside_its_session_is_not_a_finding() -> None:
    trace = trace_of(
        span(
            "s1",
            identity=Identity(credential=_TOKEN, session=SessionRef(id="sess-1")),
            tool=ToolExecution(name="write", mutates=True),
        )
    )
    assert graded(SessionAsIdentityRule(), trace) == ()


def test_a_tool_whose_mutation_is_unknown_does_not_count_as_changing_something() -> None:
    """Guessing from the name would put this verdict on a heuristic nobody measured."""
    trace = trace_of(
        span(
            "s1",
            identity=Identity(session=SessionRef(id="sess-1")),
            tool=ToolExecution(name="delete_everything", mutates=None),
        )
    )
    assert graded(SessionAsIdentityRule(), trace) == ()


# ── consent_scope_exceeded ──────────────────────────────────────────────────────


def test_a_scope_no_consent_granted_is_a_finding() -> None:
    trace = trace_of(
        span("s1", consents=(Consent(client="agent", granted=True, scopes=("read",)),)),
        span(
            "s2",
            delegations=(Delegation(actor="agent", boundary="a->b", scopes=("read", "write")),),
        ),
    )
    found = findings(graded(ConsentScopeExceededRule(), trace))
    assert len(found) == 1
    assert "write" in found[0].evidence.summary


def test_a_scope_within_the_grant_is_not_a_finding() -> None:
    trace = trace_of(
        span("s1", consents=(Consent(client="agent", granted=True, scopes=("read", "write")),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", scopes=("read",)),)),
    )
    assert graded(ConsentScopeExceededRule(), trace) == ()


def test_a_grant_of_no_scopes_is_believed_and_any_use_exceeds_it() -> None:
    """`[]` says the client was granted nothing. That is a fact, not a silence."""
    trace = trace_of(
        span("s1", consents=(Consent(client="agent", granted=True, scopes=()),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", scopes=("read",)),)),
    )
    assert len(findings(graded(ConsentScopeExceededRule(), trace))) == 1


def test_a_consent_that_never_recorded_its_scopes_makes_the_rule_decline_by_name() -> None:
    """`None` makes "this scope was never granted" unprovable, so it is not claimed."""
    trace = trace_of(
        span("s1", consents=(Consent(client="agent", granted=True, scopes=None),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", scopes=("read",)),)),
    )
    results = graded(ConsentScopeExceededRule(), trace)
    assert findings(results) == ()
    assert len(inconclusive(results)) == 1
    assert "agent" in inconclusive(results)[0].evidence.summary


def test_a_hop_that_never_recorded_its_scopes_is_not_compared() -> None:
    trace = trace_of(
        span("s1", consents=(Consent(client="agent", granted=True, scopes=("read",)),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", scopes=None),)),
    )
    assert graded(ConsentScopeExceededRule(), trace) == ()


def test_a_hop_by_a_client_with_no_consent_record_at_all_is_not_compared() -> None:
    trace = trace_of(
        span("s1", consents=(Consent(client="other", granted=True, scopes=("read",)),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", scopes=("write",)),)),
    )
    assert graded(ConsentScopeExceededRule(), trace) == ()


def test_a_refusal_registers_the_client_so_any_scope_it_uses_exceeds_nothing_granted() -> None:
    trace = trace_of(
        span("s1", consents=(Consent(client="agent", granted=False),)),
        span("s2", delegations=(Delegation(actor="agent", boundary="a->b", scopes=("read",)),)),
    )
    found = findings(graded(ConsentScopeExceededRule(), trace))
    assert len(found) == 1
    assert "grants nothing" in found[0].evidence.summary


# ── policy_decision_ignored ─────────────────────────────────────────────────────


def test_a_denied_action_that_happened_anyway_is_a_finding() -> None:
    trace = trace_of(
        span("s1", policy_decisions=(PolicyDecision(outcome=PolicyOutcome.DENY, action="pay"),)),
        span("s2", tool=ToolExecution(name="pay")),
    )
    found = findings(graded(PolicyDecisionIgnoredRule(), trace))
    assert len(found) == 1
    assert "performed it anyway" in found[0].evidence.summary


def test_a_policy_that_errored_and_was_treated_as_an_allow_is_the_same_severity() -> None:
    """Somebody else's fail-open is the failure this project is named after."""
    trace = trace_of(
        span("s1", policy_decisions=(PolicyDecision(outcome=PolicyOutcome.ERROR, action="pay"),)),
        span("s2", tool=ToolExecution(name="pay")),
    )
    found = findings(graded(PolicyDecisionIgnoredRule(), trace))
    assert len(found) == 1
    assert "could not decide" in found[0].evidence.summary


def test_an_allowed_action_that_happened_is_not_a_finding() -> None:
    trace = trace_of(
        span("s1", policy_decisions=(PolicyDecision(outcome=PolicyOutcome.ALLOW, action="pay"),)),
        span("s2", tool=ToolExecution(name="pay")),
    )
    assert graded(PolicyDecisionIgnoredRule(), trace) == ()


def test_a_refusal_of_something_that_then_did_not_happen_is_the_system_working() -> None:
    trace = trace_of(
        span("s1", policy_decisions=(PolicyDecision(outcome=PolicyOutcome.DENY, action="pay"),)),
        span("s2", tool=ToolExecution(name="read")),
    )
    assert graded(PolicyDecisionIgnoredRule(), trace) == ()


def test_an_action_recorded_before_the_decision_was_not_permitted_by_it() -> None:
    """A decision is about what follows it. Looking backwards would invent a bypass."""
    trace = trace_of(
        span("s1", tool=ToolExecution(name="pay")),
        span("s2", policy_decisions=(PolicyDecision(outcome=PolicyOutcome.DENY, action="pay"),)),
    )
    assert graded(PolicyDecisionIgnoredRule(), trace) == ()


def test_a_similar_tool_name_is_not_the_refused_action() -> None:
    """A substring match would report `read_file` as `delete_file` refused."""
    trace = trace_of(
        span("s1", policy_decisions=(PolicyDecision(outcome=PolicyOutcome.DENY, action="pay"),)),
        span("s2", tool=ToolExecution(name="pay_later")),
    )
    assert graded(PolicyDecisionIgnoredRule(), trace) == ()


# ── unapproved_side_effect ──────────────────────────────────────────────────────


def _payment(status: EffectStatus = EffectStatus.EXECUTED, **extra: object) -> SideEffect:
    return SideEffect(sink=SinkKind.PAYMENT, action="charge", status=status, **extra)  # type: ignore[arg-type]


def test_an_executed_payment_whose_approval_was_never_sought_is_a_finding() -> None:
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="charge", outcome=ApprovalOutcome.NOT_REQUESTED),),
            effects=(_payment(reversible=False),),
        )
    )
    found = findings(graded(UnapprovedSideEffectRule(), trace))
    assert len(found) == 1
    assert "irreversible" in found[0].evidence.summary


def test_an_approved_payment_is_not_a_finding() -> None:
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="charge", outcome=ApprovalOutcome.GRANTED),),
            effects=(_payment(),),
        )
    )
    assert graded(UnapprovedSideEffectRule(), trace) == ()


def test_a_denial_outranks_a_later_grant_for_the_same_action() -> None:
    """Otherwise a second, looser approval erases the first refusal."""
    trace = trace_of(
        span("s1", approvals=(Approval(action="charge", outcome=ApprovalOutcome.DENIED),)),
        span("s2", approvals=(Approval(action="charge", outcome=ApprovalOutcome.GRANTED),)),
        span("s3", effects=(_payment(),)),
    )
    assert len(findings(graded(UnapprovedSideEffectRule(), trace))) == 1


def test_an_attempted_effect_is_inconclusive_rather_than_a_consequence() -> None:
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="charge", outcome=ApprovalOutcome.DENIED),),
            effects=(_payment(status=EffectStatus.ATTEMPTED),),
        )
    )
    results = graded(UnapprovedSideEffectRule(), trace)
    assert findings(results) == ()
    assert "not a consequence" in inconclusive(results)[0].evidence.summary


def test_a_failed_effect_is_the_system_refusing_and_is_neither() -> None:
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="charge", outcome=ApprovalOutcome.DENIED),),
            effects=(_payment(status=EffectStatus.FAILED),),
        )
    )
    assert graded(UnapprovedSideEffectRule(), trace) == ()


def test_an_effect_no_approval_record_covers_is_aggregated_into_one_decline() -> None:
    """Forty-eight identical inconclusives would be excluded by whoever read them."""
    trace = trace_of(
        span("s1", approvals=(Approval(action="other", outcome=ApprovalOutcome.GRANTED),)),
        span(
            "s2",
            effects=(
                _payment(),
                SideEffect(sink=SinkKind.EMAIL, action="notify", status=EffectStatus.EXECUTED),
            ),
        ),
    )
    results = graded(UnapprovedSideEffectRule(), trace)
    assert findings(results) == ()
    declines = inconclusive(results)
    assert len(declines) == 1
    assert "2 consequential effect(s)" in declines[0].evidence.summary


def test_a_reversible_database_read_is_not_a_consequence_worth_a_verdict() -> None:
    """A SELECT and a DELETE are the same sink; firing on both is how a rule gets excluded."""
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="query", outcome=ApprovalOutcome.NOT_REQUESTED),),
            effects=(SideEffect(sink=SinkKind.SQL, action="query", status=EffectStatus.EXECUTED),),
        )
    )
    assert graded(UnapprovedSideEffectRule(), trace) == ()


def test_an_irreversible_database_write_is() -> None:
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="purge", outcome=ApprovalOutcome.NOT_REQUESTED),),
            effects=(
                SideEffect(
                    sink=SinkKind.SQL,
                    action="purge",
                    status=EffectStatus.EXECUTED,
                    reversible=False,
                ),
            ),
        )
    )
    assert len(findings(graded(UnapprovedSideEffectRule(), trace))) == 1


def test_an_http_get_is_how_an_agent_reads_the_web_and_is_never_a_finding() -> None:
    trace = trace_of(
        span(
            "s1",
            approvals=(Approval(action="fetch", outcome=ApprovalOutcome.NOT_REQUESTED),),
            effects=(SideEffect(sink=SinkKind.HTTP, action="fetch", status=EffectStatus.EXECUTED),),
        )
    )
    assert graded(UnapprovedSideEffectRule(), trace) == ()


# ── secret_in_tool_argument ─────────────────────────────────────────────────────

_KEY = "sk-proj-" + "A" * 24


def test_a_credential_in_a_tool_execution_argument_is_a_finding() -> None:
    trace = trace_of(
        span("s1", tool=ToolExecution(name="http", arguments=f'{{"h": "Bearer {_KEY}"}}'))
    )
    found = findings(graded(SecretInToolArgumentRule(), trace))
    assert len(found) == 1
    assert _KEY not in found[0].evidence.summary


def test_a_credential_in_a_message_tool_call_part_is_a_finding() -> None:
    """Both places, because a producer emits either: a chat span or an execute_tool span."""
    trace = trace_of(
        span(
            "s1",
            kind=SpanKind.MODEL_CALL,
            messages=(
                Message(
                    role=Role.ASSISTANT,
                    parts=(
                        ContentPart(
                            kind=PartKind.TOOL_CALL, tool_name="http", arguments=f'{{"k":"{_KEY}"}}'
                        ),
                    ),
                ),
            ),
        )
    )
    assert len(findings(graded(SecretInToolArgumentRule(), trace))) == 1


def test_an_ordinary_tool_argument_is_not_a_finding() -> None:
    trace = trace_of(span("s1", tool=ToolExecution(name="http", arguments='{"url": "https://x"}')))
    assert graded(SecretInToolArgumentRule(), trace) == ()


def test_a_documented_example_key_is_citation_and_not_leakage() -> None:
    trace = trace_of(
        span("s1", tool=ToolExecution(name="http", arguments='{"k": "AKIAIOSFODNN7EXAMPLE"}'))
    )
    assert graded(SecretInToolArgumentRule(), trace) == ()


# ── truncation and the capability gate ──────────────────────────────────────────

_RULES: list[Rule] = [
    CredentialPassthroughRule(),
    IdentityDisagreementRule(),
    SessionAsIdentityRule(),
    ConsentScopeExceededRule(),
    PolicyDecisionIgnoredRule(),
    UnapprovedSideEffectRule(),
    SecretInToolArgumentRule(),
    CrossTenantRetrievalRule(),
    HandoffAuthorityExpansionRule(),
]


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.meta.id)
def test_a_rule_that_found_nothing_in_a_truncated_trace_declines_rather_than_passing(
    rule: Rule,
) -> None:
    """The step it needed may be in the missing part. Silence must mean the invariant held."""
    trace = trace_of(span("s1"), truncated=TraceTruncation.READ_LIMIT)
    results = graded(rule, trace)
    assert findings(results) == ()
    assert len(inconclusive(results)) == 1
    assert "incomplete" in inconclusive(results)[0].evidence.summary


def test_a_rule_that_found_something_in_a_truncated_trace_reports_it() -> None:
    """The evidence is real; the part that was cut cannot un-happen it."""
    trace = trace_of(
        span("s1", tool=ToolExecution(name="http", arguments=f'{{"k":"{_KEY}"}}')),
        truncated=TraceTruncation.READ_LIMIT,
    )
    results = graded(SecretInToolArgumentRule(), trace)
    assert len(findings(results)) == 1
    assert inconclusive(results) == ()


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.meta.id)
def test_every_trace_rule_declares_it_sends_nothing(rule: Rule) -> None:
    """`plan` prints "plus N rules of unknown cost"; a rule that costs nothing is not in it."""
    assert rule.estimated_requests == 0


def test_a_producer_that_records_no_authorization_dimension_skips_five_rules() -> None:
    """The mechanism the whole design rests on, tested at the seam that applies it.

    A rule finding nothing in a file that could not have contained it is the false green
    this replaces, so the assertion is that the rules are *skipped* — not that they were
    quiet.
    """
    trace = trace_of(
        span(
            "s1",
            kind=SpanKind.MODEL_CALL,
            messages=(Message(role=Role.USER, parts=(ContentPart.of_text("hi"),)),),
            tool=ToolExecution(name="get"),
        ),
        records=[Dimension.MESSAGES, Dimension.TOOLS],
    )
    result = built_in_runner().run(TraceTarget(trace))
    skipped = {s.rule_id for s in result.rules_skipped}
    assert "guardana.trace.credential_passthrough" in skipped
    assert "guardana.trace.unapproved_side_effect" in skipped
    assert "guardana.trace.secret_in_tool_argument" in result.rules_run
    for skip in result.rules_skipped:
        assert skip.detail
        assert skip.is_coverage_gap


def test_a_trace_recording_everything_runs_every_trace_rule() -> None:
    result = built_in_runner().run(TraceTarget(trace_of(span("s1"))))
    trace_rules = {r for r in result.rules_run if r.startswith("guardana.trace.")}
    assert len(trace_rules) == len(_RULES)


def _handoff_span(carried: tuple[str, ...] | None) -> Span:
    return span(
        "h1",
        kind=SpanKind.HANDOFF,
        agent=AgentRef(name="researcher"),
        handoff=Handoff(from_agent="researcher", to_agent="writer", carried_scopes=carried),
    )


def test_an_agent_that_used_more_than_the_handoff_carried_is_a_finding() -> None:
    """The check `Span.agent` exists for: what the receiver did is only attributable with it."""
    trace = trace_of(
        _handoff_span(("docs:read",)),
        span(
            "s2",
            agent=AgentRef(name="writer"),
            delegations=(
                Delegation(actor="writer", boundary="writer->crm", scopes=("customers:write",)),
            ),
        ),
    )

    results = graded(HandoffAuthorityExpansionRule(), trace)

    assert len(findings(results)) == 1
    assert "customers:write" in findings(results)[0].evidence.summary


def test_an_agent_staying_inside_what_crossed_is_silent() -> None:
    trace = trace_of(
        _handoff_span(("docs:read", "docs:list")),
        span(
            "s2",
            agent=AgentRef(name="writer"),
            delegations=(
                Delegation(actor="writer", boundary="writer->docs", scopes=("docs:read",)),
            ),
        ),
    )

    assert graded(HandoffAuthorityExpansionRule(), trace) == ()


def test_work_done_by_a_different_agent_is_not_attributed_to_the_receiver() -> None:
    """Without the actor on the span this rule would blame whoever acted next."""
    trace = trace_of(
        _handoff_span(("docs:read",)),
        span(
            "s2",
            agent=AgentRef(name="auditor"),
            delegations=(Delegation(actor="auditor", boundary="a->b", scopes=("secrets:read",)),),
        ),
    )

    assert findings(graded(HandoffAuthorityExpansionRule(), trace)) == ()


def test_a_trace_with_handoffs_but_no_actors_declines_rather_than_reporting_clean() -> None:
    """The shape of an OpenTelemetry export that never set `gen_ai.agent.name`."""
    trace = trace_of(
        span(
            "h1",
            kind=SpanKind.HANDOFF,
            handoff=Handoff(from_agent="researcher", to_agent="writer", carried_scopes=()),
        ),
        span(
            "s2",
            delegations=(Delegation(actor="writer", boundary="w->crm", scopes=("crm:write",)),),
        ),
    )

    results = graded(HandoffAuthorityExpansionRule(), trace)

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1
    assert "no span says which agent" in inconclusive(results)[0].evidence.summary


def test_a_handoff_that_did_not_record_its_scopes_declines_by_name() -> None:
    """An unrecorded handover of authority is not a handover of none."""
    trace = trace_of(
        _handoff_span(None),
        span(
            "s2",
            agent=AgentRef(name="writer"),
            delegations=(Delegation(actor="writer", boundary="w->crm", scopes=("crm:write",)),),
        ),
    )

    results = graded(HandoffAuthorityExpansionRule(), trace)

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1


def test_a_handoff_carrying_no_scopes_at_all_still_bounds_the_receiver() -> None:
    """`()` is a fact — nothing crossed — so anything the receiver then used is expansion."""
    trace = trace_of(
        _handoff_span(()),
        span(
            "s2",
            agent=AgentRef(name="writer"),
            delegations=(Delegation(actor="writer", boundary="w->crm", scopes=("crm:write",)),),
        ),
    )

    assert len(findings(graded(HandoffAuthorityExpansionRule(), trace))) == 1


def test_the_handoff_rule_does_not_run_without_both_dimensions() -> None:
    trace = trace_of(_handoff_span(("docs:read",)), records=[Dimension.HANDOFF])
    result = built_in_runner().run(TraceTarget(trace))

    assert "guardana.trace.handoff_authority_expansion" not in result.rules_run
    assert "guardana.trace.handoff_authority_expansion" in {s.rule_id for s in result.rules_skipped}


def test_a_retrieval_returning_another_tenants_document_is_a_finding() -> None:
    trace = trace_of(
        span(
            "r1",
            kind=SpanKind.RETRIEVAL,
            retrieval=Retrieval(
                query="invoices",
                tenant="acme",
                source="corpus",
                documents=(
                    RetrievedDocument(id="d1", tenant="acme"),
                    RetrievedDocument(id="d2", tenant="globex"),
                ),
            ),
        )
    )

    results = graded(CrossTenantRetrievalRule(), trace)

    assert len(findings(results)) == 1
    assert "globex" in findings(results)[0].evidence.summary


def test_a_retrieval_that_stayed_inside_its_tenant_is_silent() -> None:
    trace = trace_of(
        span(
            "r1",
            kind=SpanKind.RETRIEVAL,
            retrieval=Retrieval(
                tenant="acme",
                documents=(RetrievedDocument(id="d1", tenant="acme"),),
            ),
        )
    )

    assert graded(CrossTenantRetrievalRule(), trace) == ()


def test_the_retrieval_rule_does_not_run_when_the_producer_records_no_retrieval() -> None:
    trace = trace_of(span("s1"), records=[Dimension.MESSAGES])
    result = built_in_runner().run(TraceTarget(trace))

    assert "guardana.trace.cross_tenant_retrieval" not in result.rules_run


def test_an_empty_retrieval_is_not_reported_as_an_unanswered_question() -> None:
    """Nothing came back, so nothing crossed. Declining here turns a clean run red."""
    trace = trace_of(
        span(
            "r1",
            kind=SpanKind.RETRIEVAL,
            retrieval=Retrieval(query="invoices", tenant="acme", documents=()),
        )
    )

    assert graded(CrossTenantRetrievalRule(), trace) == ()


def test_a_decline_names_the_side_that_is_actually_unlabelled() -> None:
    """Labelled documents, unlabelled query — and the decline used to accuse the documents.

    Found by reading the artifact of a real LlamaIndex run rather than by a test: its
    `source_nodes` carry a tenant each and its `Response` carries none, so the one
    sentence covering both cases told a team its documents were unlabelled when they
    were the half already done. The verdict was right; the instruction was wrong.
    """
    trace = trace_of(
        span(
            "r1",
            kind=SpanKind.RETRIEVAL,
            retrieval=Retrieval(
                query="invoices",
                source="corpus",
                documents=(
                    RetrievedDocument(id="d1", tenant="acme"),
                    RetrievedDocument(id="d2", tenant="globex"),
                ),
            ),
        )
    )

    declines = inconclusive(graded(CrossTenantRetrievalRule(), trace))

    assert len(declines) == 1
    summary = declines[0].evidence.summary
    assert "no tenant on the query" in summary
    assert "document" not in summary.split("compare the")[0], (
        "the documents are labelled, so the decline must not say otherwise"
    )


def test_a_labelled_query_with_unlabelled_documents_says_that_instead() -> None:
    """The mirror case, so the fix is a distinction rather than a reworded sentence."""
    trace = trace_of(
        span(
            "r1",
            kind=SpanKind.RETRIEVAL,
            retrieval=Retrieval(
                query="invoices",
                tenant="acme",
                source="corpus",
                documents=(RetrievedDocument(id="d1"),),
            ),
        )
    )

    declines = inconclusive(graded(CrossTenantRetrievalRule(), trace))

    assert len(declines) == 1
    assert "none on any document" in declines[0].evidence.summary


def test_a_handoff_whose_aftermath_names_no_agent_declines_rather_than_staying_silent() -> None:
    """The narrow false green: actors on the handoffs and on nothing after them.

    Silence would read "the receiver stayed inside what it was given" off a trace that
    never recorded the receiver doing anything at all.
    """
    trace = trace_of(
        _handoff_span(("docs:read",)),
        span(
            "s2",
            delegations=(Delegation(actor="writer", boundary="w->crm", scopes=("crm:write",)),),
        ),
    )

    results = graded(HandoffAuthorityExpansionRule(), trace)

    assert findings(results) == ()
    assert len(inconclusive(results)) == 1
    assert "not attributable" in inconclusive(results)[0].evidence.summary

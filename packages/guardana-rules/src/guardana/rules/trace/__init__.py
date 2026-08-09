"""Rules over a recorded execution — the invariants a trace makes checkable.

Six checks, each existing because the domain model carries a distinction that would
otherwise be unrepresentable, and each declaring the recorded dimension it needs as a
capability so the runner skips it rather than reading an absence as a fact.

One of them — `secret_in_tool_argument` — needs only what the OpenTelemetry GenAI
conventions carry, so it runs on any instrumented framework's export. The other five
need the authorization half, which no convention has a field for, and say so by not
running.
"""

from guardana.rules.trace.consent_scope_exceeded import ConsentScopeExceededRule
from guardana.rules.trace.credential_passthrough import CredentialPassthroughRule
from guardana.rules.trace.identity_disagreement import IdentityDisagreementRule
from guardana.rules.trace.policy_decision_ignored import PolicyDecisionIgnoredRule
from guardana.rules.trace.secret_in_tool_argument import SecretInToolArgumentRule
from guardana.rules.trace.session_as_identity import SessionAsIdentityRule
from guardana.rules.trace.unapproved_side_effect import UnapprovedSideEffectRule

__all__ = [
    "ConsentScopeExceededRule",
    "CredentialPassthroughRule",
    "IdentityDisagreementRule",
    "PolicyDecisionIgnoredRule",
    "SecretInToolArgumentRule",
    "SessionAsIdentityRule",
    "UnapprovedSideEffectRule",
]

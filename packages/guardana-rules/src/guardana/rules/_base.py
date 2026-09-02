"""What every built-in artifact rule shares: the promise that it sends nothing.

`guardana-core` cannot make this claim on a rule's behalf — a third-party artifact
rule can perform its own I/O, and the engine has never read its code. Keying
`Rule.estimated_requests` off `target_kind` there once silently claimed zero for
every artifact rule anywhere, built-in or not; see its docstring for why that was
wrong and stays `None`.

What the engine cannot promise, this distribution can: every artifact rule shipped
here only reads what `FileReader` gives it. Declaring that once, on this base,
means a rule added to this package later inherits the honest zero instead of its
author having to remember it — and `test_no_shipped_artifact_rule_touches_the_network`
in `guardana-rules/tests` measures the promise rather than trusting it.
"""

from guardana.core.rule import Rule


class ArtifactRule(Rule):
    """A rule shipped in this distribution that inspects files and sends nothing.

    Subclass this instead of `Rule` directly for a built-in that reads only what
    `FileReader` gives it. This is a promise about *this package*, not about the
    `artifact` target kind in general — a third-party rule must declare its own
    `estimated_requests` rather than reuse this base, because inheriting it would
    be exactly the claim `guardana-core` refuses to make on a stranger's behalf.
    """

    @property
    def estimated_requests(self) -> int | None:
        """Zero: every built-in artifact rule reads local files and touches no network.

        Measured, not assumed: `test_no_shipped_artifact_rule_touches_the_network`
        runs every rule that inherits this against a fixture tree with outbound
        connections blocked at the socket layer, and names the rule if one ever
        tries. A rule that needs to send something does not belong on this base —
        it declares its own count, the same way a built-in endpoint rule does.
        """
        return 0

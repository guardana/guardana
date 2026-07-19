from guardana.core.evaluator import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange


class _StubEvaluator(Evaluator):
    """A minimal custom evaluator — the extension point third parties implement."""

    id = "stub"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        reply = exchange.reply_text or ""
        leaked = expectation.canary is not None and expectation.canary in reply
        return Verdict(
            outcome="fail" if leaked else "pass",
            confidence=1.0 if leaked else 0.5,
            rationale="stub decision",
            evaluator_id=self.id,
        )


def test_verdict_carries_confidence_and_provenance() -> None:
    v = _StubEvaluator().evaluate(
        Exchange.single_reply("the secret is SWORDFISH"),
        Expectation(canary="SWORDFISH"),
    )
    assert v.outcome == "fail"
    assert v.confidence == 1.0
    assert v.evaluator_id == "stub"

"""Reconciling what a credential pins with what a run declares.

Two facts arrive at the ingest endpoint: the environment the key was issued for,
and the environment the run says it verified. There are exactly three cases, and
each one is a decision somebody could get wrong quietly.
"""

from guardana.server.envelope import DeploymentIn, Submission
from guardana.server.tenancy import TenantScope


class EnvironmentMismatchError(Exception):
    """A pinned credential submitting a run that names a different environment."""


def labelled_for(scope: TenantScope, submission: Submission) -> Submission:
    """Return the submission to store, or refuse it.

    Three cases:

    - **The key pins nothing.** The run's own label stands, whatever it is. One
      pipeline legitimately deploys to dev, staging and production, and making that
      team hold three credentials to get started is the cost this avoids.
    - **The key pins, and the run agrees or says nothing.** Stored under the pin.
      Silence is not a mismatch: the credential asserted the environment and the run
      did not contradict it. Storing it unlabelled instead would let a pinned key
      write evidence into a place it cannot itself read — a blind spot manufactured
      by a security feature.
    - **The key pins, and the run names something else.** Refused. Never "prefer the
      more specific one", never a silent rewrite: this is the rule the tenancy design
      wrote for the day the envelope carries a tenant identifier, applied one level
      down.
    """
    pinned = scope.environment
    if pinned is None:
        return submission
    declared = submission.deployment.environment if submission.deployment else None
    if declared is not None and declared != pinned:
        raise EnvironmentMismatchError(
            f"this key is pinned to the {pinned!r} environment and this run declares "
            f"{declared!r}; a credential that does not bound the write is not a boundary, "
            f"so this is refused rather than relabelled"
        )
    if declared == pinned:
        return submission
    block = submission.deployment or DeploymentIn()
    return submission.model_copy(
        update={"deployment": block.model_copy(update={"environment": pinned})}
    )

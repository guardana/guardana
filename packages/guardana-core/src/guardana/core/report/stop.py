"""Kept for the import path. `StopReason` now lives beside the verdict it decides.

It moved into `guardana.core.gate` because the gate needs it and `gate` must not
import the report package: doing so made the two load each other, and the cycle
only became visible once configuration started depending on the redaction policy.
"""

from guardana.core.gate import StopReason

__all__ = ["StopReason"]

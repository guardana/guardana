"""Endpoint rules: how a deployed model route treats the callers that reach it."""

from guardana.rules.endpoint.unauthenticated_inference import UnauthenticatedInferenceRule

__all__ = ["UnauthenticatedInferenceRule"]

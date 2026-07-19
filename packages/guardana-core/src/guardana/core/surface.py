from enum import StrEnum


class Surface(StrEnum):
    """Which security layer a rule belongs to — the build process, or the running model.

    This is the conceptual split between securing *how a model is built* and
    securing *how a served model behaves*. It is derived from what a rule inspects
    (`target_kind`), so it needs no per-rule declaration, and it lines up with
    where each rule runs:

    - ``BUILD`` — the model's files, weights, dependencies, and training data.
      Static, artifact checks: the dev machine, CI, and the training server.
    - ``RUNTIME`` — the served model's behaviour: prompt injection, leakage,
      output handling. Dynamic, endpoint checks: the live probe and the monitor.
    """

    BUILD = "build"
    RUNTIME = "runtime"

"""A Hermes plugin that records each agent session as a Guardana trace.

Hermes discovers this through the `hermes_agent.plugins` entry-point group, imports
the module and calls `register(ctx)`. `ctx.register_hook(name, callback)` is the
whole surface used here; the four hooks are in `VALID_HOOKS` and their payloads are
documented in `agent/shell_hooks.py` upstream.

Written against **hermes-agent 0.19.0**, read from the installed package on
2026-08-15. A later release may change these payloads; see `README.md`.
"""

import os
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from guardana_hermes.recorder import INSTRUMENTED, SINKS, SessionRecorder

__all__ = [
    "INSTRUMENTED",
    "SINKS",
    "HookRegistrar",
    "SessionRecorder",
    "register",
    "trace_directory",
]


class HookRegistrar(Protocol):
    """The one method of Hermes' `PluginContext` this plugin uses.

    A protocol rather than an import: `hermes-agent` is not a dependency of this
    package, so the seam is written down here instead of borrowed. It is also the whole
    surface an integrator needs, which is worth seeing in one line.
    """

    def register_hook(self, hook_name: str, callback: Callable[..., None]) -> None:
        """Register a lifecycle callback for one of Hermes' `VALID_HOOKS`."""
        ...


_ENV_DIRECTORY = "GUARDANA_TRACE_DIR"


def trace_directory() -> Path:
    """Where sessions are written: `$GUARDANA_TRACE_DIR`, else `./guardana-traces`.

    An environment variable rather than plugin config, because this has to work
    identically under the CLI, the gateway and a kanban worker subprocess — three
    execution contexts that do not share a config lookup.
    """
    return Path(os.environ.get(_ENV_DIRECTORY, "guardana-traces"))


def register(ctx: HookRegistrar) -> None:
    """Wire one recorder into the four hooks a session passes through.

    One recorder for the whole plugin rather than one per session: Hermes loads a
    plugin once per process and several sessions may run in it, so the recorder keys
    everything on the session id it is handed.

    `post_approval_response` is an observer — Hermes states that its return value is
    ignored and that a plugin cannot veto or pre-answer an approval from it. That is
    the right shape for this: an integrator records what happened and decides nothing,
    and a recorder that could answer an approval would be inline enforcement.
    """
    recorder = SessionRecorder(trace_directory())
    ctx.register_hook("on_session_start", recorder.on_session_start)
    ctx.register_hook("post_approval_response", recorder.post_approval_response)
    ctx.register_hook("post_tool_call", recorder.post_tool_call)
    ctx.register_hook("on_session_end", recorder.on_session_end)

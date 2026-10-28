"""The A2A target: what it sends, to whom, and how it reads what came back.

Every observation is classed once, so these tests pin the classes at the seam where
the rules read them: the view. What leaves the process is read off the scripted agent,
which records every request as the wire would carry it.
"""

import io
import ipaddress
import json
from collections.abc import Mapping
from email.message import Message
from typing import Any
from urllib.error import HTTPError

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target import (
    A2aAgentTarget,
    A2aAnswer,
    A2aSecurity,
    Capability,
    EndpointUnreachable,
)
from guardana.core.target._a2a_view import _rebuilt
from guardana.core.target._mcp_http import DiscoveryScope, HttpSender, McpError, RawReply
from guardana.core.target.endpoint import UnreadableReply
from guardana.core.testing import ScriptedA2aAgent
from guardana.core.testing.a2a import agent_card
from guardana.testing.conformance import assert_target_conforms

URL = "https://agent.invalid/"
CARD = "https://agent.invalid/.well-known/agent-card.json"
INTERFACE = "https://agent.invalid/a2a"
A = "caller-a-token"
B = "caller-b-token"
CALLERS = {A: "alice", B: "bob"}
TASK = "5d1c7e2a-0b3f-4c9e-8a6d-1f2e3c4b5a69"


def _agent(**kwargs: Any) -> ScriptedA2aAgent:  # noqa: ANN401 — the double's own keywords
    kwargs.setdefault("callers", CALLERS)
    kwargs.setdefault("tasks", {"alice": [TASK]})
    return ScriptedA2aAgent(URL, **kwargs)


def _target(
    agent: ScriptedA2aAgent, credential: str | None = A, other: str | None = B
) -> A2aAgentTarget:
    return A2aAgentTarget(URL, credential=credential, other_credential=other, sender=agent)


def _card(**overrides: object) -> dict[str, object]:
    return {**agent_card(INTERFACE), **overrides}


def _scheme_card(schemes: dict[str, object], requirements: list[object]) -> dict[str, object]:
    return _card(securitySchemes=schemes, securityRequirements=requirements)


def _authorizations(agent: ScriptedA2aAgent) -> list[str | None]:
    return [headers.get("Authorization") for _method, _url, headers in agent.requests]


def test_the_target_declares_a2a_inspection_and_implements_it() -> None:
    target = _target(_agent())

    assert target.capabilities() == {Capability.INSPECT_A2A}
    assert_target_conforms(target)
    assert target.ref == URL


def test_nothing_is_sent_until_a_section_is_read() -> None:
    agent = _agent()
    _target(agent).a2a()

    assert agent.requests == []


def test_an_owner_bound_agent_is_observed_in_every_class_it_answers() -> None:
    agent = _agent(card=_card(capabilities={"extendedAgentCard": True}))
    view = _target(agent).a2a()

    anonymous = view.anonymous
    callers = view.callers

    assert [r.answer for r in anonymous.sent] == [A2aAnswer.REFUSED] * 3
    assert callers.first_listing is not None
    assert callers.first_listing.answer is A2aAnswer.ANSWERED
    assert callers.first_tasks == 1
    assert [r.answer for r in callers.second] == [A2aAnswer.NOT_FOUND]
    assert [(m, u) for m, u, _h in agent.requests] == [
        ("GET", CARD),
        *[("POST", INTERFACE)] * 6,
    ]
    assert [call[0] for call in agent.calls] == [
        "GetTask",
        "ListTasks",
        "GetExtendedAgentCard",
        "ListTasks",
        "GetTask",
        "GetTask",
    ]
    assert agent.calls[3][1] == {"pageSize": 5}
    assert agent.calls[4][1] == {"id": TASK}
    assert agent.calls[4][2] == B


def test_every_request_states_the_version_and_carries_only_its_callers_token() -> None:
    agent = _agent()
    view = _target(agent).a2a()
    view.callers  # noqa: B018 — the read buys every section

    posts = [headers for method, _url, headers in agent.requests if method == "POST"]
    assert all(h["A2A-Version"] == "1.0" for h in posts)
    assert all(h["Content-Type"] == "application/json" for h in posts)
    assert _authorizations(agent) == [None, None, None, f"Bearer {A}", f"Bearer {B}", None]


def test_an_unknown_method_is_not_offered_only_after_the_agent_answered_an_a2a_code() -> None:
    before = _target(_agent(enforced=False, errors={"GetTask": -32601}), None, None).a2a()
    assert before.anonymous.get_task is not None
    assert before.anonymous.get_task.answer is A2aAnswer.OTHER

    after_agent = _agent(
        enforced=False,
        card=_card(capabilities={"extendedAgentCard": True}),
        errors={"GetExtendedAgentCard": -32601},
    )
    after_view = _target(after_agent, None, None).a2a()
    extended = after_view.anonymous.extended_card
    assert extended is not None
    assert extended.answer is A2aAnswer.NOT_OFFERED


def test_an_unsupported_operation_is_not_offered_and_a_result_is_answered() -> None:
    view = _target(_agent(enforced=False, errors={"ListTasks": -32004}), None, None).a2a()

    assert view.anonymous.get_task is not None
    assert view.anonymous.get_task.answer is A2aAnswer.NOT_FOUND
    assert view.anonymous.list_tasks is not None
    assert view.anonymous.list_tasks.answer is A2aAnswer.NOT_OFFERED


def test_a_status_to_a_probe_is_an_observation_not_a_stop() -> None:
    view = _target(_agent(statuses={"ListTasks": 500}), None, None).a2a()

    listed = view.anonymous.list_tasks
    assert listed is not None
    assert listed.answer is A2aAnswer.OTHER
    assert listed.status == 500


def test_an_agent_refusing_the_version_is_unsupported_and_asked_nothing_more() -> None:
    agent = _agent(errors={"GetTask": -32009}, enforced=False)
    view = _target(agent).a2a()

    assert view.anonymous.list_tasks is None
    assert view.callers.first_listing is None
    assert view.unsupported is not None
    assert "-32009" in view.unsupported
    assert [call[0] for call in agent.calls] == ["GetTask"]


def test_an_interface_on_another_origin_is_never_sent_to() -> None:
    elsewhere = "https://elsewhere.invalid/a2a"
    card = _card(
        supportedInterfaces=[
            {"url": elsewhere, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ]
    )
    agent = _agent(card=card)
    view = _target(agent).a2a()

    assert view.anonymous.sent == ()
    assert view.callers.first_listing is None
    assert view.unsupported is not None
    assert "elsewhere.invalid" in view.unsupported
    assert "run --a2a against that origin" in view.unsupported
    assert [url for _m, url, _h in agent.requests] == [CARD]


def test_a_card_without_a_json_rpc_1_0_interface_is_unsupported_naming_what_it_offers() -> None:
    card = _card(
        supportedInterfaces=[
            {"url": INTERFACE, "protocolBinding": "JSONRPC", "protocolVersion": "0.3"},
            {"url": INTERFACE, "protocolBinding": "GRPC", "protocolVersion": "1.0"},
        ]
    )
    view = _target(_agent(card=card)).a2a()

    assert view.unsupported is not None
    assert "JSONRPC 0.3, GRPC 1.0" in view.unsupported


def test_a_patch_version_of_1_0_is_the_interface() -> None:
    card = _card(
        supportedInterfaces=[
            {"url": INTERFACE, "protocolBinding": "JSONRPC", "protocolVersion": "1.0.2"}
        ]
    )
    assert _target(_agent(card=card)).a2a().unsupported is None


def test_a_card_url_ending_in_json_is_fetched_as_given() -> None:
    agent = _agent(statuses={})
    agent.card = _card()
    target = A2aAgentTarget(f"{URL}.well-known/agent-card.json", sender=agent)

    assert target.a2a().card is not None
    assert agent.requests[0][1] == CARD


@pytest.mark.parametrize(
    ("schemes", "requirements", "security"),
    [
        ({}, [], A2aSecurity.NONE),
        (
            {"b": {"httpAuthSecurityScheme": {"scheme": "bearer"}}},
            [{"schemes": {"b": {}}}],
            A2aSecurity.REQUIRED,
        ),
        (
            {"b": {"httpAuthSecurityScheme": {"scheme": "bearer"}}},
            [{"schemes": {"b": {}}}, {"schemes": {}}],
            A2aSecurity.OPTIONAL,
        ),
    ],
)
def test_the_card_security_is_required_optional_or_none(
    schemes: dict[str, object], requirements: list[object], security: A2aSecurity
) -> None:
    view = _target(_agent(card=_scheme_card(schemes, requirements))).a2a()

    assert view.security is security


def test_the_prose_spelling_of_security_is_read_when_the_proto_one_is_absent() -> None:
    card = _card(
        securitySchemes={"b": {"oauth2SecurityScheme": {}}},
        security=[{"b": ["read"]}],
    )
    card.pop("securityRequirements", None)
    view = _target(_agent(card=card)).a2a()

    assert view.security is A2aSecurity.REQUIRED
    assert view.requirements == (("b",),)
    assert view.credential_unsendable is None


@pytest.mark.parametrize(
    "declaration",
    [
        {"httpAuthSecurityScheme": {"scheme": "BEARER"}},
        {"oauth2SecurityScheme": {"flows": {}}},
        {"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://id.invalid/"}},
    ],
)
def test_a_bearer_capable_scheme_gets_the_credentials(declaration: dict[str, object]) -> None:
    agent = _agent(card=_scheme_card({"s": declaration}, [{"schemes": {"s": {}}}]))
    view = _target(agent).a2a()
    view.callers  # noqa: B018 — the read buys every section

    assert f"Bearer {A}" in _authorizations(agent)


@pytest.mark.parametrize(
    ("schemes", "requirements"),
    [
        ({"k": {"apiKeySecurityScheme": {"name": "X-Key"}}}, [{"schemes": {"k": {}}}]),
        ({"h": {"httpAuthSecurityScheme": {"scheme": "basic"}}}, [{"schemes": {"h": {}}}]),
        ({"m": {"mtlsSecurityScheme": {}}}, [{"schemes": {"m": {}}}]),
        (
            {
                "b": {"httpAuthSecurityScheme": {"scheme": "bearer"}},
                "k": {"apiKeySecurityScheme": {"name": "X-Key"}},
            },
            [{"schemes": {"b": {}, "k": {}}}],
        ),
        ({}, [{"schemes": {"undeclared": {}}}]),
        ({}, []),
    ],
)
def test_no_credential_is_sent_where_a_bearer_token_alone_meets_no_requirement(
    schemes: dict[str, object], requirements: list[object]
) -> None:
    agent = _agent(card=_scheme_card(schemes, requirements))
    view = _target(agent).a2a()

    callers = view.callers

    assert callers.not_sent_because is not None
    assert callers.not_sent_because == view.credential_unsendable
    assert all(value is None for value in _authorizations(agent))
    for name in (name for entry in view.requirements for name in entry):
        assert name in callers.not_sent_because


def test_the_callers_are_not_asked_without_both_credentials() -> None:
    nobody = _agent()
    assert "--a2a-token-env" in (_target(nobody, None, None).a2a().callers.not_sent_because or "")

    one = _agent()
    reason = _target(one, A, None).a2a().callers.not_sent_because
    assert reason is not None
    assert "--a2a-other-token-env" in reason
    assert all(value is None for value in _authorizations(one))


def test_two_equal_credentials_and_a_lone_second_one_are_refused() -> None:
    with pytest.raises(ValueError, match="same"):
        A2aAgentTarget(URL, credential=A, other_credential=A)
    with pytest.raises(ValueError, match="first caller"):
        A2aAgentTarget(URL, other_credential=B)
    with pytest.raises(ValueError, match="http or https"):
        A2aAgentTarget("ftp://agent.invalid/")


def test_both_credentials_and_every_learned_task_id_are_withheld() -> None:
    target = _target(_agent(owner_bound=False))
    assert target.sent_secrets() == (A, B)

    target.a2a().callers  # noqa: B018 — the read buys every section

    assert target.sent_secrets() == (A, B, TASK)


def test_an_anonymous_listing_teaches_the_target_ids_too() -> None:
    target = _target(_agent(enforced=False, owner_bound=False), None, None)
    target.a2a().anonymous  # noqa: B018 — the read buys the section

    assert target.sent_secrets() == (TASK,)


def test_the_version_is_reported_only_once_the_agent_spoke_a2a() -> None:
    refusing = _target(_agent(), None, None)
    refusing.a2a().anonymous  # noqa: B018 — the read buys the section
    assert refusing.protocols() == {}

    answering = _target(_agent())
    assert answering.protocols() == {}
    answering.a2a().callers  # noqa: B018 — the read buys every section
    assert answering.protocols() == {"a2a": "1.0"}


def test_every_request_is_metered_and_bounded_by_the_budget() -> None:
    agent = _agent()
    target = _target(agent)
    target.apply_budgets(Budgets(max_requests=2))

    with pytest.raises(BudgetExhausted):
        target.a2a().callers  # noqa: B018 — the read buys every section

    assert len(agent.requests) == 2
    assert target.usage().requests == 2


# --- The conversation stops the run; a probe stops it only when nothing came back. ---


def test_a_card_that_gets_no_reply_stops_the_run_and_is_never_asked_again() -> None:
    agent = _agent(silent_after=0)
    view = _target(agent).a2a()

    with pytest.raises(EndpointUnreachable, match="did not answer"):
        view.card  # noqa: B018 — the read fetches the card
    with pytest.raises(EndpointUnreachable):
        view.anonymous  # noqa: B018 — the read is refused without a request

    assert len(agent.requests) == 1


@pytest.mark.parametrize("status", [404, 408, 425, 429, 500, 503])
def test_a_card_answered_with_a_target_wide_status_stops_the_run(status: int) -> None:
    view = _target(_agent(statuses={"card": status})).a2a()

    with pytest.raises(HTTPError) as raised:
        view.card  # noqa: B018 — the read fetches the card
    assert raised.value.code == status


def test_another_client_error_on_the_card_is_a_card_error() -> None:
    view = _target(_agent(statuses={"card": 403})).a2a()

    assert view.card is None
    assert view.card_error is not None
    assert "403" in view.card_error
    assert view.unsupported is not None
    assert view.anonymous.sent == ()


def test_a_card_that_is_not_a_json_object_stops_the_run() -> None:
    class _Garbled(ScriptedA2aAgent):
        def _card(self, url: str) -> RawReply:
            return RawReply(200, {}, b"<html>agent</html>")

    view = _target(_Garbled(URL, callers=CALLERS)).a2a()

    with pytest.raises(UnreadableReply, match="not a JSON object"):
        view.card  # noqa: B018 — the read fetches the card


@pytest.mark.parametrize("status", [401, 403])
def test_the_first_callers_credential_refused_stops_the_run(status: int) -> None:
    view = _target(_agent(statuses={"ListTasks": status})).a2a()

    with pytest.raises(HTTPError) as raised:
        view.callers  # noqa: B018 — the read buys every section
    assert raised.value.code == status


def test_a_request_scoped_refusal_of_the_first_caller_is_sent_once_and_remembered() -> None:
    agent = _agent()
    view = _target(agent).a2a()
    view.anonymous  # noqa: B018 — bought before the failure is arranged
    agent.statuses["ListTasks"] = 400

    for _ in range(2):
        with pytest.raises(HTTPError) as raised:
            view.callers  # noqa: B018 — the read buys the section
        assert raised.value.code == 400
        assert raised.value.read() == b'{"error": "scripted"}'

    assert [call[0] for call in agent.calls].count("ListTasks") == 2


def test_a_first_caller_reply_that_is_not_json_rpc_stops_the_run() -> None:
    class _Garbled(ScriptedA2aAgent):
        def _read(self, method: str, params: Any, owner: str | None) -> RawReply:  # noqa: ANN401
            if method == "ListTasks" and owner == "alice":
                return RawReply(200, {}, b"not json")
            return super()._read(method, params, owner)

    view = _target(_Garbled(URL, callers=CALLERS, tasks={"alice": [TASK]})).a2a()

    with pytest.raises(UnreadableReply, match="not JSON-RPC"):
        view.callers  # noqa: B018 — the read buys every section


def test_a_probe_that_gets_no_reply_stops_the_run() -> None:
    agent = _agent(silent_after=2)
    view = _target(agent).a2a()

    with pytest.raises(EndpointUnreachable):
        view.anonymous  # noqa: B018 — the read buys the section
    with pytest.raises(EndpointUnreachable):
        view.callers  # noqa: B018 — refused without a request

    assert len(agent.requests) == 3


# --- What the first caller listed is asked for once more, by a caller presenting nothing. ---


def test_one_of_the_first_callers_tasks_is_asked_for_anonymously_once() -> None:
    agent = _agent()
    _target(agent).a2a().callers  # noqa: B018 — the read buys every section

    assert agent.calls[-1] == ("GetTask", {"id": TASK}, None)
    assert [call[0] for call in agent.calls].count("GetTask") == 3


def test_the_anonymous_read_of_a_listed_task_is_classed_like_any_answer() -> None:
    callers = _target(_agent()).a2a().callers

    assert callers.anonymous_read is not None
    assert callers.anonymous_read.answer is A2aAnswer.REFUSED


def test_no_anonymous_read_is_sent_when_the_first_caller_listed_nothing() -> None:
    agent = _agent(tasks={})
    callers = _target(agent).a2a().callers

    assert callers.anonymous_read is None
    assert [call[0] for call in agent.calls] == ["GetTask", "ListTasks", "ListTasks"]


# --- The --a2a URL names the card or the origin, never a path the card would replace. ---


@pytest.mark.parametrize(
    "url", ["https://agent.invalid/agents/foo", "https://agent.invalid/agents/foo/"]
)
def test_a_path_that_is_not_a_json_card_is_refused(url: str) -> None:
    with pytest.raises(ValueError, match=r"agent card's URL \(ending in \.json\) or the agent's"):
        A2aAgentTarget(url)


def test_the_origin_with_or_without_a_slash_is_accepted() -> None:
    for url in ("https://agent.invalid", "https://agent.invalid/"):
        assert A2aAgentTarget(url).ref == url


def test_the_interface_examined_is_shown_without_credentials() -> None:
    card = _card(
        supportedInterfaces=[
            {
                "url": "https://agent.invalid/a2a?key=secret",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ]
    )
    view = _target(_agent(card=card)).a2a()

    examined = view.examined_interface
    assert examined is not None
    assert examined.startswith("https://agent.invalid/a2a")
    assert "secret" not in examined


def test_an_interface_that_was_not_examined_is_not_shown() -> None:
    card = _card(
        supportedInterfaces=[
            {
                "url": "https://elsewhere.invalid/a2a",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ]
    )
    assert _target(_agent(card=card)).a2a().examined_interface is None


# --- A section already observed is never lost to a later stop. ---


class _SecondCallerDropped(ScriptedA2aAgent):
    """Drops the connection on the second caller's first request, answering all else."""

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        if (headers or {}).get("Authorization") == f"Bearer {B}":
            raise McpError(f"could not reach {url}: the connection was reset")
        return super().__call__(
            url, method=method, body=body, headers=headers, alongside=alongside, discovery=discovery
        )


def test_a_section_already_observed_survives_a_later_stop() -> None:
    view = _target(_SecondCallerDropped(URL, callers=CALLERS, tasks={"alice": [TASK]})).a2a()
    anonymous = view.anonymous

    with pytest.raises(EndpointUnreachable):
        view.callers  # noqa: B018 — the read buys the section that stops the run

    assert view.anonymous is anonymous
    assert view.card is not None
    assert view.unsupported is None
    with pytest.raises(EndpointUnreachable):
        view.callers  # noqa: B018 — never bought, so the stop is met again


# --- Locality of an interface on the agent's own host. ---


class _RecordingSender(HttpSender):
    """The built-in sender's bookkeeping over a scripted agent: every peer is `peer`."""

    def __init__(self, agent: ScriptedA2aAgent, peer: str) -> None:
        super().__init__()
        self._agent = agent
        self._peer = ipaddress.ip_address(peer)

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        self._record(url, self._peer)
        return self._agent(url, method=method, body=body, headers=headers)


@pytest.mark.parametrize(("peer", "local"), [("10.0.0.5", True), ("93.184.215.14", False)])
def test_an_interface_on_another_port_of_the_agents_host_is_judged_by_that_hosts_connections(
    peer: str, local: bool
) -> None:
    url = "http://agent.internal:8000/"
    card = agent_card("http://agent.internal:9000/a2a")
    sender = _RecordingSender(ScriptedA2aAgent(url, card=card, callers=CALLERS), peer)
    view = A2aAgentTarget(url, sender=sender).a2a()

    assert view.jsonrpc_interface_is_local is local
    assert view.jsonrpc_interface_judged_by_url is False


def test_an_interface_on_another_host_is_judged_by_its_url_alone() -> None:
    url = "http://agent.internal:8000/"
    card = agent_card("http://other.internal:8000/a2a")
    sender = _RecordingSender(ScriptedA2aAgent(url, card=card, callers=CALLERS), "10.0.0.5")
    view = A2aAgentTarget(url, sender=sender).a2a()

    assert view.jsonrpc_interface_is_local is False
    assert view.jsonrpc_interface_judged_by_url is True


class _ListingAs(ScriptedA2aAgent):
    """Answers every `ListTasks` with one scripted result; everything else as configured."""

    def __init__(self, result: Mapping[str, object]) -> None:
        super().__init__(URL, callers=CALLERS, enforced=False, tasks={"": [TASK]})
        self.listing = dict(result)

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        asked = json.loads(body or b"{}") if method == "POST" else {}
        if asked.get("method") != "ListTasks":
            return super().__call__(url, method=method, body=body, headers=headers)
        self.requests.append((method, url, dict(headers or {})))
        payload = {"jsonrpc": "2.0", "id": asked["id"], "result": self.listing}
        return RawReply(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())


@pytest.mark.parametrize(
    "result",
    [
        {"tasks": "not-a-list"},
        {"tasks": {"id": TASK}},
        {"tasks": [], "nextPageToken": "more"},
        {"tasks": [], "nextPageToken": 7},
    ],
    ids=["tasks-a-string", "tasks-an-object", "empty-page-with-a-token", "token-not-a-string"],
)
def test_a_listing_nobody_can_read_whole_is_no_answer(result: Mapping[str, object]) -> None:
    listed = _target(_ListingAs(result)).a2a().anonymous.list_tasks

    assert listed is not None
    assert listed.answer is A2aAnswer.OTHER
    assert not listed.lists_tasks


@pytest.mark.parametrize(
    ("result", "shows"),
    [
        ({"tasks": [], "nextPageToken": ""}, False),
        ({"tasks": [], "nextPageToken": None}, False),
        ({"tasks": []}, False),
        ({"tasks": [{"id": TASK}], "nextPageToken": "more"}, True),
        ({"tasks": [], "nextPageToken": "more", "totalSize": 3}, True),
    ],
    ids=["last-page", "null-token", "no-token", "a-task-and-more", "empty-page-totalling-three"],
)
def test_a_listing_read_whole_or_showing_a_task_is_an_answer(
    result: Mapping[str, object], shows: bool
) -> None:
    listed = _target(_ListingAs(result)).a2a().anonymous.list_tasks

    assert listed is not None
    assert listed.answer is A2aAnswer.ANSWERED
    assert listed.lists_tasks is shows


class _HungUpBody(io.BytesIO):
    """A reply body the peer hung up on before it was read."""

    def read(self, size: int | None = -1) -> bytes:
        raise ConnectionResetError("reset by peer")


def test_a_failure_whose_body_is_kept_for_later_readers_is_closed() -> None:
    error = HTTPError("http://agent", 400, "Bad Request", Message(), io.BytesIO(b"no"))

    again = _rebuilt(error)()

    assert error.fp.closed
    assert isinstance(again, HTTPError)
    assert again.read() == b"no"
    again.close()


def test_a_failure_whose_body_could_not_be_read_is_closed_all_the_same() -> None:
    error = HTTPError("http://agent", 400, "Bad Request", Message(), _HungUpBody(b"no"))

    with pytest.raises(ConnectionResetError):
        _rebuilt(error)

    assert error.fp.closed

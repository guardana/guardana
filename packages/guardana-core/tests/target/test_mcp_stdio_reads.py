"""Reading a reply from a server this process started: bounded in size, in time and in lines.

The child is the code under test. One that writes a line without end, never writes,
or writes lines answering nothing must cost a bounded amount of memory, a bounded
wait and a bounded number of lines, and end in a failure that stops the run — never
a scan that hangs, a reply read whole first, or a late answer read as the next one.
"""

import sys
import threading

import pytest
from _offline import refuse_name_lookups
from guardana.core.target import EndpointUnreachable, UnreadableReply
from guardana.core.target._mcp_client import StdioMcpTransport, open_conversation
from guardana.core.target._mcp_http import MAX_RESPONSE_BYTES
from guardana.core.target._mcp_wire import LEGACY_VERSION

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_GRACE_SECONDS = 15

_ECHO = """
import json, sys, time
for line in sys.stdin:
    asked = json.loads(line)
    if "id" not in asked:
        continue
    reply = {"jsonrpc": "2.0", "id": asked["id"], "result": {"tools": [], "seen": asked["id"]}}
    sys.stdout.write(json.dumps(reply) + "\\n")
    sys.stdout.flush()
"""
"""Answers every request with its own id, and says which id it saw."""


def _child(source: str) -> list[str]:
    return [sys.executable, "-c", source]


def _request_in_background(
    transport: StdioMcpTransport, params: dict[str, object] | None = None
) -> list[object]:
    """Make one request on a thread, so a read or write that never returns fails the test."""
    outcome: list[object] = []

    def ask() -> None:
        try:
            outcome.append(transport.request("tools/list", params or {}))
        except Exception as exc:
            outcome.append(exc)

    worker = threading.Thread(target=ask, daemon=True)
    worker.start()
    worker.join(_GRACE_SECONDS)
    assert not worker.is_alive(), "the read is still waiting on the child"
    return outcome


def test_each_request_carries_its_own_increasing_id() -> None:
    transport = StdioMcpTransport(_child(_ECHO))
    try:
        first = transport.request("tools/list", {})
        second = transport.request("tools/list", {})
    finally:
        transport.close()

    assert first["seen"] == 1
    assert second["seen"] == 2


def test_two_replies_written_together_answer_two_requests() -> None:
    replies = (
        '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\\n'
        '{"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}\\n'
    )
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            f"sys.stdout.write('{replies}')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
    )
    try:
        first = transport.request("tools/list", {})
        second = transport.request("tools/list", {})
    finally:
        transport.close()

    assert first == {"tools": []}
    assert second == {"tools": []}


def test_a_line_past_the_cap_is_unreadable_before_it_ends() -> None:
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            f"sys.stdout.write('x' * {2 * MAX_RESPONSE_BYTES})\n"
            "sys.stdout.flush()\n"
            "time.sleep(60)\n"
        )
    )
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], UnreadableReply)
    assert "exceeds" in str(outcome[0])


def test_a_line_that_is_not_json_is_unreadable_and_the_stream_stays_failed() -> None:
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            "sys.stdout.write('server starting up\\n')\n"
            'sys.stdout.write(\'{"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}\\n\')\n'
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        ),
        ref="mcp+stdio://child",
    )
    try:
        with pytest.raises(UnreadableReply, match=r"mcp\+stdio://child sent a line"):
            transport.request("tools/list", {})
        with pytest.raises(UnreadableReply):
            transport.request("tools/list", {})
    finally:
        transport.close()


def test_a_server_that_never_answers_is_unreachable_after_the_deadline() -> None:
    transport = StdioMcpTransport(_child("import time\ntime.sleep(60)\n"), timeout=0.5)
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], EndpointUnreachable)
    assert "0.5 seconds" in str(outcome[0])


def test_a_server_that_exits_without_answering_is_unreachable() -> None:
    transport = StdioMcpTransport(_child("import sys\nsys.stdin.readline()\n"))
    try:
        with pytest.raises(EndpointUnreachable, match="closed its output"):
            transport.request("tools/list", {})
    finally:
        transport.close()


def test_a_command_that_cannot_be_started_is_unreachable_by_name() -> None:
    with pytest.raises(EndpointUnreachable, match="could not start MCP server"):
        StdioMcpTransport(["/nonexistent/guardana-test-server"])


def test_a_late_reply_is_discarded_never_read_as_the_answer_to_the_next_request() -> None:
    # The child answers the first request only once the second arrives, so a transport
    # that took the next line as its answer would read the first request's reply.
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            "sys.stdin.readline()\n"
            'sys.stdout.write(\'{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\\n\')\n'
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        ),
        timeout=0.3,
    )
    try:
        with pytest.raises(EndpointUnreachable, match="within"):
            transport.request("tools/list", {})
        with pytest.raises(EndpointUnreachable, match="within"):
            transport.request("tools/list", {})
    finally:
        transport.close()


def test_lines_answering_nobody_are_discarded_up_to_a_bound_then_unreadable() -> None:
    stale = '{"jsonrpc": "2.0", "id": 99, "result": {}}\\n'
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            f"sys.stdout.write('{stale}' * 40)\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
    )
    try:
        with pytest.raises(UnreadableReply, match="answering no request"):
            transport.request("tools/list", {})
    finally:
        transport.close()


def test_a_few_lines_answering_nobody_do_not_hide_the_reply_after_them() -> None:
    stale = '{"jsonrpc": "2.0", "method": "notifications/message", "params": {}}\\n'
    reply = '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\\n'
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            f"sys.stdout.write('{stale}' * 3 + '{reply}')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
    )
    try:
        assert transport.request("tools/list", {}) == {"tools": []}
    finally:
        transport.close()


def test_a_server_request_carrying_the_asked_id_is_never_read_as_the_reply() -> None:
    # A server numbers its own requests, so one may carry the id the client just used.
    asked = '{"jsonrpc": "2.0", "id": 1, "method": "roots/list"}\\n'
    reply = '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\\n'
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            f"sys.stdout.write('{asked}' + '{reply}')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
    )
    try:
        assert transport.request("tools/list", {}) == {"tools": []}
    finally:
        transport.close()


def test_notifications_do_not_count_toward_the_lines_answering_nobody() -> None:
    notification = '{"jsonrpc": "2.0", "method": "notifications/message", "params": {}}\\n'
    reply = '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\\n'
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            f"sys.stdout.write('{notification}' * 40 + '{reply}')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
    )
    try:
        assert transport.request("tools/list", {}) == {"tools": []}
    finally:
        transport.close()


def test_a_server_that_only_sends_notifications_is_unreachable_after_the_deadline() -> None:
    notification = '{"jsonrpc": "2.0", "method": "notifications/message", "params": {}}\\n'
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            "while True:\n"
            f"    sys.stdout.write('{notification}')\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.01)\n"
        ),
        timeout=0.5,
    )
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], EndpointUnreachable)
    assert "0.5 seconds" in str(outcome[0])


def test_a_discovery_that_times_out_leaves_the_stream_for_the_handshake() -> None:
    # A legacy server that never answers `server/discover` answers it late, after the
    # client has moved on: the late line is discarded and the handshake is read.
    transport = StdioMcpTransport(
        _child(
            "import json, sys\n"
            "discover = json.loads(sys.stdin.readline())\n"
            "initialize = json.loads(sys.stdin.readline())\n"
            "late = {'jsonrpc': '2.0', 'id': discover['id'], 'error': "
            "{'code': -32601, 'message': 'Method not found'}}\n"
            "opened = {'jsonrpc': '2.0', 'id': initialize['id'], 'result': "
            f"{{'protocolVersion': '{LEGACY_VERSION}', 'capabilities': {{}}}}}}\n"
            "sys.stdout.write(json.dumps(late) + '\\n' + json.dumps(opened) + '\\n')\n"
            "sys.stdout.flush()\n"
            "assert 'id' not in json.loads(sys.stdin.readline())\n"
            "listing = json.loads(sys.stdin.readline())\n"
            "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': listing['id'], "
            "'result': {'tools': [{'name': 'read'}]}}) + '\\n')\n"
            "sys.stdout.flush()\n"
        ),
        timeout=0.5,
    )
    try:
        conversation = open_conversation(transport)
    finally:
        transport.close()

    assert [tool.name for tool in conversation.tools] == ["read"]
    assert conversation.protocol_version == LEGACY_VERSION


_ASKS_FIRST = """
import json, sys
asked = json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {}}))
sys.stdout.write("\\n" + json.dumps({"jsonrpc": "2.0", "id": "s-1", "method": METHOD}) + "\\n")
sys.stdout.flush()
answered = json.loads(sys.stdin.readline())
reply = {"jsonrpc": "2.0", "id": asked["id"], "result": {"tools": [], "answered": answered}}
sys.stdout.write(json.dumps(reply) + "\\n")
sys.stdout.flush()
"""
"""Sends a notification and a request of its own, and replies only once that is answered."""


def test_a_server_waiting_for_its_ping_is_answered_and_then_replies() -> None:
    transport = StdioMcpTransport(_child(_ASKS_FIRST.replace("METHOD", '"ping"')), timeout=2.0)
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    # The first line the server reads after its own request is the answer to it, so
    # the notification before that request was not answered.
    assert outcome == [{"tools": [], "answered": {"jsonrpc": "2.0", "id": "s-1", "result": {}}}]


def test_any_other_server_request_is_answered_as_an_unknown_method() -> None:
    transport = StdioMcpTransport(
        _child(_ASKS_FIRST.replace("METHOD", '"roots/list"')), timeout=2.0
    )
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    reply = outcome[0]
    assert isinstance(reply, dict)
    answered = reply["answered"]
    assert answered["id"] == "s-1"
    assert answered["error"]["code"] == -32601
    assert "result" not in answered


_FLOODS_PINGS = """
import json, sys, time
sys.stdin.readline()
for n in range(20000):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": f"p{n}", "method": "ping"}) + "\\n")
sys.stdout.flush()
time.sleep(60)
"""
"""Sends far more requests than a pipe holds answers for, and never reads its input again."""


def test_a_server_flooding_its_own_requests_is_unreadable_not_a_hang() -> None:
    transport = StdioMcpTransport(_child(_FLOODS_PINGS), timeout=2.0)
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], UnreadableReply)
    assert "requests of its own" in str(outcome[0])


_PINGS_WITH_A_LONG_ID = """
import json, sys, time
sys.stdin.readline()
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": "x" * 200000, "method": "ping"}) + "\\n")
sys.stdout.flush()
time.sleep(60)
"""
"""Asks with an id no pipe holds the answer to, and never reads its input again."""


def test_a_server_request_whose_id_is_too_long_to_reflect_is_unreadable() -> None:
    transport = StdioMcpTransport(_child(_PINGS_WITH_A_LONG_ID), timeout=5.0)
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], UnreadableReply)
    assert "id" in str(outcome[0])


@pytest.mark.parametrize("asked_id", ["[1]", '{"n": 1}', "true", "1.5"])
def test_a_server_request_whose_id_is_not_a_string_or_integer_is_unreadable(
    asked_id: str,
) -> None:
    asked = f'{{"jsonrpc": "2.0", "id": {asked_id}, "method": "ping"}}\\n'
    transport = StdioMcpTransport(
        _child(
            "import sys, time\n"
            "sys.stdin.readline()\n"
            f"sys.stdout.write('{asked}')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        ),
        timeout=5.0,
    )
    try:
        outcome = _request_in_background(transport)
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], UnreadableReply)


_NEVER_READS = "import time\ntime.sleep(60)\n"
"""Leaves its input unread, so a request larger than the pipe never finishes writing."""


def test_a_server_that_does_not_read_its_input_is_unreachable_within_the_deadline() -> None:
    transport = StdioMcpTransport(_child(_NEVER_READS), timeout=0.5)
    try:
        outcome = _request_in_background(transport, {"cursor": "x" * 1_000_000})
        with pytest.raises(UnreadableReply):
            transport.request("tools/list", {})
    finally:
        transport.close()

    assert len(outcome) == 1
    assert isinstance(outcome[0], EndpointUnreachable)
    assert "0.5 seconds" in str(outcome[0])

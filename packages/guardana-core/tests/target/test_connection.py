import hashlib
from pathlib import Path
from typing import Any

import pytest
import yaml
from _yaml_input_cases import NON_TEXT_KEYS
from guardana.core.target import HttpAdapterTransport
from guardana.core.target.connection import (
    Connection,
    ConnectionConfigError,
    Spelling,
    load_adapter,
    resolve_connection,
)

_URL = "https://api.example.com/chat"
_BODY = 'body:\n  message: "{{prompt}}"\nresponse_path: data.reply\n'


def _adapter(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "adapter.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_an_adapter_expands_its_headers_from_the_environment(tmp_path: Path) -> None:
    path = _adapter(tmp_path, f"url: {_URL}\nheaders:\n  X-Api-Key: ${{APP_KEY}}\n{_BODY}")

    loaded = load_adapter(path, url=_URL, environ={"APP_KEY": "sekret"})

    assert loaded.config.url == _URL
    assert loaded.config.headers["X-Api-Key"] == "sekret"
    assert loaded.config.response_path == "data.reply"


def test_an_adapter_without_a_url_posts_to_the_url_the_run_names(tmp_path: Path) -> None:
    loaded = load_adapter(_adapter(tmp_path, _BODY), url=_URL, environ={})

    assert loaded.config.url == _URL


def test_the_adapter_digest_covers_the_file_as_written_before_expansion(tmp_path: Path) -> None:
    text = f"headers:\n  X-Api-Key: ${{APP_KEY}}\n{_BODY}"
    path = _adapter(tmp_path, text)

    first = load_adapter(path, url=_URL, environ={"APP_KEY": "one"})
    second = load_adapter(path, url=_URL, environ={"APP_KEY": "two"})

    expected = f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"
    assert first.digest == second.digest == expected


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_an_adapter_header_variable_unset_or_empty_is_refused(
    tmp_path: Path, value: str | None
) -> None:
    path = _adapter(tmp_path, f"headers:\n  X-Api-Key: ${{APP_KEY}}\n{_BODY}")
    environ = {} if value is None else {"APP_KEY": value}

    with pytest.raises(ConnectionConfigError, match="APP_KEY"):
        load_adapter(path, url=_URL, environ=environ)


def test_an_adapter_loaded_not_to_send_reads_no_header_variable(tmp_path: Path) -> None:
    path = _adapter(tmp_path, f"headers:\n  X-Api-Key: ${{APP_KEY}}\n{_BODY}")

    loaded = load_adapter(path, url=_URL, environ=None)

    assert loaded.config.headers == {}


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("response_path: reply\n", "'body' is required"),
        ('body:\n  m: "{{prompt}}"\nresponse_path: r\nbogus: 1\n', "unknown key"),
        (f"method: GET\n{_BODY}", "method must be POST"),
        ("url: https://elsewhere.example.com/chat\n" + _BODY, "differs from --url"),
        ("- a list\n", "top level must be a mapping"),
    ],
    ids=["no-body", "unknown-key", "method-get", "other-url", "not-a-mapping"],
)
def test_an_adapter_the_run_cannot_honour_is_refused(
    tmp_path: Path, text: str, complaint: str
) -> None:
    with pytest.raises(ConnectionConfigError, match=complaint):
        load_adapter(_adapter(tmp_path, text), url=_URL, environ={})


def test_an_adapter_may_spell_post_in_any_case_and_its_url_with_a_trailing_slash(
    tmp_path: Path,
) -> None:
    path = _adapter(tmp_path, f"method: post\nurl: {_URL}/\n{_BODY}")

    assert load_adapter(path, url=_URL, environ={}).config.url == _URL


def test_a_missing_adapter_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConnectionConfigError, match="cannot read --adapter"):
        load_adapter(tmp_path / "absent.yaml", url=_URL, environ={})


def test_a_connection_through_an_adapter_carries_its_transport_and_digest(
    tmp_path: Path,
) -> None:
    resolved = resolve_connection(
        Connection(_URL, "m", adapter=_adapter(tmp_path, _BODY)), sending=True, environ={}
    )

    assert isinstance(resolved.transport, HttpAdapterTransport)
    assert resolved.provider is None
    assert resolved.adapter_digest is not None


def test_an_adapter_declares_the_values_it_reads_and_the_credential_headers_and_no_other(
    tmp_path: Path,
) -> None:
    headers = (
        "headers:\n"
        "  Content-Type: application/json\n"
        "  X-Org: acme\n"
        "  X-Tenant: tenant-${TENANT_ID}\n"
        "  authorization: Bearer literal-token-123\n"
        "  X-Gateway-TOKEN: gt-abc\n"
        "  Api-Key: k-1234\n"
        "  X-Signing-Secret: s-5678\n"
        "  Proxy-Authorization: Basic cHJveHk6cHc=\n"
        "  Cookie: sid=abc123\n"
    )
    resolved = resolve_connection(
        Connection(_URL, "m", adapter=_adapter(tmp_path, headers + _BODY)),
        sending=True,
        environ={"TENANT_ID": "998877"},
    )

    assert isinstance(resolved.transport, HttpAdapterTransport)
    assert set(resolved.transport.sent_secrets()) == {
        "tenant-998877",
        "998877",
        "Bearer literal-token-123",
        "literal-token-123",
        "gt-abc",
        "k-1234",
        "s-5678",
        "Basic cHJveHk6cHc=",
        "cHJveHk6cHc=",
        "sid=abc123",
    }


@pytest.mark.parametrize(
    ("connection", "complaint"),
    [
        (Connection(_URL, "m", provider="openai"), "cannot be combined with --provider"),
        (Connection(_URL, "m", api_key_env="KEY"), "cannot be combined with --api-key-env"),
    ],
    ids=["provider", "api-key-env"],
)
def test_an_adapter_with_a_provider_or_a_key_variable_is_refused(
    tmp_path: Path, connection: Connection, complaint: str
) -> None:
    with_adapter = Connection(
        connection.url,
        connection.model,
        provider=connection.provider,
        api_key_env=connection.api_key_env,
        adapter=_adapter(tmp_path, _BODY),
    )

    with pytest.raises(ConnectionConfigError, match=complaint):
        resolve_connection(with_adapter, sending=True, environ={"KEY": "k"})


def test_an_unknown_provider_is_refused_and_named() -> None:
    with pytest.raises(ConnectionConfigError, match="--provider: unknown provider 'bogus'"):
        resolve_connection(Connection(_URL, "m", provider="bogus"), sending=False)


def test_no_provider_means_the_openai_wire() -> None:
    assert resolve_connection(Connection(_URL, "m"), sending=False).provider == "openai"


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_a_key_variable_unset_or_empty_is_refused_for_a_connection_that_sends(
    value: str | None,
) -> None:
    environ = {} if value is None else {"KEY": value}

    with pytest.raises(ConnectionConfigError, match="'KEY', which is unset or empty"):
        resolve_connection(Connection(_URL, "m", api_key_env="KEY"), sending=True, environ=environ)


def test_a_key_variable_is_read_for_a_connection_that_sends() -> None:
    resolved = resolve_connection(
        Connection(_URL, "m", api_key_env="KEY"), sending=True, environ={"KEY": "k"}
    )

    assert resolved.api_key == "k"


def test_a_connection_that_will_not_send_needs_no_key_and_carries_none() -> None:
    resolved = resolve_connection(
        Connection(_URL, "m", api_key_env="KEY"), sending=False, environ={"KEY": "k"}
    )

    assert resolved.api_key is None


def test_a_judge_block_refusal_names_the_block_keys() -> None:
    with pytest.raises(ConnectionConfigError, match=r"evaluators\.guard\.api_key_env"):
        resolve_connection(
            Connection(_URL, "m", api_key_env="KEY"),
            sending=True,
            spelling=Spelling.judge("guard"),
            environ={},
        )


def test_a_connection_that_sends_holds_its_key_value() -> None:
    resolved = resolve_connection(
        Connection(_URL, "m", api_key_env="KEY"), sending=True, environ={"KEY": "k-value"}
    )

    assert resolved.secret_values == ("k-value",)
    assert "secret_values" not in repr(resolved)


def test_an_adapter_connection_holds_each_expanded_header_and_each_value_it_read(
    tmp_path: Path,
) -> None:
    path = _adapter(
        tmp_path, f"headers:\n  Authorization: Bearer ${{APP_KEY}}\n  X-Fixed: plain\n{_BODY}"
    )

    resolved = resolve_connection(
        Connection(_URL, "m", adapter=path), sending=True, environ={"APP_KEY": "sekret-1"}
    )

    assert resolved.secret_values == ("Bearer sekret-1", "sekret-1")


def test_a_connection_that_will_not_send_holds_no_secret_value(tmp_path: Path) -> None:
    path = _adapter(tmp_path, f"headers:\n  X-Key: ${{APP_KEY}}\n{_BODY}")

    resolved = resolve_connection(
        Connection(_URL, "m", adapter=path), sending=False, environ={"APP_KEY": "sekret-1"}
    )

    assert resolved.secret_values == ()


def test_no_secret_a_connection_sends_appears_in_its_repr(tmp_path: Path) -> None:
    keyed = resolve_connection(
        Connection(_URL, "m", api_key_env="KEY"), sending=True, environ={"KEY": "k-value-1"}
    )
    path = _adapter(tmp_path, f"headers:\n  X-Key: ${{APP_KEY}}\n{_BODY}")
    adapted = resolve_connection(
        Connection(_URL, "m", adapter=path), sending=True, environ={"APP_KEY": "sekret-1"}
    )
    loaded = load_adapter(path, url=_URL, environ={"APP_KEY": "sekret-1"})

    assert "k-value-1" not in repr(keyed)
    assert "sekret-1" not in repr(adapted)
    assert "sekret-1" not in repr(loaded)
    assert "sekret-1" not in repr(loaded.config)


@pytest.mark.parametrize("section", ["adapter", "decline"])
@pytest.mark.parametrize("mixed", [False, True])
@pytest.mark.parametrize(("key", "shown"), NON_TEXT_KEYS)
def test_non_text_adapter_keys_raise_connectionconfigerror(
    tmp_path: Path,
    section: str,
    mixed: bool,
    key: str,
    shown: str,
) -> None:
    document: dict[str, Any] = yaml.safe_load(_BODY)
    document["declines"] = [
        {
            "name": "policy",
            "status": 200,
            "as": "refusal",
            "path": "error.type",
            "equals": "policy",
        }
    ]

    extra: dict[Any, Any] = yaml.safe_load(f"{key}: ignored\n")
    if mixed:
        extra["unrecognised"] = "ignored"

    block = document if section == "adapter" else document["declines"][0]
    block.update(extra)
    path = _adapter(tmp_path, yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(ConnectionConfigError, match="unknown key") as caught:
        load_adapter(path, url=_URL, environ={})

    message = str(caught.value)
    assert str(path) in message
    assert shown in message.replace(str(path), "")

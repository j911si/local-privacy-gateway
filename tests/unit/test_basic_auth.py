from __future__ import annotations

from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect.structured import StructuredStage

BASIC = "ZGVtbzpkZW1vUGFzczQy"
BEARER = "abcdEFGH1234ijklMNOP5678"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def tokens(text: str, config: Config) -> list[str]:
    return [
        text[f.span.start : f.span.end]
        for f in StructuredStage().run(text, config, [])
        if f.data_class == "ACCESS_TOKEN"
    ]


@pytest.mark.parametrize(
    "text",
    [
        f"  Authorization: Basic {BASIC}\n",
        f"Proxy-Authorization: Basic {BASIC}\n",
        f"    Proxy-Authorization: Basic {BASIC}\n",
        f"\tauthorization: basic {BASIC}\n",
        f"curl -H 'Authorization: Basic {BASIC}' https://example.com\n",
        f'curl -H "Proxy-Authorization: Basic {BASIC}" https://example.com\n',
        f"-H Authorization:Basic {BASIC}",
    ],
)
def test_basic_credentials_are_found(default_config: Config, text: str) -> None:
    assert tokens(text, default_config) == [BASIC]


@pytest.mark.parametrize(
    "text",
    [
        f"  Authorization: Basic {BASIC}\n",
        f"Proxy-Authorization: Basic {BASIC}\n",
        f"curl -H 'Authorization: Basic {BASIC}' https://example.com\n",
        f"    Authorization: Bearer {BEARER}\n",
        f"Proxy-Authorization: Bearer {BEARER}\n",
    ],
)
def test_credentials_are_not_sent(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert BASIC not in out
    assert BEARER not in out


def test_padded_inline_basic_credential(default_config: Config) -> None:
    text = "curl -H 'Authorization: Basic ZGVtbzpwdw==' https://example.com"
    assert tokens(text, default_config) == ["ZGVtbzpwdw=="]


@pytest.mark.parametrize(
    "text",
    [
        "We use Authorization: Basic auth is used for the admin API.",
        "The header Authorization: Basic Authentication is deprecated.",
        "Set Authorization: Basic credentials in the client.",
    ],
)
def test_prose_about_basic_auth_stays(default_config: Config, text: str) -> None:
    assert tokens(text, default_config) == []


def test_indented_custom_headers_stay_out_of_scope(default_config: Config) -> None:
    text = "paths:\n  x-amazon-apigateway-any-method: value\n  Cookie: sessionid=abc123def\n"
    assert StructuredStage().run(text, default_config, []) == []

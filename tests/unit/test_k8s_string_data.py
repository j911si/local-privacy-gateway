from __future__ import annotations

from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect.structured import StructuredStage

HEAD = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ntype: Opaque\n"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def secrets(text: str, config: Config) -> list[str]:
    return [
        text[f.span.start : f.span.end]
        for f in StructuredStage().run(text, config, [])
        if f.data_class == "KUBERNETES_SECRET"
    ]


def test_string_data_plain_value(default_config: Config) -> None:
    text = HEAD + "stringData:\n  opaque: demoValue42\n"
    assert secrets(text, default_config) == ["demoValue42"]


def test_string_data_value_with_spaces_and_later_entries(default_config: Config) -> None:
    text = HEAD + "stringData:\n  greeting: open sesame 42\n  opaque: demoValue42\n"
    assert secrets(text, default_config) == ["open sesame 42", "demoValue42"]


def test_string_data_quoted_values(default_config: Config) -> None:
    text = HEAD + 'stringData:\n  a: "fake 12\\"tail99"\n  b: \'it\'\'s demo 7\'\n'
    assert secrets(text, default_config) == ['fake 12\\"tail99', "it''s demo 7"]


def test_string_data_block_scalar(default_config: Config) -> None:
    text = (
        HEAD
        + "stringData:\n  config.json: |-\n    {\"user\": \"demo\", \"pw\": \"hunter42x\"}\n"
        + "\n    second line 99\n  after: x1y2z3\n"
    )
    assert secrets(text, default_config) == [
        '{"user": "demo", "pw": "hunter42x"}',
        "second line 99",
        "x1y2z3",
    ]


def test_string_data_in_a_config_map_is_ignored(default_config: Config) -> None:
    text = "apiVersion: v1\nkind: ConfigMap\nstringData:\n  opaque: demoValue42\n"
    assert secrets(text, default_config) == []


def test_string_data_value_is_not_sent(gateway: Gateway) -> None:
    text = HEAD + "stringData:\n  opaque: demoValue42\n  note: open sesame 42\n"
    out = gateway.session().pseudonymize(text)
    assert "demoValue42" not in out
    assert "sesame" not in out

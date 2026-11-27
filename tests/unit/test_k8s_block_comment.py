"""YAML block scalars with a comment in Kubernetes Secrets are redacted (R2-01#5)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect import structured
from privacy_gateway.detect.structured import StructuredStage
from test_regex_linearity import _hard_timeout, assert_linear  # noqa: F401

SECRET = "Zq7mWp4Lr9TxVb2N"
HEAD = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: demo\n"


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


HEADERS = ["| # mehrzeilig", "|- # comment", ">- # c", "|+\t# c", ">2 # x", "| #", "|"]


@pytest.mark.parametrize("header", HEADERS)
@pytest.mark.parametrize("section", ["stringData", "data"])
def test_block_scalar_with_comment_is_found(
    default_config: Config, header: str, section: str
) -> None:
    text = HEAD + f"{section}:\n  app-key: {header}\n    {SECRET}\n    line two 42\n  b: x1y2z3\n"
    assert secrets(text, default_config) == [SECRET, "line two 42", "x1y2z3"]


@pytest.mark.parametrize("header", HEADERS)
def test_block_scalar_with_comment_is_not_sent(gateway: Gateway, header: str) -> None:
    text = HEAD + f"stringData:\n  app-key: {header}\n    {SECRET}\n"
    session = gateway.session()
    out = session.pseudonymize(text)
    assert SECRET not in out
    assert not session.rescan(out)


@pytest.mark.parametrize("value", ["|#nospace", "'a # b'", "plain # trailing"])
def test_non_block_values_keep_their_span(default_config: Config, value: str) -> None:
    text = HEAD + f"stringData:\n  k: {value}\n  b: x1y2z3\n"
    assert secrets(text, default_config) == [value.strip("'"), "x1y2z3"]


def test_block_scalar_header_in_a_config_map_is_ignored(default_config: Config) -> None:
    text = f"apiVersion: v1\nkind: ConfigMap\nstringData:\n  k: | # c\n    {SECRET}\n"
    assert secrets(text, default_config) == []


@pytest.mark.parametrize("comment", ["#", "# a", " #" + " " * 7])
def test_block_scalar_comments_scan_in_linear_time(default_config: Config, comment: str) -> None:
    def scan(text: str) -> object:
        return structured._parse_kubernetes_secrets(text, default_config)

    assert_linear(
        scan,
        lambda n: HEAD + "stringData:\n  k: | " + comment * (n // len(comment)) + "\n    v\n",
        n=1_000_000,
    )
    assert_linear(
        scan,
        lambda n: HEAD + "stringData:\n" + "  k: | # c\n    v1x\n" * (n // 20),
    )

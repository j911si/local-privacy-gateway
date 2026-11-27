"""Normalization folds fullwidth ASCII, skips ignorables inside clusters and stays linear."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from test_regex_linearity import _hard_timeout, assert_linear  # noqa: F401

from privacy_gateway import Gateway
from privacy_gateway.detect.normalize import MAX_CLUSTER, normalized

IBAN = "DE89370400440532013000"
FULLWIDTH_IBAN = "".join(chr(ord(char) + 0xFEE0) for char in IBAN)


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"IBAN {FULLWIDTH_IBAN}", FULLWIDTH_IBAN),
        ("IBAN ＧＢ82ＷＥＳＴ12345698765432", "ＧＢ82ＷＥＳＴ12345698765432"),
        ("IBAN GB82WE͏ST12345698765432", "GB82WE͏ST12345698765432"),
        ("IBAN GB82WE️ST12345698765432", "GB82WE️ST12345698765432"),
        ("Herr Mu\u200b̈ller kommt", "Mu\u200b̈ller"),
    ],
)
def test_disguised_value_is_replaced(gateway: Gateway, text: str, secret: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert secret not in out
    assert "<" in out


def test_fullwidth_folds_one_to_one() -> None:
    assert normalized(f"IBAN {FULLWIDTH_IBAN}") == f"IBAN {IBAN}"


def test_long_cluster_is_kept_without_nfc() -> None:
    cluster = "X" + "̀̕" * MAX_CLUSTER
    assert normalized(cluster) == cluster


def test_alternating_combining_marks_scan_in_linear_time(gateway: Gateway) -> None:
    assert_linear(gateway.scan, lambda n: "X" + "̀̕" * (n // 2), n=40_000)

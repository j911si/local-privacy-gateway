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


def _reference(text: str) -> tuple[str, list[int], list[int]]:
    """The map built one character at a time, without the ASCII fast path."""
    import unicodedata

    from privacy_gateway.detect import normalize

    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    index = 0
    while index < len(text):
        char = text[index]
        if normalize._ignorable(char):
            index += 1
            continue
        cluster, end = [char], index + 1
        while end < len(text):
            follower = text[end]
            if unicodedata.combining(follower):
                cluster.append(follower)
            elif not normalize._ignorable(follower):
                break
            end += 1
        if unicodedata.category(char) == "Zs":
            chunk = " "
        elif len(cluster) > MAX_CLUSTER:
            chunk = "".join(cluster)
        else:
            chunk = unicodedata.normalize("NFC", normalize._fold(char) + "".join(cluster[1:]))
        chars.extend(chunk)
        starts.extend([index] * len(chunk))
        ends.extend([end] * len(chunk))
        index = end
    return "".join(chars), starts, ends


def test_ascii_fast_path_builds_the_same_map() -> None:
    import random
    import string

    from privacy_gateway.detect.normalize import OffsetMap

    rng = random.Random(5)
    alphabet = [*string.printable, "̈", "́", "\u200b", " ", "ü", "Ｄ", "͏", "森"]
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        mapping = OffsetMap(text)
        assert (mapping.text, mapping.starts, mapping.ends) == _reference(text), repr(text)

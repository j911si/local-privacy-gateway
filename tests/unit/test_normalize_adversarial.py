"""Normalization folds fullwidth ASCII, drops ignorables and stays linear; glued IBANs are cut."""

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
        ("IBAN GB82WE\u034fST12345698765432", "GB82WE\u034fST12345698765432"),
        ("IBAN GB82WE\ufe0fST12345698765432", "GB82WE\ufe0fST12345698765432"),
        ("Herr Mu\u200b̈ller kommt", "Mu\u200b̈ller"),
    ],
)
def test_disguised_value_is_replaced(gateway: Gateway, text: str, secret: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert secret not in out
    assert "<" in out


@pytest.mark.parametrize("joiner", ["\ufe0f", "\u034f"])
def test_a_joiner_between_iban_and_word_keeps_the_boundary(gateway: Gateway, joiner: str) -> None:
    out = gateway.session().pseudonymize(f"IBAN {IBAN}{joiner}USD")
    assert IBAN not in out


def test_fullwidth_folds_one_to_one() -> None:
    assert normalized(f"IBAN {FULLWIDTH_IBAN}") == f"IBAN {IBAN}"


def test_long_cluster_is_kept_without_nfc() -> None:
    cluster = "X" + "̀̕" * MAX_CLUSTER
    assert normalized(cluster) == cluster


def test_alternating_combining_marks_normalize_in_linear_time() -> None:
    assert_linear(normalized, lambda n: "X" + "\u0315\u0300" * (n // 2), n=40_000)


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


GLUED = [
    f"IBAN {IBAN}USD",
    f"IBAN {IBAN}\u200bUSD",
    "IBAN DE89 3704 0044 0532 0130 00\u200bUSD",
    "IBAN DE89 3704 0044 0532 0130 00USD",
]


@pytest.mark.parametrize("text", GLUED)
def test_iban_glued_to_a_word_is_replaced(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert "<IBAN_" in out
    assert "0532" not in out


@pytest.mark.parametrize("joiner", ["\ufe0e", "\ufe0f", "\u034f"])
@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("+49 151 2345{j}6789", "2345"),
        ("DE89 3704 0044{j} 0532 0130 00", "0532"),
        ("4111 1111{j} 1111 1111", "1111 1111"),
        ("sk-ant-api03-Q7m3Np5Lr9Tx2Vb4{j}Kd8Hf6Jw1Zc0Xe3Ga5Yu7Io", "Q7m3Np5"),
        ("erika{j}.beispiel@firma-test.de", "erika"),
    ],
)
def test_joiner_inside_a_value_does_not_hide_it(
    gateway: Gateway, joiner: str, value: str, kept: str
) -> None:
    out = gateway.session().pseudonymize(f"Wert: {value.format(j=joiner)} Ende")
    assert kept not in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("IBAN G\U000e0100B82WEST12345698765432 Ende", "IBAN <IBAN_001> Ende"),
        ("Tel +49 151 2345\U000e01ef6789 Ende", "Tel <PHONE_001> Ende"),
    ],
)
def test_supplementary_variation_selector_does_not_hide_a_value(
    gateway: Gateway, text: str, expected: str
) -> None:
    session = gateway.session()
    out = session.pseudonymize(text)
    assert out == expected
    assert session.restore(out, mode="strict").text == text


@pytest.mark.parametrize("expiry", ["05/29", "05.29"])
def test_card_followed_by_an_expiry_is_replaced(gateway: Gateway, expiry: str) -> None:
    out = gateway.session().pseudonymize(f"Zahlung 4111 1111 1111 1111 {expiry} erledigt")
    assert "4111" not in out

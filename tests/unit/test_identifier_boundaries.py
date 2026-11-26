from __future__ import annotations

from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect.patterns import PatternStage

IBAN = "DE89370400440532013000"
CARD = "4111111111111111"
TAX_ID = "65929970489"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def classes_at(text: str, config: Config, value: str) -> list[str]:
    start = text.index(value)
    return [
        f.data_class
        for f in PatternStage().run(text, config, [])
        if (f.span.start, f.span.end) == (start, start + len(value))
    ]


@pytest.mark.parametrize(
    "text",
    [
        f"Kontoauszug_{IBAN}_2026.pdf",
        f"Kontoauszug-{IBAN}-2026.pdf",
        f"Kontoauszug.{IBAN}.pdf",
        f"/home/x/Kontoauszug_{IBAN}_2026.pdf",
        f"IBAN <{IBAN}_001>",
        f"{IBAN}_",
    ],
)
def test_iban_next_to_separators_is_replaced(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert IBAN not in out
    assert "<IBAN_" in out


@pytest.mark.parametrize(
    "text",
    [f"Beleg_{CARD}_x", f"Karte <X_{CARD}_001>", f"scan_{CARD}.pdf", f"/tmp/beleg_{CARD}_2026.png"],
)
def test_card_next_to_underscores_is_replaced(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert CARD not in out
    assert "<CREDIT_CARD_" in out


def test_tax_id_next_to_underscores_is_detected(default_config: Config) -> None:
    text = f"Steuer_{TAX_ID}_2026.pdf"
    assert classes_at(text, default_config, TAX_ID) == ["TAX_ID"]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Kontoauszug_DE89370400440532013001_2026.pdf", "DE89370400440532013001"),
        ("build_4111111111111112_x", "4111111111111112"),
        ("run_id_7392018465537281_done", "7392018465537281"),
        ("Steuer_65929970488_2026.pdf", "65929970488"),
        (f"X{IBAN}", IBAN),
        (f"IBAN{IBAN}", IBAN),
        (f"id{CARD}", CARD),
        (f"Karte{CARD[:-1]}2", CARD[:-1] + "2"),
        ("Karte1234567812345670", "1234567812345670"),
        (f"discard_{CARD}x", CARD),
    ],
)
def test_wrong_check_digits_and_glued_letters_stay(
    default_config: Config, text: str, value: str
) -> None:
    assert classes_at(text, default_config, value) == []


@pytest.mark.parametrize(
    "text",
    [f"x{IBAN}", f"Konto{IBAN}", f"kontoauszug{IBAN}.pdf", f"ibanäDE{IBAN[2:]}"],
)
def test_iban_glued_to_lowercase_letters_is_replaced(gateway: Gateway, text: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert IBAN not in out
    assert "<IBAN_" in out


@pytest.mark.parametrize(
    ("text", "card"),
    [
        (f"Karte{CARD}", CARD),
        (f"KARTE{CARD}", CARD),
        (f"visa{CARD}.pdf", CARD),
        ("mastercard5555555555554444", "5555555555554444"),
        ("Kreditkarte378282246310005", "378282246310005"),
    ],
)
def test_card_glued_to_a_card_word_is_replaced(gateway: Gateway, text: str, card: str) -> None:
    out = gateway.session().pseudonymize(text)
    assert card not in out
    assert "<CREDIT_CARD_" in out

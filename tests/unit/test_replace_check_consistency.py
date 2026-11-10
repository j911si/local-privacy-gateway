"""Replacing and leak checking must agree: a value the session knows never blocks a later text."""

from __future__ import annotations

import pytest

from privacy_gateway.api import Gateway
from privacy_gateway.config import Config
from privacy_gateway.model import LeakageError

# (introducing text, the value's digits or letters to look for afterwards)
SEEDS = {
    "phone": ("Tel. +49 30 12345678", "12345678"),
    "phone_local": ("Mobil 0171 2345678", "2345678"),
    "account_short": ("Konto 4711", "4711"),
    "account_long": ("Kundennummer 98765432", "98765432"),
    "iban": ("IBAN DE89 3704 0044 0532 0130 00", "0532013000"),
    "email": ("Mail an anna.berg@example-firma.de", "anna.berg"),
    "name": ("Brief an Anna Berg", "Berg"),
}

PHONE_VARIANTS = [
    "+49 30 12345678",
    "+4930 12345678",
    "+493012345678",
    "0049 30 12345678",
    "004930 12345678",
    "030 12345678",
    "030/12345678",
    "(030) 12345678",
    "030 / 1234 5678",
    "x+49 30 12345678y",
    "tel:+4930-12345678",
]
NUMBER_VARIANTS = {
    "account_short": [
        "4711",
        "AB4711CD",
        "ab4711",
        "4711ab",
        "14711",
        "47112",
        "id=4711;",
        "'4711'",
    ],
    "account_long": [
        "98765432",
        "AB98765432CD",
        "098765432",
        "987654321",
        "9876 5432",
        "98-765-432",
    ],
    "iban": [
        "DE89 3704 0044 0532 0130 00",
        "DE89370400440532013000",
        "de89 3704 0044 0532 0130 00",
        "xDE89370400440532013000x",
        "0532013000",
    ],
}
NUMBER_VARIANTS["email"] = [
    "anna.berg@example-firma.de",
    "ANNA.BERG@EXAMPLE-FIRMA.DE",
    "mailto:anna.berg@example-firma.de",
    "<anna.berg@example-firma.de>",
    "anna.berg",
    "anna.berg_old",
    "x-anna.berg@host",
    "anna.berg@example-firma.de.",
]
NUMBER_VARIANTS["name"] = [
    "Anna Berg",
    "Berg",
    "Bergs",
    "ANNA BERG",
    "anna_berg",
    "Anna-Berg",
    "/home/anna_berg/x",
    "Annas Buch",
]
FRAMES = [
    "{v}",
    "Wert: {v}.",
    '{{"k": "{v}"}}',
    "echo '{v}' | grep x",
    "/tmp/{v}/file",
    "x={v}&y=1",
    "({v})",
]


def _cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    for seed in ("phone", "phone_local"):
        cases += [(seed, v) for v in PHONE_VARIANTS]
    for seed, variants in NUMBER_VARIANTS.items():
        cases += [(seed, v) for v in variants]
    return cases


@pytest.mark.parametrize(("seed", "variant"), _cases())
@pytest.mark.parametrize("frame", FRAMES)
def test_a_known_value_in_any_spelling_never_blocks_a_later_text(
    default_config: Config, seed: str, variant: str, frame: str
) -> None:
    intro, _ = SEEDS[seed]
    later = frame.format(v=variant)
    with Gateway(default_config) as gateway:
        session = gateway.session()
        session.pseudonymize(intro)
        try:
            session.pseudonymize(later)
        except LeakageError as error:
            pytest.fail(f"blocked: {[(x.kind, x.data_class) for x in error.leaks]}")

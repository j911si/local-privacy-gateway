"""The digit index stores only starts that can match, and a regrouped number is found."""

from __future__ import annotations

import tracemalloc
from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect.session import KnownMatcher

EMAILS = {f"a{'1' * k}@firma-test.de": ("EMAIL", f"<EMAIL_{k:03d}>") for k in range(6, 38)}


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def _peak_mib(matcher: KnownMatcher, text: str) -> float:
    tracemalloc.start()
    try:
        matcher.find(text)
        return tracemalloc.get_traced_memory()[1] / 2**20
    finally:
        tracemalloc.stop()


def test_digits_split_by_letters_store_no_starts(default_config: Config) -> None:
    # ponytail: 32 known addresses ending in 6..37 ones made `1x` * n store ~32 n starts.
    matcher = KnownMatcher(EMAILS, default_config.registry)
    assert _peak_mib(matcher, "1x" * 50_000) < 20


def test_a_known_address_is_still_found(default_config: Config) -> None:
    matcher = KnownMatcher(EMAILS, default_config.registry)
    text = "Mail an a1111111@firma-test.de bitte"
    assert [text[span.start : span.end] for span, _ in matcher.find(text)] == [
        "a1111111@firma-test.de"
    ]


@pytest.mark.parametrize("text", ["12 Positionen; 1212 1212", "9912 1212 1212"])
def test_regrouped_number_next_to_other_digits_is_found(gateway: Gateway, text: str) -> None:
    session = gateway.session()
    session.pseudonymize("Kundennummer: 12121212")
    assert "1212 1212" not in session.pseudonymize(text)


def test_a_long_digit_run_stays_linear(default_config: Config) -> None:
    from test_regex_linearity import assert_linear

    matcher = KnownMatcher({"111111": ("CUSTOMER_ID", "<X_001>")}, default_config.registry)
    assert_linear(matcher.find, lambda n: "1" * n, n=20_000)


def test_regrouped_number_after_another_number_is_found(gateway: Gateway) -> None:
    session = gateway.session()
    session.pseudonymize("Kundennummer: 12121212")
    assert "1212 1212" not in session.pseudonymize("12 Positionen; 1212 1212")

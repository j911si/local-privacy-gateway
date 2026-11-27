"""A redacted value inside a tokenized finding never reaches the vault or a restored text."""

from __future__ import annotations

import gc
import signal
import time
from collections.abc import Iterator
from types import FrameType

import pytest

from privacy_gateway import Gateway
from privacy_gateway.pseudonymize import pseudonymize_text

PIN = "482913"
PATH_TEXT = f"PIN: {PIN}. Link: https://bank.example/pin/{PIN}/confirm"
QUERY_PIN = "4711"
QUERY_TEXT = f"Link: https://bank.example/login?pin={QUERY_PIN}&lang=de"
SCALE_LIMIT_SECONDS = 60
SCALE_FACTOR = 8


def _stored_values(session_id: str) -> list[str]:
    with Gateway() as fresh:
        return [entry.value for entry in fresh.vault.load(session_id).values()]


def test_a_pin_inside_a_url_path_is_not_stored(gateway: Gateway) -> None:
    session = gateway.session("pin-path")
    out = session.pseudonymize(PATH_TEXT)
    assert PIN not in out
    assert "<PIN_REDACTED>" in out and "<URL_001>" in out
    assert all(PIN not in value for value in _stored_values(session.session_id))
    with Gateway() as fresh:
        restored = fresh.restore(out, session.session_id).text
    assert PIN not in restored
    assert "https://bank.example/pin/<PIN_REDACTED>/confirm" in restored


def test_a_pin_query_parameter_is_not_stored(gateway: Gateway) -> None:
    session = gateway.session("pin-query")
    out = session.pseudonymize(QUERY_TEXT)
    assert QUERY_PIN not in out
    assert all(QUERY_PIN not in value for value in _stored_values(session.session_id))
    restored = session.restore_text(out)
    assert restored == "Link: https://bank.example/login?pin=<PIN_REDACTED>&lang=de"


def test_the_same_url_keeps_its_token_across_calls(gateway: Gateway) -> None:
    session = gateway.session("pin-repeat")
    first = session.pseudonymize(QUERY_TEXT)
    again = session.pseudonymize_many([QUERY_TEXT + " ", f"Nochmal: {QUERY_TEXT}"])
    assert all("<URL_001>" in out for out in [first, *again])
    assert len(_stored_values(session.session_id)) == 1


@pytest.mark.parametrize(
    "text",
    [
        "Link: https://bank.example/list?page=1234&lang=de",
        "Link: https://bank.example/list?pinned=true&id=5678",
        "Link: https://bank.example/run?spin=3456",
        "Link: https://bank.example/v1.2.3/release-2024-11-27/build",
    ],
)
def test_urls_without_a_pin_restore_unchanged(gateway: Gateway, text: str) -> None:
    session = gateway.session("no-pin")
    out = session.pseudonymize(text)
    assert "_REDACTED>" not in out
    assert session.restore_text(out) == text
    assert all("_REDACTED>" not in value for value in _stored_values(session.session_id))


@pytest.fixture
def time_limit() -> Iterator[None]:
    def expired(signum: int, frame: FrameType | None) -> None:
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(SCALE_LIMIT_SECONDS)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _many_pins(count: int) -> str:
    return "\n".join(
        f"PIN: {100000 + index}. Link: https://bank.example/pin/{100000 + index}/c?pin="
        f"{200000 + index}"
        for index in range(count)
    )


def _seconds(gateway: Gateway, key: str, text: str) -> float:
    session = gateway.session(key)
    started = time.perf_counter()
    out = session.pseudonymize(text)
    elapsed = time.perf_counter() - started
    assert "100000" not in out and "200000" not in out
    return elapsed


def test_masking_scales_linearly(gateway: Gateway, time_limit: None) -> None:
    small = min(_seconds(gateway, f"scale-small-{run}", _many_pins(100)) for run in range(2))
    large = min(_seconds(gateway, f"scale-large-{run}", _many_pins(400)) for run in range(2))
    print(f"masking: n=100 {small:.3f}s, n=400 {large:.3f}s, factor {large / small:.2f}")
    assert large / small < SCALE_FACTOR


def _masking_seconds(gateway: Gateway, key: str, values: int, lines: int) -> float:
    """Time of the masking step alone: `values` learned passwords, `lines` URLs to store."""
    session = gateway.session(key)
    learned = [f"Pw{index:06d}!x" for index in range(values)]
    for value in learned:
        session._redacted[value] = "PASSWORD"
    text = "\n".join(
        f"Link: https://bank.example/u/{learned[index % values]}/r{index}?pin={1000 + index % 9000}"
        for index in range(lines)
    )
    report = gateway._pipeline.run(text)
    fresh = pseudonymize_text(text, report, gateway.config, counters={}).assignments
    gc.collect()
    gc.disable()
    try:
        started = time.perf_counter()
        masks = session._redacted_spans(text, report, fresh, list(learned))
        elapsed = time.perf_counter() - started
    finally:
        gc.enable()
    assert len(masks) == len(fresh) == lines
    return elapsed


def test_masking_cost_does_not_grow_with_the_number_of_redacted_values(
    gateway: Gateway, time_limit: None
) -> None:
    few = min(_masking_seconds(gateway, f"k-small-{run}", 2_000, 2_000) for run in range(3))
    many = min(_masking_seconds(gateway, f"k-large-{run}", 8_000, 2_000) for run in range(3))
    print(f"masking by values: k=2000 {few:.3f}s, k=8000 {many:.3f}s, factor {many / few:.2f}")
    assert many / few < SCALE_FACTOR


def test_masking_cost_grows_linearly_with_the_text(gateway: Gateway, time_limit: None) -> None:
    short = min(_masking_seconds(gateway, f"l-small-{run}", 500, 2_000) for run in range(3))
    long = min(_masking_seconds(gateway, f"l-large-{run}", 500, 8_000) for run in range(3))
    print(f"masking by text: n=2000 {short:.3f}s, n=8000 {long:.3f}s, factor {long / short:.2f}")
    assert long / short < SCALE_FACTOR

"""The per-session result cache serves repeated texts without running the pipeline."""

from __future__ import annotations

import pytest

from privacy_gateway import Gateway
from privacy_gateway.api import RESULT_CACHE_SIZE
from privacy_gateway.detect import Pipeline

TEXT = "Bitte an Frau Anna Meier, IBAN DE89370400440532013000, senden."


@pytest.fixture
def counted_pipeline(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls = [0]
    original = Pipeline.run

    def counting(self: Pipeline, *args: object, **kwargs: object) -> object:
        calls[0] += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Pipeline, "run", counting)
    return calls


def test_repeated_text_is_served_from_the_cache(
    gateway: Gateway, counted_pipeline: list[int]
) -> None:
    session = gateway.session("cache")
    first = session.pseudonymize(TEXT)
    after_first = counted_pipeline[0]
    assert after_first > 0
    assert session.pseudonymize(TEXT) == first
    assert counted_pipeline[0] == after_first


def test_a_different_text_still_runs_the_pipeline(
    gateway: Gateway, counted_pipeline: list[int]
) -> None:
    session = gateway.session("cache")
    session.pseudonymize(TEXT)
    after_first = counted_pipeline[0]
    session.pseudonymize("Anruf von Herrn Bernd Klein aus Hamburg.")
    assert counted_pipeline[0] > after_first


def test_the_cache_is_bounded(gateway: Gateway, counted_pipeline: list[int]) -> None:
    session = gateway.session("cache")
    for index in range(RESULT_CACHE_SIZE + 1):
        session.pseudonymize(f"Vorgang {index} ohne personenbezogene Daten.")
    after_fill = counted_pipeline[0]
    session.pseudonymize("Vorgang 0 ohne personenbezogene Daten.")
    assert counted_pipeline[0] > after_fill


def test_pseudonymize_many_reuses_the_cache_across_calls(
    gateway: Gateway, counted_pipeline: list[int]
) -> None:
    session = gateway.session("cache")
    texts = [TEXT, "Rechnung an Bernd Klein, Kundennummer 4711."]
    first = session.pseudonymize_many(texts)
    after_first = counted_pipeline[0]
    assert session.pseudonymize_many(texts) == first
    assert counted_pipeline[0] == after_first

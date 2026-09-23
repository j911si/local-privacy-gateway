from __future__ import annotations

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.model import DetectionReport, LeakageError
from privacy_gateway.pseudonymize import PseudonymizedText, pseudonymize_text

IBAN = "DE89370400440532013000"
TEXT_A = f"Sehr geehrte Frau Müller, Ihre IBAN {IBAN} ist vorgemerkt."
TEXT_B = "Müller hat mit Thomas Schmidt gesprochen."
TEXT_C = f"Die Überweisung auf {IBAN} ist raus."
TEXT_D = "Auch Petra Neumann ist beteiligt."
PERSON_TOKEN = "<PERSON_FEMALE_001>"
IBAN_TOKEN = "<IBAN_001>"


def test_tokens_continue_across_calls_of_one_session(gateway: Gateway) -> None:
    session = gateway.session("conversation-1")

    first = session.pseudonymize(TEXT_A)
    second = session.pseudonymize(TEXT_B)
    third = session.pseudonymize(TEXT_C)

    assert first == f"Sehr geehrte Frau {PERSON_TOKEN}, Ihre IBAN {IBAN_TOKEN} ist vorgemerkt."
    assert second == f"{PERSON_TOKEN} hat mit <PERSON_002> gesprochen."
    assert third == f"Die Überweisung auf {IBAN_TOKEN} ist raus."
    assert set(session.entries()) == {PERSON_TOKEN, IBAN_TOKEN, "<PERSON_002>"}
    assert session.restore_text(second) == TEXT_B


def test_leakage_on_a_later_call_keeps_the_earlier_mappings(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = gateway.session("conversation-1")
    session.pseudonymize_many([TEXT_A, TEXT_B, TEXT_C])
    before = dict(session.entries())

    def leaking(
        text: str,
        report: DetectionReport,
        config: Config,
        *,
        counters: dict[str, int] | None = None,
    ) -> PseudonymizedText:
        real = pseudonymize_text(text, report, config, counters=counters)
        return PseudonymizedText(text=text, assignments=real.assignments)

    monkeypatch.setattr("privacy_gateway.api.pseudonymize_text", leaking)
    with pytest.raises(LeakageError):
        session.pseudonymize(TEXT_D)

    assert set(session.entries()) == set(before)
    for token, entry in before.items():
        assert session.entries()[token].surface_forms == entry.surface_forms
    monkeypatch.undo()
    assert session.pseudonymize(TEXT_C) == f"Die Überweisung auf {IBAN_TOKEN} ist raus."


def test_a_reopened_session_key_keeps_the_mapping(gateway: Gateway) -> None:
    gateway.session("conversation-1").pseudonymize(TEXT_A)

    reopened = gateway.session("conversation-1")

    assert reopened.pseudonymize(TEXT_B) == f"{PERSON_TOKEN} hat mit <PERSON_002> gesprochen."
    assert reopened.restore_text(PERSON_TOKEN) == "Müller"


def test_a_different_session_key_starts_at_001_again(gateway: Gateway) -> None:
    gateway.session("conversation-1").pseudonymize_many([TEXT_A, TEXT_B])

    other = gateway.session("conversation-2")

    assert other.pseudonymize(TEXT_A) == (
        f"Sehr geehrte Frau {PERSON_TOKEN}, Ihre IBAN {IBAN_TOKEN} ist vorgemerkt."
    )


def test_session_without_key_is_independent(gateway: Gateway) -> None:
    first = gateway.session()
    second = gateway.session()

    assert first.session_id != second.session_id
    assert first.pseudonymize(TEXT_B) == second.pseudonymize(TEXT_B)


def test_a_full_name_around_a_known_last_name_is_tokenized_as_a_whole(gateway: Gateway) -> None:
    session = gateway.session("conversation-1")
    session.pseudonymize(TEXT_A)

    result = session.pseudonymize("Anna Müller ruft an.")

    assert result == f"{PERSON_TOKEN} ruft an."
    assert set(session.entries()) == {PERSON_TOKEN, IBAN_TOKEN}


def test_a_known_full_name_keeps_its_token_for_the_bare_last_name(gateway: Gateway) -> None:
    session = gateway.session("conversation-2")
    first = session.pseudonymize("Anna Müller ruft an.")

    second = session.pseudonymize("Bitte Anna Müller zurückrufen.")

    assert first == "<PERSON_001> ruft an."
    assert second == "Bitte <PERSON_001> zurückrufen."
    assert set(session.entries()) == {"<PERSON_001>"}


def test_the_same_iban_in_another_spelling_keeps_its_token(gateway: Gateway) -> None:
    session = gateway.session("conversation-6")
    first = session.pseudonymize(f"Ihre IBAN {IBAN} ist vorgemerkt.")

    second = session.pseudonymize("Konto DE89 3704 0044 0532 0130 00 bitte prüfen.")

    assert first == f"Ihre IBAN {IBAN_TOKEN} ist vorgemerkt."
    assert second == f"Konto {IBAN_TOKEN} bitte prüfen."
    assert set(session.entries()) == {IBAN_TOKEN}


def test_a_url_around_a_known_hostname_is_tokenized_as_a_whole(gateway: Gateway) -> None:
    session = gateway.session("conversation-3")
    first = session.pseudonymize("Bitte intranet.example.com prüfen.")

    second = session.pseudonymize("Siehe https://intranet.example.com/kunden/4711 dazu.")

    assert first == "Bitte <FQDN_001> prüfen."
    assert "intranet.example.com" not in second
    assert "4711" not in second
    assert second == "Siehe <URL_001> dazu."


def test_pseudonymize_many_shares_counters_in_order(gateway: Gateway) -> None:
    session = gateway.session("conversation-1")

    results = session.pseudonymize_many([TEXT_A, TEXT_B, TEXT_C])

    assert results[1] == f"{PERSON_TOKEN} hat mit <PERSON_002> gesprochen."
    assert results[2] == f"Die Überweisung auf {IBAN_TOKEN} ist raus."

"""The generic identifier rule next to the marker rule: precedence and shared entities."""

from __future__ import annotations

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect import Pipeline
from privacy_gateway.pseudonymize import pseudonymize_text

TICKET = "AK-2026-0917"


def classes_at(text: str, config: Config) -> dict[str, str]:
    report = Pipeline(config).run(text)
    return {text[f.span.start : f.span.end]: f.data_class for f in report.findings}


def test_a_marked_id_stays_a_ticket_id(default_config: Config) -> None:
    text = f"Ticket {TICKET} wurde eskaliert."
    assert classes_at(text, default_config)[TICKET] == "TICKET_ID"


def test_a_bare_id_becomes_a_generic_id(default_config: Config) -> None:
    text = f"Der Vorgang {TICKET} ist noch offen."
    assert classes_at(text, default_config)[TICKET] == "GENERIC_ID"


def test_marked_and_bare_occurrence_share_one_token(default_config: Config) -> None:
    text = f"Ticket: {TICKET}.\nSpäter wurde {TICKET} geschlossen."
    report = Pipeline(default_config).run(text)

    result = pseudonymize_text(text, report, default_config)

    assert TICKET not in result.text
    assert len(result.assignments) == 1
    assert result.text.count(result.assignments[0].token) == 2


def test_a_bare_id_keeps_the_token_of_the_earlier_call(gateway: Gateway) -> None:
    session = gateway.session("ticket-conversation")

    first = session.pseudonymize(f"Ticket: {TICKET}.")
    second = session.pseudonymize(f"Ticketnummer {TICKET}.. wurde zusammengefasst.")

    assert first == "Ticket: <TICKET_ID_001>."
    assert second == "Ticketnummer <TICKET_ID_001>.. wurde zusammengefasst."

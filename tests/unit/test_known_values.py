"""Replacing and checking share one search for known values: what the check finds is replaced."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from privacy_gateway.api import Gateway, GatewaySession
from privacy_gateway.config import load_config
from privacy_gateway.detect.session import known_occurrences
from privacy_gateway.model import Span
from privacy_gateway.tokens import ANY_TOKEN


@pytest.fixture(scope="module")
def gateway(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Gateway]:
    base: Path = tmp_path_factory.mktemp("known")
    env = {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(base / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(base / "vault.key"),
        "PGW_AUDIT_LOG": str(base / "audit.jsonl"),
    }
    with Gateway(load_config(env=env)) as gw:
        yield gw


def _seeded(gateway: Gateway, value: str, data_class: str) -> GatewaySession:
    session_id = gateway.vault.create_session("", gateway.config.hash())
    label = gateway.config.registry.label_for(data_class)
    gateway.vault.store(session_id, f"<{label}_001>", data_class, value, [value], {})
    return GatewaySession(gateway, session_id)


def _outside_tokens(session: GatewaySession, output: str) -> list[Span]:
    known = {
        form: (entry.data_class, token)
        for token, entry in session.entries().items()
        for form in [entry.value, *entry.surface_forms]
    }
    tokens = [Span(m.start(), m.end()) for m in ANY_TOKEN.finditer(output)]
    registry = session._gateway.config.registry
    return [
        span
        for span, _ in known_occurrences(output, known, registry)
        if not any(token.contains(span) for token in tokens)
    ]


@pytest.mark.parametrize(
    ("value", "data_class", "later"),
    [
        ("anna1985", "PERSON_USERNAME", "joanna1985"),
        ("anna1985", "PERSON_USERNAME", "anna1985x"),
        ("host01a", "HOSTNAME", "myhost01a"),
        ("Müller", "PERSON_LAST_NAME", "Herr Müller schrieb"),
        ("Anna\u200bBerg", "PERSON_FULL_NAME", "Anna\u200bBerg kam"),
        ("Anna\u200bBerg", "PERSON_FULL_NAME", "AnnaBerg kam"),
    ],
)
def test_the_four_cases_are_replaced_and_the_value_is_gone(
    gateway: Gateway, value: str, data_class: str, later: str
) -> None:
    session = _seeded(gateway, value, data_class)
    output = session.pseudonymize(later)
    assert not _outside_tokens(session, output)
    plain = value.replace("\u200b", "").replace("ü", "ü")
    for spelling in (value, plain):
        assert spelling not in output
    assert "<" in output


def test_the_replaced_output_still_restores_to_the_original_spelling(gateway: Gateway) -> None:
    session = _seeded(gateway, "anna1985", "PERSON_USERNAME")
    output = session.pseudonymize("joanna1985")
    assert session.restore(output).text == "joanna1985"


def _shapes() -> st.SearchStrategy[tuple[str, str]]:
    letters = st.text(alphabet="abcdefghklmnorst", min_size=3, max_size=7)
    digits = st.text(alphabet="0123456789", min_size=1, max_size=4)
    name = letters.map(str.capitalize)
    return st.one_of(
        st.tuples(st.just("PERSON_LAST_NAME"), name),
        st.tuples(st.just("CUSTOMER_NAME"), st.tuples(name, name).map(" ".join)),
        st.tuples(st.just("PERSON_USERNAME"), st.tuples(letters, digits).map("".join)),
        st.tuples(st.just("HOSTNAME"), st.tuples(letters, digits, st.just("a")).map("".join)),
        st.tuples(st.just("CUSTOMER_ID"), st.text(alphabet="0123456789", min_size=4, max_size=12)),
        st.tuples(st.just("PERSON_USERNAME"), st.tuples(letters, st.sampled_from("-_."), letters)
                  .map("".join)),
    )


AROUND = st.sampled_from(
    ["{v}", "x{v}", "{v}x", "7{v}", "{v}7", "_{v}", "{v}_", "-{v}", "{v}-", ".{v}", "{v}.",
     "/{v}/", "<EMAIL_001>{v}", "{v}<EMAIL_002>", "Wert: {v}.", "a\n{v}\tb"]
)
CASES = st.sampled_from([str, str.upper, str.lower])
GAPS = st.sampled_from([" ", "\n", "\t", " ", "  "])


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(shape=_shapes(), around=AROUND, case=CASES, gap=GAPS)
def test_whatever_the_check_would_report_is_replaced(
    gateway: Gateway, shape: tuple[str, str], around: str, case: object, gap: str
) -> None:
    data_class, value = shape
    session = _seeded(gateway, value, data_class)
    variant = re.sub(r" ", gap, case(value))  # type: ignore[operator]
    output = session.pseudonymize(around.format(v=variant))
    assert not _outside_tokens(session, output)

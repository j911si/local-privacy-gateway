from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect.structured import StructuredStage
from privacy_gateway.model import Finding

TOKEN_RE = re.compile(r"<[A-Z][A-Z_]*_\d{3}>")
URL = "https://example.com/docs/page"


def url_values(text: str, config: Config) -> list[str]:
    findings: list[Finding] = StructuredStage().run(text, config, [])
    return [
        text[f.span.start : f.span.end] for f in findings if f.data_class in {"URL", "INTERNAL_URL"}
    ]


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    monkeypatch.setenv("PGW_VAULT_DB", str(tmp_path / "vault" / "vault.db"))
    monkeypatch.setenv("PGW_VAULT_KEY_FILE", str(tmp_path / "vault" / "vault.key"))
    monkeypatch.setenv("PGW_AUDIT_LOG", str(tmp_path / "audit" / "audit.jsonl"))
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize("mark", [",", ".", ";", ":", "!", "?", "..."])
def test_trailing_punctuation_is_not_part_of_the_url(default_config: Config, mark: str) -> None:
    text = f"Siehe {URL}{mark} danach weiter"
    assert url_values(text, default_config) == [URL]


def test_query_url_with_trailing_period(default_config: Config) -> None:
    text = "Aufruf: https://example.com/search?q=abc&page=2."
    assert url_values(text, default_config) == ["https://example.com/search?q=abc&page=2"]


def test_path_ending_in_file_extension_stays_complete(default_config: Config) -> None:
    text = "Datei unter https://example.com/files/datei.html liegt bereit"
    assert url_values(text, default_config) == ["https://example.com/files/datei.html"]


def test_file_extension_followed_by_period(default_config: Config) -> None:
    text = "Datei unter https://example.com/files/datei.html."
    assert url_values(text, default_config) == ["https://example.com/files/datei.html"]


def test_scheme_only_match_is_skipped(default_config: Config) -> None:
    assert url_values("Nur https://. am Ende", default_config) == []


def test_same_url_gets_one_token_regardless_of_following_mark(gateway: Gateway) -> None:
    text = f"Erst {URL}, dann {URL}. Und {URL}; sowie {URL}: oder {URL}! wirklich {URL}?"
    result = gateway.pseudonymize(text)
    url_tokens = {t for t in TOKEN_RE.findall(result.text) if "URL" in t}
    assert len(url_tokens) == 1
    assert URL not in result.text


@pytest.mark.parametrize("mark", [",", ".", ";", ":", "!", "?"])
def test_round_trip_is_exact(gateway: Gateway, mark: str) -> None:
    text = f"Bitte {URL}{mark} prüfen und https://example.com/a?x=1{mark}"
    result = gateway.pseudonymize(text)
    assert gateway.restore(result.text, result.session_id).text == text


def test_model_comma_after_token_restores_to_a_single_comma(gateway: Gateway) -> None:
    result = gateway.pseudonymize(f"Die Seite {URL} ist neu")
    token = next(t for t in TOKEN_RE.findall(result.text) if "URL" in t)
    answer = f"Ich habe {token}, wie gewünscht, geprüft."
    restored = gateway.restore(answer, result.session_id, mode="lenient")
    assert restored.text == f"Ich habe {URL}, wie gewünscht, geprüft."
    assert ",," not in restored.text

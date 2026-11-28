from __future__ import annotations

import pytest

from privacy_gateway.api import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect.public import is_public_reference


@pytest.mark.parametrize(
    "value",
    [
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2020-12/schema",
        "json-schema.org",
        "https://www.w3.org/2001/XMLSchema",
        "user@example.com",
        "https://example.org/path?x=1",
        "api.example.net",
        "Name@Mail.EXAMPLE.COM",
    ],
)
def test_reserved_and_schema_references_are_public(value: str) -> None:
    assert is_public_reference(value)


@pytest.mark.parametrize(
    "value",
    [
        "https://intern.kanarie-firma.example/api",
        "hg.wolkenstein@kanarie-firma.example",
        "https://example.com.evil.test/x",
        "https://json-schema.org.evil.test/x",
        "https://evil.test/?u=json-schema.org",
        "user@json-schema.org.attacker.test",
        "https://notexample.com/x",
        "DE89370400440532013000",
        "",
    ],
)
def test_other_values_are_not_public(value: str) -> None:
    assert not is_public_reference(value)


def test_rescan_skips_public_references_but_keeps_real_findings(default_config: Config) -> None:
    text = (
        '{"$schema": "http://json-schema.org/draft-07/schema#", '
        '"to": "kontakt@example.com", "real": "https://intern.kanarie-firma.example/kunden"}'
    )
    with Gateway(default_config) as gateway:
        leaks = gateway.session("pub").rescan(text)
    spans = [text[leak.start : leak.end] for leak in leaks]
    assert any("kanarie-firma" in span for span in spans)
    assert not any("json-schema" in span or "example.com" in span for span in spans)

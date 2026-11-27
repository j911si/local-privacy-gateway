"""Short Basic credentials in an inline Authorization header are redacted."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize("value", ["dTpwdw==", "dTpw", "YTpiYw=="])
def test_short_basic_is_redacted(gateway: Gateway, value: str) -> None:
    out = gateway.session().pseudonymize(f"curl -H 'Authorization: Basic {value}' x")
    assert value not in out


@pytest.mark.parametrize("value", ["abcd", "aGFsbG8="])
def test_base64_without_colon_stays(gateway: Gateway, value: str) -> None:
    text = f"curl -H 'Authorization: Basic {value}' x"
    assert value in gateway.session().pseudonymize(text)

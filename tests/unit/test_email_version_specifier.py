"""A package version specifier is not an e-mail address; real addresses stay findings."""

from __future__ import annotations

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import Pipeline


def emails(text: str, config: Config) -> list[str]:
    return [
        text[f.span.start : f.span.end]
        for f in Pipeline(config).run(text).findings
        if f.data_class == "EMAIL"
    ]


@pytest.mark.parametrize(
    "text", ["Import `react@18.2.0` from the CDN", "pin lodash@4.17 and vue@3.5.13", "x@1.2"]
)
def test_version_specifier_is_not_an_email(text: str, default_config: Config) -> None:
    # Claude Code's Artifact tool text names packages like this; it blocked interactive sessions.
    assert emails(text, default_config) == []


@pytest.mark.parametrize(
    "address",
    ["erika.beispiel@firma-test.de", "anna@10.0.0.5", "ops@build9.example9.io", "a@b.c9"],
)
def test_addresses_are_still_found(address: str, default_config: Config) -> None:
    assert emails(f"Kontakt {address} bitte", default_config) == [address]


@pytest.mark.parametrize("address", ["ERIKA@10.0.1", "erika@١٠.٠.١", "Erika.M@1.2"])
def test_address_shapes_outside_a_package_spec_are_found(
    address: str, default_config: Config
) -> None:
    assert emails(f"Kontakt {address} bitte", default_config) == [address]

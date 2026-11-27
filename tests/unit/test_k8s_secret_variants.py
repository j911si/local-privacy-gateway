"""Kubernetes Secret values are found with comments, quoted keys and CRLF line ends."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from test_regex_linearity import _hard_timeout, assert_linear  # noqa: F401

from privacy_gateway import Gateway
from privacy_gateway.detect import structured

SECRET = "zQ7dK9pLmN3x"


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


@pytest.mark.parametrize(
    "manifest",
    [
        f"kind: Secret # demo\nstringData:\n  app.key: |2-\n    {SECRET}\n",
        f"kind: Secret\nstringData: # demo\n  app.key: {SECRET}\n",
        f'kind: Secret\nstringData:\n  "app.key": {SECRET}\n',
        f"kind: Secret\nstringData:\n  'app.key': {SECRET}\n",
        f"kind: Secret\r\nstringData:\r\n  app.key: {SECRET}\r\n",
        f"kind: Secret\r\ndata:\r\n  app.key: |\r\n    {SECRET}\r\n",
        f'"kind": "Secret"\n"stringData":\n  "app.key": "{SECRET}"\n',
    ],
)
def test_secret_value_is_redacted(gateway: Gateway, manifest: str) -> None:
    out = gateway.session().pseudonymize(manifest)
    assert SECRET not in out


def test_config_map_stays_untouched(gateway: Gateway) -> None:
    manifest = "kind: ConfigMap # demo\r\ndata:\r\n  mode: fast\r\n"
    assert gateway.session().pseudonymize(manifest) == manifest


@pytest.mark.parametrize(
    "line", ["  app.key: " + "a " * 4 + "#", '  "' + "k" * 8, "kind: Secret #" + " " * 8]
)
def test_kubernetes_rules_stay_linear(line: str) -> None:
    for pattern in (structured.K8S_SECRET_RE, structured.K8S_ENTRY_RE, structured.K8S_DATA_RE):
        assert_linear(
            lambda text, pattern=pattern: list(pattern.finditer(text)),
            lambda n, line=line: line * (n // len(line)),
        )

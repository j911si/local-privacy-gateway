"""Provider keys with a fixed prefix next to `_` are found; identifiers stay free (R2-01#4)."""

from __future__ import annotations

import random
import re
from collections.abc import Iterator

import pytest

from privacy_gateway import Gateway
from privacy_gateway.config import Config
from privacy_gateway.detect import patterns
from privacy_gateway.detect.patterns import PatternStage
from privacy_gateway.detect.runs import JWT_PATTERN, jwt_finditer
from test_regex_linearity import _hard_timeout, assert_linear  # noqa: F401

SAMPLES = {
    "AWS_ACCESS_KEY": "AKIAZ7Q3M5N2B8K4R6T1",
    "AWS_ACCESS_KEY_ASIA": "ASIAZ7Q3M5N2B8K4R6T1",
    "GCP_CREDENTIAL": "AIzaSy7Qm3Np5Lr9Tx2Vb4Kd8Hf6Jw1Zc0Xe3Ga",
    "GITHUB_TOKEN": "ghp_Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw1Zc0Xe3Ga5Yu",
    "GITHUB_TOKEN_PAT": "github_pat_" + ("Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw1Zc0Xe3Ga5Yu" * 3)[:82],
    "GITLAB_TOKEN": "glpat-Q7m3Np5Lr9Tx2Vb4Kd8Hf",
    "PERSONAL_ACCESS_TOKEN": "xoxb-1234567890-Q7m3Np5Lr9Tx",
    "ANTHROPIC_API_KEY": "sk-ant-api03-Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw1Zc0Xe3Ga5Yu7Io",
    "OPENAI_API_KEY": "sk-proj-Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw",
    "STRIPE_SECRET_KEY": "sk_live_Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw",
    "JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vMTIzIn0.Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw",
}
CHANGED = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "STRIPE_SECRET_KEY", "JWT", "AWS_ACCESS_KEY",
    "GCP_CREDENTIAL", "GITHUB_TOKEN", "GITLAB_TOKEN", "PERSONAL_ACCESS_TOKEN",
]
SECRET_CLASSES = frozenset(CHANGED)


@pytest.fixture
def gateway(monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    monkeypatch.setenv("PGW_SKIP_USER_CONFIG", "1")
    with Gateway() as instance:
        yield instance


def assert_gone(gateway: Gateway, text: str, value: str) -> None:
    session = gateway.session()
    out = session.pseudonymize(text)
    assert value not in out
    assert value[-8:] not in out
    assert not session.rescan(out)


@pytest.mark.parametrize("name", list(SAMPLES))
@pytest.mark.parametrize(
    "shape",
    ["log: backup_{v} end", "log: {v}_old end", "KEY_{v}_2026", "x_{v}", "log: backup {v} end"],
)
def test_key_next_to_underscore_is_replaced(gateway: Gateway, name: str, shape: str) -> None:
    value = SAMPLES[name]
    assert_gone(gateway, shape.format(v=value), value)


def secret_hits(text: str, config: Config) -> list[str]:
    return [
        f.data_class for f in PatternStage().run(text, config, []) if f.data_class in SECRET_CLASSES
    ]


@pytest.mark.parametrize(
    "text",
    [
        "ASIA_PACIFIC_REGION_CODE_2026",
        "AKIA_PREFIX_LENGTH = 20",
        "use_ghp_prefix_for_personal_tokens_in_tests",
        "test_sk_live_mode_enabled_for_checkout_flow",
        "x_eyJhbGciOi_parser_helper_function_name",
        "my_AIzaHelper_class",
        "slack_xoxb_handler_registry",
        "release_sk-proj-notes",
        "commit a3f5c9e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2 on main",
        "id 7c9e6679-7425-40de-944b-e07fc1f90ae7 at 12:30:45",
        "version v1.2.3_rc1 and build_20261127_1530",
        "xAKIAZ7Q3M5N2B8K4R6T1",
        "AKIAZ7Q3M5N2B8K4R6T1x",
        "aghp_Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw1Zc0Xe3Ga5Yu",
        "ghp_Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw1Zc0Xe3Ga5Yuä",
        "taskeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vMTIzIn0.Q7m3Np5Lr9Tx2Vb4Kd8Hf6Jw",
    ],
)
def test_identifiers_and_glued_letters_stay_free(default_config: Config, text: str) -> None:
    assert secret_hits(text, default_config) == []


def test_jwt_rule_keeps_its_linear_finder(default_config: Config) -> None:
    (pattern,) = default_config.registry.get("JWT").patterns
    assert pattern == JWT_PATTERN
    assert patterns.LINEAR_FINDERS[pattern] is jwt_finditer


def test_jwt_finditer_equals_finditer_around_underscores() -> None:
    alphabet = ["eyJ", "x_eyJ", "_", "-", ".", "a", "Z", "0", "abcdefghij", " ", "ä", "\n"]
    pattern = re.compile(JWT_PATTERN, re.MULTILINE)
    rng = random.Random(4)
    matched = 0
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
        expected = [m.span() for m in pattern.finditer(text)]
        assert [m.span() for m in jwt_finditer(pattern, text)] == expected
        matched += len(expected)
    assert matched > 0


UNITS = [
    "_AKIA", "_AKIAZ7Q3M5N2B8K4R6T", "_AIza", "_ghp_", "ghp_" + "a" * 40 + "ä", "_xoxb-",
    "xoxb-" + "a" * 30 + "ä", "_sk-ant-", "_sk-", "_sk_live_", "_glpat-", "_github_pat_",
    "x_eyJ", "_eyJaaaaaaaaaaaa.",
]


@pytest.mark.parametrize("name", CHANGED)
@pytest.mark.parametrize("unit", UNITS)
def test_changed_rules_scan_in_linear_time(default_config: Config, name: str, unit: str) -> None:
    for source in default_config.registry.get(name).patterns:
        pattern = re.compile(source, re.MULTILINE)
        assert_linear(
            lambda text, pattern=pattern: list(patterns.finditer(pattern, text)),
            lambda n: unit * (n // len(unit)),
        )

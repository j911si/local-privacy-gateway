from __future__ import annotations

import re
from pathlib import Path

import pytest

from privacy_gateway.classes import Category, Policy
from privacy_gateway.config import Config, load_config
from privacy_gateway.model import ConfigError

SKIP_USER = {"PGW_SKIP_USER_CONFIG": "1"}

EXPECTED_CLASS_COUNT = 140


def write_config(tmp_path: Path, body: str, name: str = "user.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_register_every_documented_class(default_config: Config) -> None:
    assert len(list(default_config.registry)) == EXPECTED_CLASS_COUNT


def test_defaults_contain_representative_classes(default_config: Config) -> None:
    for name in ("PERSON_FIRST_NAME", "IBAN", "KUBERNETES_SECRET", "COOKIE_VALUE", "SAS_TOKEN"):
        assert name in default_config.registry


def test_every_bundled_pattern_compiles(default_config: Config) -> None:
    for data_class in default_config.registry:
        for pattern in data_class.patterns:
            re.compile(pattern)


def test_bundled_patterns_survive_yaml_backslashes(default_config: Config) -> None:
    assert default_config.registry.get("IBAN").patterns[0].startswith("\\b[A-Z]{2}")


def test_secret_classes_are_redacted(default_config: Config) -> None:
    secrets = [c for c in default_config.registry if c.category is Category.SECRET]
    assert len(secrets) == 32
    for data_class in secrets:
        assert data_class.policy is Policy.REDACT


def test_non_secret_classes_are_tokenized(default_config: Config) -> None:
    for data_class in default_config.registry:
        if data_class.category is not Category.SECRET and data_class.name != "SALUTATION":
            assert data_class.policy is Policy.TOKENIZE


def test_person_classes_share_the_person_label(default_config: Config) -> None:
    assert default_config.registry.label_for("PERSON_FIRST_NAME") == "PERSON"
    assert default_config.registry.label_for("PERSON_INITIALS") == "PERSON"


def test_ip_scope_classes_outrank_generic_ip(default_config: Config) -> None:
    registry = default_config.registry
    assert registry.priority_for("PRIVATE_IP") == 171
    assert registry.priority_for("PUBLIC_IP") == 171
    assert registry.priority_for("IP_ADDRESS") == 170


def test_url_secret_classes_keep_category_priority(default_config: Config) -> None:
    registry = default_config.registry
    assert registry.priority_for("INTERNAL_URL") == 160
    assert registry.priority_for("SIGNED_URL") == 220
    assert registry.priority_for("SAS_TOKEN") == 220


def test_context_required_flags(default_config: Config) -> None:
    registry = default_config.registry
    assert registry.get("CVV").context_required is True
    assert registry.get("CARD_EXPIRY").context_required is True
    assert registry.get("DATE_OF_BIRTH").context_required is True
    assert registry.get("IBAN").context_required is False


def test_context_words_and_validators(default_config: Config) -> None:
    registry = default_config.registry
    assert registry.get("CREDIT_CARD").validator == "luhn"
    assert registry.get("ACCOUNT_ID").context_words == ("account", "konto", "kontonummer", "acct")
    assert registry.get("ACCOUNT_ID").patterns == ()


def test_defaults_for_vault_audit_restore_person(default_config: Config) -> None:
    assert default_config.vault.db_path.is_absolute()
    assert default_config.vault.key_file.is_absolute()
    assert default_config.audit.path is not None
    assert default_config.restore.mode == "strict"
    assert default_config.person.record_gender_from_salutation is True
    assert default_config.languages == ["de", "en"]
    assert default_config.min_confidence == 0.5
    assert default_config.dictionaries == {}


def test_user_config_adds_class(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        "classes:\n"
        "  PROJECT_CODE:\n"
        "    category: PROJECT\n"
        "    policy: tokenize\n"
        "    patterns: ['\\bPRJ-\\d{5}\\b']\n"
        "    context_words: [project, projekt]\n",
    )
    config = load_config(path, env=SKIP_USER)
    project_code = config.registry.get("PROJECT_CODE")
    assert project_code.category is Category.PROJECT
    assert project_code.patterns == ("\\bPRJ-\\d{5}\\b",)
    assert project_code.priority == 90
    assert len(list(config.registry)) == EXPECTED_CLASS_COUNT + 1


def test_user_config_overrides_single_field(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  API_KEY:\n    policy: tokenize\n")
    config = load_config(path, env=SKIP_USER)
    api_key = config.registry.get("API_KEY")
    assert api_key.policy is Policy.TOKENIZE
    assert api_key.category is Category.SECRET
    assert api_key.patterns != ()


def test_user_config_may_set_policy_ignore(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  IBAN:\n    policy: ignore\n")
    assert load_config(path, env=SKIP_USER).registry.get("IBAN").policy is Policy.IGNORE


def test_salutation_is_the_only_bundled_class_with_policy_ignore(default_config: Config) -> None:
    ignored = {c.name for c in default_config.registry if c.policy is Policy.IGNORE}
    assert ignored == {"SALUTATION"}


def test_unknown_category_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  WEIRD:\n    category: NOPE\n    policy: tokenize\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_unknown_policy_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  IBAN:\n    policy: shred\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_new_class_without_category_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  WEIRD:\n    policy: tokenize\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_unknown_top_level_key_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "nonsense: 1\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_unknown_class_field_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  IBAN:\n    colour: blue\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_missing_config_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "absent.yaml", env=SKIP_USER)


def test_dictionaries_from_lists(tmp_path: Path) -> None:
    path = write_config(
        tmp_path, "dictionaries:\n  CUSTOMER_NAME: [Contoso GmbH, Fabrikam AG]\n"
    )
    config = load_config(path, env=SKIP_USER)
    assert config.dictionaries["CUSTOMER_NAME"] == ["Contoso GmbH", "Fabrikam AG"]


def test_dictionaries_from_files_relative_to_config(tmp_path: Path) -> None:
    (tmp_path / "ids.txt").write_text("E-1\n\n# comment\n  E-2  \n", encoding="utf-8")
    path = write_config(
        tmp_path,
        "dictionaries:\n  EMPLOYEE_ID: [E-0]\n  files:\n    EMPLOYEE_ID: ./ids.txt\n",
    )
    config = load_config(path, env=SKIP_USER)
    assert config.dictionaries["EMPLOYEE_ID"] == ["E-0", "E-1", "E-2"]


def test_dictionaries_unknown_class_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "dictionaries:\n  NOPE: [x]\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_env_overrides(tmp_path: Path) -> None:
    config = load_config(
        env={
            "PGW_SKIP_USER_CONFIG": "1",
            "PGW_VAULT_DB": "/tmp/x.db",
            "PGW_VAULT_KEY_FILE": "/tmp/x.key",
            "PGW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
            "PGW_RESTORE_MODE": "lenient",
        }
    )
    assert config.vault.db_path == Path("/tmp/x.db")
    assert config.vault.key_file == Path("/tmp/x.key")
    assert config.audit.path == tmp_path / "audit.jsonl"
    assert config.restore.mode == "lenient"


def test_env_config_path_is_applied(tmp_path: Path) -> None:
    path = write_config(tmp_path, "min_confidence: 0.75\n", name="extra.yaml")
    config = load_config(env={"PGW_SKIP_USER_CONFIG": "1", "PGW_CONFIG": str(path)})
    assert config.min_confidence == 0.75


def test_env_config_is_applied_after_the_explicit_path(tmp_path: Path) -> None:
    env_path = write_config(tmp_path, "min_confidence: 0.75\n", name="env.yaml")
    arg_path = write_config(tmp_path, "min_confidence: 0.25\n", name="arg.yaml")
    config = load_config(
        arg_path, env={"PGW_SKIP_USER_CONFIG": "1", "PGW_CONFIG": str(env_path)}
    )
    assert config.min_confidence == 0.75


def test_invalid_restore_mode_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(env={"PGW_SKIP_USER_CONFIG": "1", "PGW_RESTORE_MODE": "sloppy"})


def test_hash_is_stable_across_loads() -> None:
    assert load_config(env=SKIP_USER).hash() == load_config(env=SKIP_USER).hash()


def test_hash_is_hex_sha256() -> None:
    digest = load_config(env=SKIP_USER).hash()
    assert len(digest) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_hash_changes_with_configuration(tmp_path: Path) -> None:
    path = write_config(tmp_path, "min_confidence: 0.9\n")
    assert load_config(path, env=SKIP_USER).hash() != load_config(env=SKIP_USER).hash()


def test_user_config_file_is_skipped_by_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    user_config = home / ".config" / "privacy-gateway" / "config.yaml"
    user_config.parent.mkdir(parents=True)
    user_config.write_text("min_confidence: 0.11\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    assert load_config(env={}).min_confidence == 0.11
    assert load_config(env=SKIP_USER).min_confidence == 0.5


@pytest.mark.parametrize("value", ["1.5", "-0.1"])
def test_min_confidence_outside_the_unit_interval_raises(tmp_path: Path, value: str) -> None:
    path = write_config(tmp_path, f"min_confidence: {value}\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


@pytest.mark.parametrize("value", ["0", "1"])
def test_min_confidence_accepts_the_interval_bounds(tmp_path: Path, value: str) -> None:
    path = write_config(tmp_path, f"min_confidence: {value}\n")
    assert load_config(path, env=SKIP_USER).min_confidence == float(value)


def test_class_restore_key_is_unknown(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  IBAN:\n    restore: false\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


@pytest.mark.parametrize(
    "body",
    [
        "classes:\n  IBAN:\n    enabled: 'false'\n",
        "classes:\n  IBAN:\n    context_required: 'yes'\n",
        "person:\n  record_gender_from_salutation: 'no'\n",
    ],
)
def test_non_bool_flag_raises(tmp_path: Path, body: str) -> None:
    path = write_config(tmp_path, body)
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_bool_flags_accept_real_booleans(tmp_path: Path) -> None:
    path = write_config(tmp_path, "classes:\n  IBAN:\n    enabled: false\n")
    assert load_config(path, env=SKIP_USER).registry.get("IBAN").enabled is False


def test_empty_audit_path_raises(tmp_path: Path) -> None:
    path = write_config(tmp_path, "audit:\n  path: ''\n")
    with pytest.raises(ConfigError):
        load_config(path, env=SKIP_USER)


def test_empty_audit_env_raises() -> None:
    with pytest.raises(ConfigError):
        load_config(env={"PGW_SKIP_USER_CONFIG": "1", "PGW_AUDIT_LOG": ""})


def test_null_audit_path_disables_auditing(tmp_path: Path) -> None:
    path = write_config(tmp_path, "audit:\n  path: null\n")
    assert load_config(path, env=SKIP_USER).audit.path is None

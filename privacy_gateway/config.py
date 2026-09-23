"""YAML configuration loading, validation and class registry construction."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from privacy_gateway.classes import (
    PRIORITY_UNSET,
    Category,
    ClassRegistry,
    DataClass,
    Policy,
)
from privacy_gateway.model import ConfigError

DEFAULT_CONFIG_PATH = Path(__file__).parent / "data" / "default_config.yaml"
USER_CONFIG_RELATIVE = Path(".config") / "privacy-gateway" / "config.yaml"

TOP_LEVEL_KEYS = frozenset(
    {
        "classes",
        "dictionaries",
        "vault",
        "audit",
        "restore",
        "person",
        "languages",
        "min_confidence",
    }
)
CLASS_KEYS = frozenset(
    {
        "category",
        "policy",
        "priority",
        "enabled",
        "token_label",
        "patterns",
        "validator",
        "context_words",
        "context_required",
    }
)
VAULT_KEYS = frozenset({"db_path", "key_file"})
AUDIT_KEYS = frozenset({"path"})
RESTORE_KEYS = frozenset({"mode"})
PERSON_KEYS = frozenset({"record_gender_from_salutation"})
RESTORE_MODES = ("strict", "lenient")

SKIP_USER_CONFIG_ENV = "PGW_SKIP_USER_CONFIG"


@dataclass
class VaultConfig:
    """Where the encrypted vault and its key live."""

    db_path: Path
    key_file: Path


@dataclass
class AuditConfig:
    """Where audit events are appended; None disables auditing."""

    path: Path | None


@dataclass
class RestoreConfig:
    """How unknown tokens are handled during restoration."""

    mode: str = "strict"


@dataclass
class PersonConfig:
    """Rules for person attributes."""

    record_gender_from_salutation: bool = True


@dataclass
class Config:
    """Fully resolved configuration for one gateway instance."""

    registry: ClassRegistry
    dictionaries: dict[str, list[str]]
    vault: VaultConfig
    audit: AuditConfig
    restore: RestoreConfig
    person: PersonConfig
    languages: list[str] = field(default_factory=lambda: ["de", "en"])
    min_confidence: float = 0.5

    def hash(self) -> str:
        normalized = {
            "classes": sorted(
                (
                    c.name,
                    c.category.value,
                    c.policy.value,
                    c.priority,
                    c.enabled,
                    c.token_label,
                    list(c.patterns),
                    c.validator,
                    list(c.context_words),
                    c.context_required,
                )
                for c in self.registry
            ),
            "dictionaries": {k: sorted(v) for k, v in sorted(self.dictionaries.items())},
            "vault": [str(self.vault.db_path), str(self.vault.key_file)],
            "audit": str(self.audit.path) if self.audit.path else None,
            "restore": self.restore.mode,
            "person": self.person.record_gender_from_salutation,
            "languages": self.languages,
            "min_confidence": self.min_confidence,
        }
        payload = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in config file: {path}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config file must contain a mapping: {path}")
    unknown = set(raw) - TOP_LEVEL_KEYS
    if unknown:
        raise ConfigError(f"unknown configuration keys in {path}: {sorted(unknown)}")
    return raw


def _read_terms(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"cannot read dictionary file: {path}") from exc
    terms = []
    for line in lines:
        term = line.strip()
        if term and not term.startswith("#"):
            terms.append(term)
    return terms


def _merge_section(
    target: dict[str, Any], data: dict[str, Any], key: str, allowed: frozenset[str]
) -> None:
    section = data.get(key)
    if section is None:
        return
    if not isinstance(section, dict):
        raise ConfigError(f"'{key}' must be a mapping")
    unknown = set(section) - allowed
    if unknown:
        raise ConfigError(f"unknown keys in '{key}': {sorted(unknown)}")
    target.update(section)


def _merge_classes(target: dict[str, dict[str, Any]], data: dict[str, Any]) -> None:
    classes = data.get("classes")
    if classes is None:
        return
    if not isinstance(classes, dict):
        raise ConfigError("'classes' must be a mapping")
    for name, spec in classes.items():
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise ConfigError(f"class '{name}' must be a mapping")
        unknown = set(spec) - CLASS_KEYS
        if unknown:
            raise ConfigError(f"unknown keys for class '{name}': {sorted(unknown)}")
        target.setdefault(name, {}).update(spec)


def _merge_dictionaries(
    target: dict[str, list[str]], data: dict[str, Any], base_dir: Path
) -> None:
    dictionaries = data.get("dictionaries")
    if dictionaries is None:
        return
    if not isinstance(dictionaries, dict):
        raise ConfigError("'dictionaries' must be a mapping")
    for key, value in dictionaries.items():
        if key == "files":
            continue
        if not isinstance(value, list):
            raise ConfigError(f"dictionary '{key}' must be a list of terms")
        _extend_unique(target.setdefault(key, []), [str(term) for term in value])
    files = dictionaries.get("files")
    if files is None:
        return
    if not isinstance(files, dict):
        raise ConfigError("'dictionaries.files' must be a mapping")
    for key, rel in files.items():
        path = Path(str(rel)).expanduser()
        if not path.is_absolute():
            path = base_dir / path
        _extend_unique(target.setdefault(key, []), _read_terms(path))


def _extend_unique(target: list[str], terms: list[str]) -> None:
    for term in terms:
        if term not in target:
            target.append(term)


def _as_tuple(name: str, key: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"'{key}' of class '{name}' must be a list")
    return tuple(str(item) for item in value)


def _as_bool(where: str, key: str, value: Any, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"'{key}' of {where} must be true or false")
    return value


def _build_class(name: str, spec: dict[str, Any]) -> DataClass:
    category_name = spec.get("category")
    if category_name is None:
        raise ConfigError(f"class '{name}' has no category")
    try:
        category = Category(str(category_name))
    except ValueError:
        raise ConfigError(f"unknown category '{category_name}' for class '{name}'") from None
    try:
        policy = Policy(str(spec.get("policy", Policy.TOKENIZE.value)))
    except ValueError:
        raise ConfigError(f"unknown policy '{spec.get('policy')}' for class '{name}'") from None
    priority = spec.get("priority", PRIORITY_UNSET)
    if not isinstance(priority, int):
        raise ConfigError(f"'priority' of class '{name}' must be an integer")
    return DataClass(
        name=name,
        category=category,
        policy=policy,
        priority=priority,
        enabled=_as_bool(f"class '{name}'", "enabled", spec.get("enabled"), True),
        token_label=spec.get("token_label"),
        patterns=_as_tuple(name, "patterns", spec.get("patterns", [])),
        validator=spec.get("validator"),
        context_words=_as_tuple(name, "context_words", spec.get("context_words", [])),
        context_required=_as_bool(
            f"class '{name}'", "context_required", spec.get("context_required"), False
        ),
    )


def _layer_paths(path: str | Path | None, env: Mapping[str, str]) -> list[Path]:
    paths = [DEFAULT_CONFIG_PATH]
    if env.get(SKIP_USER_CONFIG_ENV, "") not in ("1", "true", "yes"):
        user_config = Path.home() / USER_CONFIG_RELATIVE
        if user_config.exists():
            paths.append(user_config)
    for candidate in (path, env.get("PGW_CONFIG")):
        if candidate is None:
            continue
        resolved = Path(candidate).expanduser()
        if not resolved.exists():
            raise ConfigError(f"config file not found: {resolved}")
        paths.append(resolved)
    return paths


def _apply_env(
    env: Mapping[str, str], vault: dict[str, Any], audit: dict[str, Any], restore: dict[str, Any]
) -> None:
    if "PGW_VAULT_DB" in env:
        vault["db_path"] = env["PGW_VAULT_DB"]
    if "PGW_VAULT_KEY_FILE" in env:
        vault["key_file"] = env["PGW_VAULT_KEY_FILE"]
    if "PGW_AUDIT_LOG" in env:
        audit["path"] = env["PGW_AUDIT_LOG"]
    if "PGW_RESTORE_MODE" in env:
        restore["mode"] = env["PGW_RESTORE_MODE"]


def load_config(path: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> Config:
    """Load defaults, ~/.config (skipped when PGW_SKIP_USER_CONFIG=1), `path`, then PGW_* env."""
    env = os.environ if env is None else env

    class_specs: dict[str, dict[str, Any]] = {}
    dictionaries: dict[str, list[str]] = {}
    vault_raw: dict[str, Any] = {}
    audit_raw: dict[str, Any] = {}
    restore_raw: dict[str, Any] = {}
    person_raw: dict[str, Any] = {}
    scalars: dict[str, Any] = {}

    for layer_path in _layer_paths(path, env):
        data = _read_yaml(layer_path)
        _merge_classes(class_specs, data)
        _merge_dictionaries(dictionaries, data, layer_path.parent)
        _merge_section(vault_raw, data, "vault", VAULT_KEYS)
        _merge_section(audit_raw, data, "audit", AUDIT_KEYS)
        _merge_section(restore_raw, data, "restore", RESTORE_KEYS)
        _merge_section(person_raw, data, "person", PERSON_KEYS)
        for key in ("languages", "min_confidence"):
            if key in data:
                scalars[key] = data[key]

    _apply_env(env, vault_raw, audit_raw, restore_raw)

    registry = ClassRegistry(_build_class(name, spec) for name, spec in class_specs.items())
    unknown_dicts = set(dictionaries) - {c.name for c in registry}
    if unknown_dicts:
        raise ConfigError(f"dictionaries for unknown classes: {sorted(unknown_dicts)}")

    mode = str(restore_raw.get("mode", "strict"))
    if mode not in RESTORE_MODES:
        raise ConfigError(f"restore mode must be one of {RESTORE_MODES}, got '{mode}'")

    audit_path = audit_raw.get("path")
    if audit_path is not None and not str(audit_path).strip():
        raise ConfigError("'audit.path' must be a path or null")
    languages = scalars.get("languages", ["de", "en"])
    if not isinstance(languages, list):
        raise ConfigError("'languages' must be a list")
    min_confidence = scalars.get("min_confidence", 0.5)
    if not isinstance(min_confidence, (int, float)) or isinstance(min_confidence, bool):
        raise ConfigError("'min_confidence' must be a number")
    if not 0 <= min_confidence <= 1:
        raise ConfigError("'min_confidence' must be between 0 and 1")

    return Config(
        registry=registry,
        dictionaries=dictionaries,
        vault=VaultConfig(
            db_path=Path(str(vault_raw["db_path"])).expanduser(),
            key_file=Path(str(vault_raw["key_file"])).expanduser(),
        ),
        audit=AuditConfig(path=Path(str(audit_path)).expanduser() if audit_path else None),
        restore=RestoreConfig(mode=mode),
        person=PersonConfig(
            record_gender_from_salutation=_as_bool(
                "'person'",
                "record_gender_from_salutation",
                person_raw.get("record_gender_from_salutation"),
                True,
            )
        ),
        languages=[str(item) for item in languages],
        min_confidence=float(min_confidence),
    )

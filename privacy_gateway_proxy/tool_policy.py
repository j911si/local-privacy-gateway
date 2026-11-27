"""Default-deny policy for restoring placeholders inside tool-call arguments."""

from __future__ import annotations

import copy
import json
import posixpath
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path as FilePath
from typing import Any

import yaml

from privacy_gateway.model import ConfigError
from privacy_gateway.restore import LENIENT_TOKEN
from privacy_gateway.tokens import ANY_TOKEN
from privacy_gateway_proxy.transform import KeyAt, Path, Slot, format_path

KEEP_TOKEN = "keep_token"
BLOCK = "block"
ON_DENY_MODES = (KEEP_TOKEN, BLOCK)
RESTORED = "restored"
KEPT = "kept"
BLOCKED = "blocked"
ERROR_TYPE = "privacy_gateway_tool_restore_denied"
AUDIT_PREFIX = "tool-restore"
AUDIT_EVENT = "tool_restore"
AUDIT_NAME_CHARS = 64
POLICY_KEYS = frozenset({"rules"})
RULE_KEYS = frozenset({"tool", "argument", "classes", "target"})
REQUIRED_RULE_KEYS = frozenset({"tool", "argument", "classes"})
TARGET_KEYS = frozenset({"argument", "under"})
TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
TOOL_NAME_CHAR_RE = re.compile(r"[A-Za-z0-9_-]")
CLASS_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_SEGMENT = r"[A-Za-z_][A-Za-z0-9_-]*"
ARGUMENT_RE = re.compile(rf"{_SEGMENT}(?:\[\*\])*(?:\.{_SEGMENT}(?:\[\*\])*)*")
TARGET_ARGUMENT_RE = re.compile(rf"{_SEGMENT}(?:\.{_SEGMENT})*")
ARGUMENT_PART_RE = re.compile(rf"{_SEGMENT}|\[\*\]")
ANY_INDEX = "[*]"


@dataclass(frozen=True)
class Target:
    """The argument whose path must lie under a directory for the rule to apply."""

    argument: tuple[str, ...]
    under: str


@dataclass(frozen=True)
class ToolRule:
    """Restore `classes` in `argument` of the tool named exactly `tool`; None is any list index."""

    tool: str
    argument: tuple[str | None, ...]
    classes: tuple[str, ...]
    target: Target | None = None


def load_policy(path: FilePath | str) -> tuple[ToolRule, ...]:
    """Read and validate a policy file; every problem is a value-free ConfigError."""
    try:
        text = FilePath(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"tool restore policy is not readable: {type(exc).__name__}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise ConfigError(f"tool restore policy is not valid YAML{where}") from None
    return parse_policy(data)


def parse_policy(data: Any) -> tuple[ToolRule, ...]:
    """Validate parsed policy data: a mapping with a `rules` list."""
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ConfigError("tool restore policy must be a mapping with a 'rules' list")
    _only(data, POLICY_KEYS, "tool restore policy")
    return tuple(
        _rule(item, f"tool restore policy rules[{index}]")
        for index, item in enumerate(data["rules"])
    )


def check_settings(
    rules: tuple[ToolRule, ...], on_deny: str, known_classes: Collection[str] | None
) -> None:
    """Fail when the deny mode is unknown or a rule names a class the gateway does not know."""
    if on_deny not in ON_DENY_MODES:
        raise ConfigError(f"tool restore on-deny mode must be one of {', '.join(ON_DENY_MODES)}")
    if not rules:
        return
    if known_classes is None:
        raise ConfigError("tool restore policy cannot be checked: no class registry")
    for index, rule in enumerate(rules):
        for position, name in enumerate(rule.classes):
            if name not in known_classes:
                raise ConfigError(
                    f"tool restore policy rules[{index}].classes[{position}] is not a known "
                    "data class (see `pgw classes`)"
                )


def audit_name(name: Any) -> str:
    """A tool name safe for the audit: unusual characters escaped, cut to 64 characters."""
    if not isinstance(name, str):
        return "\\invalid"
    if TOOL_NAME_RE.fullmatch(name) and len(name) <= AUDIT_NAME_CHARS:
        return name
    escaped = "".join(
        char if TOOL_NAME_CHAR_RE.fullmatch(char) else f"\\u{ord(char):04x}"
        for char in name[:AUDIT_NAME_CHARS]
    )
    return escaped + ("…" if len(name) > AUDIT_NAME_CHARS else "")


class ToolGuard:
    """Restores tool-call placeholders only where a rule allows it, and records each decision."""

    def __init__(
        self,
        rules: tuple[ToolRule, ...],
        on_deny: str,
        entries: Mapping[str, Any],
        *,
        streaming: bool,
    ) -> None:
        check_settings((), on_deny, None)
        self._rules = rules
        self._on_deny = on_deny
        self._entries = entries
        self.streaming = streaming
        self.entries: list[dict[str, str]] = []
        self.blocked = False

    def restore_response(self, body: dict) -> dict:
        """A copy of a non-streaming response with allowed tool_use placeholders restored."""
        new_body = copy.deepcopy(body)
        content = new_body.get("content")
        if not isinstance(content, list):
            return new_body
        for index, block in enumerate(content):
            if isinstance(block, dict) and block.get("type") == "tool_use" and "input" in block:
                block["input"] = self.restore_input(index, block.get("name"), block["input"])
        if self.blocked:
            for item in self.entries:
                item["decision"] = BLOCKED
        return new_body

    def restore_input(self, index: int, name: Any, value: Any) -> Any:
        """The input of block `index` with allowed placeholders restored."""
        first = len(self.entries)
        context = _Call(name if isinstance(name, str) else "", value, ("content", index, "input"))
        restored = self._walk(value, (), context.position, context)
        self._settle(first)
        return restored

    def restore_partial(self, index: int, name: Any, text: str) -> str | None:
        """Streamed input JSON with allowed placeholders restored; None when it is blocked."""
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            first = len(self.entries)
            path = ("content", index, "input")
            for match in LENIENT_TOKEN.finditer(text):
                entry = self._entry(match)
                if entry is not None:
                    self._record(name, path, entry, KEPT)
            self._settle(first)
            return None if self.blocked else text
        restored = self.restore_input(index, name, parsed)
        if self.blocked:
            return None
        return json.dumps(restored, separators=(",", ":"), ensure_ascii=False)

    def message(self) -> str:
        """The value-free reason of a block."""
        denied = [item for item in self.entries if item["decision"] == BLOCKED]
        classes = ", ".join(sorted({item["cls"] for item in denied}))
        return (
            f"a tool call holds {len(denied)} placeholder(s) the tool restore policy "
            f"does not release (classes: {classes or 'none'})"
        )

    def audit_fields(self, request_id: str | None) -> dict[str, object]:
        """The `tool_restore` audit fields: names, positions, classes and decisions only."""
        return {
            "request_id": request_id,
            "streaming": self.streaming,
            "on_deny": self._on_deny,
            "entries": self.entries,
        }

    def _settle(self, first: int) -> None:
        if self._on_deny != BLOCK:
            return
        block_entries = self.entries[first:]
        if any(item["decision"] == KEPT for item in block_entries):
            self.blocked = True
            for item in block_entries:
                item["decision"] = BLOCKED

    def _walk(self, value: Any, real: tuple[str | int, ...], position: Path, call: _Call) -> Any:
        if isinstance(value, str):
            return self._leaf(value, real, position, call)
        if isinstance(value, dict):
            result = {}
            for slot, (key, item) in enumerate(value.items()):
                self._deny_all(key, (*position, KeyAt(slot)), call)
                result[key] = self._walk(item, (*real, key), (*position, Slot(slot)), call)
            return result
        if isinstance(value, list):
            return [
                self._walk(item, (*real, index), (*position, index), call)
                for index, item in enumerate(value)
            ]
        return value

    def _leaf(self, text: str, real: tuple[str | int, ...], position: Path, call: _Call) -> str:
        def replace(match: re.Match[str]) -> str:
            entry = self._entry(match)
            if entry is None:
                return match.group(0)
            if self._allowed(call, real, entry.data_class):
                self._record(call.name, position, entry, RESTORED)
                quote = match.group("quote") or ""
                return f"{quote}{entry.value}{quote}"
            self._record(call.name, position, entry, KEPT)
            return match.group(0)

        return LENIENT_TOKEN.sub(replace, text)

    def _deny_all(self, key: Any, position: Path, call: _Call) -> None:
        if not isinstance(key, str):
            return
        for match in LENIENT_TOKEN.finditer(key):
            entry = self._entry(match)
            if entry is not None:
                self._record(call.name, position, entry, KEPT)

    def _entry(self, match: re.Match[str]) -> Any:
        name = match.group("bracketed") or match.group("bare")
        return self._entries.get(f"<{name.upper()}>")

    def _allowed(self, call: _Call, real: tuple[str | int, ...], data_class: str) -> bool:
        return any(
            rule.tool == call.name
            and _argument_matches(rule.argument, real)
            and data_class in rule.classes
            and _target_ok(rule.target, call.raw)
            for rule in self._rules
        )

    def _record(self, name: Any, position: Path, entry: Any, decision: str) -> None:
        self.entries.append(
            {
                "tool": audit_name(name),
                "path": format_path(position),
                "cls": str(entry.data_class),
                "decision": decision,
            }
        )


@dataclass(frozen=True)
class _Call:
    name: str
    raw: Any
    position: Path


def _argument_matches(pattern: tuple[str | None, ...], real: tuple[str | int, ...]) -> bool:
    if len(pattern) != len(real):
        return False
    for expected, part in zip(pattern, real, strict=True):
        if expected is None:
            if not isinstance(part, int):
                return False
        elif not isinstance(part, str) or part != expected:
            return False
    return True


def _target_ok(target: Target | None, raw: Any) -> bool:
    if target is None:
        return True
    value = raw
    for key in target.argument:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    if not isinstance(value, str) or LENIENT_TOKEN.search(value) or ANY_TOKEN.search(value):
        return False
    normalized = _normalized(value)
    if normalized is None:
        return False
    return target.under == "/" or normalized == target.under or normalized.startswith(
        target.under + "/"
    )


def _normalized(path: str) -> str | None:
    """An absolute path without `.`, `//` or a trailing slash; None with `..`, NUL or relative."""
    if not path.startswith("/") or "\x00" in path or ".." in path.split("/"):
        return None
    normalized = posixpath.normpath(path)
    return "/" + normalized.lstrip("/")


def _only(data: dict, allowed: frozenset[str], where: str) -> None:
    if any(key not in allowed for key in data):
        raise ConfigError(f"{where} has an unknown key (allowed: {', '.join(sorted(allowed))})")


def _rule(item: Any, where: str) -> ToolRule:
    if not isinstance(item, dict):
        raise ConfigError(f"{where} must be a mapping")
    _only(item, RULE_KEYS, where)
    if not REQUIRED_RULE_KEYS <= set(item):
        raise ConfigError(f"{where} needs tool, argument and classes")
    tool = item["tool"]
    if not isinstance(tool, str) or not TOOL_NAME_RE.fullmatch(tool):
        raise ConfigError(
            f"{where}.tool must be one exact tool name (letters, digits, '_' or '-'; no pattern)"
        )
    argument = item["argument"]
    if not isinstance(argument, str) or not ARGUMENT_RE.fullmatch(argument):
        raise ConfigError(f"{where}.argument must be a path like 'content' or 'edits[*].text'")
    classes = item["classes"]
    if (
        not isinstance(classes, list)
        or not classes
        or not all(isinstance(name, str) and CLASS_RE.fullmatch(name) for name in classes)
    ):
        raise ConfigError(f"{where}.classes must be a non-empty list of data class names")
    target = _target(item["target"], f"{where}.target") if "target" in item else None
    return ToolRule(tool, _argument(argument), tuple(classes), target)


def _argument(text: str) -> tuple[str | None, ...]:
    return tuple(
        None if part == ANY_INDEX else part for part in ARGUMENT_PART_RE.findall(text)
    )


def _target(item: Any, where: str) -> Target:
    if not isinstance(item, dict):
        raise ConfigError(f"{where} must be a mapping with argument and under")
    _only(item, TARGET_KEYS, where)
    if not TARGET_KEYS <= set(item):
        raise ConfigError(f"{where} needs argument and under")
    argument, under = item["argument"], item["under"]
    if not isinstance(argument, str) or not TARGET_ARGUMENT_RE.fullmatch(argument):
        raise ConfigError(f"{where}.argument must be a plain path like 'file_path'")
    normalized = _normalized(under) if isinstance(under, str) else None
    if normalized is None:
        raise ConfigError(f"{where}.under must be an absolute directory without '..'")
    return Target(tuple(argument.split(".")), normalized)

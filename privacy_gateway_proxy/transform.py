"""Pure request/response transforms over parsed Anthropic Messages API bodies."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

Path = tuple[str | int, ...]

NOTICE_MARKER = "<privacy-gateway>"
NOTICE_TEXT = (
    "<privacy-gateway>\n"
    "Some values in this conversation are pseudonymized placeholders: an uppercase class name "
    "and a three-digit number in angle brackets, written <CLASS_NNN>. They stand for real values "
    "that are restored locally after your reply. Always reproduce placeholders verbatim, exactly "
    "as written, including angle brackets and numbers. Never guess, invent or replace them with "
    "example values, and never remove them.\n"
    "</privacy-gateway>"
)


@runtime_checkable
class TextSession(Protocol):
    """The subset of a gateway session the transforms need."""

    def pseudonymize_many(self, texts: list[str]) -> list[str]: ...

    def restore_text(self, text: str) -> str: ...


@dataclass(frozen=True)
class TextRef:
    """A transformable string and its JSON-pointer-like path in the body."""

    path: Path
    text: str


def collect_request_texts(body: dict, *, include_system: bool = True) -> list[TextRef]:
    """Return every transformable request string in document order."""
    refs: list[TextRef] = []
    if include_system:
        _collect_system(body.get("system"), refs)
    messages = body.get("messages")
    if isinstance(messages, list):
        for index, message in enumerate(messages):
            if isinstance(message, dict):
                _collect_content(message.get("content"), ("messages", index, "content"), refs)
    return refs


def pseudonymize_request(
    body: dict, sess: TextSession, *, include_system: bool = True, notice: bool = False
) -> tuple[dict, int]:
    """Return a copy of the request with all transformable texts pseudonymized."""
    new_body = copy.deepcopy(body)
    refs = collect_request_texts(new_body, include_system=include_system)
    if not refs:
        return new_body, 0
    if notice and _insert_notice(new_body):
        refs = collect_request_texts(new_body, include_system=include_system)
    replaced = sess.pseudonymize_many([ref.text for ref in refs])
    for ref, text in zip(refs, replaced, strict=True):
        _set_at(new_body, ref.path, text)
    return new_body, len(refs)


def restore_response(body: dict, sess: TextSession) -> dict:
    """Return a copy of the response with text blocks and tool_use inputs restored."""
    new_body = copy.deepcopy(body)
    content = new_body.get("content")
    if not isinstance(content, list):
        return new_body
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            block["text"] = sess.restore_text(block["text"])
        elif block.get("type") == "tool_use" and "input" in block:
            block["input"] = restore_json(block["input"], sess.restore_text)
    return new_body


def restore_json(value: Any, restore: Callable[[str], str]) -> Any:
    """Apply `restore` to every string leaf, leaving other types untouched."""
    if isinstance(value, str):
        return restore(value)
    if isinstance(value, dict):
        return {key: restore_json(item, restore) for key, item in value.items()}
    if isinstance(value, list):
        return [restore_json(item, restore) for item in value]
    return value


def _insert_notice(body: dict) -> bool:
    """Prepend the placeholder notice to the first user message; True when it was added."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return False
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
            message["content"] = content
        if not isinstance(content, list) or _starts_with_notice(content):
            return False
        content.insert(0, {"type": "text", "text": NOTICE_TEXT})
        return True
    return False


def _starts_with_notice(content: list) -> bool:
    first = content[0] if content else None
    if not isinstance(first, dict) or first.get("type") != "text":
        return False
    return isinstance(first.get("text"), str) and first["text"].startswith(NOTICE_MARKER)


def _collect_system(system: Any, refs: list[TextRef]) -> None:
    if isinstance(system, str):
        _add(refs, ("system",), system)
    elif isinstance(system, list):
        for index, block in enumerate(system):
            if isinstance(block, dict) and block.get("type") == "text":
                _add_if_str(refs, ("system", index, "text"), block.get("text"))


def _collect_content(content: Any, path: Path, refs: list[TextRef]) -> None:
    if isinstance(content, str):
        _add(refs, path, content)
        return
    if not isinstance(content, list):
        return
    for index, block in enumerate(content):
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text":
            _add_if_str(refs, (*path, index, "text"), block.get("text"))
        elif block_type == "tool_result":
            _collect_tool_result(block.get("content"), (*path, index, "content"), refs)
        elif block_type == "tool_use":
            _collect_strings(block.get("input"), (*path, index, "input"), refs)
        elif block_type == "document":
            _collect_document(block.get("source"), (*path, index, "source"), refs)


def _collect_document(source: Any, path: Path, refs: list[TextRef]) -> None:
    if isinstance(source, dict) and source.get("type") == "text":
        _add_if_str(refs, (*path, "data"), source.get("data"))


def _collect_tool_result(content: Any, path: Path, refs: list[TextRef]) -> None:
    if isinstance(content, str):
        _add(refs, path, content)
        return
    if not isinstance(content, list):
        return
    for index, block in enumerate(content):
        if isinstance(block, dict) and block.get("type") == "text":
            _add_if_str(refs, (*path, index, "text"), block.get("text"))


def _collect_strings(value: Any, path: Path, refs: list[TextRef]) -> None:
    if isinstance(value, str):
        _add(refs, path, value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _collect_strings(item, (*path, key), refs)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_strings(item, (*path, index), refs)


def _add(refs: list[TextRef], path: Path, text: str) -> None:
    if text:
        refs.append(TextRef(path, text))


def _add_if_str(refs: list[TextRef], path: Path, text: Any) -> None:
    if isinstance(text, str):
        _add(refs, path, text)


def _set_at(body: dict, path: Path, text: str) -> None:
    target: Any = body
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = text

"""Tests for the request/response transform."""

from __future__ import annotations

import copy
import json
from typing import Any

from privacy_gateway_proxy.transform import (
    NOTICE_TEXT,
    TextRef,
    collect_request_texts,
    pseudonymize_request,
    restore_json,
    restore_response,
)

from .conftest import ORIGINAL_VALUES, FakeSession

EXPECTED_PATHS = [
    ("system", 0, "text"),
    ("system", 1, "text"),
    ("messages", 0, "content"),
    ("messages", 1, "content", 1, "text"),
    ("messages", 1, "content", 2, "input", "file_path"),
    ("messages", 2, "content", 0, "content", 0, "text"),
    ("messages", 3, "content", 0, "input", "file_path"),
    ("messages", 3, "content", 0, "input", "content"),
]


def walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in walk_strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in walk_strings(item)]
    return []


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def test_collect_request_texts_walks_in_document_order(request_body: dict) -> None:
    refs = collect_request_texts(request_body)

    assert [ref.path for ref in refs] == EXPECTED_PATHS


def test_collect_request_texts_returns_the_text_at_each_path(request_body: dict) -> None:
    refs = collect_request_texts(request_body)

    expected = TextRef(("messages", 0, "content"), "Lies bitte die Notizen und schreibe den Brief.")
    assert refs[2] == expected
    assert refs[5].text == "Sehr geehrte Frau Müller, IBAN DE89370400440532013000"


def test_collect_request_texts_handles_string_system_and_tool_result() -> None:
    body = {
        "system": "Du bist Claude.",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "Frau Müller"},
                ],
            }
        ],
    }

    refs = collect_request_texts(body)

    assert [ref.path for ref in refs] == [
        ("system",),
        ("messages", 0, "content", 0, "content"),
    ]


def test_collect_request_texts_skips_empty_strings() -> None:
    body = {
        "system": "",
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": ""},
                    {"type": "tool_use", "id": "t1", "name": "W", "input": {"a": "", "b": "x"}},
                ],
            }
        ],
    }

    refs = collect_request_texts(body)

    assert [ref.path for ref in refs] == [("messages", 0, "content", 1, "input", "b")]


def test_collect_request_texts_skips_unknown_block_types() -> None:
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "document", "source": {"data": "Frau Müller"}},
                    {"type": "thinking", "thinking": "Frau Müller", "signature": "sig=="},
                ],
            }
        ]
    }

    assert collect_request_texts(body) == []


def test_pseudonymize_request_removes_every_original_value(
    request_body: dict, fake_session: FakeSession
) -> None:
    new_body, _ = pseudonymize_request(request_body, fake_session)

    texts = walk_strings(new_body["system"]) + walk_strings(new_body["messages"])
    for value in ORIGINAL_VALUES:
        assert not any(value in text for text in texts), value
    assert "<CUSTOMER_NAME_001>" in new_body["system"][1]["text"]
    assert "Frau <PERSON_FEMALE_001>" in new_body["messages"][2]["content"][0]["content"][0]["text"]


def test_pseudonymize_request_leaves_untouched_subtrees_byte_identical(
    request_body: dict, fake_session: FakeSession
) -> None:
    new_body, _ = pseudonymize_request(request_body, fake_session)

    assert canonical(new_body["tools"]) == canonical(request_body["tools"])
    assert canonical(new_body["metadata"]) == canonical(request_body["metadata"])
    assert new_body["model"] == request_body["model"]
    assert new_body["stream"] == request_body["stream"]
    thinking = new_body["messages"][1]["content"][0]
    assert canonical(thinking) == canonical(request_body["messages"][1]["content"][0])
    assert thinking["signature"] == request_body["messages"][1]["content"][0]["signature"]
    image = new_body["messages"][4]["content"][0]
    assert canonical(image) == canonical(request_body["messages"][4]["content"][0])


def test_pseudonymize_request_preserves_sibling_keys(
    request_body: dict, fake_session: FakeSession
) -> None:
    new_body, _ = pseudonymize_request(request_body, fake_session)

    assert new_body["system"][1]["cache_control"] == {"type": "ephemeral"}
    tool_use = new_body["messages"][3]["content"][0]
    assert tool_use["id"] == "toolu_02WriteLetter"
    assert tool_use["input"]["overwrite"] is True
    assert tool_use["input"]["retries"] == 2


def test_pseudonymize_request_does_not_mutate_the_input(
    request_body: dict, fake_session: FakeSession
) -> None:
    before = copy.deepcopy(request_body)

    pseudonymize_request(request_body, fake_session)

    assert request_body == before


def test_pseudonymize_request_counts_fields_and_calls_the_session_once(
    request_body: dict, fake_session: FakeSession
) -> None:
    _, count = pseudonymize_request(request_body, fake_session)

    assert count == len(EXPECTED_PATHS)
    assert len(fake_session.pseudonymize_calls) == 1
    assert len(fake_session.pseudonymize_calls[0]) == count


def test_pseudonymize_request_without_texts_makes_no_session_call(
    fake_session: FakeSession,
) -> None:
    body = {"model": "m", "messages": []}

    new_body, count = pseudonymize_request(body, fake_session)

    assert (new_body, count) == (body, 0)
    assert fake_session.pseudonymize_calls == []


def test_collect_request_texts_skips_system_when_excluded(request_body: dict) -> None:
    refs = collect_request_texts(request_body, include_system=False)

    assert [ref.path for ref in refs] == EXPECTED_PATHS[2:]


def test_pseudonymize_request_leaves_system_byte_identical_when_excluded(
    request_body: dict, fake_session: FakeSession
) -> None:
    new_body, _ = pseudonymize_request(request_body, fake_session, include_system=False)

    assert canonical(new_body["system"]) == canonical(request_body["system"])
    assert new_body["messages"][2]["content"][0]["content"][0]["text"] == (
        "Sehr geehrte Frau <PERSON_FEMALE_001>, IBAN <IBAN_001>"
    )


def test_pseudonymize_request_without_system_counts_fewer_fields(
    request_body: dict, fake_session: FakeSession
) -> None:
    system_blocks = len([path for path in EXPECTED_PATHS if path[0] == "system"])

    _, count = pseudonymize_request(request_body, fake_session, include_system=False)

    assert count == len(EXPECTED_PATHS) - system_blocks


def test_pseudonymize_request_with_a_string_system_leaves_it_alone(
    fake_session: FakeSession,
) -> None:
    body = {
        "system": "Du bist Claude. Frau Müller",
        "messages": [{"role": "user", "content": "Frau Müller"}],
    }

    new_body, count = pseudonymize_request(body, fake_session, include_system=False)

    assert new_body["system"] == "Du bist Claude. Frau Müller"
    assert new_body["messages"][0]["content"] == "Frau <PERSON_FEMALE_001>"
    assert count == 1


def test_notice_turns_a_string_content_into_a_block_list(fake_session: FakeSession) -> None:
    body = {"messages": [{"role": "user", "content": "Frau Müller"}]}

    new_body, count = pseudonymize_request(body, fake_session, notice=True)

    assert new_body["messages"][0]["content"] == [
        {"type": "text", "text": NOTICE_TEXT},
        {"type": "text", "text": "Frau <PERSON_FEMALE_001>"},
    ]
    assert count == 2


def test_notice_is_prepended_to_an_existing_block_list(fake_session: FakeSession) -> None:
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "image", "source": {"data": "x"}},
                    {"type": "text", "text": "Frau Müller"},
                ],
            }
        ]
    }

    new_body, _ = pseudonymize_request(body, fake_session, notice=True)

    content = new_body["messages"][0]["content"]
    assert content[0] == {"type": "text", "text": NOTICE_TEXT}
    assert content[1]["type"] == "image"
    assert content[2]["text"] == "Frau <PERSON_FEMALE_001>"


def test_notice_is_inserted_only_once(fake_session: FakeSession) -> None:
    body = {"messages": [{"role": "user", "content": "Frau Müller"}]}

    once, _ = pseudonymize_request(body, fake_session, notice=True)
    twice, count = pseudonymize_request(once, fake_session, notice=True)

    assert twice == once
    assert count == 2


def test_notice_is_not_inserted_when_disabled(fake_session: FakeSession) -> None:
    body = {"messages": [{"role": "user", "content": "Frau Müller"}]}

    new_body, count = pseudonymize_request(body, fake_session)

    assert new_body["messages"][0]["content"] == "Frau <PERSON_FEMALE_001>"
    assert count == 1


def test_notice_goes_to_the_first_user_message_not_an_assistant_one(
    fake_session: FakeSession,
) -> None:
    body = {
        "messages": [
            {"role": "assistant", "content": [{"type": "text", "text": "Hallo"}]},
            {"role": "user", "content": [{"type": "text", "text": "Frau Müller"}]},
            {"role": "user", "content": [{"type": "text", "text": "Noch etwas"}]},
        ]
    }

    new_body, _ = pseudonymize_request(body, fake_session, notice=True)

    assert new_body["messages"][0]["content"] == [{"type": "text", "text": "Hallo"}]
    assert new_body["messages"][1]["content"][0]["text"] == NOTICE_TEXT
    assert new_body["messages"][2]["content"] == [{"type": "text", "text": "Noch etwas"}]


def test_notice_is_not_inserted_without_any_transformable_text(
    fake_session: FakeSession,
) -> None:
    body = {"model": "m", "messages": []}

    new_body, count = pseudonymize_request(body, fake_session, notice=True)

    assert (new_body, count) == (body, 0)
    assert fake_session.pseudonymize_calls == []


def test_notice_does_not_touch_the_system_prompt(
    request_body: dict, fake_session: FakeSession
) -> None:
    new_body, _ = pseudonymize_request(request_body, fake_session, notice=True)

    assert NOTICE_TEXT not in canonical(new_body["system"])
    assert new_body["messages"][0]["content"][0]["text"] == NOTICE_TEXT


def test_restore_response_restores_text_and_tool_use_input(
    response_body: dict, fake_session: FakeSession
) -> None:
    restored = restore_response(response_body, fake_session)

    assert restored["content"][1]["text"] == (
        "Hallo Frau Müller, die Alpenbank AG nutzt DE89370400440532013000."
    )
    tool_input = restored["content"][2]["input"]
    assert tool_input["content"] == (
        "Sehr geehrte Frau Müller, Ihre IBAN DE89370400440532013000 liegt vor."
    )
    assert tool_input["tags"] == ["Alpenbank AG", 7, None]
    assert tool_input["overwrite"] is True
    assert tool_input["retries"] == 2


def test_restore_response_leaves_thinking_and_metadata_untouched(
    response_body: dict, fake_session: FakeSession
) -> None:
    restored = restore_response(response_body, fake_session)

    assert canonical(restored["content"][0]) == canonical(response_body["content"][0])
    assert restored["usage"] == response_body["usage"]
    assert restored["stop_reason"] == "tool_use"


def test_restore_response_does_not_mutate_the_input(
    response_body: dict, fake_session: FakeSession
) -> None:
    before = copy.deepcopy(response_body)

    restore_response(response_body, fake_session)

    assert response_body == before


def test_restore_response_without_content_returns_a_copy(fake_session: FakeSession) -> None:
    body = {"type": "error", "error": {"type": "overloaded_error", "message": "x"}}

    assert restore_response(body, fake_session) == body


def test_restore_json_recurses_and_keeps_non_string_leaves() -> None:
    value = {
        "a": "x",
        "b": [1, True, None, 2.5, "x", {"c": "x"}],
        "d": {"e": {"f": ["x"]}},
    }

    restored = restore_json(value, lambda text: text.upper())

    assert restored == {
        "a": "X",
        "b": [1, True, None, 2.5, "X", {"c": "X"}],
        "d": {"e": {"f": ["X"]}},
    }


def test_restore_json_does_not_touch_dict_keys() -> None:
    assert restore_json({"x": "x"}, lambda text: text.upper()) == {"x": "X"}


def test_text_document_blocks_are_collected() -> None:
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {"type": "text", "media_type": "text/plain", "data": "IBAN"},
                    },
                    {
                        "type": "document",
                        "source": {"type": "base64", "media_type": "application/pdf",
                                   "data": "JVBERi0="},
                    },
                ],
            }
        ]
    }

    refs = collect_request_texts(body)

    assert refs == [TextRef(("messages", 0, "content", 0, "source", "data"), "IBAN")]

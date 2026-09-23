from __future__ import annotations

import pytest

from privacy_gateway.model import (
    DetectionReport,
    Entity,
    Finding,
    Leak,
    LeakageError,
    PrivacyGatewayError,
    PseudonymizeResult,
    RestoreResult,
    SessionInfo,
    Span,
    SummaryReport,
    VaultEntry,
)


def test_span_len() -> None:
    assert len(Span(5, 12)) == 7
    assert len(Span(0, 0)) == 0


def test_span_overlaps_intersecting_ranges() -> None:
    assert Span(0, 10).overlaps(Span(5, 15))
    assert Span(5, 15).overlaps(Span(0, 10))
    assert Span(0, 10).overlaps(Span(2, 4))


def test_span_touching_ends_do_not_overlap() -> None:
    assert not Span(0, 10).overlaps(Span(10, 20))
    assert not Span(10, 20).overlaps(Span(0, 10))


def test_span_disjoint_do_not_overlap() -> None:
    assert not Span(0, 5).overlaps(Span(7, 9))


def test_span_contains() -> None:
    assert Span(0, 10).contains(Span(2, 4))
    assert Span(0, 10).contains(Span(0, 10))
    assert not Span(2, 4).contains(Span(0, 10))
    assert not Span(0, 10).contains(Span(5, 15))


def test_span_is_ordered_and_hashable() -> None:
    assert Span(0, 5) < Span(1, 2)
    assert len({Span(0, 5), Span(0, 5)}) == 1


def test_finding_defaults() -> None:
    finding = Finding(span=Span(0, 4), data_class="EMAIL", stage="pattern", confidence=0.9)
    assert finding.entity_id is None
    assert finding.attributes == {}
    assert finding.children == []


def test_entity_defaults() -> None:
    entity = Entity(id="e1", data_class="PERSON_LAST_NAME", canonical_norm="mueller", spans=[])
    assert entity.attributes == {}


def test_detection_report_counts_by_class() -> None:
    report = DetectionReport(
        findings=[
            Finding(span=Span(0, 4), data_class="EMAIL", stage="structured", confidence=0.98),
            Finding(span=Span(5, 9), data_class="EMAIL", stage="structured", confidence=0.98),
            Finding(span=Span(10, 14), data_class="IBAN", stage="pattern", confidence=0.95),
        ],
        entities={},
        stage_stats={"structured": 2, "pattern": 1},
    )
    assert report.counts_by_class() == {"EMAIL": 2, "IBAN": 1}


def test_detection_report_counts_by_class_empty() -> None:
    assert DetectionReport(findings=[], entities={}, stage_stats={}).counts_by_class() == {}


def test_exception_hierarchy() -> None:
    from privacy_gateway.model import ConfigError, RestoreError, VaultError

    for exc in (ConfigError, VaultError, RestoreError, LeakageError):
        assert issubclass(exc, PrivacyGatewayError)


def test_leakage_error_carries_leaks() -> None:
    leaks = [Leak(kind="original_value", data_class="IBAN", start=10, end=32)]
    error = LeakageError(leaks)
    assert error.leaks == leaks


def test_leakage_error_str_lists_kind_class_and_positions_only() -> None:
    error = LeakageError(
        [
            Leak(kind="original_value", data_class="IBAN", start=10, end=32),
            Leak(kind="unknown_token", data_class="", start=40, end=51),
        ]
    )
    text = str(error)
    assert "original_value" in text
    assert "IBAN" in text
    assert "10" in text and "32" in text
    assert "unknown_token" in text
    assert "40" in text and "51" in text
    assert text == "original_value IBAN 10-32; unknown_token  40-51"


def test_leakage_error_can_be_raised() -> None:
    with pytest.raises(PrivacyGatewayError):
        raise LeakageError([Leak(kind="residual_finding", data_class="EMAIL", start=0, end=5)])


def test_result_types() -> None:
    summary = SummaryReport(
        counts={"EMAIL": 1}, tokens=["<EMAIL_001>"], leakage="ok", duration_ms=3
    )
    result = PseudonymizeResult(text="x", session_id="s1", report=summary)
    assert result.report.leakage == "ok"

    restore = RestoreResult(text="y", restored_count=1, unknown_tokens=[])
    assert restore.restored_count == 1

    entry = VaultEntry(value="v", data_class="EMAIL", surface_forms=["v"], attributes={})
    assert entry.surface_forms == ["v"]

    info = SessionInfo(id="s1", created_at="2026-09-22T10:15:00+00:00", token_count=2)
    assert info.token_count == 2


def test_vault_entry_repr_hides_the_value() -> None:
    entry = VaultEntry(
        value="Müller",
        data_class="PERSON_LAST_NAME",
        surface_forms=["MÜLLER"],
        attributes={},
    )

    text = repr(entry)

    assert "Müller" not in text
    assert "MÜLLER" not in text
    assert "PERSON_LAST_NAME" in text


def test_restore_result_repr_hides_the_text() -> None:
    result = RestoreResult(text="Müller", restored_count=1, unknown_tokens=[])

    assert "Müller" not in repr(result)
    assert "restored_count=1" in repr(result)

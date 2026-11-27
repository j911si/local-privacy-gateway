"""The audit entry counts unchecked findings per field in time linear in fields and hits."""

from __future__ import annotations

import time

from privacy_gateway_proxy import audit_trail
from privacy_gateway_proxy.transform import UncheckedRef


def _build(fields: int) -> float:
    unchecked = [UncheckedRef((f"k{index}",), "unknown_field", 1) for index in range(fields)]
    observed = [audit_trail.Hit((f"k{index}", "#key"), "EMAIL", 0, 5) for index in range(fields)]
    best = float("inf")
    for _ in range(3):
        started = time.process_time()
        audit_trail.entry(
            session_key="s", path="/v1/messages", streaming=False, duration_ms=0, verdict="ok",
            checked=[], findings=[], unchecked=unchecked, observed=observed, leakage="ok",
            payload=None, rescan=audit_trail.Rescan("findings", observed),
        )
        best = min(best, time.process_time() - started)
    return best


def test_counts_scale_linearly() -> None:
    small, large = _build(2_000), _build(8_000)
    # ponytail: 4x the fields; linear costs ~4x, the old scan per field cost ~16x.
    assert large < 1.0
    assert large < 0.02 or large / small < 8


def test_counts_land_on_their_field() -> None:
    unchecked = [UncheckedRef(("a",), "unknown_field", 1), UncheckedRef(("b",), "unknown_field", 1)]
    observed = [audit_trail.Hit(("a", "x"), "EMAIL", 0, 5), audit_trail.Hit(("a",), "IBAN", 0, 5)]
    record = audit_trail.entry(
        session_key="s", path="/v1/messages", streaming=False, duration_ms=0, verdict="ok",
        checked=[], findings=[], unchecked=unchecked, observed=observed, leakage="ok",
        payload=None, rescan=audit_trail.Rescan("findings", observed),
    )
    observed_per_field = [item["observed"] for item in record["fields"]]
    assert observed_per_field == [
        [{"cls": "EMAIL", "count": 1}, {"cls": "IBAN", "count": 1}],
        [],
    ]

"""Core data types and exceptions shared by every stage."""

from __future__ import annotations

from dataclasses import dataclass, field


class PrivacyGatewayError(Exception):
    """Base class for all errors raised by the gateway."""


class ConfigError(PrivacyGatewayError):
    """Raised when configuration is invalid or unknown."""


class VaultError(PrivacyGatewayError):
    """Raised when the encrypted vault cannot be read or written."""


class RestoreError(PrivacyGatewayError):
    """Raised when a token cannot be restored."""


@dataclass(frozen=True)
class Leak:
    """One potential leak found in pseudonymized text."""

    kind: str
    data_class: str
    start: int
    end: int


class LeakageError(PrivacyGatewayError):
    """Raised when leakage validation finds sensitive residue."""

    def __init__(self, leaks: list[Leak]) -> None:
        self.leaks: list[Leak] = leaks
        super().__init__(self._describe(leaks))

    @staticmethod
    def _describe(leaks: list[Leak]) -> str:
        return "; ".join(f"{i.kind} {i.data_class} {i.start}-{i.end}" for i in leaks)


@dataclass(frozen=True, order=True)
class Span:
    """Character offsets into the original text."""

    start: int
    end: int

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: Span) -> bool:
        return self.start <= other.start and other.end <= self.end

    def __len__(self) -> int:
        return self.end - self.start


@dataclass
class Finding:
    """A detected piece of sensitive data; never carries the value itself."""

    span: Span
    data_class: str
    stage: str
    confidence: float
    entity_id: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    children: list[Finding] = field(default_factory=list)


@dataclass
class Entity:
    """A real-world subject that several findings refer to."""

    id: str
    data_class: str
    canonical_norm: str
    spans: list[Span]
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class DetectionReport:
    """Result of a full detection pipeline run."""

    findings: list[Finding]
    entities: dict[str, Entity]
    stage_stats: dict[str, int]

    def counts_by_class(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.data_class] = counts.get(finding.data_class, 0) + 1
        return counts


@dataclass
class SummaryReport:
    """Value-free summary of a pseudonymization run."""

    counts: dict[str, int]
    tokens: list[str]
    leakage: str
    duration_ms: int


@dataclass
class PseudonymizeResult:
    """Pseudonymized text plus the session needed to restore it."""

    text: str
    session_id: str
    report: SummaryReport


@dataclass
class RestoreResult:
    """Restored text plus tokens that could not be resolved."""

    text: str = field(repr=False)
    restored_count: int
    unknown_tokens: list[str]


@dataclass
class VaultEntry:
    """One decrypted token mapping."""

    value: str = field(repr=False)
    data_class: str
    surface_forms: list[str] = field(repr=False)
    attributes: dict[str, str]


@dataclass
class SessionInfo:
    """Metadata about a stored session."""

    id: str
    created_at: str
    token_count: int

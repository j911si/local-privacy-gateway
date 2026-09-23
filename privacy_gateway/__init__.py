"""Offline pseudonymization gateway between documents and external LLMs."""

from __future__ import annotations

from privacy_gateway.api import Gateway, GatewaySession
from privacy_gateway.model import (
    ConfigError,
    DetectionReport,
    Entity,
    Finding,
    Leak,
    LeakageError,
    PrivacyGatewayError,
    PseudonymizeResult,
    RestoreError,
    RestoreResult,
    SessionInfo,
    Span,
    SummaryReport,
    VaultEntry,
    VaultError,
)

__all__ = [
    "ConfigError",
    "DetectionReport",
    "Entity",
    "Finding",
    "Gateway",
    "GatewaySession",
    "Leak",
    "LeakageError",
    "PrivacyGatewayError",
    "PseudonymizeResult",
    "RestoreError",
    "RestoreResult",
    "SessionInfo",
    "Span",
    "SummaryReport",
    "VaultEntry",
    "VaultError",
]

__version__ = "0.1.0"

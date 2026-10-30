"""Shared result type for audits and lint checks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"   # will be rejected / spam-foldered, or is illegal
    WARN = "warn"     # hurts reputation or inbox placement
    INFO = "info"     # nice to have


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    message: str

    def __str__(self) -> str:
        icon = {"error": "✗", "warn": "!", "info": "·"}[self.severity.value]
        return f"[{icon} {self.severity.value.upper():5}] {self.code}: {self.message}"


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity is Severity.ERROR for f in findings)

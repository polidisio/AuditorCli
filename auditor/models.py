from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Priority(str, Enum):
    HIGH = "alta"
    MEDIUM = "media"
    LOW = "baja"


class Finding(BaseModel):
    id: str
    title: str
    component: str
    vector: str
    mitre_id: str | None = None
    severity: Severity
    priority: Priority
    description: str
    evidence: str | None = None
    remediation: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditTarget(BaseModel):
    domain: str
    ip_ranges: list[str] = Field(default_factory=list)
    tenant_id: str | None = None
    authorized: bool = False


class AuditSession(BaseModel):
    id: str
    target: AuditTarget
    started_at: datetime = Field(default_factory=datetime.utcnow)
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == Priority.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == Priority.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.priority == Priority.LOW)

"""Core data models for security findings."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Vector(str, Enum):
    CRYPTO_MINING = "crypto_mining"
    GEMINI_ABUSE = "gemini_abuse"
    COMMON = "common"


class FindingStatus(str, Enum):
    FAIL = "FAIL"
    PASS = "PASS"  # nosec B105 — not a password; this is a finding status enum value
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class RemediationEffort(str, Enum):
    LOW = "LOW"  # < 1 hour
    MEDIUM = "MEDIUM"  # 1–4 hours
    HIGH = "HIGH"  # > 4 hours / requires planning


class GCPResource(BaseModel):
    """Identifies a GCP resource associated with a finding."""

    resource_type: str = Field(description="e.g. 'compute.googleapis.com/Instance'")
    resource_id: str = Field(description="Full resource name or ID")
    project_id: str
    organization_id: str | None = None
    region: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class Remediation(BaseModel):
    """Actionable remediation guidance for a finding."""

    summary: str
    steps: list[str] = Field(default_factory=list)
    gcloud_commands: list[str] = Field(default_factory=list)
    iac_reference: str | None = None
    docs: list[str] = Field(default_factory=list)
    effort: RemediationEffort = RemediationEffort.MEDIUM
    auto_remediable: bool = False


class Finding(BaseModel):
    """A single security finding produced by a check."""

    finding_id: str = Field(description="Unique ID: {check_id}-{project_id}-{resource_hash}")
    check_id: str = Field(description="e.g. 'GEM-002'")
    vector: Vector
    title: str
    severity: Severity
    status: FindingStatus = FindingStatus.FAIL

    # Prioritization
    priority_rank: int | None = None
    exploitability_score: float = Field(default=5.0, ge=0.0, le=10.0)
    blast_radius: str = Field(
        default="project", description="project | organization | billing_account"
    )

    # Context
    resource: GCPResource
    evidence: dict[str, Any] = Field(default_factory=dict)
    description: str
    impact: str

    # Remediation
    remediation: Remediation

    # Metadata
    references: list[str] = Field(default_factory=list)
    first_detected: datetime = Field(default_factory=lambda: datetime.now(UTC))
    suppressed: bool = False
    suppression_reason: str | None = None

    @model_validator(mode="after")
    def validate_finding_id(self) -> Finding:
        if not self.finding_id:
            raise ValueError("finding_id must not be empty")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

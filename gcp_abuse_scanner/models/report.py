"""Scan report model — top-level output of a scanner run."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from gcp_abuse_scanner.models.finding import Finding, Severity, Vector


class ScanMetadata(BaseModel):
    tool_name: str = "gcp-abuse-scanner"
    tool_version: str = "0.1.0"
    scan_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    scope_type: str = Field(description="organization | project_list")
    organization_id: str | None = None
    project_ids: list[str] = Field(default_factory=list)
    service_account: str | None = None
    vectors_scanned: list[str] = Field(default_factory=list)


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class VectorSummary(BaseModel):
    vector: str
    findings_count: int = 0
    by_severity: SeveritySummary = Field(default_factory=SeveritySummary)


class CoverageReport(BaseModel):
    projects_scanned: int = 0
    projects_inaccessible: int = 0
    inaccessible_project_ids: list[str] = Field(default_factory=list)
    checks_executed: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_not_applicable: int = 0
    checks_skipped: int = 0
    checks_errored: int = 0
    skipped_apis_by_project: dict[str, list[str]] = Field(default_factory=dict)
    collector_errors: list[dict[str, str]] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    posture_score: float = Field(
        description="0–100 score (100 = no findings). Weighted by severity.",
        ge=0.0,
        le=100.0,
    )
    total_findings: int = 0
    by_severity: SeveritySummary = Field(default_factory=SeveritySummary)
    by_vector: list[VectorSummary] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Top 10 findings by priority_rank (summary fields only)",
    )


class ScanReport(BaseModel):
    """Top-level output of a gcp-abuse-scanner run."""

    metadata: ScanMetadata
    executive_summary: ExecutiveSummary
    coverage: CoverageReport
    findings: list[Finding] = Field(default_factory=list)

    # Convenience accessors
    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity and not f.suppressed]

    def findings_by_vector(self, vector: Vector) -> list[Finding]:
        return [f for f in self.findings if f.vector == vector and not f.suppressed]

    def prioritized_findings(self) -> list[Finding]:
        """Return active findings sorted by priority_rank, then severity."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        active = [f for f in self.findings if not f.suppressed]
        return sorted(
            active,
            key=lambda f: (
                f.priority_rank if f.priority_rank is not None else 9999,
                severity_order.get(f.severity, 5),
            ),
        )

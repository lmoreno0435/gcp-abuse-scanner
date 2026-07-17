"""Unit tests for the scoring engine."""

from __future__ import annotations

from gcp_abuse_scanner.models.finding import (
    Finding,
    FindingStatus,
    GCPResource,
    Remediation,
    RemediationEffort,
    Severity,
    Vector,
)
from gcp_abuse_scanner.scoring.engine import ScoringEngine


def _make_finding(
    check_id: str,
    severity: Severity,
    exploitability: float = 5.0,
    blast_radius: str = "project",
    project_id: str = "test-project",
) -> Finding:
    return Finding(
        finding_id=f"{check_id}-{project_id}-test",
        check_id=check_id,
        vector=Vector.CRYPTO_MINING,
        title=f"Test finding {check_id}",
        severity=severity,
        status=FindingStatus.FAIL,
        exploitability_score=exploitability,
        blast_radius=blast_radius,
        resource=GCPResource(
            resource_type="compute.googleapis.com/Instance",
            resource_id=f"projects/{project_id}/instances/test-vm",
            project_id=project_id,
        ),
        description="Test description",
        impact="Test impact",
        remediation=Remediation(
            summary="Test remediation",
            effort=RemediationEffort.LOW,
        ),
    )


class TestScoringEngine:
    def test_priority_ranks_assigned(self) -> None:
        findings = [
            _make_finding("CM-001", Severity.LOW, exploitability=2.0),
            _make_finding("CM-004", Severity.CRITICAL, exploitability=9.5),
            _make_finding("CM-009", Severity.MEDIUM, exploitability=4.0),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)

        ranked = sorted(result, key=lambda f: f.priority_rank or 9999)
        assert ranked[0].check_id == "CM-004"  # CRITICAL + highest exploitability
        assert ranked[-1].check_id == "CM-001"  # LOW + lowest exploitability

    def test_allowlist_suppresses_finding(self) -> None:
        findings = [
            _make_finding("CM-001", Severity.HIGH, project_id="allowed-project"),
            _make_finding("CM-004", Severity.CRITICAL, project_id="other-project"),
        ]
        allowlist = [{"check_id": "CM-001", "project_id": "allowed-project", "reason": "Known exception"}]
        engine = ScoringEngine(allowlist=allowlist)
        result = engine.process(findings)

        suppressed = [f for f in result if f.suppressed]
        active = [f for f in result if not f.suppressed]
        assert len(suppressed) == 1
        assert suppressed[0].check_id == "CM-001"
        assert len(active) == 1
        assert active[0].check_id == "CM-004"

    def test_blast_radius_affects_priority(self) -> None:
        # Same exploitability, different blast radius
        findings = [
            _make_finding("CM-001", Severity.HIGH, exploitability=7.0, blast_radius="project"),
            _make_finding("CM-002", Severity.HIGH, exploitability=7.0, blast_radius="billing_account"),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)
        ranked = sorted(result, key=lambda f: f.priority_rank or 9999)
        assert ranked[0].check_id == "CM-002"  # billing_account has higher weight

    def test_posture_score_100_when_no_findings(self) -> None:
        engine = ScoringEngine()
        summary = engine.build_executive_summary([], max_projects=1)
        assert summary.posture_score == 100.0

    def test_posture_score_decreases_with_critical_findings(self) -> None:
        findings = [
            _make_finding("CM-004", Severity.CRITICAL, exploitability=9.5)
            for _ in range(5)
        ]
        engine = ScoringEngine()
        processed = engine.process(findings)
        summary = engine.build_executive_summary(processed, max_projects=1)
        assert summary.posture_score < 100.0
        assert summary.by_severity.critical == 5

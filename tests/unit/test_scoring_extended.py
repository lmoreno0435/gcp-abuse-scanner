"""Extended scoring engine tests — allowlist edge cases, posture score, executive summary."""

from __future__ import annotations

import pytest

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


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _f(
    check_id: str = "CM-001",
    severity: Severity = Severity.HIGH,
    vector: Vector = Vector.CRYPTO_MINING,
    exploitability: float = 5.0,
    blast_radius: str = "project",
    project_id: str = "proj-1",
    resource_id: str = "projects/proj-1/instances/vm-1",
    status: FindingStatus = FindingStatus.FAIL,
    suppressed: bool = False,
) -> Finding:
    return Finding(
        finding_id=f"{check_id}-{project_id}-x",
        check_id=check_id,
        vector=vector,
        title=f"Test {check_id}",
        severity=severity,
        status=status,
        exploitability_score=exploitability,
        blast_radius=blast_radius,
        suppressed=suppressed,
        resource=GCPResource(
            resource_type="compute.googleapis.com/Instance",
            resource_id=resource_id,
            project_id=project_id,
        ),
        description="desc",
        impact="impact",
        remediation=Remediation(summary="fix", effort=RemediationEffort.LOW),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Allowlist edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestAllowlist:
    def test_wildcard_check_id_suppresses_all_projects(self):
        """Rule with no project_id suppresses all findings for that check."""
        findings = [
            _f("CM-001", project_id="proj-1"),
            _f("CM-001", project_id="proj-2"),
            _f("CM-004", project_id="proj-1"),
        ]
        engine = ScoringEngine(allowlist=[{"check_id": "CM-001", "reason": "global exception"}])
        result = engine.process(findings)

        suppressed = [f for f in result if f.suppressed]
        active = [f for f in result if not f.suppressed]
        assert len(suppressed) == 2
        assert all(f.check_id == "CM-001" for f in suppressed)
        assert len(active) == 1
        assert active[0].check_id == "CM-004"

    def test_project_specific_rule_only_suppresses_that_project(self):
        findings = [
            _f("CM-001", project_id="proj-1"),
            _f("CM-001", project_id="proj-2"),
        ]
        engine = ScoringEngine(allowlist=[{"check_id": "CM-001", "project_id": "proj-1"}])
        result = engine.process(findings)

        suppressed = [f for f in result if f.suppressed]
        assert len(suppressed) == 1
        assert suppressed[0].resource.project_id == "proj-1"

    def test_resource_id_partial_match(self):
        """resource_id in allowlist uses substring match."""
        findings = [
            _f("CM-001", resource_id="projects/proj-1/instances/vm-special"),
            _f("CM-001", resource_id="projects/proj-1/instances/vm-other"),
        ]
        engine = ScoringEngine(allowlist=[{"check_id": "CM-001", "resource_id": "vm-special"}])
        result = engine.process(findings)

        suppressed = [f for f in result if f.suppressed]
        assert len(suppressed) == 1
        assert "vm-special" in suppressed[0].resource.resource_id

    def test_suppression_reason_stored(self):
        findings = [_f("CM-001")]
        engine = ScoringEngine(allowlist=[{"check_id": "CM-001", "reason": "Approved by security team"}])
        result = engine.process(findings)

        suppressed = next(f for f in result if f.suppressed)
        assert suppressed.suppression_reason == "Approved by security team"

    def test_suppression_reason_default_when_absent(self):
        findings = [_f("CM-001")]
        engine = ScoringEngine(allowlist=[{"check_id": "CM-001"}])
        result = engine.process(findings)

        suppressed = next(f for f in result if f.suppressed)
        assert suppressed.suppression_reason is not None
        assert len(suppressed.suppression_reason) > 0

    def test_empty_allowlist_suppresses_nothing(self):
        findings = [_f("CM-001"), _f("CM-004")]
        engine = ScoringEngine(allowlist=[])
        result = engine.process(findings)

        assert all(not f.suppressed for f in result)

    def test_already_suppressed_finding_stays_suppressed(self):
        """Pre-suppressed findings are not double-processed."""
        findings = [_f("CM-001", suppressed=True)]
        engine = ScoringEngine(allowlist=[])
        result = engine.process(findings)

        assert result[0].suppressed is True

    def test_allowlist_rule_with_only_project_id(self):
        """Rule with only project_id suppresses all checks in that project."""
        findings = [
            _f("CM-001", project_id="proj-sandbox"),
            _f("GEM-001", project_id="proj-sandbox", vector=Vector.GEMINI_ABUSE),
            _f("CM-001", project_id="proj-prod"),
        ]
        engine = ScoringEngine(allowlist=[{"project_id": "proj-sandbox", "reason": "sandbox"}])
        result = engine.process(findings)

        suppressed = [f for f in result if f.suppressed]
        assert len(suppressed) == 2
        assert all(f.resource.project_id == "proj-sandbox" for f in suppressed)


# ─────────────────────────────────────────────────────────────────────────────
# Priority ranking
# ─────────────────────────────────────────────────────────────────────────────

class TestPriorityRanking:
    def test_ranks_start_at_one(self):
        findings = [_f("CM-001"), _f("CM-004")]
        engine = ScoringEngine()
        result = engine.process(findings)

        active = [f for f in result if not f.suppressed]
        ranks = sorted(f.priority_rank for f in active)
        assert ranks[0] == 1

    def test_ranks_are_unique(self):
        findings = [_f(f"CM-00{i}", exploitability=float(i)) for i in range(1, 6)]
        engine = ScoringEngine()
        result = engine.process(findings)

        active = [f for f in result if not f.suppressed]
        ranks = [f.priority_rank for f in active]
        assert len(ranks) == len(set(ranks))

    def test_suppressed_findings_have_no_rank_in_active_set(self):
        findings = [
            _f("CM-001", severity=Severity.CRITICAL),
            _f("CM-004", severity=Severity.HIGH),
        ]
        engine = ScoringEngine(allowlist=[{"check_id": "CM-001"}])
        result = engine.process(findings)

        active = [f for f in result if not f.suppressed]
        assert len(active) == 1
        assert active[0].priority_rank == 1

    def test_organization_blast_radius_ranks_higher_than_project(self):
        findings = [
            _f("CM-001", blast_radius="project", exploitability=8.0),
            _f("CM-002", blast_radius="organization", exploitability=8.0),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)

        ranked = sorted(result, key=lambda f: f.priority_rank or 9999)
        assert ranked[0].check_id == "CM-002"

    def test_higher_exploitability_ranks_first_same_severity(self):
        findings = [
            _f("CM-001", severity=Severity.HIGH, exploitability=3.0),
            _f("CM-002", severity=Severity.HIGH, exploitability=9.0),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)

        ranked = sorted(result, key=lambda f: f.priority_rank or 9999)
        assert ranked[0].check_id == "CM-002"

    def test_single_finding_gets_rank_one(self):
        findings = [_f("CM-001")]
        engine = ScoringEngine()
        result = engine.process(findings)
        assert result[0].priority_rank == 1


# ─────────────────────────────────────────────────────────────────────────────
# Posture score
# ─────────────────────────────────────────────────────────────────────────────

class TestPostureScore:
    def test_score_100_no_findings(self):
        engine = ScoringEngine()
        summary = engine.build_executive_summary([], max_projects=1)
        assert summary.posture_score == 100.0

    def test_score_decreases_with_more_findings(self):
        engine = ScoringEngine()
        few = [_f("CM-001", severity=Severity.HIGH)]
        many = [_f(f"CM-00{i}", severity=Severity.HIGH) for i in range(1, 8)]

        score_few = engine.build_executive_summary(few, max_projects=1).posture_score
        score_many = engine.build_executive_summary(many, max_projects=1).posture_score

        assert score_few > score_many

    def test_score_never_negative(self):
        engine = ScoringEngine()
        findings = [_f(f"CM-{i:03d}", severity=Severity.CRITICAL, exploitability=10.0) for i in range(50)]
        summary = engine.build_executive_summary(findings, max_projects=1)
        assert summary.posture_score >= 0.0

    def test_score_never_above_100(self):
        engine = ScoringEngine()
        findings = [_f("CM-001", severity=Severity.LOW)]
        summary = engine.build_executive_summary(findings, max_projects=100)
        assert summary.posture_score <= 100.0

    def test_critical_penalizes_more_than_low(self):
        engine = ScoringEngine()
        critical = [_f("CM-001", severity=Severity.CRITICAL)]
        low = [_f("CM-001", severity=Severity.LOW)]

        score_critical = engine.build_executive_summary(critical, max_projects=1).posture_score
        score_low = engine.build_executive_summary(low, max_projects=1).posture_score

        assert score_critical < score_low

    def test_suppressed_findings_not_counted_in_score(self):
        engine = ScoringEngine()
        findings = [_f("CM-001", severity=Severity.CRITICAL, suppressed=True)]
        summary = engine.build_executive_summary(findings, max_projects=1)
        assert summary.posture_score == 100.0

    def test_score_is_rounded_to_one_decimal(self):
        engine = ScoringEngine()
        findings = [_f("CM-001", severity=Severity.HIGH)]
        summary = engine.build_executive_summary(findings, max_projects=1)
        # Should be a float with at most 1 decimal place
        assert summary.posture_score == round(summary.posture_score, 1)


# ─────────────────────────────────────────────────────────────────────────────
# Executive summary
# ─────────────────────────────────────────────────────────────────────────────

class TestExecutiveSummary:
    def test_total_findings_excludes_suppressed(self):
        findings = [
            _f("CM-001", suppressed=False),
            _f("CM-002", suppressed=True),
        ]
        engine = ScoringEngine()
        summary = engine.build_executive_summary(findings, max_projects=1)
        assert summary.total_findings == 1

    def test_by_severity_counts_correct(self):
        findings = [
            _f("CM-001", severity=Severity.CRITICAL),
            _f("CM-002", severity=Severity.CRITICAL),
            _f("CM-003", severity=Severity.HIGH),
            _f("CM-004", severity=Severity.MEDIUM),
            _f("CM-005", severity=Severity.LOW),
        ]
        engine = ScoringEngine()
        summary = engine.build_executive_summary(findings, max_projects=1)

        assert summary.by_severity.critical == 2
        assert summary.by_severity.high == 1
        assert summary.by_severity.medium == 1
        assert summary.by_severity.low == 1
        assert summary.by_severity.total == 5

    def test_by_vector_present_for_all_vectors(self):
        findings = [
            _f("CM-001", vector=Vector.CRYPTO_MINING),
            _f("GEM-001", vector=Vector.GEMINI_ABUSE),
        ]
        engine = ScoringEngine()
        summary = engine.build_executive_summary(findings, max_projects=1)

        vector_names = {v.vector for v in summary.by_vector}
        assert "crypto_mining" in vector_names
        assert "gemini_abuse" in vector_names

    def test_top_findings_capped_at_10(self):
        findings = [_f(f"CM-{i:03d}", severity=Severity.HIGH) for i in range(1, 20)]
        engine = ScoringEngine()
        result = engine.process(findings)
        summary = engine.build_executive_summary(result, max_projects=1)

        assert len(summary.top_findings) <= 10

    def test_top_findings_ordered_by_priority(self):
        findings = [
            _f("CM-001", severity=Severity.LOW, exploitability=1.0),
            _f("CM-002", severity=Severity.CRITICAL, exploitability=9.5),
            _f("CM-003", severity=Severity.HIGH, exploitability=7.0),
        ]
        engine = ScoringEngine()
        result = engine.process(findings)
        summary = engine.build_executive_summary(result, max_projects=1)

        ranks = [tf["priority_rank"] for tf in summary.top_findings]
        assert ranks == sorted(ranks)

    def test_empty_findings_summary(self):
        engine = ScoringEngine()
        summary = engine.build_executive_summary([], max_projects=5)

        assert summary.total_findings == 0
        assert summary.posture_score == 100.0
        assert summary.by_severity.total == 0
        assert summary.top_findings == []

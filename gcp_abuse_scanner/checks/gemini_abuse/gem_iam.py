"""
Gemini Abuse checks — IAM on Vertex AI / Gemini.

GEM-020: Broad aiplatform.user / aiplatform.admin grants
GEM-021: allUsers/allAuthenticatedUsers on Vertex AI resources
GEM-022: SA with Vertex AI access AND exported keys
"""

from __future__ import annotations

import hashlib

from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry
from gcp_abuse_scanner.models.finding import (
    Finding,
    FindingStatus,
    GCPResource,
    Remediation,
    RemediationEffort,
    Severity,
    Vector,
)
from gcp_abuse_scanner.models.inventory import ResourceInventory

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
_VERTEX_ROLES = {
    "roles/aiplatform.user",
    "roles/aiplatform.admin",
    "roles/aiplatform.endpointUser",
    "roles/ml.admin",
    "roles/ml.developer",
}
_BROAD_MEMBER_PREFIXES = ("domain:", "group:")


def _make_id(check_id: str, project_id: str, key: str) -> str:
    h = hashlib.md5(key.encode()).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


def _is_broad_member(member: str) -> bool:
    return any(member.startswith(p) for p in _BROAD_MEMBER_PREFIXES)


@CheckRegistry.register
class GEM020BroadVertexIAM(BaseCheck):
    """Vertex AI roles granted to broad principals (domains, large groups)."""

    check_id = "GEM-020"
    title = "Vertex AI / Gemini role granted to a broad principal (domain or group)"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    tags = ["iam", "gemini_abuse", "vertex_ai"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
            if binding.role not in _VERTEX_ROLES:
                continue
            broad = [m for m in binding.members if _is_broad_member(m)]
            if not broad:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id, binding.project_id, f"{binding.resource}-{binding.role}"
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.5,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type=binding.resource_type,
                        resource_id=binding.resource,
                        project_id=binding.project_id,
                    ),
                    evidence={
                        "role": binding.role,
                        "broad_members": broad,
                        "all_members": binding.members,
                    },
                    description=(
                        f"Role '{binding.role}' (Vertex AI / Gemini access) is granted to "
                        f"broad principals: {broad}. This means any member of those domains "
                        "or groups can invoke Gemini models, creating a large abuse surface."
                    ),
                    impact=(
                        "Any member of the domain/group can call Gemini APIs, including "
                        "compromised accounts, leading to unauthorized cost generation."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Replace broad domain/group grants with specific user or SA "
                            "identities that actually need Vertex AI access."
                        ),
                        steps=[
                            "Audit who in the domain/group actually needs Vertex AI access.",
                            "Create a dedicated group with only those members.",
                            "Replace the broad binding with the scoped group or individual SAs.",
                            "Enable Org Policy: constraints/iam.allowedPolicyMemberDomains.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} "
                            f"--member=BROAD_MEMBER --role={binding.role}",
                            f"gcloud projects add-iam-policy-binding {binding.project_id} "
                            f"--member=serviceAccount:SPECIFIC_SA --role={binding.role}",
                        ],
                        iac_reference="google_project_iam_binding.members",
                        docs=["https://cloud.google.com/vertex-ai/docs/general/access-control"],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class GEM021PublicVertexBinding(BaseCheck):
    """allUsers/allAuthenticatedUsers granted Vertex AI roles."""

    check_id = "GEM-021"
    title = "Vertex AI role granted to allUsers or allAuthenticatedUsers"
    vector = Vector.GEMINI_ABUSE
    severity_base = Severity.CRITICAL
    required_collectors = ["iam"]
    tags = ["iam", "gemini_abuse", "vertex_ai", "public_access"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
            if binding.role not in _VERTEX_ROLES:
                continue
            public = [m for m in binding.members if m in _PUBLIC_MEMBERS]
            if not public:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id, binding.project_id, f"{binding.resource}-{binding.role}"
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=10.0,
                    blast_radius="billing_account",
                    resource=GCPResource(
                        resource_type=binding.resource_type,
                        resource_id=binding.resource,
                        project_id=binding.project_id,
                    ),
                    evidence={
                        "role": binding.role,
                        "public_members": public,
                    },
                    description=(
                        f"Role '{binding.role}' (Vertex AI / Gemini access) is granted to "
                        f"{public}. ANY internet user can invoke Gemini models on this project."
                    ),
                    impact=(
                        "CRITICAL: Any person on the internet can call Gemini APIs at the "
                        "project's expense. Immediate remediation required."
                    ),
                    remediation=Remediation(
                        summary="Immediately remove allUsers/allAuthenticatedUsers from Vertex AI bindings.",
                        steps=[
                            "Remove the public binding immediately.",
                            "Audit Vertex AI usage logs for unauthorized calls.",
                            "Grant access only to specific, authenticated identities.",
                            "File a support ticket if unauthorized usage is detected.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} "
                            f"--member=allUsers --role={binding.role}",
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} "
                            f"--member=allAuthenticatedUsers --role={binding.role}",
                        ],
                        iac_reference="google_project_iam_binding.members",
                        docs=["https://cloud.google.com/vertex-ai/docs/general/access-control"],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

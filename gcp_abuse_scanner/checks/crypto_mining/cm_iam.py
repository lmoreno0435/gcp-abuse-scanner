"""
Crypto Mining checks — IAM.

CM-043: allUsers/allAuthenticatedUsers bindings on project resources
CM-044: Default Compute SA with Editor role
CM-041: User-managed SA keys (long-lived credentials)
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
_COMPUTE_DEFAULT_SA_SUFFIX = "-compute@developer.gserviceaccount.com"
_EDITOR_ROLES = {"roles/editor", "roles/owner"}


def _make_id(check_id: str, project_id: str, key: str) -> str:
    h = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


@CheckRegistry.register
class CM043PublicIAMBinding(BaseCheck):
    """IAM bindings granting access to allUsers or allAuthenticatedUsers."""

    check_id = "CM-043"
    title = "IAM binding grants access to allUsers or allAuthenticatedUsers"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.CRITICAL
    required_collectors = ["iam"]
    references = ["CIS GCP 1.18"]
    tags = ["iam", "crypto_mining", "public_access"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
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
                    exploitability_score=9.8,
                    blast_radius="organization",
                    resource=GCPResource(
                        resource_type=binding.resource_type,
                        resource_id=binding.resource,
                        project_id=binding.project_id,
                    ),
                    evidence={
                        "role": binding.role,
                        "public_members": public,
                        "all_members": binding.members,
                    },
                    description=(
                        f"Role '{binding.role}' is granted to {public} on resource "
                        f"'{binding.resource}'. This allows any internet user (allUsers) "
                        "or any Google-authenticated user (allAuthenticatedUsers) to assume "
                        "this role, enabling unauthorized compute resource creation."
                    ),
                    impact=(
                        "Any attacker can use this binding to create compute resources "
                        "for crypto mining, billed to the project owner."
                    ),
                    remediation=Remediation(
                        summary="Remove allUsers/allAuthenticatedUsers from all IAM bindings.",
                        steps=[
                            "Identify the legitimate principals that need this role.",
                            "Remove allUsers/allAuthenticatedUsers from the binding.",
                            "Grant the role only to specific, authenticated identities.",
                            "Enable Org Policy: constraints/iam.allowedPolicyMemberDomains.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} --member=allUsers --role={binding.role}",
                        ],
                        iac_reference="google_project_iam_binding.members",
                        docs=[
                            "https://cloud.google.com/iam/docs/overview#concepts_related_to_access_control"
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM044DefaultComputeSAEditor(BaseCheck):
    """Default Compute Engine SA has Editor or Owner role."""

    check_id = "CM-044"
    title = "Default Compute Engine service account has Editor or Owner role"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    references = ["CIS GCP 4.1"]
    tags = ["iam", "service_account", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for binding in inventory.iam_bindings:
            if binding.role not in _EDITOR_ROLES:
                continue
            default_sas = [
                m
                for m in binding.members
                if m.startswith("serviceAccount:") and m.endswith(_COMPUTE_DEFAULT_SA_SUFFIX)
            ]
            if not default_sas:
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
                    exploitability_score=8.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type=binding.resource_type,
                        resource_id=binding.resource,
                        project_id=binding.project_id,
                    ),
                    evidence={
                        "role": binding.role,
                        "default_compute_sas": default_sas,
                    },
                    description=(
                        f"The default Compute Engine service account(s) {default_sas} "
                        f"have the '{binding.role}' role. Any VM using this SA can create "
                        "new compute resources, enabling crypto mining at scale."
                    ),
                    impact=(
                        "A compromised VM can use the default SA to spin up additional "
                        "instances for crypto mining, escalating costs rapidly."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Remove Editor/Owner from the default Compute SA and use "
                            "dedicated SAs with minimal permissions per workload."
                        ),
                        steps=[
                            "Create a dedicated service account for each workload.",
                            "Grant only the permissions required by that workload.",
                            "Remove the default Compute SA from Editor/Owner bindings.",
                            "Update VMs to use the dedicated SA.",
                        ],
                        gcloud_commands=[
                            f"gcloud projects remove-iam-policy-binding {binding.project_id} --member=serviceAccount:PROJECT_NUMBER{_COMPUTE_DEFAULT_SA_SUFFIX} --role={binding.role}",
                        ],
                        iac_reference="google_project_iam_binding",
                        docs=[
                            "https://cloud.google.com/compute/docs/access/service-accounts#default_service_account"
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM041SAUserManagedKeys(BaseCheck):
    """Service accounts with user-managed (exported) keys."""

    check_id = "CM-041"
    title = "Service account has user-managed (exported) keys"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    references = ["CIS GCP 1.4"]
    tags = ["iam", "service_account", "credentials", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for sa in inventory.service_accounts:
            user_keys = [k for k in sa.keys if k.get("keyType") == "USER_MANAGED"]
            if not user_keys:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, sa.project_id, sa.email),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="iam.googleapis.com/ServiceAccount",
                        resource_id=sa.name,
                        project_id=sa.project_id,
                    ),
                    evidence={
                        "sa_email": sa.email,
                        "user_managed_keys": [
                            {
                                "key_id": k.get("name", "").split("/")[-1],
                                "valid_after": k.get("validAfterTime"),
                                "valid_before": k.get("validBeforeTime"),
                            }
                            for k in user_keys
                        ],
                    },
                    description=(
                        f"Service account '{sa.email}' has {len(user_keys)} user-managed "
                        "key(s). These long-lived credentials, if leaked (e.g. in source "
                        "code, CI logs), can be used to authenticate as the SA and create "
                        "compute resources for crypto mining."
                    ),
                    impact=(
                        "Stolen SA keys can be used from anywhere to create VMs or GKE "
                        "nodes for crypto mining, billed to the project."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Delete user-managed SA keys and migrate to Workload Identity "
                            "Federation or service account impersonation."
                        ),
                        steps=[
                            "Identify all consumers of this SA key.",
                            "Migrate consumers to Workload Identity Federation or ADC.",
                            "Delete the user-managed key(s).",
                            "Enforce via Org Policy: constraints/iam.disableServiceAccountKeyCreation.",
                        ],
                        gcloud_commands=[
                            f"gcloud iam service-accounts keys delete KEY_ID --iam-account={sa.email}",
                        ],
                        iac_reference="google_service_account_key",
                        docs=[
                            "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
                            "https://cloud.google.com/iam/docs/workload-identity-federation",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

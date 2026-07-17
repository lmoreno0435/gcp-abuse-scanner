"""
Common checks — Extended governance and security controls.

CMN-003: Project has no owner or team label (accountability gap)
CMN-004: Default Compute Engine service account has user-managed keys
CMN-005: Critical org-level security policies are not enforced
CMN-006: Cloud Audit Logs (Data Access) may not be enabled for critical services
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


def _make_id(check_id: str, resource: str, suffix: str = "") -> str:
    key = f"{resource}-{suffix}" if suffix else resource
    h = hashlib.md5(key.encode()).hexdigest()[:8]
    return f"{check_id}-{h}"


# ---------------------------------------------------------------------------
# CMN-003 — Project has no owner or team label
# ---------------------------------------------------------------------------

_OWNER_LABEL_KEYS = {"owner", "team", "contact", "responsible"}


@CheckRegistry.register
class CMN003ProjectNoOwnerLabel(BaseCheck):
    """Active project has compute instances but no accountability labels."""

    check_id = "CMN-003"
    title = "Project has no owner or team label (accountability gap)"
    vector = Vector.COMMON
    severity_base = Severity.LOW
    required_collectors = ["compute"]
    tags = ["governance", "labels", "accountability", "ownership"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        for project_id in inventory.project_ids:
            project_instances = [
                inst
                for inst in inventory.compute_instances
                if inst.project_id == project_id
            ]

            # No compute activity detected — skip (cannot determine accountability gap)
            if not project_instances:
                continue

            # Check whether ANY instance carries an accountability label
            has_owner_label = any(
                _OWNER_LABEL_KEYS & set(inst.labels.keys())
                for inst in project_instances
            )

            if has_owner_label:
                continue

            sample_names = [inst.name for inst in project_instances[:5]]

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=1.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Project",
                        resource_id=project_id,
                        project_id=project_id,
                    ),
                    evidence={
                        "project_id": project_id,
                        "instance_count": len(project_instances),
                        "sample_instance_names": sample_names,
                        "checked_label_keys": sorted(_OWNER_LABEL_KEYS),
                    },
                    description=(
                        f"Project '{project_id}' has {len(project_instances)} compute instance(s) "
                        "but none of them carry an accountability label "
                        f"({', '.join(sorted(_OWNER_LABEL_KEYS))}). "
                        "Without ownership labels it is impossible to identify who is responsible "
                        "for resources when an incident occurs."
                    ),
                    impact=(
                        "Unowned resources slow incident response, complicate cost attribution, "
                        "and are more likely to be left misconfigured or abandoned — increasing "
                        "the attack surface over time."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Add accountability labels (owner, team, contact) to all resources "
                            "and enforce them via Org Policy."
                        ),
                        steps=[
                            "Identify the team or individual responsible for each project.",
                            "Add labels such as 'owner', 'team', and 'contact' to all compute instances.",
                            "Apply the same labels at the project level for inherited visibility.",
                            "Use an Org Policy (constraints/gcp.resourceLocations or a custom constraint) "
                            "to require specific labels on new resources.",
                            "Integrate label validation into your CI/CD pipeline (e.g., Terraform variable validation).",
                        ],
                        gcloud_commands=[
                            "# Add labels to a compute instance\n"
                            "gcloud compute instances add-labels INSTANCE_NAME \\\n"
                            "  --labels=owner=team-name,contact=team@example.com \\\n"
                            "  --zone=ZONE --project=PROJECT_ID",
                            "# Add labels to the project itself\n"
                            "gcloud projects update PROJECT_ID \\\n"
                            "  --update-labels=owner=team-name,team=platform",
                        ],
                        iac_reference="google_compute_instance.labels / google_project.labels",
                        docs=[
                            "https://cloud.google.com/resource-manager/docs/creating-managing-labels",
                            "https://cloud.google.com/resource-manager/docs/organization-policy/overview",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=["CIS GCP Foundations — Resource Tagging"],
                )
            )

        return findings


# ---------------------------------------------------------------------------
# CMN-004 — Default Compute Engine SA has user-managed keys
# ---------------------------------------------------------------------------

@CheckRegistry.register
class CMN004DefaultSAWithActiveKeys(BaseCheck):
    """Default Compute Engine service account has user-managed keys."""

    check_id = "CMN-004"
    title = "Default Compute Engine service account has user-managed keys"
    vector = Vector.COMMON
    severity_base = Severity.HIGH
    required_collectors = ["iam"]
    tags = ["iam", "service_account", "keys", "credential_exposure", "default_sa"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        for sa in inventory.service_accounts:
            # Default Compute Engine SA ends with @developer.gserviceaccount.com
            if not sa.email.endswith("@developer.gserviceaccount.com"):
                continue

            user_managed_keys = [
                key for key in sa.keys if key.get("keyType") == "USER_MANAGED"
            ]

            if not user_managed_keys:
                continue

            key_names = [k.get("name", "<unknown>") for k in user_managed_keys]
            key_ages = [
                {
                    "name": k.get("name", "<unknown>"),
                    "validAfterTime": k.get("validAfterTime", ""),
                    "validBeforeTime": k.get("validBeforeTime", ""),
                }
                for k in user_managed_keys
            ]

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, sa.project_id, sa.email),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="iam.googleapis.com/ServiceAccount",
                        resource_id=sa.email,
                        project_id=sa.project_id,
                    ),
                    evidence={
                        "service_account_email": sa.email,
                        "project_id": sa.project_id,
                        "user_managed_key_count": len(user_managed_keys),
                        "key_names": key_names,
                        "key_ages": key_ages,
                    },
                    description=(
                        f"The default Compute Engine service account '{sa.email}' in project "
                        f"'{sa.project_id}' has {len(user_managed_keys)} user-managed key(s). "
                        "The default SA typically has broad Editor permissions. A leaked key "
                        "grants persistent, hard-to-revoke access to the entire project."
                    ),
                    impact=(
                        "User-managed keys for the default Compute SA are a high-value target: "
                        "they are long-lived, grant Editor-level access, and are frequently "
                        "committed to source code or embedded in CI/CD pipelines. A compromised "
                        "key enables crypto mining, data exfiltration, and lateral movement."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Delete all user-managed keys from the default Compute Engine SA. "
                            "Use Workload Identity or dedicated, least-privilege SAs instead."
                        ),
                        steps=[
                            "Identify all workloads using the default Compute Engine SA.",
                            "Migrate each workload to a dedicated SA with minimal permissions.",
                            "For GKE workloads, enable Workload Identity Federation.",
                            "Delete the user-managed keys from the default SA.",
                            "Consider disabling the default SA entirely if no workloads require it.",
                            "Apply the org policy 'constraints/iam.disableServiceAccountKeyCreation' "
                            "to prevent future key creation.",
                        ],
                        gcloud_commands=[
                            "# List keys for the default SA\n"
                            "gcloud iam service-accounts keys list \\\n"
                            "  --iam-account=SA_EMAIL --project=PROJECT_ID",
                            "# Delete a specific user-managed key\n"
                            "gcloud iam service-accounts keys delete KEY_ID \\\n"
                            "  --iam-account=SA_EMAIL --project=PROJECT_ID",
                        ],
                        iac_reference="google_service_account_key (avoid creating these)",
                        docs=[
                            "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
                            "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=[
                        "CIS GCP Foundations — 1.4 (Service Account Keys)",
                        "MITRE ATT&CK — T1552.001 (Credentials in Files)",
                    ],
                )
            )

        return findings


# ---------------------------------------------------------------------------
# CMN-005 — Critical org-level security policies are not enforced
# ---------------------------------------------------------------------------

_CRITICAL_CONSTRAINTS = [
    "constraints/compute.vmExternalIpAccess",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/compute.skipDefaultNetworkCreation",
    "constraints/iam.allowedPolicyMemberDomains",
]


@CheckRegistry.register
class CMN005OrgSecurityPoliciesAbsent(BaseCheck):
    """Critical org-level security policies are not enforced."""

    check_id = "CMN-005"
    title = "Critical org-level security policies are not enforced"
    vector = Vector.COMMON
    severity_base = Severity.MEDIUM
    required_collectors = ["org_policy"]
    tags = ["org_policy", "governance", "cis", "security_baseline"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Build a set of enforced constraints (non-empty policy)
        enforced_constraints: set[str] = set()
        for policy in inventory.org_policies:
            if policy.policy:  # non-empty dict means the policy is configured
                enforced_constraints.add(policy.constraint)

        not_enforced = [
            c for c in _CRITICAL_CONSTRAINTS if c not in enforced_constraints
        ]

        # Only raise a finding when 2 or more critical constraints are absent
        if len(not_enforced) < 2:
            return findings

        org_id = inventory.organization_id or "unknown-org"

        findings.append(
            Finding(
                finding_id=_make_id(self.check_id, org_id),
                check_id=self.check_id,
                vector=self.vector,
                title=self.title,
                severity=self.severity_base,
                status=FindingStatus.FAIL,
                exploitability_score=5.0,
                blast_radius="organization",
                resource=GCPResource(
                    resource_type="cloudresourcemanager.googleapis.com/Organization",
                    resource_id=org_id,
                    project_id="",
                    organization_id=org_id,
                ),
                evidence={
                    "organization_id": org_id,
                    "not_enforced_constraints": not_enforced,
                    "enforced_constraints": sorted(enforced_constraints),
                    "total_critical_checked": len(_CRITICAL_CONSTRAINTS),
                    "total_not_enforced": len(not_enforced),
                },
                description=(
                    f"{len(not_enforced)} of {len(_CRITICAL_CONSTRAINTS)} critical org-level "
                    "security constraints are not enforced: "
                    + ", ".join(f"'{c}'" for c in not_enforced)
                    + ". These policies form the security baseline recommended by CIS GCP Foundations "
                    "and Google's own hardening guides."
                ),
                impact=(
                    "Without these org policies, individual projects can create resources with "
                    "external IPs, generate long-lived SA keys, use default networks, and grant "
                    "access to external identities — all of which are common entry points for "
                    "crypto mining and data exfiltration attacks."
                ),
                remediation=Remediation(
                    summary=(
                        "Apply the missing org-level security policies at the organization or "
                        "top-level folder. Review CIS GCP Foundations for the full baseline."
                    ),
                    steps=[
                        "Review each missing constraint and understand its impact before enforcing.",
                        "Apply 'constraints/compute.vmExternalIpAccess' to restrict external IPs "
                        "to approved projects/VMs only.",
                        "Apply 'constraints/iam.disableServiceAccountKeyCreation' to prevent "
                        "creation of long-lived SA keys.",
                        "Apply 'constraints/compute.skipDefaultNetworkCreation' to prevent "
                        "auto-created default VPCs in new projects.",
                        "Apply 'constraints/iam.allowedPolicyMemberDomains' to restrict IAM "
                        "bindings to your organization's domain(s).",
                        "Use 'dry-run' mode (audit) before enforcing to identify existing violations.",
                    ],
                    gcloud_commands=[
                        "# Disable SA key creation at org level\n"
                        "gcloud resource-manager org-policies enable-enforce \\\n"
                        "  constraints/iam.disableServiceAccountKeyCreation \\\n"
                        "  --organization=ORG_ID",
                        "# Skip default network creation\n"
                        "gcloud resource-manager org-policies enable-enforce \\\n"
                        "  constraints/compute.skipDefaultNetworkCreation \\\n"
                        "  --organization=ORG_ID",
                    ],
                    iac_reference="google_org_policy_policy / google_organization_policy",
                    docs=[
                        "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints",
                        "https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
                    ],
                    effort=RemediationEffort.MEDIUM,
                ),
                references=[
                    "CIS GCP Foundations Benchmark — Section 2 (Org Policies)",
                    "Google Cloud Security Foundations Guide",
                ],
            )
        )

        return findings


# ---------------------------------------------------------------------------
# CMN-006 — Cloud Audit Logs (Data Access) may not be enabled
# ---------------------------------------------------------------------------

@CheckRegistry.register
class CMN006AuditLogsDisabled(BaseCheck):
    """Cloud Logging API not enabled for projects with active compute workloads."""

    check_id = "CMN-006"
    title = "Cloud Audit Logs (Data Access) may not be enabled for critical services"
    vector = Vector.COMMON
    severity_base = Severity.MEDIUM
    required_collectors = ["iam"]
    tags = ["logging", "audit", "compliance", "visibility", "detection"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        # Build a set of projects that have logging.googleapis.com enabled
        projects_with_logging: set[str] = {
            api.project_id
            for api in inventory.enabled_apis
            if api.service_name == "logging.googleapis.com"
        }

        # Build a set of projects that have active compute instances
        projects_with_compute: set[str] = {
            inst.project_id for inst in inventory.compute_instances
        }

        # Flag projects that have compute activity but logging API is absent
        for project_id in projects_with_compute:
            if project_id in projects_with_logging:
                continue

            project_enabled_apis = [
                api.service_name
                for api in inventory.enabled_apis
                if api.project_id == project_id
            ]

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=3.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Project",
                        resource_id=project_id,
                        project_id=project_id,
                    ),
                    evidence={
                        "project_id": project_id,
                        "logging_api_enabled": False,
                        "logging_service": "logging.googleapis.com",
                        "enabled_apis_in_project": project_enabled_apis,
                        "compute_instances_count": sum(
                            1
                            for inst in inventory.compute_instances
                            if inst.project_id == project_id
                        ),
                    },
                    description=(
                        f"Project '{project_id}' has active compute instances but "
                        "'logging.googleapis.com' is not present in its enabled APIs. "
                        "Without Cloud Logging, Data Access audit logs (DATA_READ, DATA_WRITE) "
                        "cannot be collected, leaving the project blind to unauthorized access "
                        "and suspicious activity."
                    ),
                    impact=(
                        "Disabled or absent audit logging eliminates the primary forensic trail "
                        "for detecting crypto mining, credential abuse, and data exfiltration. "
                        "Incident response becomes guesswork, and compliance requirements "
                        "(PCI-DSS, ISO 27001, SOC 2) cannot be met."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Enable the Cloud Logging API and configure Data Access audit logs "
                            "for DATA_READ and DATA_WRITE on critical services."
                        ),
                        steps=[
                            "Enable the Cloud Logging API for the project.",
                            "Navigate to Cloud Console → IAM & Admin → Audit Logs.",
                            "Enable DATA_READ and DATA_WRITE audit logs for critical services: "
                            "compute.googleapis.com, iam.googleapis.com, storage.googleapis.com.",
                            "Configure log sinks to export audit logs to Cloud Storage or BigQuery "
                            "for long-term retention.",
                            "Set up log-based alerts for suspicious patterns (e.g., SA key creation, "
                            "firewall rule changes, IAM policy modifications).",
                            "Apply the org policy to enforce audit logging across all projects.",
                        ],
                        gcloud_commands=[
                            "# Enable the Cloud Logging API\n"
                            "gcloud services enable logging.googleapis.com --project=PROJECT_ID",
                            "# Enable Data Access audit logs for Compute (via IAM policy)\n"
                            "# Use Cloud Console → IAM & Admin → Audit Logs for granular control.",
                            "# Create a log sink to Cloud Storage for retention\n"
                            "gcloud logging sinks create audit-sink \\\n"
                            "  storage.googleapis.com/BUCKET_NAME \\\n"
                            "  --log-filter='logName:cloudaudit.googleapis.com' \\\n"
                            "  --project=PROJECT_ID",
                        ],
                        iac_reference="google_project_iam_audit_config",
                        docs=[
                            "https://cloud.google.com/logging/docs/audit",
                            "https://cloud.google.com/logging/docs/audit/configure-data-access",
                            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam_audit_config",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=[
                        "CIS GCP Foundations — 2.1 (Audit Logging)",
                        "MITRE ATT&CK — T1562.008 (Disable Cloud Logs)",
                    ],
                )
            )

        return findings

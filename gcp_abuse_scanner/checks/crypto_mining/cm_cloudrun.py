"""
Crypto Mining checks — Cloud Run.

CM-030: Cloud Run service allows public invocation (allUsers invoker)
CM-031: Cloud Run service has no maxScale limit configured (unbounded scaling)
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


def _make_id(check_id: str, project_id: str, resource: str) -> str:
    h = hashlib.md5(resource.encode()).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


@CheckRegistry.register
class CM030CloudRunPublicInvoker(BaseCheck):
    """Cloud Run service grants invocation rights to allUsers."""

    check_id = "CM-030"
    title = "Cloud Run service allows public invocation (allUsers invoker)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["cloud_run"]
    references = ["CIS GCP 2.13"]
    tags = ["cloud_run", "iam", "public_access", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for service in inventory.cloud_run_services:
            offending_bindings = self._public_invoker_bindings(service.iam_bindings)
            if not offending_bindings:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        service.project_id,
                        f"{service.region}/{service.name}",
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="run.googleapis.com/Service",
                        resource_id=service.name,
                        project_id=service.project_id,
                        region=service.region,
                    ),
                    evidence={
                        "service_name": service.name,
                        "region": service.region,
                        "offending_bindings": offending_bindings,
                    },
                    description=(
                        f"Cloud Run service '{service.name}' in region '{service.region}' "
                        "has 'roles/run.invoker' granted to 'allUsers'. Any unauthenticated "
                        "internet user can invoke this service, which may be exploited to "
                        "trigger compute-intensive workloads (e.g. crypto mining) at the "
                        "project owner's expense."
                    ),
                    impact=(
                        "Unrestricted public invocation allows attackers to trigger "
                        "arbitrary executions of the service, driving up compute costs "
                        "and potentially enabling crypto mining via the service's runtime."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Remove 'allUsers' from the 'roles/run.invoker' binding. "
                            "Use Identity-Aware Proxy (IAP) or service account authentication "
                            "to restrict invocation to authorized principals only."
                        ),
                        steps=[
                            "Identify the legitimate callers of this Cloud Run service.",
                            "Remove 'allUsers' from the 'roles/run.invoker' IAM binding.",
                            "Grant 'roles/run.invoker' only to specific service accounts or user groups.",
                            "If public access is required, front the service with Cloud Endpoints "
                            "or API Gateway with authentication enforced.",
                            "Consider enabling IAP for browser-based access.",
                        ],
                        gcloud_commands=[
                            f"gcloud run services remove-iam-policy-binding {service.name} "
                            f"--region={service.region} "
                            "--member=allUsers "
                            "--role=roles/run.invoker",
                        ],
                        iac_reference="google_cloud_run_service_iam_binding.members",
                        docs=[
                            "https://cloud.google.com/run/docs/securing/managing-access",
                            "https://cloud.google.com/run/docs/authenticating/overview",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _public_invoker_bindings(iam_bindings: list[dict]) -> list[dict]:
        """Return bindings where role is run.invoker and allUsers is a member."""
        result = []
        for binding in iam_bindings:
            if binding.get("role") != "roles/run.invoker":
                continue
            members = binding.get("members", [])
            if "allUsers" in members:
                result.append(binding)
        return result


@CheckRegistry.register
class CM031CloudRunUnboundedMaxScale(BaseCheck):
    """Cloud Run service has no maxInstanceCount limit, enabling unbounded scaling."""

    check_id = "CM-031"
    title = "Cloud Run service has no maxScale limit configured (unbounded scaling)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["cloud_run"]
    references = []
    tags = ["cloud_run", "scaling", "cost", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for service in inventory.cloud_run_services:
            max_instances = self._resolve_max_instances(service)
            if max_instances is not None and max_instances > 0:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(
                        self.check_id,
                        service.project_id,
                        f"{service.region}/{service.name}",
                    ),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="run.googleapis.com/Service",
                        resource_id=service.name,
                        project_id=service.project_id,
                        region=service.region,
                    ),
                    evidence={
                        "service_name": service.name,
                        "region": service.region,
                        "service_scaling": service.scaling,
                        "template_scaling": service.template.get("scaling", {}),
                        "resolved_max_instances": max_instances,
                    },
                    description=(
                        f"Cloud Run service '{service.name}' in region '{service.region}' "
                        "has no 'maxInstanceCount' limit configured (value is absent, null, "
                        "or 0). Without an upper bound, a burst of requests — whether "
                        "legitimate or adversarially triggered — can scale the service to "
                        "thousands of instances, generating unbounded compute costs that "
                        "mirror the financial impact of a crypto mining attack."
                    ),
                    impact=(
                        "Unbounded scaling can result in runaway costs if the service is "
                        "abused or misconfigured. An attacker who can trigger invocations "
                        "(e.g. via a public endpoint) can force massive scale-out, "
                        "exhausting the project's budget."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Set a 'maxInstanceCount' limit appropriate for the expected "
                            "workload to cap compute spend and prevent runaway scaling."
                        ),
                        steps=[
                            "Determine the maximum expected concurrency for this service.",
                            "Set 'maxInstanceCount' to a value that covers peak load with headroom.",
                            "Combine with budget alerts (see CM-060) to detect anomalous spend.",
                            "Review Cloud Run metrics to right-size the limit over time.",
                        ],
                        gcloud_commands=[
                            f"gcloud run services update {service.name} "
                            f"--region={service.region} "
                            "--max-instances=N",
                        ],
                        iac_reference=(
                            "google_cloud_run_v2_service.template.scaling.max_instance_count"
                        ),
                        docs=[
                            "https://cloud.google.com/run/docs/configuring/max-instances",
                            "https://cloud.google.com/run/docs/tips/general#setting-concurrency",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _resolve_max_instances(service) -> int | None:
        """
        Return the effective maxInstanceCount for the service, or None if not set.

        Checks both the top-level scaling dict and the template.scaling dict,
        preferring the top-level value (Cloud Run v2 API shape).
        """
        # Top-level scaling (Cloud Run v2 / Admin API)
        top_level = service.scaling.get("maxInstanceCount")
        if top_level is not None:
            return int(top_level)

        # Template-level scaling (Cloud Run v1 / YAML annotation shape)
        template_scaling = service.template.get("scaling", {})
        template_max = template_scaling.get("maxInstanceCount")
        if template_max is not None:
            return int(template_max)

        return None

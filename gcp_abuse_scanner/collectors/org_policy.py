"""Org Policy collector — reads Organization Policy constraints."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import OrgPolicy, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Key constraints relevant to crypto mining and Gemini abuse prevention
_RELEVANT_CONSTRAINTS = [
    "constraints/compute.vmExternalIpAccess",
    "constraints/compute.requireShieldedVm",
    "constraints/compute.restrictCloudRunRegion",
    "constraints/gcp.resourceLocations",
    "constraints/iam.disableServiceAccountKeyCreation",
    "constraints/iam.disableServiceAccountKeyUpload",
    "constraints/iam.allowedPolicyMemberDomains",
    "constraints/compute.restrictXpnProjectLienRemoval",
    "constraints/compute.skipDefaultNetworkCreation",
    "constraints/run.allowedIngress",
    "constraints/run.allowedVPCEgress",
    "constraints/aiplatform.allowedModels",
    "constraints/compute.restrictProtocolForwardingCreationForTypes",
]


class OrgPolicyCollector(BaseCollector):
    name = "org_policy"
    required_apis = ["orgpolicy.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()

        try:
            import googleapiclient.discovery

            orgpolicy = googleapiclient.discovery.build("orgpolicy", "v2", credentials=creds)
        except Exception as exc:
            logger.error("Failed to build Org Policy client: %s", exc)
            return

        # Collect at org level if available
        resources_to_check: list[str] = []
        if organization_id:
            resources_to_check.append(f"organizations/{organization_id}")

        # Also check at project level for project-specific overrides
        for project_id in project_ids[:20]:  # cap to avoid quota exhaustion
            resources_to_check.append(f"projects/{project_id}")

        for resource in resources_to_check:
            try:
                self._collect_policies(orgpolicy, inventory, resource)
            except Exception as exc:
                logger.warning("Org Policy collection failed for %s: %s", resource, exc)

    def _collect_policies(
        self, orgpolicy: object, inventory: ResourceInventory, resource: str
    ) -> None:
        for constraint in _RELEVANT_CONSTRAINTS:
            try:
                policy = (
                    orgpolicy.organizations()  # type: ignore
                    .policies()
                    .get(name=f"{resource}/policies/{constraint.replace('constraints/', '')}")
                    .execute()
                    if resource.startswith("organizations/")
                    else (
                        orgpolicy.projects()  # type: ignore
                        .policies()
                        .get(name=f"{resource}/policies/{constraint.replace('constraints/', '')}")
                        .execute()
                    )
                )
                inventory.org_policies.append(
                    OrgPolicy(
                        resource=resource,
                        constraint=constraint,
                        policy=policy,
                    )
                )
            except Exception:
                # Policy not set = constraint not enforced (important signal)
                inventory.org_policies.append(
                    OrgPolicy(
                        resource=resource,
                        constraint=constraint,
                        policy={},  # empty = not configured
                    )
                )

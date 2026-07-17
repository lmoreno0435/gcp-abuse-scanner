"""Network collector — firewall rules, VPC, public IPs."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import FirewallRule, ResourceInventory

if TYPE_CHECKING:
    from gcp_abuse_scanner.auth.manager import AuthManager

logger = logging.getLogger(__name__)


class NetworkCollector(BaseCollector):
    name = "network"
    required_apis = ["compute.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()

        try:
            import googleapiclient.discovery
            compute = googleapiclient.discovery.build("compute", "v1", credentials=creds)
        except Exception as exc:
            logger.error("Failed to build Compute client for network: %s", exc)
            return

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                continue
            try:
                request = compute.firewalls().list(project=project_id)  # type: ignore
                while request is not None:
                    response = request.execute()
                    for rule in response.get("items", []):
                        inventory.firewall_rules.append(
                            FirewallRule(
                                name=rule["name"],
                                project_id=project_id,
                                network=rule.get("network", "").split("/")[-1],
                                direction=rule.get("direction", "INGRESS"),
                                priority=rule.get("priority", 1000),
                                source_ranges=rule.get("sourceRanges", []),
                                destination_ranges=rule.get("destinationRanges", []),
                                allowed=rule.get("allowed", []),
                                denied=rule.get("denied", []),
                                target_tags=rule.get("targetTags", []),
                                disabled=rule.get("disabled", False),
                            )
                        )
                    request = compute.firewalls().list_next(  # type: ignore
                        previous_request=request, previous_response=response
                    )
            except Exception as exc:
                logger.warning("Network collection failed for %s: %s", project_id, exc)

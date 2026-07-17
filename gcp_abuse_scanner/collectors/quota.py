"""Quota collector — reads service quotas for Vertex AI and Compute Engine."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Quotas we care about for abuse detection
# Format: (service, metric_name, description)
_QUOTA_TARGETS: list[tuple[str, str, str]] = [
    # Vertex AI / Gemini
    (
        "aiplatform.googleapis.com",
        "online_prediction_requests_per_base_model_per_minute_per_project",
        "Vertex AI online prediction RPM",
    ),
    (
        "aiplatform.googleapis.com",
        "generate_content_requests_per_minute_per_project_per_base_model",
        "Gemini generateContent RPM",
    ),
    # Compute Engine (for crypto mining scale)
    (
        "compute.googleapis.com",
        "CPUS",
        "Compute Engine CPU quota",
    ),
    (
        "compute.googleapis.com",
        "GPUS_ALL_REGIONS",
        "Compute Engine GPU quota (all regions)",
    ),
    (
        "compute.googleapis.com",
        "INSTANCES",
        "Compute Engine instance quota",
    ),
]


class QuotaCollector(BaseCollector):
    """
    Reads project-level service quotas.
    Results stored as raw dicts in inventory.quota_info (added dynamically).

    The check layer evaluates whether quotas are at default (high) values
    that provide no friction against abuse.
    """

    name = "quota"
    required_apis = ["serviceusage.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()

        # Initialize quota_info on inventory if not present
        if not hasattr(inventory, "quota_info"):
            object.__setattr__(inventory, "quota_info", [])

        try:
            import googleapiclient.discovery

            serviceusage = googleapiclient.discovery.build(
                "serviceusage", "v1beta1", credentials=creds
            )
        except Exception as exc:
            logger.error("Failed to build Service Usage client for quotas: %s", _fmt_exc(exc))
            return

        for project_id in project_ids:
            try:
                self._collect_project_quotas(serviceusage, inventory, project_id)
            except Exception as exc:
                logger.debug("Quota collection failed for %s: %s", project_id, exc)

    def _collect_project_quotas(
        self,
        serviceusage: object,
        inventory: ResourceInventory,
        project_id: str,
    ) -> None:
        services_to_check = {svc for svc, _, _ in _QUOTA_TARGETS}

        for service_name in services_to_check:
            try:
                # Check if service is enabled
                enabled = any(
                    api.project_id == project_id and api.service_name == service_name
                    for api in inventory.enabled_apis
                )
                if not enabled:
                    continue

                resp = (
                    serviceusage.services()  # type: ignore
                    .consumerQuotaMetrics()
                    .list(
                        parent=f"projects/{project_id}/services/{service_name}",
                        pageSize=100,
                    )
                    .execute()
                )

                for metric in resp.get("metrics", []):
                    metric_name = metric.get("metric", "")
                    # Filter to only the metrics we care about
                    relevant = [
                        (svc, m, desc)
                        for svc, m, desc in _QUOTA_TARGETS
                        if svc == service_name and m in metric_name
                    ]
                    if not relevant:
                        continue

                    for limit_info in metric.get("consumerQuotaLimits", []):
                        quota_entry: dict[str, Any] = {
                            "project_id": project_id,
                            "service": service_name,
                            "metric": metric_name,
                            "limit_name": limit_info.get("name", ""),
                            "unit": limit_info.get("unit", ""),
                            "quota_buckets": limit_info.get("quotaBuckets", []),
                            "is_precise": limit_info.get("isPrecise", False),
                        }
                        inventory.quota_info.append(quota_entry)  # type: ignore[attr-defined]

            except Exception as exc:
                logger.debug("Quota fetch failed for %s/%s: %s", project_id, service_name, exc)

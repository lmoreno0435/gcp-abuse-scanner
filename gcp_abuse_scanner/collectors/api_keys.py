"""API Keys collector — lists API keys and their restrictions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import APIKey, ResourceInventory

if TYPE_CHECKING:
    from gcp_abuse_scanner.auth.manager import AuthManager

logger = logging.getLogger(__name__)


class APIKeysCollector(BaseCollector):
    name = "api_keys"
    required_apis = ["apikeys.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()

        try:
            import googleapiclient.discovery
            apikeys = googleapiclient.discovery.build("apikeys", "v2", credentials=creds)
        except Exception as exc:
            logger.error("Failed to build API Keys client: %s", exc)
            return

        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                inventory.skipped_apis.setdefault(project_id, []).append("apikeys.googleapis.com")
                continue
            try:
                request = apikeys.projects().locations().keys().list(  # type: ignore
                    parent=f"projects/{project_id}/locations/global"
                )
                while request is not None:
                    response = request.execute()
                    for key in response.get("keys", []):
                        inventory.api_keys.append(
                            APIKey(
                                name=key["name"],
                                project_id=project_id,
                                display_name=key.get("displayName", ""),
                                restrictions=key.get("restrictions", {}),
                                create_time=key.get("createTime", ""),
                                uid=key.get("uid", ""),
                            )
                        )
                    request = apikeys.projects().locations().keys().list_next(  # type: ignore
                        previous_request=request, previous_response=response
                    )
            except Exception as exc:
                logger.warning("API Keys collection failed for %s: %s", project_id, exc)

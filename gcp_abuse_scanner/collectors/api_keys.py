"""API Keys collector — lists API keys and their restrictions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector, _fmt_exc
from gcp_abuse_scanner.models.inventory import APIKey, ResourceInventory

if TYPE_CHECKING:
    pass

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
            logger.error("Failed to build API Keys client: %s", _fmt_exc(exc))
            return

        for project_id in project_ids:
            try:
                request = (
                    apikeys.projects()
                    .locations()
                    .keys()
                    .list(parent=f"projects/{project_id}/locations/global")  # type: ignore
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
                    request = (
                        apikeys.projects()
                        .locations()
                        .keys()
                        .list_next(  # type: ignore
                            previous_request=request, previous_response=response
                        )
                    )
            except Exception as exc:
                fmt = _fmt_exc(exc)
                # 403/404 usually means the API Keys API is not enabled — not an error worth
                # surfacing loudly; the checks will simply find nothing for this project.
                if "HTTP 403" in fmt or "HTTP 404" in fmt:
                    logger.debug(
                        "API Keys collection skipped for %s (API not enabled or no permission): %s",
                        project_id,
                        fmt,
                    )
                else:
                    logger.warning("API Keys collection failed for %s: %s", project_id, fmt)

"""ScopeResolver — enumerate GCP projects for a given org or project list."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from google.cloud import asset_v1, resourcemanager_v3

if TYPE_CHECKING:
    from gcp_abuse_scanner.auth.manager import AuthManager

logger = logging.getLogger(__name__)


class ScopeResolver:
    """
    Resolves the list of GCP projects to scan.

    - Organization scope: uses Cloud Asset Inventory to enumerate all projects
      under the org (handles folders, nested structures).
    - Project list scope: validates each project_id and returns as-is.
    """

    def __init__(self, auth_manager: AuthManager) -> None:
        self._auth = auth_manager

    def resolve_projects(
        self,
        organization_id: str | None = None,
        project_ids: list[str] | None = None,
        exclude_project_ids: list[str] | None = None,
    ) -> list[str]:
        """
        Returns a deduplicated list of project IDs to scan.

        Args:
            organization_id: GCP org ID (digits only, e.g. '123456789012').
            project_ids: Explicit list of project IDs.
            exclude_project_ids: Projects to skip.

        Raises:
            ValueError: If neither org nor project_ids is provided.
        """
        if not organization_id and not project_ids:
            raise ValueError("Provide --org or at least one --project")

        exclude = set(exclude_project_ids or [])
        projects: list[str] = []

        if organization_id:
            projects = self._enumerate_org_projects(organization_id)
            logger.info("Found %d projects under org %s", len(projects), organization_id)
        else:
            projects = list(project_ids or [])

        result = [p for p in projects if p not in exclude]
        if exclude:
            logger.info("Excluded %d projects: %s", len(exclude), sorted(exclude))

        return sorted(set(result))

    def _enumerate_org_projects(self, organization_id: str) -> list[str]:
        """Use Cloud Asset Inventory to list all projects under an org."""
        creds = self._auth.get_credentials()
        client = asset_v1.AssetServiceClient(credentials=creds)

        parent = f"organizations/{organization_id}"
        project_ids: list[str] = []

        try:
            request = asset_v1.SearchAllResourcesRequest(
                scope=parent,
                asset_types=["cloudresourcemanager.googleapis.com/Project"],
                page_size=500,
            )
            for resource in client.search_all_resources(request=request):
                # resource.name format: //cloudresourcemanager.googleapis.com/projects/{id}
                parts = resource.name.split("/")
                if parts:
                    project_id = parts[-1]
                    # Filter only ACTIVE projects
                    if resource.state == "ACTIVE":
                        project_ids.append(project_id)
        except Exception as exc:
            logger.error(
                "Failed to enumerate projects via Cloud Asset for org %s: %s",
                organization_id,
                exc,
            )
            raise

        return project_ids

    def validate_project(self, project_id: str) -> bool:
        """Check if a project exists and is accessible."""
        creds = self._auth.get_credentials()
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        try:
            project = client.get_project(name=f"projects/{project_id}")
            return project.state.name == "ACTIVE"
        except Exception:
            return False

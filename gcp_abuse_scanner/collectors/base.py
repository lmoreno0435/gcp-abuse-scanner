"""Base collector with retry, pagination, and API-disabled handling."""

from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING, Any

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

if TYPE_CHECKING:
    from gcp_abuse_scanner.auth.manager import AuthManager
    from gcp_abuse_scanner.models.inventory import ResourceInventory

logger = logging.getLogger(__name__)


class APINotEnabledError(Exception):
    """Raised when a required API is not enabled in a project."""


class BaseCollector(abc.ABC):
    """
    Base class for all resource collectors.

    Collectors fetch raw facts from GCP APIs and populate the ResourceInventory.
    They must NOT contain any check logic.
    """

    name: str  # e.g. "compute", "iam"
    required_apis: list[str] = []

    def __init__(self, auth_manager: AuthManager) -> None:
        self._auth = auth_manager
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abc.abstractmethod
    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        """
        Populate the inventory with data from this collector.
        Modifies inventory in-place.
        """

    def is_api_enabled(self, inventory: ResourceInventory, project_id: str) -> bool:
        if not self.required_apis:
            return True
        enabled = {
            api.service_name
            for api in inventory.enabled_apis
            if api.project_id == project_id
        }
        return any(api in enabled for api in self.required_apis)

    @staticmethod
    @retry(
        retry=retry_if_exception_type(Exception),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    def _with_retry(fn: Any, *args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

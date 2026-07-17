"""Base class and registry for security checks."""

from __future__ import annotations

import abc
import logging
from typing import ClassVar

from gcp_abuse_scanner.models.finding import Finding, Severity, Vector
from gcp_abuse_scanner.models.inventory import ResourceInventory

logger = logging.getLogger(__name__)


class BaseCheck(abc.ABC):
    """
    Contract for all security checks.

    Subclasses must define class-level metadata and implement `evaluate()`.
    Checks are auto-registered via CheckRegistry when imported.

    Example:
        @CheckRegistry.register
        class MyCheck(BaseCheck):
            check_id = "GEM-001"
            title = "..."
            vector = Vector.GEMINI_ABUSE
            severity_base = Severity.CRITICAL
            required_apis = ["generativelanguage.googleapis.com"]
            required_collectors = ["api_keys"]

            def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
                ...
    """

    # --- Required class-level metadata ---
    check_id: ClassVar[str]
    title: ClassVar[str]
    vector: ClassVar[Vector]
    severity_base: ClassVar[Severity]

    # --- Optional metadata ---
    description: ClassVar[str] = ""
    required_apis: ClassVar[list[str]] = []
    required_collectors: ClassVar[list[str]] = []
    references: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = []

    @abc.abstractmethod
    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        """
        Evaluate the inventory and return a list of findings.

        - Return an empty list if no issues found (PASS).
        - Each Finding must have status=FAIL.
        - Do NOT make API calls here — use inventory data only.
        """

    def is_applicable(self, inventory: ResourceInventory) -> bool:
        """
        Return False if this check cannot run (e.g. required API not enabled
        in any project). Checks returning False are marked NOT_APPLICABLE.
        """
        if not self.required_apis:
            return True
        enabled = {api.service_name for api in inventory.enabled_apis}
        return any(api in enabled for api in self.required_apis)

    def safe_evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        """Wrapper that catches exceptions and logs them without crashing the scan."""
        try:
            if not self.is_applicable(inventory):
                logger.debug("Check %s is not applicable — skipping", self.check_id)
                return []
            return self.evaluate(inventory)
        except Exception as exc:
            logger.error("Check %s raised an error: %s", self.check_id, exc, exc_info=True)
            return []


class CheckRegistry:
    """Auto-registration registry for BaseCheck subclasses."""

    _registry: ClassVar[dict[str, type[BaseCheck]]] = {}

    @classmethod
    def register(cls, check_cls: type[BaseCheck]) -> type[BaseCheck]:
        """Decorator to register a check class."""
        check_id = getattr(check_cls, "check_id", None)
        if not check_id:
            raise ValueError(f"Check class {check_cls.__name__} must define check_id")
        if check_id in cls._registry:
            raise ValueError(f"Duplicate check_id: {check_id}")
        cls._registry[check_id] = check_cls
        logger.debug("Registered check: %s", check_id)
        return check_cls

    @classmethod
    def all_checks(cls) -> list[BaseCheck]:
        """Return instantiated instances of all registered checks."""
        return [check_cls() for check_cls in cls._registry.values()]

    @classmethod
    def checks_for_vector(cls, vector: Vector) -> list[BaseCheck]:
        return [
            check_cls()
            for check_cls in cls._registry.values()
            if check_cls.vector == vector
        ]

    @classmethod
    def get_check(cls, check_id: str) -> BaseCheck | None:
        check_cls = cls._registry.get(check_id)
        return check_cls() if check_cls else None

    @classmethod
    def list_metadata(cls) -> list[dict[str, str]]:
        """Return metadata for all registered checks (for `list-checks` command)."""
        return [
            {
                "check_id": c.check_id,
                "title": c.title,
                "vector": c.vector.value,
                "severity": c.severity_base.value,
                "required_apis": ", ".join(c.required_apis) or "—",
                "tags": ", ".join(c.tags) or "—",
            }
            for c in cls._registry.values()
        ]

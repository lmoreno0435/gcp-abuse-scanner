"""Billing collector — billing accounts, budgets, and alert thresholds."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import BudgetInfo, ProjectInfo, ResourceInventory

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BillingCollector(BaseCollector):
    name = "billing"
    required_apis = ["cloudbilling.googleapis.com"]

    def collect(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> None:
        creds = self._auth.get_credentials()

        try:
            import googleapiclient.discovery
            billing = googleapiclient.discovery.build("cloudbilling", "v1", credentials=creds)
            budget_client = googleapiclient.discovery.build("billingbudgets", "v1", credentials=creds)
        except Exception as exc:
            logger.error("Failed to build Billing clients: %s", exc)
            return

        # Collect billing account info per project
        billing_accounts: set[str] = set()
        for project_id in project_ids:
            try:
                info = billing.projects().getBillingInfo(name=f"projects/{project_id}").execute()
                ba_name = info.get("billingAccountName", "")
                if ba_name:
                    ba_id = ba_name.replace("billingAccounts/", "")
                    billing_accounts.add(ba_id)
                    # Update project info
                    for proj in inventory.projects:
                        if proj.project_id == project_id:
                            proj.billing_account_id = ba_id
                    # If project not in inventory yet, add minimal info
                    if not any(p.project_id == project_id for p in inventory.projects):
                        inventory.projects.append(
                            ProjectInfo(project_id=project_id, billing_account_id=ba_id)
                        )
            except Exception as exc:
                logger.warning("Billing info failed for %s: %s", project_id, exc)

        # Collect budgets for each billing account
        for ba_id in billing_accounts:
            try:
                request = budget_client.billingAccounts().budgets().list(
                    parent=f"billingAccounts/{ba_id}"
                )
                while request is not None:
                    response = request.execute()
                    for budget in response.get("budgets", []):
                        inventory.budgets.append(
                            BudgetInfo(
                                name=budget["name"],
                                billing_account_id=ba_id,
                                display_name=budget.get("displayName", ""),
                                amount=budget.get("amount", {}),
                                threshold_rules=budget.get("thresholdRules", []),
                                budget_filter=budget.get("budgetFilter", {}),
                            )
                        )
                    request = budget_client.billingAccounts().budgets().list_next(
                        previous_request=request, previous_response=response
                    )
            except Exception as exc:
                logger.warning("Budget collection failed for billing account %s: %s", ba_id, exc)

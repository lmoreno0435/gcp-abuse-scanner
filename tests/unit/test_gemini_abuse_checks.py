"""Unit tests for Gemini abuse checks — offline, using inventory fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_abuse_scanner.checks.gemini_abuse.gem_api_keys import (
    GEM001NoAPIRestrictions,
    GEM002NoAppRestrictions,
    GEM003KeyTargetsGemini,
)
from gcp_abuse_scanner.checks.gemini_abuse.gem_iam import (
    GEM020BroadVertexIAM,
    GEM021PublicVertexBinding,
)
from gcp_abuse_scanner.models.finding import Severity
from gcp_abuse_scanner.models.inventory import ResourceInventory

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def gemini_inventory() -> ResourceInventory:
    data = json.loads((FIXTURES_DIR / "inventory_gemini_abuse.json").read_text())
    return ResourceInventory(**data)


@pytest.fixture
def clean_inventory() -> ResourceInventory:
    return ResourceInventory(project_ids=["clean-project"])


# --- GEM-001 ---


class TestGEM001NoAPIRestrictions:
    def test_fail_when_key_has_no_api_restrictions(
        self, gemini_inventory: ResourceInventory
    ) -> None:
        check = GEM001NoAPIRestrictions()
        findings = check.evaluate(gemini_inventory)
        # "Frontend Key" has no restrictions at all
        assert any(f.check_id == "GEM-001" for f in findings)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_pass_when_key_has_api_restrictions(self, clean_inventory: ResourceInventory) -> None:
        from gcp_abuse_scanner.models.inventory import APIKey

        clean_inventory.api_keys.append(
            APIKey(
                name="projects/clean-project/locations/global/keys/restricted-key",
                project_id="clean-project",
                display_name="Restricted Key",
                restrictions={
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}],
                    "browserKeyRestrictions": {"allowedReferrers": ["https://example.com/*"]},
                },
                uid="uid-restricted",
            )
        )
        check = GEM001NoAPIRestrictions()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- GEM-002 ---


class TestGEM002NoAppRestrictions:
    def test_fail_when_key_has_no_app_restrictions(
        self, gemini_inventory: ResourceInventory
    ) -> None:
        check = GEM002NoAppRestrictions()
        findings = check.evaluate(gemini_inventory)
        # Both keys in fixture have no app restrictions
        assert len(findings) == 2
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_pass_when_key_has_browser_restrictions(
        self, clean_inventory: ResourceInventory
    ) -> None:
        from gcp_abuse_scanner.models.inventory import APIKey

        clean_inventory.api_keys.append(
            APIKey(
                name="projects/clean-project/locations/global/keys/browser-key",
                project_id="clean-project",
                restrictions={
                    "browserKeyRestrictions": {"allowedReferrers": ["https://example.com/*"]}
                },
                uid="uid-browser",
            )
        )
        check = GEM002NoAppRestrictions()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- GEM-003 ---


class TestGEM003KeyTargetsGemini:
    def test_fail_when_gemini_key_has_no_app_restrictions(
        self, gemini_inventory: ResourceInventory
    ) -> None:
        check = GEM003KeyTargetsGemini()
        findings = check.evaluate(gemini_inventory)
        # "Gemini Key" targets generativelanguage but has no app restrictions
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-003"
        assert findings[0].severity == Severity.HIGH

    def test_pass_when_gemini_key_has_app_restrictions(
        self, clean_inventory: ResourceInventory
    ) -> None:
        from gcp_abuse_scanner.models.inventory import APIKey

        clean_inventory.api_keys.append(
            APIKey(
                name="projects/clean-project/locations/global/keys/gemini-restricted",
                project_id="clean-project",
                restrictions={
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}],
                    "serverKeyRestrictions": {"allowedIps": ["203.0.113.0/24"]},
                },
                uid="uid-gemini-ok",
            )
        )
        check = GEM003KeyTargetsGemini()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- GEM-020 ---


class TestGEM020BroadVertexIAM:
    def test_fail_when_domain_has_vertex_role(self, gemini_inventory: ResourceInventory) -> None:
        check = GEM020BroadVertexIAM()
        findings = check.evaluate(gemini_inventory)
        assert len(findings) >= 1
        assert findings[0].check_id == "GEM-020"
        assert "domain:example.com" in findings[0].evidence["broad_members"]

    def test_pass_when_only_specific_sa(self, clean_inventory: ResourceInventory) -> None:
        from gcp_abuse_scanner.models.inventory import IAMBinding

        clean_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/clean-project",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="clean-project",
                role="roles/aiplatform.user",
                members=["serviceAccount:specific-sa@clean-project.iam.gserviceaccount.com"],
            )
        )
        check = GEM020BroadVertexIAM()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- GEM-021 ---


class TestGEM021PublicVertexBinding:
    def test_fail_when_all_authenticated_users_has_vertex_role(
        self, gemini_inventory: ResourceInventory
    ) -> None:
        check = GEM021PublicVertexBinding()
        findings = check.evaluate(gemini_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "GEM-021"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].exploitability_score == 10.0

    def test_pass_when_no_public_vertex_bindings(self, clean_inventory: ResourceInventory) -> None:
        check = GEM021PublicVertexBinding()
        findings = check.evaluate(clean_inventory)
        assert findings == []

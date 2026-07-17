"""Unit tests for crypto mining checks — offline, using inventory fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gcp_abuse_scanner.checks.crypto_mining.cm_compute import (
    CM001ExternalIP,
    CM004FirewallAdminPortsOpen,
    CM009ShieldedVMDisabled,
)
from gcp_abuse_scanner.checks.crypto_mining.cm_iam import (
    CM041SAUserManagedKeys,
    CM043PublicIAMBinding,
    CM044DefaultComputeSAEditor,
)
from gcp_abuse_scanner.models.finding import FindingStatus, Severity
from gcp_abuse_scanner.models.inventory import ResourceInventory

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def crypto_inventory() -> ResourceInventory:
    data = json.loads((FIXTURES_DIR / "inventory_crypto_mining.json").read_text())
    return ResourceInventory(**data)


@pytest.fixture
def clean_inventory() -> ResourceInventory:
    """Inventory with no security issues."""
    return ResourceInventory(project_ids=["clean-project"])


# --- CM-001 ---


class TestCM001ExternalIP:
    def test_fail_when_vm_has_external_ip(self, crypto_inventory: ResourceInventory) -> None:
        check = CM001ExternalIP()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-001"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].status == FindingStatus.FAIL
        assert "34.123.45.67" in findings[0].evidence["external_ips"]

    def test_pass_when_no_external_ip(self, clean_inventory: ResourceInventory) -> None:
        check = CM001ExternalIP()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- CM-004 ---


class TestCM004FirewallAdminPorts:
    def test_fail_when_ssh_open_to_internet(self, crypto_inventory: ResourceInventory) -> None:
        check = CM004FirewallAdminPortsOpen()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-004"
        assert findings[0].severity == Severity.CRITICAL
        assert "22" in findings[0].evidence["exposed_ports"]

    def test_pass_when_no_open_admin_ports(self, clean_inventory: ResourceInventory) -> None:
        check = CM004FirewallAdminPortsOpen()
        findings = check.evaluate(clean_inventory)
        assert findings == []

    def test_pass_when_rule_disabled(self, crypto_inventory: ResourceInventory) -> None:
        for rule in crypto_inventory.firewall_rules:
            rule.disabled = True
        check = CM004FirewallAdminPortsOpen()
        findings = check.evaluate(crypto_inventory)
        assert findings == []


# --- CM-009 ---


class TestCM009ShieldedVM:
    def test_fail_when_shielded_vm_disabled(self, crypto_inventory: ResourceInventory) -> None:
        check = CM009ShieldedVMDisabled()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-009"
        assert "Secure Boot" in findings[0].evidence["missing_features"]

    def test_pass_when_shielded_vm_enabled(self, crypto_inventory: ResourceInventory) -> None:
        for instance in crypto_inventory.compute_instances:
            instance.shielded_instance_config = {
                "enableSecureBoot": True,
                "enableVtpm": True,
                "enableIntegrityMonitoring": True,
            }
        check = CM009ShieldedVMDisabled()
        findings = check.evaluate(crypto_inventory)
        assert findings == []


# --- CM-043 ---


class TestCM043PublicIAMBinding:
    def test_pass_when_no_public_bindings(self, crypto_inventory: ResourceInventory) -> None:
        check = CM043PublicIAMBinding()
        findings = check.evaluate(crypto_inventory)
        assert findings == []

    def test_fail_when_all_users_binding(self, crypto_inventory: ResourceInventory) -> None:
        from gcp_abuse_scanner.models.inventory import IAMBinding

        crypto_inventory.iam_bindings.append(
            IAMBinding(
                resource="//cloudresourcemanager.googleapis.com/projects/test-project-001",
                resource_type="cloudresourcemanager.googleapis.com/Project",
                project_id="test-project-001",
                role="roles/compute.instanceAdmin",
                members=["allUsers"],
            )
        )
        check = CM043PublicIAMBinding()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


# --- CM-044 ---


class TestCM044DefaultComputeSAEditor:
    def test_fail_when_default_sa_has_editor(self, crypto_inventory: ResourceInventory) -> None:
        check = CM044DefaultComputeSAEditor()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-044"
        assert findings[0].severity == Severity.HIGH

    def test_pass_when_no_default_sa_editor(self, clean_inventory: ResourceInventory) -> None:
        check = CM044DefaultComputeSAEditor()
        findings = check.evaluate(clean_inventory)
        assert findings == []


# --- CM-041 ---


class TestCM041SAUserManagedKeys:
    def test_fail_when_user_managed_keys_exist(self, crypto_inventory: ResourceInventory) -> None:
        check = CM041SAUserManagedKeys()
        findings = check.evaluate(crypto_inventory)
        assert len(findings) == 1
        assert findings[0].check_id == "CM-041"

    def test_pass_when_no_user_managed_keys(self, clean_inventory: ResourceInventory) -> None:
        check = CM041SAUserManagedKeys()
        findings = check.evaluate(clean_inventory)
        assert findings == []

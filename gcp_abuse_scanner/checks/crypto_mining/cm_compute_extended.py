"""
Crypto Mining checks — Compute Engine (extended).

CM-002: Org Policy compute.vmExternalIpAccess is not enforced
CM-003: Firewall allows unrestricted egress to the internet (0.0.0.0/0)
CM-005: VM instances with GPU accelerators detected without org-level restriction
CM-006: VM instance or project has insecure metadata (serial port enabled or OS Login disabled)
CM-007: VM startup script downloads or executes content from external URLs
CM-011: Org Policy gcp.resourceLocations is not configured (no region restriction)
"""

from __future__ import annotations

import hashlib

from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry
from gcp_abuse_scanner.models.finding import (
    Finding,
    FindingStatus,
    GCPResource,
    Remediation,
    RemediationEffort,
    Severity,
    Vector,
)
from gcp_abuse_scanner.models.inventory import (
    ComputeInstance,
    FirewallRule,
    OrgPolicy,
    ResourceInventory,
)

_STARTUP_SCRIPT_PATTERNS = [
    "curl ",
    "wget ",
    "pip install",
    "apt-get install",
    "yum install",
    "bash <(",
    "sh <(",
    "python -c",
    "exec(",
]


def _make_id(check_id: str, project_id: str, resource: str) -> str:
    h = hashlib.md5(resource.encode()).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


def _org_policy_is_restricted(policy: OrgPolicy) -> bool:
    """Return True if the org policy has a meaningful restrictive rule."""
    spec = policy.policy.get("spec", {})
    if not spec:
        return False
    rules = spec.get("rules", [])
    if not rules:
        return False
    for rule in rules:
        # denyAll: "TRUE" means all values are denied → restrictive
        if rule.get("denyAll", "").upper() == "TRUE":
            return True
        # allowAll: "TRUE" means everything is allowed → NOT restrictive
        if rule.get("allowAll", "").upper() == "TRUE":
            return False
        # An explicit allowList with no values (empty) means deny all → restrictive
        values = rule.get("values", {})
        if isinstance(values, dict):
            allowed_values = values.get("allowedValues", None)
            if allowed_values is not None and len(allowed_values) == 0:
                return True
            if allowed_values:
                return True  # at least some restriction is in place
    return False


@CheckRegistry.register
class CM002OrgPolicyExternalIPNotRestricted(BaseCheck):
    """Org Policy compute.vmExternalIpAccess is not enforced at the org/project level."""

    check_id = "CM-002"
    title = "Org Policy compute.vmExternalIpAccess is not enforced"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["org_policy"]
    references = ["CIS GCP 4.9"]
    tags = ["org_policy", "compute", "network", "crypto_mining"]

    _CONSTRAINT = "constraints/compute.vmExternalIpAccess"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        matching = [
            p for p in inventory.org_policies
            if p.constraint == self._CONSTRAINT
        ]

        if not matching:
            # No policy entry at all — constraint is not configured
            resource_id = (
                f"organizations/{inventory.organization_id}"
                if inventory.organization_id
                else "unknown-org"
            )
            project_id = inventory.project_ids[0] if inventory.project_ids else "unknown"
            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, resource_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.0,
                    blast_radius="organization",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Organization",
                        resource_id=resource_id,
                        project_id=project_id,
                        organization_id=inventory.organization_id,
                    ),
                    evidence={
                        "constraint": self._CONSTRAINT,
                        "reason": "No org policy entry found for this constraint.",
                    },
                    description=(
                        f"The org policy constraint '{self._CONSTRAINT}' has not been configured. "
                        "Without this constraint, any VM can be assigned an external IP address, "
                        "enabling direct communication with crypto mining pools."
                    ),
                    impact=(
                        "VMs can freely obtain external IPs, dramatically increasing the attack "
                        "surface and enabling outbound connections to mining pools."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Apply the org policy constraint with denyAll or an empty allowList "
                            "to prevent VMs from having external IPs."
                        ),
                        steps=[
                            "Identify all VMs that currently have external IPs.",
                            "Migrate outbound connectivity to Cloud NAT.",
                            "Apply the org policy to deny external IPs organization-wide.",
                        ],
                        gcloud_commands=[
                            "gcloud resource-manager org-policies deny "
                            "constraints/compute.vmExternalIpAccess --organization=ORG_ID",
                        ],
                        iac_reference="google_org_policy_policy.compute_vm_external_ip_access",
                        docs=[
                            "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
                            "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
            return findings

        # Evaluate each matching policy entry
        for policy in matching:
            if not policy.policy or policy.policy == {}:
                restricted = False
            else:
                restricted = _org_policy_is_restricted(policy)

            if restricted:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, "org", policy.resource),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.0,
                    blast_radius="organization",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Organization",
                        resource_id=policy.resource,
                        project_id=inventory.project_ids[0] if inventory.project_ids else "unknown",
                        organization_id=inventory.organization_id,
                    ),
                    evidence={
                        "constraint": self._CONSTRAINT,
                        "resource": policy.resource,
                        "policy": policy.policy,
                        "reason": "Policy exists but does not enforce a restrictive rule.",
                    },
                    description=(
                        f"The org policy constraint '{self._CONSTRAINT}' is present on "
                        f"'{policy.resource}' but does not enforce a restrictive rule "
                        "(no denyAll or empty allowList). VMs can still obtain external IPs."
                    ),
                    impact=(
                        "VMs can freely obtain external IPs, enabling outbound connections "
                        "to crypto mining pools and increasing the attack surface."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Update the org policy to use denyAll or an empty allowList "
                            "to prevent VMs from having external IPs."
                        ),
                        steps=[
                            "Review the current policy configuration.",
                            "Update the policy to include a denyAll rule or an empty allowList.",
                            "Migrate outbound connectivity to Cloud NAT before enforcing.",
                        ],
                        gcloud_commands=[
                            "gcloud resource-manager org-policies deny "
                            "constraints/compute.vmExternalIpAccess --organization=ORG_ID",
                        ],
                        iac_reference="google_org_policy_policy.compute_vm_external_ip_access",
                        docs=[
                            "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
                            "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM003FirewallEgressPermissive(BaseCheck):
    """Firewall egress rule allows unrestricted outbound traffic to 0.0.0.0/0."""

    check_id = "CM-003"
    title = "Firewall allows unrestricted egress to the internet (0.0.0.0/0)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["network"]
    references = ["CIS GCP 3.8"]
    tags = ["network", "firewall", "egress", "crypto_mining"]

    # GCP default-allow-internal and implied-allow-egress rules use priority 65534/65535
    _DEFAULT_RULE_PRIORITY_THRESHOLD = 65534

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for rule in inventory.firewall_rules:
            if rule.direction != "EGRESS":
                continue
            if rule.disabled:
                continue
            if rule.priority >= self._DEFAULT_RULE_PRIORITY_THRESHOLD:
                continue
            if not self._is_open_to_internet(rule):
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, rule.project_id, rule.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=6.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Firewall",
                        resource_id=rule.name,
                        project_id=rule.project_id,
                    ),
                    evidence={
                        "rule_name": rule.name,
                        "network": rule.network,
                        "direction": rule.direction,
                        "priority": rule.priority,
                        "destination_ranges": rule.destination_ranges,
                        "allowed": rule.allowed,
                    },
                    description=(
                        f"Firewall rule '{rule.name}' allows unrestricted egress traffic "
                        f"to 0.0.0.0/0 or ::/0 (any destination). This enables VMs to "
                        "communicate freely with crypto mining pools and C2 servers on the internet."
                    ),
                    impact=(
                        "Compromised or malicious VMs can establish outbound connections to "
                        "mining pools, exfiltrate data, or receive commands from C2 infrastructure "
                        "without restriction."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Replace the permissive egress rule with a deny-all egress default "
                            "and allowlist only required destinations and ports."
                        ),
                        steps=[
                            "Audit legitimate outbound traffic requirements for the network.",
                            "Create a deny-all egress rule at low priority (e.g., priority 65000).",
                            "Create specific allow rules for required destinations (e.g., Google APIs, known SaaS).",
                            "Use Cloud NAT with logging enabled for outbound internet access.",
                            f"Delete or restrict the permissive rule '{rule.name}'.",
                        ],
                        gcloud_commands=[
                            f"gcloud compute firewall-rules update {rule.name} "
                            "--destination-ranges=SPECIFIC_CIDR_RANGE",
                            "# Or create a deny-all egress rule:\n"
                            "gcloud compute firewall-rules create deny-all-egress "
                            f"--network={rule.network} --direction=EGRESS --action=DENY "
                            "--rules=all --destination-ranges=0.0.0.0/0 --priority=65000",
                        ],
                        iac_reference="google_compute_firewall.direction",
                        docs=[
                            "https://cloud.google.com/vpc/docs/firewalls",
                            "https://cloud.google.com/nat/docs/overview",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _is_open_to_internet(rule: FirewallRule) -> bool:
        return (
            "0.0.0.0/0" in rule.destination_ranges
            or "::/0" in rule.destination_ranges
        )


@CheckRegistry.register
class CM005VMsWithGPUNoRestriction(BaseCheck):
    """VM instances with GPU accelerators detected without org-level restriction."""

    check_id = "CM-005"
    title = "VM instances with GPU accelerators detected without org-level restriction"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["compute"]
    references = []
    tags = ["compute", "gpu", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for instance in inventory.compute_instances:
            gpu_accelerators = self._get_gpu_accelerators(instance)
            if not gpu_accelerators:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, instance.project_id, instance.self_link or instance.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Instance",
                        resource_id=instance.self_link or instance.name,
                        project_id=instance.project_id,
                        region=instance.zone,
                    ),
                    evidence={
                        "instance_name": instance.name,
                        "zone": instance.zone,
                        "gpu_accelerators": gpu_accelerators,
                    },
                    description=(
                        f"Instance '{instance.name}' in zone '{instance.zone}' has "
                        f"GPU accelerator(s) attached: {gpu_accelerators}. "
                        "GPU-equipped VMs are prime targets for crypto mining abuse. "
                        "Without org-level restrictions on GPU machine types, attackers "
                        "who gain access can exploit these resources for mining."
                    ),
                    impact=(
                        "GPU instances can mine cryptocurrency at high rates, leading to "
                        "significant unexpected billing charges and resource exhaustion."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Review whether GPU instances are necessary. Apply org policies "
                            "or quotas to restrict GPU machine types to approved use cases."
                        ),
                        steps=[
                            "Verify that the GPU instance has a legitimate business purpose.",
                            "Review the instance's workload and owner.",
                            "Apply org policy constraints/compute.restrictCloudTPUUsage or "
                            "quota limits to restrict GPU availability.",
                            "Enable billing alerts and anomaly detection for GPU usage.",
                            "Consider using labels and resource hierarchy to track GPU instances.",
                        ],
                        gcloud_commands=[
                            "# List all GPU instances:\n"
                            "gcloud compute instances list --filter='accelerators:*' --format='table(name,zone,accelerators)'",
                            "# Set GPU quota to 0 in a region:\n"
                            "# Use Cloud Console: IAM & Admin > Quotas > filter by GPU",
                        ],
                        iac_reference="google_compute_instance.guest_accelerator",
                        docs=[
                            "https://cloud.google.com/compute/docs/gpus",
                            "https://cloud.google.com/resource-manager/docs/organization-policy/overview",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _get_gpu_accelerators(instance: ComputeInstance) -> list[dict]:
        """Return accelerator entries with acceleratorCount > 0."""
        return [
            acc for acc in instance.accelerators
            if acc.get("acceleratorCount", 0) > 0
        ]


@CheckRegistry.register
class CM006InsecureInstanceMetadata(BaseCheck):
    """VM instance has insecure metadata: serial port enabled or OS Login disabled."""

    check_id = "CM-006"
    title = "VM instance or project has insecure metadata (serial port enabled or OS Login disabled)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["compute"]
    references = ["CIS GCP 4.5", "CIS GCP 4.4"]
    tags = ["compute", "metadata", "hardening", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for instance in inventory.compute_instances:
            flags = self._check_insecure_metadata(instance)
            if not flags:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, instance.project_id, instance.self_link or instance.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.5,
                    blast_radius="instance",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Instance",
                        resource_id=instance.self_link or instance.name,
                        project_id=instance.project_id,
                        region=instance.zone,
                    ),
                    evidence={
                        "instance_name": instance.name,
                        "zone": instance.zone,
                        "insecure_flags": flags,
                        "metadata_keys": list(instance.metadata.keys()),
                    },
                    description=(
                        f"Instance '{instance.name}' in zone '{instance.zone}' has "
                        f"insecure metadata configuration: {', '.join(flags)}. "
                        "Serial port access provides an out-of-band channel that can be "
                        "exploited by attackers. Disabling OS Login weakens SSH key management."
                    ),
                    impact=(
                        "Serial port access can be used to interact with a compromised VM "
                        "without going through normal network channels, aiding persistence. "
                        "Disabled OS Login makes it harder to centrally revoke SSH access."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Disable serial port access and enable OS Login on all VM instances."
                        ),
                        steps=[
                            "Disable serial port: set metadata 'serial-port-enable' to 'false'.",
                            "Enable OS Login: set metadata 'enable-oslogin' to 'true'.",
                            "Enforce via Org Policy: constraints/compute.disableSerialPortAccess.",
                            "Enforce OS Login via Org Policy: constraints/compute.requireOsLogin.",
                        ],
                        gcloud_commands=[
                            f"gcloud compute instances add-metadata {instance.name} "
                            f"--zone={instance.zone} --metadata=serial-port-enable=false",
                            f"gcloud compute instances add-metadata {instance.name} "
                            f"--zone={instance.zone} --metadata=enable-oslogin=true",
                            "# Enforce org-wide:\n"
                            "gcloud resource-manager org-policies enable-enforce "
                            "constraints/compute.disableSerialPortAccess --organization=ORG_ID",
                        ],
                        iac_reference="google_compute_instance.metadata",
                        docs=[
                            "https://cloud.google.com/compute/docs/instances/interacting-with-serial-console",
                            "https://cloud.google.com/compute/docs/oslogin",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _check_insecure_metadata(instance: ComputeInstance) -> list[str]:
        """Return a list of insecure metadata flags found on the instance."""
        flags = []
        metadata = instance.metadata

        serial_port_value = metadata.get("serial-port-enable", "").lower()
        if serial_port_value in ("true", "1"):
            flags.append("serial_port_enabled")

        oslogin_value = metadata.get("enable-oslogin", "").lower()
        if oslogin_value == "false":
            flags.append("oslogin_disabled")

        return flags


@CheckRegistry.register
class CM007StartupScriptExternalDownload(BaseCheck):
    """VM startup script downloads or executes content from external URLs."""

    check_id = "CM-007"
    title = "VM startup script downloads or executes content from external URLs"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["compute"]
    references = []
    tags = ["compute", "startup_script", "supply_chain", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for instance in inventory.compute_instances:
            startup_script = instance.metadata.get("startup-script", "")
            if not startup_script:
                continue

            matched_patterns = self._find_suspicious_patterns(startup_script)
            if not matched_patterns:
                continue

            snippet = startup_script[:200]

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, instance.project_id, instance.self_link or instance.name),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=6.0,
                    blast_radius="instance",
                    resource=GCPResource(
                        resource_type="compute.googleapis.com/Instance",
                        resource_id=instance.self_link or instance.name,
                        project_id=instance.project_id,
                        region=instance.zone,
                    ),
                    evidence={
                        "instance_name": instance.name,
                        "zone": instance.zone,
                        "matched_patterns": matched_patterns,
                        "startup_script_snippet": snippet,
                    },
                    description=(
                        f"Instance '{instance.name}' in zone '{instance.zone}' has a "
                        f"startup script containing suspicious patterns: {matched_patterns}. "
                        "These patterns suggest the script downloads or executes code from "
                        "external sources, which is a common vector for deploying crypto miners."
                    ),
                    impact=(
                        "Startup scripts that fetch and execute external content can be used "
                        "to deploy crypto mining software, backdoors, or other malware on "
                        "every VM boot, including after restarts."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Store startup scripts in GCS and avoid downloading or executing "
                            "content from external URLs. Use hardened or Container-Optimized OS images."
                        ),
                        steps=[
                            "Review the startup script for legitimate vs. suspicious downloads.",
                            "Move any required scripts or binaries to a private GCS bucket.",
                            "Reference the GCS path using the 'startup-script-url' metadata key.",
                            "Consider using Container-Optimized OS or hardened images.",
                            "Enable VM startup script logging and alerting.",
                        ],
                        gcloud_commands=[
                            "# Upload script to GCS:\n"
                            "gsutil cp startup.sh gs://YOUR_BUCKET/startup.sh",
                            f"gcloud compute instances add-metadata {instance.name} "
                            f"--zone={instance.zone} "
                            "--metadata=startup-script-url=gs://YOUR_BUCKET/startup.sh",
                            f"# Remove inline startup script:\n"
                            f"gcloud compute instances remove-metadata {instance.name} "
                            f"--zone={instance.zone} --keys=startup-script",
                        ],
                        iac_reference="google_compute_instance.metadata.startup-script",
                        docs=[
                            "https://cloud.google.com/compute/docs/instances/startup-scripts/linux",
                            "https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _find_suspicious_patterns(script: str) -> list[str]:
        """Return patterns found in the startup script (case-insensitive)."""
        script_lower = script.lower()
        return [
            pattern
            for pattern in _STARTUP_SCRIPT_PATTERNS
            if pattern.lower() in script_lower
        ]


@CheckRegistry.register
class CM011NoResourceLocationRestriction(BaseCheck):
    """Org Policy gcp.resourceLocations is not configured (no region restriction)."""

    check_id = "CM-011"
    title = "Org Policy gcp.resourceLocations is not configured (no region restriction)"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["org_policy"]
    references = []
    tags = ["org_policy", "location", "crypto_mining"]

    _CONSTRAINT = "constraints/gcp.resourceLocations"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []

        matching = [
            p for p in inventory.org_policies
            if p.constraint == self._CONSTRAINT
        ]

        if not matching:
            # No policy entry at all — constraint is not configured
            resource_id = (
                f"organizations/{inventory.organization_id}"
                if inventory.organization_id
                else "unknown-org"
            )
            project_id = inventory.project_ids[0] if inventory.project_ids else "unknown"
            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, project_id, resource_id),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.5,
                    blast_radius="organization",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Organization",
                        resource_id=resource_id,
                        project_id=project_id,
                        organization_id=inventory.organization_id,
                    ),
                    evidence={
                        "constraint": self._CONSTRAINT,
                        "reason": "No org policy entry found for this constraint.",
                    },
                    description=(
                        f"The org policy constraint '{self._CONSTRAINT}' has not been configured. "
                        "Without this constraint, resources can be created in any GCP region, "
                        "including regions with lax controls or outside approved jurisdictions. "
                        "Attackers may spin up resources in unexpected regions to evade detection."
                    ),
                    impact=(
                        "Resources (including crypto mining VMs) can be created in any region, "
                        "making it harder to detect and respond to abuse. Data sovereignty "
                        "requirements may also be violated."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Configure the gcp.resourceLocations org policy to restrict "
                            "resource creation to approved regions."
                        ),
                        steps=[
                            "Identify the list of approved GCP regions for your organization.",
                            "Create an org policy that allowlists only approved regions.",
                            "Apply the policy at the organization level.",
                            "Review existing resources in non-approved regions.",
                        ],
                        gcloud_commands=[
                            "# Create a policy file (policy.yaml) with allowed locations, then:\n"
                            "gcloud resource-manager org-policies set-policy policy.yaml "
                            "--organization=ORG_ID",
                            "# Example policy.yaml content:\n"
                            "# constraint: constraints/gcp.resourceLocations\n"
                            "# listPolicy:\n"
                            "#   allowedValues:\n"
                            "#     - in:us-locations\n"
                            "#     - in:eu-locations",
                        ],
                        iac_reference="google_org_policy_policy.gcp_resource_locations",
                        docs=[
                            "https://cloud.google.com/resource-manager/docs/organization-policy/defining-locations",
                            "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
            return findings

        # Evaluate each matching policy entry
        for policy in matching:
            if not policy.policy or policy.policy == {}:
                has_restriction = False
            else:
                has_restriction = self._has_location_restriction(policy)

            if has_restriction:
                continue

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, "org", policy.resource),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=4.5,
                    blast_radius="organization",
                    resource=GCPResource(
                        resource_type="cloudresourcemanager.googleapis.com/Organization",
                        resource_id=policy.resource,
                        project_id=inventory.project_ids[0] if inventory.project_ids else "unknown",
                        organization_id=inventory.organization_id,
                    ),
                    evidence={
                        "constraint": self._CONSTRAINT,
                        "resource": policy.resource,
                        "policy": policy.policy,
                        "reason": "Policy exists but does not restrict resource locations.",
                    },
                    description=(
                        f"The org policy constraint '{self._CONSTRAINT}' is present on "
                        f"'{policy.resource}' but does not restrict resource locations "
                        "(no allowedValues configured). Resources can be created in any region."
                    ),
                    impact=(
                        "Resources (including crypto mining VMs) can be created in any region, "
                        "making it harder to detect and respond to abuse."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Update the gcp.resourceLocations org policy to include "
                            "at least one approved region in the allowedValues list."
                        ),
                        steps=[
                            "Identify the list of approved GCP regions for your organization.",
                            "Update the org policy to allowlist only approved regions.",
                            "Review existing resources in non-approved regions.",
                        ],
                        gcloud_commands=[
                            "# Update the policy with allowed locations:\n"
                            "gcloud resource-manager org-policies set-policy policy.yaml "
                            "--organization=ORG_ID",
                        ],
                        iac_reference="google_org_policy_policy.gcp_resource_locations",
                        docs=[
                            "https://cloud.google.com/resource-manager/docs/organization-policy/defining-locations",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings

    @staticmethod
    def _has_location_restriction(policy: OrgPolicy) -> bool:
        """Return True if the policy has at least one allowed location configured."""
        spec = policy.policy.get("spec", {})
        if not spec:
            return False
        rules = spec.get("rules", [])
        for rule in rules:
            values = rule.get("values", {})
            if isinstance(values, dict):
                allowed_values = values.get("allowedValues", [])
                if allowed_values:
                    return True
        return False

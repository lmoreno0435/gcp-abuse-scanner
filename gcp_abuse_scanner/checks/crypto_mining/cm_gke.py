"""
Crypto Mining checks — Google Kubernetes Engine (GKE).

CM-020: GKE node pool has autoscaling enabled without a maxNodeCount limit
CM-021: GKE cluster has Node Auto-Provisioning enabled without resource limits
CM-023: GKE cluster has a public control plane endpoint without authorized networks configured
CM-024: GKE cluster does not have Workload Identity enabled
CM-025: GKE cluster has Legacy ABAC (Attribute-Based Access Control) enabled
CM-026: GKE node pool uses the default Compute Engine service account
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
from gcp_abuse_scanner.models.inventory import ResourceInventory


def _make_id(check_id: str, project_id: str, resource: str) -> str:
    h = hashlib.md5(resource.encode()).hexdigest()[:8]
    return f"{check_id}-{project_id}-{h}"


@CheckRegistry.register
class CM020GKENodePoolUnboundedAutoscaling(BaseCheck):
    """GKE node pool with autoscaling enabled but no effective maxNodeCount cap."""

    check_id = "CM-020"
    title = "GKE node pool has autoscaling enabled without a maxNodeCount limit"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["gke"]
    references = ["CIS GKE 6.8.1"]
    tags = ["gke", "autoscaling", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for cluster in inventory.gke_clusters:
            for pool in cluster.node_pools:
                autoscaling = pool.get("autoscaling", {})
                if not autoscaling.get("enabled", False):
                    continue

                max_nodes = autoscaling.get("maxNodeCount")
                if max_nodes is None or max_nodes == 0 or max_nodes >= 1000:
                    pool_name = pool.get("name", "<unknown>")
                    resource_key = f"{cluster.project_id}/{cluster.name}/{pool_name}"

                    findings.append(
                        Finding(
                            finding_id=_make_id(self.check_id, cluster.project_id, resource_key),
                            check_id=self.check_id,
                            vector=self.vector,
                            title=self.title,
                            severity=self.severity_base,
                            status=FindingStatus.FAIL,
                            exploitability_score=7.0,
                            blast_radius="project",
                            resource=GCPResource(
                                resource_type="container.googleapis.com/NodePool",
                                resource_id=resource_key,
                                project_id=cluster.project_id,
                                region=cluster.location,
                            ),
                            evidence={
                                "cluster_name": cluster.name,
                                "node_pool_name": pool_name,
                                "location": cluster.location,
                                "autoscaling_enabled": True,
                                "max_node_count": max_nodes,
                            },
                            description=(
                                f"Node pool '{pool_name}' in cluster '{cluster.name}' "
                                f"(project '{cluster.project_id}', location '{cluster.location}') "
                                f"has autoscaling enabled with maxNodeCount={max_nodes!r}. "
                                "An unbounded node pool allows an attacker (or a compromised "
                                "workload) to scale the cluster to thousands of nodes, running "
                                "crypto mining at massive scale and generating enormous costs."
                            ),
                            impact=(
                                "Unbounded autoscaling can be exploited to spin up hundreds or "
                                "thousands of GPU/CPU nodes for crypto mining, leading to "
                                "catastrophic billing abuse before the anomaly is detected."
                            ),
                            remediation=Remediation(
                                summary=(
                                    "Set a reasonable maxNodeCount on the node pool to cap "
                                    "the maximum compute capacity that can be provisioned."
                                ),
                                steps=[
                                    "Determine the maximum number of nodes legitimately needed "
                                    "by the workloads running in this pool.",
                                    "Update the node pool autoscaling configuration with an "
                                    "appropriate maxNodeCount value.",
                                    "Set up billing alerts and quota limits as an additional "
                                    "safeguard against runaway scaling.",
                                ],
                                gcloud_commands=[
                                    "gcloud container node-pools update POOL_NAME "
                                    "--max-nodes=MAX_NODES "
                                    "--cluster=CLUSTER_NAME "
                                    "--zone=ZONE",
                                ],
                                iac_reference=(
                                    "google_container_node_pool.autoscaling.max_node_count"
                                ),
                                docs=[
                                    "https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-autoscaler",
                                    "https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-autoscaler",
                                ],
                                effort=RemediationEffort.LOW,
                            ),
                            references=self.references,
                        )
                    )
        return findings


@CheckRegistry.register
class CM021GKENAPNoResourceLimits(BaseCheck):
    """GKE cluster with Node Auto-Provisioning enabled but no resource limits defined."""

    check_id = "CM-021"
    title = "GKE cluster has Node Auto-Provisioning enabled without resource limits"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["gke"]
    references = ["CIS GKE 6.8.2"]
    tags = ["gke", "autoscaling", "nap", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for cluster in inventory.gke_clusters:
            # Autopilot clusters manage their own resource controls — skip.
            if cluster.autopilot.get("enabled", False):
                continue

            # Detect NAP via autoprovisioned node pools.
            autoprovisioned_pools = [
                pool for pool in cluster.node_pools
                if pool.get("autoscaling", {}).get("autoprovisioned", False)
            ]
            if not autoprovisioned_pools:
                continue

            pool_names = [p.get("name", "<unknown>") for p in autoprovisioned_pools]
            resource_key = f"{cluster.project_id}/{cluster.name}"

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, cluster.project_id, resource_key),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=7.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="container.googleapis.com/Cluster",
                        resource_id=resource_key,
                        project_id=cluster.project_id,
                        region=cluster.location,
                    ),
                    evidence={
                        "cluster_name": cluster.name,
                        "location": cluster.location,
                        "autoprovisioned_pools": pool_names,
                    },
                    description=(
                        f"Cluster '{cluster.name}' (project '{cluster.project_id}', "
                        f"location '{cluster.location}') has Node Auto-Provisioning (NAP) "
                        f"active (detected via autoprovisioned pools: {pool_names}) "
                        "without cluster-level resource limits for CPU and memory. "
                        "Without resource limits, NAP can provision an unlimited number of "
                        "nodes, enabling large-scale crypto mining workloads."
                    ),
                    impact=(
                        "Node Auto-Provisioning without resource limits allows workloads to "
                        "trigger the creation of arbitrary numbers of nodes, enabling "
                        "unconstrained crypto mining and runaway billing."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Define cluster-level resource limits for CPU and memory in the "
                            "Node Auto-Provisioning configuration to cap total provisioned "
                            "resources."
                        ),
                        steps=[
                            "Identify the maximum CPU and memory your cluster legitimately needs.",
                            "Update the cluster's NAP configuration with explicit resource limits.",
                            "Monitor cluster resource usage and billing to detect anomalies.",
                        ],
                        gcloud_commands=[
                            "gcloud container clusters update CLUSTER_NAME "
                            "--enable-autoprovisioning "
                            "--max-cpu=MAX_CPU "
                            "--max-memory=MAX_MEMORY_GB "
                            "--zone=ZONE",
                        ],
                        iac_reference=(
                            "google_container_cluster.cluster_autoscaling.resource_limits"
                        ),
                        docs=[
                            "https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-provisioning",
                        ],
                        effort=RemediationEffort.LOW,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM023GKEPublicControlPlaneNoAuthorizedNetworks(BaseCheck):
    """GKE cluster with a public control plane and no authorized networks restriction."""

    check_id = "CM-023"
    title = (
        "GKE cluster has a public control plane endpoint without authorized networks configured"
    )
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["gke"]
    references = ["CIS GKE 6.6.2", "CIS GKE 6.6.3"]
    tags = ["gke", "network", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for cluster in inventory.gke_clusters:
            # Determine whether the cluster uses private nodes.
            private_cfg = cluster.private_cluster_config
            is_private = bool(private_cfg) and private_cfg.get("enablePrivateNodes", False)
            if is_private:
                continue

            # Cluster is public — check whether authorized networks are configured.
            man_cfg = cluster.master_authorized_networks_config
            authorized_networks_enabled = bool(man_cfg) and man_cfg.get("enabled", False)
            if authorized_networks_enabled:
                continue

            resource_key = f"{cluster.project_id}/{cluster.name}"

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, cluster.project_id, resource_key),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=8.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="container.googleapis.com/Cluster",
                        resource_id=resource_key,
                        project_id=cluster.project_id,
                        region=cluster.location,
                    ),
                    evidence={
                        "cluster_name": cluster.name,
                        "location": cluster.location,
                        "endpoint": cluster.endpoint,
                        "private_cluster_config": private_cfg,
                        "master_authorized_networks_config": man_cfg,
                    },
                    description=(
                        f"Cluster '{cluster.name}' (project '{cluster.project_id}', "
                        f"location '{cluster.location}') exposes its control plane endpoint "
                        f"publicly (endpoint: {cluster.endpoint or 'unknown'}) and does not "
                        "restrict access via Master Authorized Networks. Any IP on the internet "
                        "can attempt to reach the Kubernetes API server, enabling brute-force "
                        "or credential-stuffing attacks that could lead to cluster takeover "
                        "and crypto mining workload deployment."
                    ),
                    impact=(
                        "An unrestricted public API server allows attackers to attempt "
                        "authentication attacks. A successful compromise grants full cluster "
                        "control, enabling deployment of crypto mining pods across all nodes."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Enable Master Authorized Networks to restrict control plane access "
                            "to known IP ranges, or migrate to a private cluster."
                        ),
                        steps=[
                            "Identify all IP ranges that legitimately need access to the "
                            "Kubernetes API server (e.g., CI/CD systems, admin workstations).",
                            "Enable Master Authorized Networks with those specific CIDR ranges.",
                            "Alternatively, enable private nodes and use a private endpoint "
                            "to eliminate public API server exposure entirely.",
                            "Audit existing cluster credentials and rotate if exposure is suspected.",
                        ],
                        gcloud_commands=[
                            "# Enable authorized networks:\n"
                            "gcloud container clusters update CLUSTER_NAME "
                            "--enable-master-authorized-networks "
                            "--master-authorized-networks=CIDR1,CIDR2 "
                            "--zone=ZONE",
                            "# Or enable private cluster (requires recreation):\n"
                            "gcloud container clusters create CLUSTER_NAME "
                            "--enable-private-nodes "
                            "--master-ipv4-cidr=172.16.0.0/28 "
                            "--zone=ZONE",
                        ],
                        iac_reference=(
                            "google_container_cluster.master_authorized_networks_config"
                        ),
                        docs=[
                            "https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks",
                            "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM024WorkloadIdentityDisabled(BaseCheck):
    """GKE cluster without Workload Identity, forcing use of node-level SA credentials."""

    check_id = "CM-024"
    title = "GKE cluster does not have Workload Identity enabled"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["gke"]
    references = ["CIS GKE 6.2.2"]
    tags = ["gke", "iam", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for cluster in inventory.gke_clusters:
            wi_config = cluster.workload_identity_config
            if wi_config and wi_config.get("workloadPool"):
                continue

            resource_key = f"{cluster.project_id}/{cluster.name}"

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, cluster.project_id, resource_key),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.5,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="container.googleapis.com/Cluster",
                        resource_id=resource_key,
                        project_id=cluster.project_id,
                        region=cluster.location,
                    ),
                    evidence={
                        "cluster_name": cluster.name,
                        "location": cluster.location,
                        "workload_identity_config": wi_config,
                    },
                    description=(
                        f"Cluster '{cluster.name}' (project '{cluster.project_id}', "
                        f"location '{cluster.location}') does not have Workload Identity "
                        "enabled. Without Workload Identity, pods must rely on the node's "
                        "Compute Engine service account or long-lived key files to access "
                        "GCP APIs. A compromised pod can then access any GCP resource "
                        "permitted to the node SA, including spinning up additional compute "
                        "for crypto mining."
                    ),
                    impact=(
                        "Pods without Workload Identity inherit the node service account's "
                        "permissions. If that SA is over-privileged, a compromised pod can "
                        "create VMs, access storage, or perform other actions that facilitate "
                        "crypto mining at scale."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Enable Workload Identity on the cluster so that pods can use "
                            "fine-grained, per-workload GCP identities instead of the node SA."
                        ),
                        steps=[
                            "Enable Workload Identity on the cluster.",
                            "Annotate Kubernetes service accounts with the corresponding "
                            "GCP service account.",
                            "Grant only the minimum required IAM roles to each GCP SA.",
                            "Remove broad IAM roles from the node service account.",
                        ],
                        gcloud_commands=[
                            "gcloud container clusters update CLUSTER_NAME "
                            "--workload-pool=PROJECT_ID.svc.id.goog "
                            "--zone=ZONE",
                            "# Annotate a Kubernetes SA:\n"
                            "kubectl annotate serviceaccount KSA_NAME "
                            "--namespace=NAMESPACE "
                            "iam.gke.io/gcp-service-account=GSA_NAME@PROJECT_ID.iam.gserviceaccount.com",
                        ],
                        iac_reference=(
                            "google_container_cluster.workload_identity_config.workload_pool"
                        ),
                        docs=[
                            "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM025LegacyABACEnabled(BaseCheck):
    """GKE cluster with Legacy ABAC enabled, bypassing RBAC controls."""

    check_id = "CM-025"
    title = "GKE cluster has Legacy ABAC (Attribute-Based Access Control) enabled"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.MEDIUM
    required_collectors = ["gke"]
    references = ["CIS GKE 6.8.4"]
    tags = ["gke", "iam", "rbac", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for cluster in inventory.gke_clusters:
            legacy_abac = cluster.legacy_abac
            if not (isinstance(legacy_abac, dict) and legacy_abac.get("enabled", False)):
                continue

            resource_key = f"{cluster.project_id}/{cluster.name}"

            findings.append(
                Finding(
                    finding_id=_make_id(self.check_id, cluster.project_id, resource_key),
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    status=FindingStatus.FAIL,
                    exploitability_score=5.0,
                    blast_radius="project",
                    resource=GCPResource(
                        resource_type="container.googleapis.com/Cluster",
                        resource_id=resource_key,
                        project_id=cluster.project_id,
                        region=cluster.location,
                    ),
                    evidence={
                        "cluster_name": cluster.name,
                        "location": cluster.location,
                        "legacy_abac": legacy_abac,
                    },
                    description=(
                        f"Cluster '{cluster.name}' (project '{cluster.project_id}', "
                        f"location '{cluster.location}') has Legacy ABAC enabled. "
                        "Legacy ABAC grants all service accounts in the cluster broad "
                        "permissions, effectively bypassing Kubernetes RBAC. An attacker "
                        "who gains access to any pod can exploit these permissions to "
                        "deploy crypto mining workloads across the cluster."
                    ),
                    impact=(
                        "Legacy ABAC allows any authenticated user or service account to "
                        "perform privileged Kubernetes operations, making it trivial for a "
                        "compromised workload to deploy crypto mining pods cluster-wide."
                    ),
                    remediation=Remediation(
                        summary=(
                            "Disable Legacy ABAC and rely exclusively on Kubernetes RBAC "
                            "for access control."
                        ),
                        steps=[
                            "Audit existing RBAC roles and bindings to ensure they cover "
                            "all legitimate access requirements before disabling ABAC.",
                            "Disable Legacy ABAC on the cluster.",
                            "Verify that workloads continue to function correctly after "
                            "the change.",
                        ],
                        gcloud_commands=[
                            "gcloud container clusters update CLUSTER_NAME "
                            "--no-enable-legacy-authorization "
                            "--zone=ZONE",
                        ],
                        iac_reference=(
                            "google_container_cluster.enable_legacy_abac"
                        ),
                        docs=[
                            "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110",
                        ],
                        effort=RemediationEffort.MEDIUM,
                    ),
                    references=self.references,
                )
            )
        return findings


@CheckRegistry.register
class CM026NodePoolDefaultComputeSA(BaseCheck):
    """GKE node pool using the default Compute Engine SA with broad project permissions."""

    check_id = "CM-026"
    title = "GKE node pool uses the default Compute Engine service account"
    vector = Vector.CRYPTO_MINING
    severity_base = Severity.HIGH
    required_collectors = ["gke"]
    references = ["CIS GKE 6.2.1"]
    tags = ["gke", "iam", "service_account", "crypto_mining"]

    _DEFAULT_SA_SUFFIX = "@developer.gserviceaccount.com"

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings: list[Finding] = []
        for cluster in inventory.gke_clusters:
            for pool in cluster.node_pools:
                pool_name = pool.get("name", "<unknown>")
                config = pool.get("config", {})
                sa = config.get("serviceAccount", "")

                if not self._is_default_sa(sa):
                    continue

                resource_key = f"{cluster.project_id}/{cluster.name}/{pool_name}"

                findings.append(
                    Finding(
                        finding_id=_make_id(self.check_id, cluster.project_id, resource_key),
                        check_id=self.check_id,
                        vector=self.vector,
                        title=self.title,
                        severity=self.severity_base,
                        status=FindingStatus.FAIL,
                        exploitability_score=7.5,
                        blast_radius="project",
                        resource=GCPResource(
                            resource_type="container.googleapis.com/NodePool",
                            resource_id=resource_key,
                            project_id=cluster.project_id,
                            region=cluster.location,
                        ),
                        evidence={
                            "cluster_name": cluster.name,
                            "node_pool_name": pool_name,
                            "location": cluster.location,
                            "service_account": sa,
                        },
                        description=(
                            f"Node pool '{pool_name}' in cluster '{cluster.name}' "
                            f"(project '{cluster.project_id}', location '{cluster.location}') "
                            f"uses the service account '{sa or 'default'}'. "
                            "The default Compute Engine SA has the Editor role on the project, "
                            "granting every pod running on these nodes broad GCP permissions. "
                            "A compromised pod can use these credentials to create VMs, "
                            "access storage, or perform other actions that enable crypto mining."
                        ),
                        impact=(
                            "Pods on nodes using the default Compute Engine SA inherit Editor "
                            "permissions on the project. A single compromised container can "
                            "create additional compute resources for crypto mining or exfiltrate "
                            "sensitive data."
                        ),
                        remediation=Remediation(
                            summary=(
                                "Create a dedicated, least-privilege service account for the "
                                "node pool and assign only the minimum IAM roles required."
                            ),
                            steps=[
                                "Create a new GCP service account dedicated to this node pool.",
                                "Grant only the minimum IAM roles required by GKE nodes "
                                "(e.g., roles/logging.logWriter, roles/monitoring.metricWriter, "
                                "roles/monitoring.viewer, roles/storage.objectViewer for "
                                "private GCR).",
                                "Recreate the node pool specifying the new service account.",
                                "Enable Workload Identity (CM-024) to further restrict "
                                "per-pod GCP access.",
                            ],
                            gcloud_commands=[
                                "# Create a dedicated SA:\n"
                                "gcloud iam service-accounts create gke-node-sa "
                                "--display-name='GKE Node Pool SA' "
                                "--project=PROJECT_ID",
                                "# Grant minimum roles:\n"
                                "gcloud projects add-iam-policy-binding PROJECT_ID "
                                "--member=serviceAccount:gke-node-sa@PROJECT_ID.iam.gserviceaccount.com "
                                "--role=roles/logging.logWriter",
                                "# Recreate node pool with the new SA:\n"
                                "gcloud container node-pools create POOL_NAME "
                                "--cluster=CLUSTER_NAME "
                                "--service-account=gke-node-sa@PROJECT_ID.iam.gserviceaccount.com "
                                "--zone=ZONE",
                            ],
                            iac_reference=(
                                "google_container_node_pool.node_config.service_account"
                            ),
                            docs=[
                                "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
                                "https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity",
                            ],
                            effort=RemediationEffort.MEDIUM,
                        ),
                        references=self.references,
                    )
                )
        return findings

    def _is_default_sa(self, sa: str) -> bool:
        """Return True if the service account is the default Compute Engine SA."""
        if not sa or sa == "default":
            return True
        return sa.endswith(self._DEFAULT_SA_SUFFIX)

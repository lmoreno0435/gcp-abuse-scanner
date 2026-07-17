"""Unit tests for Phase 1 collectors using mocked GCP API responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gcp_abuse_scanner.models.inventory import (
    EnabledAPI,
    GKECluster,
    CloudRunService,
    OrgPolicy,
    ResourceInventory,
    VertexAIEndpoint,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_auth(creds: object = None) -> MagicMock:
    auth = MagicMock()
    auth.get_credentials.return_value = creds or MagicMock()
    return auth


def _inventory_with_apis(*service_names: str, project_id: str = "proj-1") -> ResourceInventory:
    inv = ResourceInventory(project_ids=[project_id])
    for svc in service_names:
        inv.enabled_apis.append(EnabledAPI(project_id=project_id, service_name=svc))
    return inv


# ─────────────────────────────────────────────────────────────────────────────
# GKECollector
# ─────────────────────────────────────────────────────────────────────────────

class TestGKECollector:
    def test_collects_clusters(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = _inventory_with_apis("container.googleapis.com")
        auth = _make_auth()

        mock_cluster = {
            "name": "prod-cluster",
            "location": "us-central1",
            "endpoint": "10.0.0.1",
            "masterAuthorizedNetworksConfig": {"enabled": True},
            "workloadIdentityConfig": {"workloadPool": "proj-1.svc.id.goog"},
            "nodePools": [
                {
                    "name": "default-pool",
                    "config": {"serviceAccount": "default"},
                    "autoscaling": {"enabled": True, "maxNodeCount": 100},
                }
            ],
            "legacyAbac": {"enabled": False},
            "privateClusterConfig": {"enablePrivateNodes": True},
            "autopilot": {},
        }

        mock_response = {"clusters": [mock_cluster]}

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_container = MagicMock()
            mock_build.return_value = mock_container
            (
                mock_container.projects()
                .locations()
                .clusters()
                .list()
                .execute.return_value
            ) = mock_response

            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.gke_clusters) == 1
        cluster = inv.gke_clusters[0]
        assert cluster.name == "prod-cluster"
        assert cluster.project_id == "proj-1"
        assert cluster.location == "us-central1"
        assert cluster.workload_identity_config == {"workloadPool": "proj-1.svc.id.goog"}
        assert cluster.legacy_abac == {"enabled": False}

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = ResourceInventory(project_ids=["proj-1"])  # no APIs enabled
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_build.return_value = MagicMock()
            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.gke_clusters) == 0
        assert "container.googleapis.com" in inv.skipped_apis.get("proj-1", [])

    def test_handles_api_error_gracefully(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = _inventory_with_apis("container.googleapis.com")
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_container = MagicMock()
            mock_build.return_value = mock_container
            (
                mock_container.projects()
                .locations()
                .clusters()
                .list()
                .execute.side_effect
            ) = Exception("403 Forbidden")

            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.gke_clusters) == 0
        assert any("gke" in e.get("collector", "") for e in inv.collector_errors)

    def test_node_pool_high_autoscaling_captured(self):
        from gcp_abuse_scanner.collectors.gke import GKECollector

        inv = _inventory_with_apis("container.googleapis.com")
        auth = _make_auth()

        mock_cluster = {
            "name": "big-cluster",
            "location": "us-east1",
            "endpoint": "10.0.0.2",
            "nodePools": [
                {
                    "name": "gpu-pool",
                    "config": {"serviceAccount": "compute@developer.gserviceaccount.com"},
                    "autoscaling": {"enabled": True, "maxNodeCount": 1000},
                }
            ],
            "legacyAbac": {"enabled": True},
            "privateClusterConfig": {},
            "autopilot": {},
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_container = MagicMock()
            mock_build.return_value = mock_container
            (
                mock_container.projects()
                .locations()
                .clusters()
                .list()
                .execute.return_value
            ) = {"clusters": [mock_cluster]}

            collector = GKECollector(auth)
            collector.collect(inv, ["proj-1"])

        assert inv.gke_clusters[0].legacy_abac == {"enabled": True}
        assert inv.gke_clusters[0].node_pools[0]["autoscaling"]["maxNodeCount"] == 1000


# ─────────────────────────────────────────────────────────────────────────────
# CloudRunCollector
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudRunCollector:
    def test_collects_services(self):
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector

        inv = _inventory_with_apis("run.googleapis.com")
        auth = _make_auth()

        mock_service = {
            "name": "projects/proj-1/locations/us-central1/services/my-svc",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "scaling": {"minInstanceCount": 0, "maxInstanceCount": 1000},
            "template": {},
        }
        mock_iam = {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_run = MagicMock()
            mock_build.return_value = mock_run

            # list services
            (
                mock_run.projects()
                .locations()
                .services()
                .list()
                .execute.return_value
            ) = {"services": [mock_service]}
            # list_next returns None (no more pages)
            mock_run.projects().locations().services().list_next.return_value = None

            # getIamPolicy
            (
                mock_run.projects()
                .locations()
                .services()
                .getIamPolicy()
                .execute.return_value
            ) = mock_iam

            collector = CloudRunCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.cloud_run_services) == 1
        svc = inv.cloud_run_services[0]
        assert svc.name == "my-svc"
        assert svc.region == "us-central1"
        assert svc.ingress == "INGRESS_TRAFFIC_ALL"
        # IAM bindings should include allUsers
        assert any(
            "allUsers" in b.get("members", []) for b in svc.iam_bindings
        )

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build"):
            collector = CloudRunCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.cloud_run_services) == 0
        assert "run.googleapis.com" in inv.skipped_apis.get("proj-1", [])

    def test_handles_error_gracefully(self):
        from gcp_abuse_scanner.collectors.cloud_run import CloudRunCollector

        inv = _inventory_with_apis("run.googleapis.com")
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_run = MagicMock()
            mock_build.return_value = mock_run
            (
                mock_run.projects()
                .locations()
                .services()
                .list()
                .execute.side_effect
            ) = Exception("500 Internal Server Error")

            collector = CloudRunCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.cloud_run_services) == 0
        assert any("cloud_run" in e.get("collector", "") for e in inv.collector_errors)


# ─────────────────────────────────────────────────────────────────────────────
# VertexAICollector
# ─────────────────────────────────────────────────────────────────────────────

class TestVertexAICollector:
    def test_collects_endpoints(self):
        from gcp_abuse_scanner.collectors.vertex_ai import VertexAICollector

        inv = _inventory_with_apis("aiplatform.googleapis.com")
        auth = _make_auth()

        mock_endpoint = {
            "name": "projects/proj-1/locations/us-central1/endpoints/12345",
            "displayName": "gemini-endpoint",
            "network": "",  # no private network = public
        }
        mock_iam = {"bindings": [{"role": "roles/aiplatform.user", "members": ["allUsers"]}]}

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_ai = MagicMock()
            mock_build.return_value = mock_ai

            (
                mock_ai.projects()
                .locations()
                .endpoints()
                .list()
                .execute.return_value
            ) = {"endpoints": [mock_endpoint]}
            mock_ai.projects().locations().endpoints().list_next.return_value = None

            (
                mock_ai.projects()
                .locations()
                .endpoints()
                .getIamPolicy()
                .execute.return_value
            ) = mock_iam

            collector = VertexAICollector(auth)
            collector.collect(inv, ["proj-1"])

        # At least one endpoint collected (from us-central1)
        assert len(inv.vertex_ai_endpoints) >= 1
        ep = inv.vertex_ai_endpoints[0]
        assert ep.name == "12345"
        assert ep.display_name == "gemini-endpoint"
        assert ep.network == ""

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.vertex_ai import VertexAICollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build"):
            collector = VertexAICollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.vertex_ai_endpoints) == 0
        assert "aiplatform.googleapis.com" in inv.skipped_apis.get("proj-1", [])


# ─────────────────────────────────────────────────────────────────────────────
# OrgPolicyCollector
# ─────────────────────────────────────────────────────────────────────────────

class TestOrgPolicyCollector:
    def test_collects_org_level_policies(self):
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        mock_policy = {
            "name": "organizations/123/policies/compute.vmExternalIpAccess",
            "spec": {"rules": [{"denyAll": "TRUE"}]},
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_orgpolicy = MagicMock()
            mock_build.return_value = mock_orgpolicy

            # Org-level get returns a policy
            (
                mock_orgpolicy.organizations()
                .policies()
                .get()
                .execute.return_value
            ) = mock_policy

            # Project-level get raises (not set)
            (
                mock_orgpolicy.projects()
                .policies()
                .get()
                .execute.side_effect
            ) = Exception("404 Not Found")

            collector = OrgPolicyCollector(auth)
            collector.collect(inv, ["proj-1"], organization_id="123")

        # Should have entries for org + project for each constraint
        assert len(inv.org_policies) > 0
        # At least one should have the deny-all policy
        policies_with_spec = [p for p in inv.org_policies if p.policy]
        assert len(policies_with_spec) > 0

    def test_records_empty_policy_when_not_set(self):
        from gcp_abuse_scanner.collectors.org_policy import OrgPolicyCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_orgpolicy = MagicMock()
            mock_build.return_value = mock_orgpolicy

            # All gets raise 404 (policy not configured)
            (
                mock_orgpolicy.organizations()
                .policies()
                .get()
                .execute.side_effect
            ) = Exception("404 Not Found")
            (
                mock_orgpolicy.projects()
                .policies()
                .get()
                .execute.side_effect
            ) = Exception("404 Not Found")

            collector = OrgPolicyCollector(auth)
            collector.collect(inv, ["proj-1"], organization_id="123")

        # Empty policy dicts recorded (not configured = important signal)
        empty_policies = [p for p in inv.org_policies if p.policy == {}]
        assert len(empty_policies) > 0


# ─────────────────────────────────────────────────────────────────────────────
# RecommenderCollector
# ─────────────────────────────────────────────────────────────────────────────

class TestRecommenderCollector:
    def test_collects_iam_recommendations(self):
        from gcp_abuse_scanner.collectors.recommender import RecommenderCollector

        inv = _inventory_with_apis("recommender.googleapis.com")
        auth = _make_auth()

        mock_rec = {
            "name": "projects/proj-1/locations/global/recommenders/google.iam.policy.Recommender/recommendations/abc123",
            "description": "Remove unused role from service account",
            "recommenderSubtype": "REMOVE_ROLE",
            "primaryImpact": {"category": "SECURITY"},
            "content": {
                "operationGroups": [
                    {
                        "operations": [
                            {
                                "action": "remove",
                                "resourceType": "cloudresourcemanager.googleapis.com/Project",
                                "resource": "//cloudresourcemanager.googleapis.com/projects/proj-1",
                                "path": "/iamPolicy",
                            }
                        ]
                    }
                ]
            },
            "stateInfo": {"state": "ACTIVE"},
            "priority": "P2",
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_recommender = MagicMock()
            mock_build.return_value = mock_recommender

            (
                mock_recommender.projects()
                .locations()
                .recommenders()
                .recommendations()
                .list()
                .execute.return_value
            ) = {"recommendations": [mock_rec]}
            (
                mock_recommender.projects()
                .locations()
                .recommenders()
                .recommendations()
                .list_next.return_value
            ) = None

            collector = RecommenderCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.recommender_insights) == 1
        insight = inv.recommender_insights[0]
        assert insight["project_id"] == "proj-1"
        assert insight["recommender_subtype"] == "REMOVE_ROLE"
        assert insight["priority"] == "P2"

    def test_skips_when_api_not_enabled(self):
        from gcp_abuse_scanner.collectors.recommender import RecommenderCollector

        inv = ResourceInventory(project_ids=["proj-1"])
        auth = _make_auth()

        with patch("googleapiclient.discovery.build"):
            collector = RecommenderCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.recommender_insights) == 0
        assert "recommender.googleapis.com" in inv.skipped_apis.get("proj-1", [])


# ─────────────────────────────────────────────────────────────────────────────
# QuotaCollector
# ─────────────────────────────────────────────────────────────────────────────

class TestQuotaCollector:
    def test_collects_quota_info(self):
        from gcp_abuse_scanner.collectors.quota import QuotaCollector

        inv = _inventory_with_apis(
            "serviceusage.googleapis.com",
            "aiplatform.googleapis.com",
            "compute.googleapis.com",
        )
        auth = _make_auth()

        mock_metrics_response = {
            "metrics": [
                {
                    "metric": "aiplatform.googleapis.com/online_prediction_requests_per_base_model_per_minute_per_project",
                    "consumerQuotaLimits": [
                        {
                            "name": "projects/proj-1/services/aiplatform.googleapis.com/consumerQuotaMetrics/online_prediction_requests_per_base_model_per_minute_per_project/limits/%2Fmin%2Fproject%2Fbase_model",
                            "unit": "1/min/{project}/{base_model}",
                            "isPrecise": True,
                            "quotaBuckets": [
                                {
                                    "effectiveLimit": "60",
                                    "defaultLimit": "60",
                                    "dimensions": {},
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_su = MagicMock()
            mock_build.return_value = mock_su

            (
                mock_su.services()
                .consumerQuotaMetrics()
                .list()
                .execute.return_value
            ) = mock_metrics_response

            collector = QuotaCollector(auth)
            collector.collect(inv, ["proj-1"])

        assert len(inv.quota_info) >= 1
        entry = inv.quota_info[0]
        assert entry["project_id"] == "proj-1"
        assert "aiplatform" in entry["service"]

    def test_no_quota_when_service_not_enabled(self):
        from gcp_abuse_scanner.collectors.quota import QuotaCollector

        # Only serviceusage enabled, not aiplatform or compute
        inv = _inventory_with_apis("serviceusage.googleapis.com")
        auth = _make_auth()

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_su = MagicMock()
            mock_build.return_value = mock_su

            collector = QuotaCollector(auth)
            collector.collect(inv, ["proj-1"])

        # No quotas collected because target services not enabled
        assert len(inv.quota_info) == 0


# ─────────────────────────────────────────────────────────────────────────────
# CollectorEngine integration (smoke test)
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectorEngine:
    """
    Engine tests patch at the source module level (imports are local inside
    CollectorEngine.collect, so we patch the actual collector classes).
    """

    _PATCH_TARGETS = [
        "gcp_abuse_scanner.collectors.service_usage.ServiceUsageCollector",
        "gcp_abuse_scanner.collectors.iam.IAMCollector",
        "gcp_abuse_scanner.collectors.compute.ComputeCollector",
        "gcp_abuse_scanner.collectors.network.NetworkCollector",
        "gcp_abuse_scanner.collectors.api_keys.APIKeysCollector",
        "gcp_abuse_scanner.collectors.billing.BillingCollector",
        "gcp_abuse_scanner.collectors.gke.GKECollector",
        "gcp_abuse_scanner.collectors.cloud_run.CloudRunCollector",
        "gcp_abuse_scanner.collectors.vertex_ai.VertexAICollector",
        "gcp_abuse_scanner.collectors.org_policy.OrgPolicyCollector",
        "gcp_abuse_scanner.collectors.recommender.RecommenderCollector",
        "gcp_abuse_scanner.collectors.quota.QuotaCollector",
    ]

    def test_engine_returns_inventory(self):
        from gcp_abuse_scanner.collectors.engine import CollectorEngine

        auth = _make_auth()

        patches = [patch(t) for t in self._PATCH_TARGETS]
        mocks = [p.start() for p in patches]
        try:
            for m in mocks:
                instance = m.return_value
                instance.collect.return_value = None
                instance.name = "mock_collector"
                instance.required_apis = []

            engine = CollectorEngine(auth, max_workers=2)
            inventory = engine.collect(["proj-1", "proj-2"], organization_id="org-123")
        finally:
            for p in patches:
                p.stop()

        assert isinstance(inventory, ResourceInventory)
        assert inventory.organization_id == "org-123"
        assert set(inventory.project_ids) == {"proj-1", "proj-2"}

    def test_engine_handles_collector_failure(self):
        from gcp_abuse_scanner.collectors.engine import CollectorEngine

        auth = _make_auth()

        patches = [patch(t) for t in self._PATCH_TARGETS]
        mocks = [p.start() for p in patches]
        try:
            for m in mocks:
                instance = m.return_value
                instance.collect.return_value = None
                instance.name = "mock_collector"
                instance.required_apis = []

            # Make IAMCollector raise
            iam_mock = mocks[1]  # index 1 = IAMCollector
            iam_mock.return_value.collect.side_effect = RuntimeError("IAM API down")
            iam_mock.return_value.name = "iam"

            engine = CollectorEngine(auth, max_workers=2)
            inventory = engine.collect(["proj-1"])
        finally:
            for p in patches:
                p.stop()

        # Should not raise — errors captured in inventory
        assert isinstance(inventory, ResourceInventory)

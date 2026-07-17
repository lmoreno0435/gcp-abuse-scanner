# gcp-abuse-scanner

> **Preventive GCP security scanner** for crypto mining and Gemini API abuse vectors.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![CI](https://github.com/lmoreno0435/gcp-abuse-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/lmoreno0435/gcp-abuse-scanner/actions)
[![PyPI](https://img.shields.io/pypi/v/gcp-abuse-scanner.svg)](https://pypi.org/project/gcp-abuse-scanner/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io/lmoreno0435/gcp-abuse-scanner)
[![codecov](https://codecov.io/gh/lmoreno0435/gcp-abuse-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/lmoreno0435/gcp-abuse-scanner)

`gcp-abuse-scanner` is an open source CLI tool that scans Google Cloud Platform organizations and projects for **security misconfigurations** that can be exploited for:

- 🪙 **Crypto mining** — unauthorized compute resource abuse
- 🤖 **Gemini API abuse** — unauthorized or uncontrolled access to Generative AI APIs

The tool is **read-only** and **preventive**: it never modifies resources, never disables APIs, and never revokes permissions. It produces a **prioritized remediation report** so you know exactly what to fix and in what order.

---

## Features

- 🔍 **~65+ security checks** across Compute, GKE, Cloud Run, IAM, Networking, API Keys, Vertex AI, Billing, and Org Policies
- 🏢 **Organization-wide or per-project** scanning
- 🔐 **Service account authentication** (impersonation recommended, key file supported)
- 📊 **Multiple output formats**: Console (rich), JSON, Markdown, HTML, SARIF 2.1.0
- ⚡ **Concurrent collection** with retry/backoff — handles large orgs with thousands of projects
- 🎯 **Prioritized findings** with CRITICAL / HIGH / MEDIUM / LOW severity
- 🚫 **Allowlist support** for known exceptions
- 🔌 **Plugin architecture** — add new checks without touching the core

---

## Quickstart

### Installation

```bash
# Recommended: pipx (isolated environment)
pipx install gcp-abuse-scanner

# Or pip
pip install gcp-abuse-scanner

# Or Docker
docker run --rm -v ~/.config/gcloud:/root/.config/gcloud \
  ghcr.io/lmoreno0435/gcp-abuse-scanner:latest scan --org YOUR_ORG_ID
```

### Authentication

**Recommended: Service Account Impersonation**
```bash
gcp-abuse-scanner scan --org 123456789012 \
  --impersonate-service-account scanner-sa@your-project.iam.gserviceaccount.com
```

**Alternative: Service Account Key File**
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
gcp-abuse-scanner scan --org 123456789012
```

> ⚠️ Using key files is an anti-pattern. Prefer impersonation or Workload Identity Federation.

### Basic Usage

```bash
# Scan entire organization
gcp-abuse-scanner scan --org 123456789012

# Scan specific projects
gcp-abuse-scanner scan --project my-project-1 --project my-project-2

# Output as JSON
gcp-abuse-scanner scan --org 123456789012 --format json --output report.json

# Output as Markdown
gcp-abuse-scanner scan --org 123456789012 --format markdown --output report.md

# Output as self-contained HTML report
gcp-abuse-scanner scan --org 123456789012 --format html --output report.html

# Output as SARIF 2.1.0 (GitHub Advanced Security, VS Code)
gcp-abuse-scanner scan --org 123456789012 --format sarif --output results.sarif

# All formats at once (auto-named files)
gcp-abuse-scanner scan --org 123456789012 --format all

# Scan only Gemini abuse vector
gcp-abuse-scanner scan --org 123456789012 --vector gemini_abuse

# Speed up re-runs with inventory cache (1h TTL)
gcp-abuse-scanner scan --org 123456789012 --cache

# List all available checks
gcp-abuse-scanner list-checks

# Dry run (resolve scope without scanning)
gcp-abuse-scanner scan --org 123456789012 --dry-run
```

---

## Prerequisites — GCP APIs

The scanner calls GCP APIs to collect resource inventory. **These APIs must be enabled before running a scan.**

### Quick setup (recommended)

```bash
# Clone the repo to get the script, then run:
bash scripts/enable_apis.sh \
  --org YOUR_ORG_ID \
  --scanner-project YOUR_SCANNER_PROJECT

# Dry-run first to preview changes:
bash scripts/enable_apis.sh \
  --org YOUR_ORG_ID \
  --scanner-project YOUR_SCANNER_PROJECT \
  --dry-run
```

### Manual setup

**In the scanner project** (enable once):
```bash
gcloud services enable \
  cloudasset.googleapis.com \
  cloudbilling.googleapis.com \
  billingbudgets.googleapis.com \
  orgpolicy.googleapis.com \
  --project=YOUR_SCANNER_PROJECT
```

**In each scanned project**:
```bash
gcloud services enable \
  serviceusage.googleapis.com \
  iam.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  run.googleapis.com \
  aiplatform.googleapis.com \
  apikeys.googleapis.com \
  recommender.googleapis.com \
  --project=PROJECT_ID
```

> **What happens if an API is disabled?** The scanner skips that resource type for that project — it does not fail the scan. Use `--verbose` to see which APIs were skipped. See [docs/apis.md](docs/apis.md) for the full dependency map.

---

## Required IAM Roles

The service account running this tool needs the following **read-only** roles, assigned at the **organization level** (for org-wide scans) or project level:

| Role | Purpose |
|------|---------|
| `roles/cloudasset.viewer` | Enumerate all resources and IAM policies efficiently |
| `roles/iam.securityReviewer` | Read IAM policies across all resources |
| `roles/compute.viewer` | Read Compute Engine instances, firewall rules, networks |
| `roles/container.viewer` | Read GKE clusters and node pools |
| `roles/run.viewer` | Read Cloud Run services and jobs |
| `roles/serviceusage.serviceUsageViewer` | Determine which APIs are enabled per project |
| `roles/serviceusage.apiKeysViewer` | List API keys and their restrictions |
| `roles/aiplatform.viewer` | Read Vertex AI endpoints and model configuration |
| `roles/billing.viewer` | Verify billing accounts and budget existence |
| `roles/recommender.viewer` | Read IAM recommender insights |
| `roles/orgpolicy.policyViewer` | Read Organization Policy constraints |
| `roles/monitoring.viewer` | *(Optional)* Verify alerting policies |

See [docs/iam-setup.md](docs/iam-setup.md) for step-by-step setup instructions and [docs/apis.md](docs/apis.md) for the complete API reference.

---

## Security Checks

### Crypto Mining Vector (~40 checks)

| ID | Severity | Description |
|----|----------|-------------|
| CM-001 | HIGH | VM instances with external IP addresses |
| CM-004 | CRITICAL | Firewall allows SSH/RDP from 0.0.0.0/0 |
| CM-009 | MEDIUM | Shielded VM not enabled |
| CM-020 | HIGH | GKE node pools with unbounded autoscaling |
| CM-023 | HIGH | GKE cluster with public endpoint and no authorized networks |
| CM-030 | HIGH | Cloud Run services with public invoker (allUsers) |
| CM-040 | HIGH | SA with compute admin roles granted broadly |
| CM-041 | HIGH | Service accounts with user-managed (exported) keys |
| CM-043 | CRITICAL | IAM binding grants allUsers/allAuthenticatedUsers |
| CM-044 | HIGH | Default Compute SA has Editor/Owner role |
| ... | ... | See [docs/checks/crypto_mining.md](docs/checks/crypto_mining.md) |

### Gemini API Abuse Vector (~25 checks)

| ID | Severity | Description |
|----|----------|-------------|
| GEM-001 | CRITICAL | API key has no API restrictions |
| GEM-002 | CRITICAL | API key has no application restrictions |
| GEM-003 | HIGH | API key explicitly targets Gemini API without app restrictions |
| GEM-020 | HIGH | Vertex AI role granted to broad principal (domain/group) |
| GEM-021 | CRITICAL | Vertex AI role granted to allUsers/allAuthenticatedUsers |
| GEM-030 | HIGH | Vertex AI endpoint accessible without private endpoint |
| GEM-040 | MEDIUM | Vertex AI quotas at default (high) values |
| GEM-051 | HIGH | No budget covering Vertex AI/Gemini spend |
| ... | ... | See [docs/checks/gemini_abuse.md](docs/checks/gemini_abuse.md) |

### Common Checks (~6 checks)

| ID | Severity | Description |
|----|----------|-------------|
| CMN-001 | HIGH | Billing account has no budget configured |
| CMN-002 | MEDIUM | Budget exists but has no threshold alert rules |
| CMN-005 | MEDIUM | Key org policy constraints absent |
| CMN-006 | MEDIUM | Cloud Audit Logs (Data Access) disabled |

---

## Report Format

Each finding includes:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Priority rank**: Global ordering for the remediation plan
- **Evidence**: Exact resource details that triggered the finding
- **Impact**: What an attacker can do with this misconfiguration
- **Remediation**: Step-by-step fix with `gcloud` commands, Terraform reference, and effort estimate

Example finding (JSON):
```json
{
  "check_id": "GEM-002",
  "title": "API key has no application restrictions",
  "severity": "CRITICAL",
  "priority_rank": 1,
  "resource": {"project_id": "my-project", "resource_id": "..."},
  "remediation": {
    "summary": "Add HTTP referrer or IP restrictions to the key.",
    "effort": "LOW",
    "gcloud_commands": ["gcloud services api-keys update KEY_UID --allowed-referrers=..."]
  }
}
```

---

## Configuration

Create a `config.yaml` to customize behavior:

```yaml
# See examples/config.example.yaml for full reference
allowlist:
  - check_id: CM-001
    project_id: my-legacy-project
    reason: "External IP required for on-prem VPN — reviewed 2024-01-15"
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new checks, collectors, and reporters.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

> **Disclaimer**: This tool is read-only and preventive. It does not guarantee detection of all security issues. Always combine with other security controls and monitoring.

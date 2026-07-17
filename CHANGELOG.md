# Changelog

All notable changes to `gcp-abuse-scanner` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-07-17

### Fixed
- **CM-002 crash on real org scans**: `_org_policy_is_restricted()` called `.upper()` on `denyAll`/`allowAll` fields that the Org Policy REST v2 API returns as native Python booleans, not strings. Fixed to handle both `bool` and `str` representations.

## [0.1.2] - 2026-07-17

### Fixed
- **API Keys checks (GEM-001 to GEM-004) were silently skipped** in most real projects. Root cause: `required_apis = ["apikeys.googleapis.com"]` caused `is_applicable()` to return `False` when that API was not listed in the ServiceUsage response — even though API keys exist independently of whether the API Keys API is explicitly enabled. Removed `required_apis` from GEM-001, GEM-002, and GEM-003 (GEM-004 was already unaffected).
- **`APIKeysCollector` was also skipping projects** via the same `is_api_enabled()` guard. The collector now always attempts collection. HTTP 403/404 responses (API not enabled or no permission) are logged at DEBUG level instead of WARNING, keeping logs clean while still collecting keys when accessible.
- Added 5 new tests covering: collection without `apikeys.googleapis.com` in enabled_apis, collection with it present, 403 is silent, 500 is a warning, and `GEM-001.is_applicable()` returns `True` without the API in enabled_apis.

## [0.1.1] - 2026-07-17

### Fixed
- Suppressed noisy `googleapiclient` internal log messages (`Encountered 403 Forbidden with reason "PERMISSION_DENIED"`) that appeared before each collector's own contextual warning. These are now silenced at `CRITICAL` level (downgraded to `ERROR` in `--verbose` mode).
- Collector error messages now show a concise one-line summary instead of dumping the full JSON response body. Example: `GKE collection failed for my-proj: HTTP 403: This API method requires billing to be enabled` instead of a multi-line `<HttpError 403 when requesting ... details: [{'@type': ...}]>`.
- Added `_fmt_exc()` helper in `collectors/base.py` with 17 unit tests covering `HttpError` formatting, generic exceptions, truncation, and collector integration.

## [0.1.0] - 2026-07-17

### Added

#### Core framework
- Project scaffold: `pyproject.toml`, `hatchling` build, `ruff`/`black`/`mypy` toolchain
- Core models: `Finding`, `ResourceInventory`, `ScanReport`, `ScanMetadata`, `ExecutiveSummary`
- Auth layer: `AuthManager` (key file + impersonation), `ScopeResolver` (org → project list)
- CLI: `scan`, `list-checks`, `version` commands via `typer`; `--format`, `--vector`, `--allowlist`, `--dry-run`, `--cache/--no-cache`, `--cache-ttl` options
- Base check/collector plugin framework with auto-registration via `CheckRegistry`
- Scoring engine: priority ranking, CVSS-inspired exploitability score, allowlist suppression

#### Collectors (11 total)
- `ComputeCollector`, `IAMCollector`, `NetworkCollector`, `ServiceUsageCollector`, `APIKeysCollector`, `BillingCollector`
- `GKECollector`, `CloudRunCollector`, `VertexAICollector`, `OrgPolicyCollector`, `RecommenderCollector`, `QuotaCollector`
- `CollectorEngine`: concurrent collection with `tenacity` retry/backoff
- `InventoryCache`: gzip-compressed JSON cache with SHA256 key and configurable TTL

#### Crypto Mining checks (25)
- **CM-001** HIGH — VM instances with external IP addresses
- **CM-002** MEDIUM — VM instances without OS Login enabled
- **CM-003** MEDIUM — VM instances with serial port access enabled
- **CM-004** CRITICAL — Firewall allows SSH/RDP from 0.0.0.0/0
- **CM-005** HIGH — Firewall allows all ingress traffic (0.0.0.0/0 any port)
- **CM-006** MEDIUM — Default network exists in project
- **CM-007** HIGH — VM instance running as default Compute service account
- **CM-009** MEDIUM — Shielded VM not enabled
- **CM-011** HIGH — VM instance with full cloud-platform OAuth scope
- **CM-020** HIGH — GKE node pools with unbounded autoscaling
- **CM-021** MEDIUM — GKE cluster without Workload Identity
- **CM-023** HIGH — GKE cluster with public endpoint and no authorized networks
- **CM-024** MEDIUM — GKE cluster without network policy
- **CM-025** MEDIUM — GKE node pool without auto-upgrade
- **CM-026** MEDIUM — GKE cluster with legacy ABAC enabled
- **CM-030** HIGH — Cloud Run service with public invoker (allUsers)
- **CM-031** MEDIUM — Cloud Run service with no CPU/memory limits
- **CM-040** HIGH — Service account with Compute Admin role granted broadly
- **CM-041** HIGH — Service account with user-managed (exported) keys
- **CM-042** HIGH — Overly permissive custom role (compute.instances.create + iam.serviceAccounts.actAs)
- **CM-043** CRITICAL — IAM binding grants allUsers/allAuthenticatedUsers
- **CM-044** HIGH — Default Compute SA has Editor/Owner role
- **CM-045** HIGH — Service account key older than 90 days
- **CM-050** HIGH — Workload Identity not used (SA key attached to GKE workload)
- **CM-060** MEDIUM — IAM recommender: unused permissions on SA

#### Gemini API Abuse checks (16)
- **GEM-001** CRITICAL — API key has no API restrictions
- **GEM-002** CRITICAL — API key has no application restrictions
- **GEM-003** HIGH — API key targets Gemini API without app restrictions
- **GEM-004** HIGH — API key not rotated in 90+ days
- **GEM-005** MEDIUM — API key with no expiry date
- **GEM-006** HIGH — Multiple Gemini-enabled API keys in project
- **GEM-010** HIGH — Gemini API enabled but no VPC Service Controls perimeter
- **GEM-011** MEDIUM — Gemini API enabled but no org policy restricting API key creation
- **GEM-020** HIGH — Vertex AI role granted to broad principal (domain/group)
- **GEM-021** CRITICAL — Vertex AI role granted to allUsers/allAuthenticatedUsers
- **GEM-022** HIGH — Vertex AI User role granted at project level (not resource level)
- **GEM-023** MEDIUM — External identity (gmail.com) has Vertex AI role
- **GEM-030** HIGH — Vertex AI endpoint accessible without private endpoint
- **GEM-040** MEDIUM — Vertex AI quotas at default (high) values
- **GEM-050** HIGH — No budget alert covering Vertex AI/Gemini spend
- **GEM-051** HIGH — No budget covering Vertex AI/Gemini spend at all

#### Common checks (6)
- **CMN-001** HIGH — Billing account has no budget configured
- **CMN-002** MEDIUM — Budget exists but has no threshold alert rules
- **CMN-003** HIGH — Cloud Audit Logs (Data Access) not enabled for critical services
- **CMN-004** MEDIUM — Audit log sink not configured (no log export)
- **CMN-005** MEDIUM — Key org policy constraints absent (domain restriction, resource location)
- **CMN-006** MEDIUM — Cloud Audit Logs (Data Access) disabled for all services

#### Reporters (5)
- `ConsoleReporter` — rich terminal output with severity-colored tables
- `JSONReporter` — machine-readable structured JSON
- `MarkdownReporter` — GitHub-flavored Markdown with summary tables
- `HTMLReporter` — self-contained HTML with Jinja2 template, severity badges, remediation accordion
- `SARIFReporter` — SARIF 2.1.0 for GitHub Advanced Security, VS Code, and SAST tooling

#### Documentation
- `docs/checks/crypto_mining.md` — 25 checks with full detail blocks
- `docs/checks/gemini_abuse.md` — 16 GEM + 6 CMN checks documented
- `docs/iam-setup.md` — step-by-step IAM setup with `gcloud` commands
- `CONTRIBUTING.md` — check/collector/reporter authoring guide
- `examples/config.example.yaml` — allowlist and configuration reference

#### CI/CD
- GitHub Actions: `ci.yml` (lint + type check + test matrix 3.11/3.12 + Codecov)
- GitHub Actions: `release.yml` (PyPI trusted publishing + Docker push to ghcr.io)

#### Tests
- 179 unit tests, all offline (no GCP API calls)
- Fixtures: `inventory_crypto_mining.json`, `inventory_gemini_abuse.json`

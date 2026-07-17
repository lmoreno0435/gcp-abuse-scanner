# Contributing to gcp-abuse-scanner

Thank you for contributing! This guide explains how to add checks, collectors, and reporters.

## Development Setup

```bash
git clone https://github.com/lmoreno0435/gcp-abuse-scanner
cd gcp-abuse-scanner
pip install -e ".[dev]"
pre-commit install
```

## Adding a New Security Check

Every check must follow the `BaseCheck` contract. Here's the minimal template:

```python
# gcp_abuse_scanner/checks/<vector>/<check_file>.py

from gcp_abuse_scanner.checks.base import BaseCheck, CheckRegistry
from gcp_abuse_scanner.models.finding import Finding, Severity, Vector, ...
from gcp_abuse_scanner.models.inventory import ResourceInventory

@CheckRegistry.register
class MY001MyCheck(BaseCheck):
    check_id = "MY-001"           # Unique ID — never reuse
    title = "Short description"
    vector = Vector.CRYPTO_MINING  # or GEMINI_ABUSE, COMMON
    severity_base = Severity.HIGH
    required_apis = ["compute.googleapis.com"]   # skip if API not enabled
    required_collectors = ["compute"]
    references = ["CIS GCP 4.x"]
    tags = ["compute", "crypto_mining"]

    def evaluate(self, inventory: ResourceInventory) -> list[Finding]:
        findings = []
        for resource in inventory.compute_instances:
            if <condition>:
                findings.append(Finding(
                    finding_id=f"{self.check_id}-{resource.project_id}-{hash(resource.name)}",
                    check_id=self.check_id,
                    vector=self.vector,
                    title=self.title,
                    severity=self.severity_base,
                    ...
                ))
        return findings
```

### Rules for checks

1. **No API calls** — use only `inventory` data. Collectors fetch data; checks evaluate it.
2. **Every new check requires**:
   - A unit test with at least one FAIL fixture and one PASS case.
   - An entry in `docs/checks/<vector>.md`.
3. **`finding_id` must be unique** per resource instance. Use `hashlib.md5` on the resource identifier.
4. **`safe_evaluate()`** is called by the engine — it catches exceptions. Don't swallow errors silently.
5. **Remediation must include** at least: `summary`, one `step`, and one `gcloud_command` or `iac_reference`.

## Adding a New Collector

```python
# gcp_abuse_scanner/collectors/my_collector.py

from gcp_abuse_scanner.collectors.base import BaseCollector
from gcp_abuse_scanner.models.inventory import ResourceInventory

class MyCollector(BaseCollector):
    name = "my_collector"
    required_apis = ["myservice.googleapis.com"]

    def collect(self, inventory: ResourceInventory, project_ids: list[str], organization_id=None):
        creds = self._auth.get_credentials()
        for project_id in project_ids:
            if not self.is_api_enabled(inventory, project_id):
                inventory.skipped_apis.setdefault(project_id, []).append("myservice.googleapis.com")
                continue
            # ... fetch and append to inventory
```

Then register it in `collectors/engine.py`.

## Running Tests

```bash
# All tests
pytest

# Specific check
pytest tests/unit/test_crypto_mining_checks.py -v

# With coverage
pytest --cov=gcp_abuse_scanner --cov-report=html
```

## Code Style

```bash
ruff check .          # linting
black .               # formatting
mypy gcp_abuse_scanner  # type checking
```

## Pull Request Checklist

- [ ] New check has `check_id`, `title`, `vector`, `severity_base`, `required_apis`, `required_collectors`
- [ ] Unit test with FAIL fixture + PASS case
- [ ] Entry in `docs/checks/<vector>.md`
- [ ] `ruff`, `black`, `mypy` pass
- [ ] `pytest` passes with no regressions

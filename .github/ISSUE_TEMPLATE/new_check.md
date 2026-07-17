---
name: Propose a new security check
about: Suggest a new check for crypto mining or Gemini abuse detection
labels: new-check
---

**Check ID** (proposed)
e.g. CM-050 or GEM-060

**Vector**
- [ ] crypto_mining
- [ ] gemini_abuse
- [ ] common

**Proposed severity**
- [ ] CRITICAL
- [ ] HIGH
- [ ] MEDIUM
- [ ] LOW

**What misconfiguration does this check detect?**
Describe the GCP configuration that is exploitable.

**How can it be exploited?**
Explain the attack scenario (crypto mining or Gemini abuse).

**What GCP API/resource does it inspect?**
e.g. Compute Engine instances, IAM bindings, API keys...

**Proposed remediation**
What should the user do to fix it? Include `gcloud` commands if possible.

**References**
CIS benchmark, GCP documentation, CVE, etc.

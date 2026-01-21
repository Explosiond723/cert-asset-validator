# cert-asset-validator

Tool to validate, normalize, and inspect **certificate asset definitions** stored as YAML, designed for Kubernetes / OpenShift workflows.

This project focuses on **describing and validating certificate assets**, not on handling certificates or interacting with clusters directly (yet).

---

## Purpose

In real-world Kubernetes/OpenShift environments, certificates are often:
- spread across multiple namespaces
- stored in Secrets with non-standard layouts
- composed of keystores, truststores, and passwords stored separately
- documented manually (e.g. spreadsheets)

`cert-asset-validator` aims to replace fragile documentation with a **declarative, version-controlled YAML definition** that can be:
- validated offline
- reviewed safely (no secrets stored)
- used as the foundation for future automation

---

## What this tool does (current state)

✔ Parses a YAML certificate asset definition  
✔ Validates required fields and structure  
✔ Fails fast with explicit, human-readable errors  
✔ Prints a minimal summary of the asset  

❌ Does **not** interact with Kubernetes/OpenShift  
❌ Does **not** retrieve Secrets  
❌ Does **not** handle certificates, keystores, or passwords  

---

## Configuration model

The YAML configuration describes **how certificate material is stored**, not the material itself.

Key design principles:
- Secrets are **referenced**, never embedded
- Passwords are **located**, not stored
- Configuration is separate from runtime cluster data

See `example-cfg.yaml` for a complete reference example.

---

## Example

```yaml
id: energia-api
namespace: energia-prod
certType: keystore

keystore:
  secret:
    name: tls-secret
    key: keystore.jks
  passwordRef:
    name: tls-pass
    key: keystorePassword

truststore:
  secret:
    name: tls-secret
    key: truststore.jks
  passwordRef:
    name: tls-secret
    key: truststorePassword

mtls: true
```
---
## How it works (today)
1. Load a YAML configuration file
2. Validate mandatory fields and structure
3. Stop execution if the configuration is invalid
4. Print a short summary if validation succeeds

---
## Build & run

### Dependencies
- Python 3.9+
- `pyyaml`

Install dependencies:
```bash
python -m pip install -r requirements.txt
```

If you prefer not to use a requirements file:
```bash
python -m pip install pyyaml
```

### Run
```bash
python main.py
```

The script currently expects `example-cfg.yaml` in the project root.

---
## Roadmap (planned)
- Extend validation to fully match the configuration schema
- Introduce warnings vs errors
- Support multiple certificate asset definitions
- Add mock Secret resolvers for offline testing
- Integrate Kubernetes/OpenShift Secret retrieval
- Automate certificate inspection and renewal workflows

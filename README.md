# cert-asset-validator

Tool to validate, normalize, and inspect **certificate asset definitions** stored as YAML, and **analyse actual certificate files**, designed for Kubernetes / OpenShift workflows.

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

### YAML validation (`main.py`)
- Parses a YAML certificate asset definition (single or multiple assets)
- Validates required fields and structure
- Fails fast with explicit, human-readable errors
- Prints a minimal summary of each asset

### Certificate analysis (`cert_analysis.py`)
- Detects certificate format from raw bytes (PEM, DER, PKCS12, JKS)
- Extracts metadata: Subject, Issuer, Serial Number, Validity Period, SANs, EKU
- Handles password-protected PKCS12 and JKS keystores
- Inspects Extended Key Usage to flag mTLS candidates (both `serverAuth` and `clientAuth` present)

### Not yet implemented
- Kubernetes/OpenShift cluster interaction
- Secret retrieval
- Integration between YAML validation and certificate analysis (they are separate entry points today)
- Cross-validation of declared `certType` against detected format

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

### YAML validation
1. Load a YAML configuration file
2. Validate mandatory fields and structure
3. Stop execution if the configuration is invalid
4. Print a short summary if validation succeeds

### Certificate analysis
1. Read a certificate file from disk
2. Detect the format (PEM, DER, PKCS12, JKS)
3. Extract metadata (Subject, Issuer, SANs, EKU, validity dates)
4. Inspect EKU for mTLS indicators

---
## Build & run

### Dependencies
- Python 3.9+
- `pyyaml`
- `cryptography`
- `pyjks`

Install dependencies:
```bash
python -m pip install -r requirements.txt
```

### Run

Validate YAML asset definitions:
```bash
python main.py
```
The script currently expects `example-cfg.yaml` in the project root.

Analyse a certificate file:
```bash
python cert_analysis.py
```
You will be prompted for a file path and an optional password.

---
## Roadmap (planned)
- Accept YAML config path as a CLI argument
- Wire certificate analysis into the main validation loop
- Cross-validate declared `certType` against detected format
- Introduce warnings vs errors
- Add mock Secret resolvers for offline testing
- Integrate Kubernetes/OpenShift Secret retrieval
- Automate certificate inspection and renewal workflows

See `ROADMAP.md` for the detailed implementation plan.

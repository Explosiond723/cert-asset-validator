# Certificate Analysis — Implementation Roadmap

This document outlines the steps to add actual certificate file analysis to cert-asset-validator. The goal is to read real certificate material, detect its format, extract metadata (CN, expiration, SANs), and infer whether the cert supports mTLS.

---

## ~~Step 1: Add the `cryptography` dependency~~ DONE

Added `cryptography` and `pyjks` to `requirements.txt`. JKS support is included from the start since Java keystores are common in enterprise Kubernetes/OpenShift environments.

---

## ~~Step 2: Create a separate module for cert analysis~~ DONE

`cert_analysis.py` contains three public functions:
- `cert_format()` — format detection
- `cert_metadata_extract()` — metadata extraction
- `eku_inspect()` — mTLS/EKU inspection

Plus a shared helper `_extract_cert_metadata()` for consistent metadata extraction across all formats.

---

## ~~Step 3: Detect certificate format from file bytes~~ DONE

`cert_format(data, path, optional_password)` probes formats in order: PEM, DER, PKCS12, JKS.

### Current detection approach

- **PEM**: Attempt `x509.load_pem_x509_certificate(data)`.
- **DER**: Attempt `x509.load_der_x509_certificate(data)`.
- **PKCS12**: Attempt `pkcs12.load_key_and_certificates(data, b"")`. If it raises `ValueError` and the data starts with ASN.1 SEQUENCE (`0x30`), it's likely a password-protected PKCS12 (PEM and DER would have matched earlier).
- **JKS**: Only checked if the file path ends with `.jks`. First tries PKCS12 (some `.jks` files are PKCS12 underneath), then falls back to `jks.KeyStore.loads()`.

### Not yet implemented

- Cross-validation of detected format against the YAML `certType` field.
- JKS magic-byte check (`0xFEEDFEED`) as a fast pre-filter before attempting full parse.
- PEM chain detection (multiple certificates concatenated in a single file).

---

## ~~Step 4: Extract basic certificate metadata~~ DONE

`cert_metadata_extract(data, cert_type, optional_password)` returns a dict (PEM/DER) or list of dicts (PKCS12/JKS).

### Fields extracted

- Subject (RFC 4514 string)
- Issuer (RFC 4514 string)
- Serial number
- Validity period (not_valid_before, not_valid_after) in UTC ISO format
- Subject Alternative Names (empty list if extension absent)
- Extended Key Usage (empty list if extension absent)
- Alias (JKS entries only)

### Not yet implemented

- Expiration warning (days remaining, flag if expired or expiring within 30 days).
- Self-signed detection (Subject == Issuer).
- PEM chain handling (currently only parses the first certificate in a PEM file).

---

## ~~Step 5: Detect mTLS capability via Extended Key Usage (EKU)~~ DONE

`eku_inspect(metadata)` checks whether any certificate in the metadata has both `serverAuth` and `clientAuth` EKU OIDs.

### Not yet implemented

- **Cross-validation with YAML config**: Compare EKU results against the `mtls: true/false` flag in the YAML definition.
  - If `mtls: true` but no `clientAuth` EKU → warning.
  - If `mtls: false` but `clientAuth` present → informational note.
- **Truststore signal**: If `mtls: true` but no truststore defined in the YAML config → warning.
- **Private key detection**: Currently cannot detect private key presence from cert metadata alone. Would require parsing the key material separately.

---

## Step 6: Wire analysis into the main loop

The next major step is integrating `cert_analysis.py` into `main.py` so that certificate analysis runs as an optional post-validation phase.

### Prerequisites

- Accept the YAML config path as a CLI argument (currently hardcoded to `example-cfg.yaml`).

### Design considerations

- **File access**: The YAML config references Kubernetes Secret names/keys, not local file paths. Options for providing cert files:
  - Add an optional `localPath` field to the YAML config for offline analysis.
  - Accept a directory path where cert files are stored, matched by naming convention.
  - A CLI flag or separate config that maps secret references to local files.

- **Password handling for PKCS12/JKS**: The YAML config references a Kubernetes Secret for the password (`passwordRef`), but local analysis needs the actual value. Options: environment variable, a separate secrets file, or interactive prompt — never hardcoded or logged.

- **Output format**: Move from `print()` to a structured summary per asset:
  - Detected format vs declared `certType` (match/mismatch)
  - Subject CN and SANs
  - Issuer (and whether self-signed)
  - Expiration date and days remaining
  - EKU capabilities and mTLS cross-check result

- **Error handling**: Each analysis step should fail gracefully per-asset without stopping the entire run, similar to how YAML validation currently works.

---

## Step 7: Connect to Kubernetes / OpenShift clusters

Add the ability to connect to a live cluster and retrieve actual Secret data referenced in the YAML config. This turns the tool from an offline validator into an active inspector.

### Cluster flavours to support

- **Vanilla Kubernetes** — via `kubernetes` Python client (uses `~/.kube/config` or in-cluster service account).
- **OpenShift** — same client works; OpenShift clusters expose a standard Kubernetes API. For OpenShift-specific resources (Routes, DeploymentConfigs) a separate `openshift-client` may be needed later, but for Secrets the standard client suffices.
- **GKE (Google Kubernetes Engine)** — requires `google-auth` for authentication. The `kubernetes` client supports GKE out of the box when `gcloud` is configured or a GKE kubeconfig entry exists.
- **EKS (Amazon Elastic Kubernetes Service)** — requires `awscli` or `boto3` for token generation. The `kubernetes` client supports EKS via the `aws eks get-token` flow or the `aws-iam-authenticator` exec plugin in kubeconfig.
- **AKS (Azure Kubernetes Service)** — requires `azure-identity` for authentication. The `kubernetes` client supports AKS when `az aks get-credentials` has been run or an exec plugin is configured in kubeconfig.

### Authentication modes

The `connect()` function should support two distinct modes:

1. **Kubeconfig (developer / CI workstation)** — `config.load_kube_config(context=...)`. Works with all providers via exec-based auth plugins in kubeconfig. No provider-specific code needed in most cases.
2. **In-cluster ServiceAccount (running inside a pod)** — `config.load_incluster_config()`. Uses the auto-mounted token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This is the primary production scenario: the tool runs as a CronJob or sidecar with a ServiceAccount that has `get`/`list` on Secrets.

The `connect()` function should try in-cluster config first (fast check: does the token file exist?), then fall back to kubeconfig. A `--kubeconfig` / `--context` flag can force a specific kubeconfig entry.

### ServiceAccount RBAC

For in-cluster mode, the ServiceAccount needs minimal permissions. Example Role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-asset-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
```

For cross-namespace scanning (Step 8), a ClusterRole + ClusterRoleBinding would be needed instead. The tool should detect whether it has the required permissions and emit a clear error if not (e.g. "ServiceAccount lacks `get` on secrets in namespace X", this should not block the script if it can access at least 1 namespace, just outputting a warning).

### Approach

All managed Kubernetes services (GKE, EKS, AKS) produce standard kubeconfig entries with exec-based auth plugins. The `kubernetes` Python client already supports exec-based authentication, so in most cases **no provider-specific code is needed** — just ensure the user has the right CLI tool installed and authenticated.

1. **Add `kubernetes` to requirements.txt** (`kubernetes>=29.0.0`).
2. **Create a `cluster.py` module** with:
   - `connect(context=None)` — try in-cluster config first, fall back to kubeconfig. Optionally target a specific context.
   - `get_secret(namespace, name, key)` → raw bytes of the secret data field.
   - `list_tls_secrets(namespace)` → list of Secret names with type `kubernetes.io/tls` or `Opaque` containing cert-like keys.
3. **Auth detection**: Before connecting, check which auth mechanism is being used and emit a clear error if setup is missing (e.g. "EKS context detected but `aws` CLI not found", or "in-cluster mode but token file not found").
4. **Dry-run / offline mode**: Cluster connection should always be opt-in (e.g. `--live` flag). Default behaviour remains offline validation only.

### How the `kubernetes` Python client works

The `kubernetes` pip package wraps the Kubernetes REST API. Quick primer on the key concepts:

```python
from kubernetes import client, config

# --- Connect ---
# Option A: from a developer machine (reads ~/.kube/config)
config.load_kube_config(context="my-gke-cluster")

# Option B: from inside a pod (uses mounted ServiceAccount token)
config.load_incluster_config()

# --- Use the API ---
v1 = client.CoreV1Api()

# List secrets in a namespace
secrets = v1.list_namespaced_secret(namespace="energia-prod")
for s in secrets.items:
    print(s.metadata.name, s.type, list(s.data.keys()))

# Get a specific secret
secret = v1.read_namespaced_secret(name="tls-secret", namespace="energia-prod")
# secret.data is a dict of {key: base64-encoded-string}
import base64
cert_bytes = base64.b64decode(secret.data["tls.crt"])
```

Key things to know:
- `secret.data` values are **base64-encoded strings**, not raw bytes. Always `base64.b64decode()`.
- `secret.type` tells you what kind of secret it is: `kubernetes.io/tls`, `Opaque`, etc.
- API errors raise `kubernetes.client.exceptions.ApiException` with an HTTP status code (403 = forbidden, 404 = not found).
- The client respects the kubeconfig's current context, namespace defaults, and auth plugins automatically.

### How to test without a cluster

For development and testing, you don't need a real cluster. Options:

1. **kind (Kubernetes IN Docker)** — spins up a local cluster in Docker containers. Lightweight, fast, free.
   ```bash
   # Install kind: https://kind.sigs.k8s.io/
   kind create cluster --name cert-test
   kubectl create namespace test-ns
   kubectl -n test-ns create secret tls my-tls --cert=test_certs/full.pem --key=test_certs/full.pem
   # Now your code can connect via kubeconfig
   ```

2. **minikube** — similar to kind, slightly heavier but also well-supported.

3. **Mock the API client** — for unit tests, mock `client.CoreV1Api()` to return fake Secret objects without any cluster.

### Security considerations

- Secret data is base64-decoded but should **never** be printed or logged in full.
- Passwords retrieved from `passwordRef` Secrets should be held in memory only for the duration of analysis, then discarded.
- Support `--redact` flag (default on) that masks secret values in output.
- When running in-cluster, the ServiceAccount token itself is sensitive — never log it.

---

## Step 8: Auto-generate YAML asset definitions from cluster state

Scan a cluster namespace (or all namespaces) and automatically produce YAML asset definitions by discovering TLS-related Secrets.

### Discovery logic

1. List all Secrets in the target namespace(s).
2. Filter for TLS-relevant Secrets:
   - Type `kubernetes.io/tls` (contains `tls.crt` and `tls.key`).
   - Type `Opaque` with keys matching common patterns: `*.pem`, `*.crt`, `*.p12`, `*.pfx`, `*.jks`, `keystore*`, `truststore*`.
3. For each discovered cert Secret, build a YAML asset entry:
   - `id` — derived from the Secret name (e.g. `my-namespace/tls-secret`).
   - `namespace` — the Secret's namespace.
   - `certType` — inferred from the key names or by analysing the Secret data with `cert_format()`.
   - `keystore.secret.name` / `keystore.secret.key` — populated from the Secret metadata.
4. For password Secrets:
   - Look for companion Secrets or keys within the same Secret that match password patterns (`*password*`, `*pass*`, `*passwd*`).
   - If found, populate `passwordRef` fields.
5. For truststores:
   - Look for keys matching `truststore*`, `ca.crt`, `ca-bundle.crt`, `ca-certificates.crt`.
   - If found in the same or a related Secret, populate the `truststore` section.
6. **mTLS hint**: If both a keystore and a truststore are found for the same logical asset, set `mtls: true` as a suggestion.

### Output

- Write the generated YAML to stdout or a specified output file.
- Include comments marking auto-generated fields vs inferred values (e.g. `# inferred from key name`).
- The generated YAML should pass `validate_config()` immediately — it's both a discovery tool and a validation bootstrap.

### Matching and grouping

The hardest part is grouping related Secrets into a single asset. Heuristics:
- Secrets in the same namespace with matching name prefixes (e.g. `myapp-tls`, `myapp-tls-password`).
- Secrets referenced by the same Deployment/StatefulSet via volume mounts or env vars.
- Labels or annotations that link Secrets together (e.g. `cert-manager.io` annotations).

This step should be iterative — start with simple name-based grouping and improve with label/mount analysis later.

### CLI interface

```bash
# Scan a namespace and print generated YAML
python main.py --discover --namespace energia-prod

# Scan all namespaces
python main.py --discover --all-namespaces

# Write to file
python main.py --discover --namespace energia-prod --output assets.yaml
```

### Example: what the generated YAML would look like

Given a namespace `energia-prod` containing:
- Secret `tls-secret` (type `kubernetes.io/tls`) with keys `tls.crt`, `tls.key`
- Secret `tls-pass` (type `Opaque`) with key `keystorePassword`
- Secret `ca-bundle` (type `Opaque`) with key `ca.crt`

The tool would generate:

```yaml
# Auto-generated by cert-asset-validator --discover
# Namespace: energia-prod
# Date: 2026-02-27

- id: energia-prod/tls-secret        # derived from namespace/secret-name
  namespace: energia-prod
  certType: pem                       # inferred: kubernetes.io/tls secrets are PEM
  keystore:
    secret:
      name: tls-secret
      key: tls.crt
  # passwordRef not set — PEM certs typically don't need a password
  truststore:                         # inferred: ca-bundle secret found in same namespace
    secret:
      name: ca-bundle
      key: ca.crt
  mtls: true                          # inferred: keystore + truststore both present
```

---

## Step 9: CLI argument parsing with `argparse`

Before Steps 6–8 can work together, the tool needs a proper CLI interface. Currently `main.py` has a hardcoded filename and `cert_analysis.py` uses `input()` prompts. Replace both with `argparse`.

### Proposed CLI design

```bash
# Validate a YAML asset definition (current behaviour, but now with a CLI arg)
python main.py validate assets.yaml

# Analyse a certificate file directly
python main.py analyse /path/to/cert.pem --password secret123

# Validate YAML + fetch secrets from cluster + analyse certs end-to-end
python main.py validate assets.yaml --live --context my-cluster

# Discover and generate YAML from cluster state
python main.py discover --namespace energia-prod --output assets.yaml
```

### Implementation notes

Use `argparse` subcommands:

```python
import argparse

parser = argparse.ArgumentParser(description="cert-asset-validator")
subparsers = parser.add_subparsers(dest="command")

# validate subcommand
validate_parser = subparsers.add_parser("validate", help="Validate YAML asset definitions")
validate_parser.add_argument("config", help="Path to YAML config file")
validate_parser.add_argument("--live", action="store_true", help="Fetch secrets from cluster")
validate_parser.add_argument("--context", help="Kubernetes context to use")

# analyse subcommand
analyse_parser = subparsers.add_parser("analyse", help="Analyse a certificate file")
analyse_parser.add_argument("cert", help="Path to certificate file")
analyse_parser.add_argument("--password", help="Password for PKCS12/JKS")

# discover subcommand
discover_parser = subparsers.add_parser("discover", help="Discover cert assets from cluster")
discover_parser.add_argument("--namespace", "-n", help="Namespace to scan")
discover_parser.add_argument("--all-namespaces", action="store_true")
discover_parser.add_argument("--output", "-o", help="Output file (default: stdout)")
discover_parser.add_argument("--context", help="Kubernetes context to use")
```

This keeps `main.py` as the single entry point and each module (`cert_analysis.py`, `cluster.py`) stays a pure library with no `input()` calls or hardcoded paths.

---

## Implementation order (suggested)

For practical purposes, here's the recommended order to tackle the remaining work:

1. **Step 9 (argparse)** — quick win, unblocks everything else. Replace hardcoded paths and `input()` prompts.
2. **Step 6 (wire analysis into main loop)** — connect the two existing modules. This is where the tool starts feeling like a real product.
3. **Step 7 (cluster connectivity)** — start with kubeconfig only, add in-cluster later. Test with `kind`.
4. **Step 8 (auto-generate YAML)** — builds on Step 7. Start with simple `kubernetes.io/tls` discovery, add heuristic grouping later.

Steps 3–5 "not yet implemented" items (PEM chains, expiration warnings, cross-validation) can be done incrementally alongside any of the above.

# cert-asset-validator — Implementation Roadmap

A certificate lifecycle management tool for Kubernetes/OpenShift environments. Maintains a YAML inventory of certificate assets across one or more clusters, validates them, analyses the actual cert material, generates CSRs for renewal, maps where the same cert lives, and rotates certs across all locations.

---

## What's done

### Cert analysis library (`cert_analysis.py`) — DONE

- `cert_format(data, path, optional_password)` — probes raw bytes: PEM → DER → PKCS12 → JKS
- `cert_metadata_extract(data, cert_type, optional_password)` — returns subject, issuer, serial, validity, SANs, EKU
- `eku_inspect(metadata)` — flags mTLS candidates (serverAuth + clientAuth)
- `_extract_cert_metadata(cert, alias)` — shared helper for consistent extraction

### YAML validation (`main.py`) — DONE

- `load_config(path)` / `validate_config(cfg, cluster_names)` — validates required fields based on `certType`, validates cluster references
- `validate_cluster(cluster)` — validates cluster definitions (name + context)
- Argparse CLI with `validate` and `analyse` subcommands
- Top-level error handling with `sys.exit(1)` for clean CLI output
- Logging with `-v`/`--verbose` flag

### Test certificates — DONE

`test_certs/` contains PEM, DER, PKCS12 (with/without password), JKS, and intentionally invalid files.

---

## Step 1: Multi-cluster YAML schema — DONE

Redesigned the YAML config to support multiple clusters in a single file. Backwards compatible with legacy flat list format.

### Schema

```yaml
clusters:
  - name: prod-ocp
    context: prod-ocp-admin         # kubeconfig context name
  - name: staging-gke
    context: gke_myproject_us-east1_staging

assets:
  - id: energia-api
    cluster: prod-ocp               # references clusters[].name
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

  - id: billing-api
    cluster: staging-gke
    namespace: billing-prod
    certType: pkcs12
    keystore:
      secret:
        name: billing-tls
        key: keystore.p12
      passwordRef:
        name: billing-tls-pass
        key: keystorePassword
```

### What was implemented

- `clusters` top-level key with `name` and `context` per cluster
- `cluster` field on each asset (required when clusters defined), must reference a defined cluster name
- `validate_config()` and `validate_cluster()` validate the new schema
- Backwards compatibility: if `clusters` is absent and no `cluster` field on assets, treat it as a single-cluster config (legacy mode)
- `example-cfg.yaml` updated to use the new schema

---

## Step 2: Cluster connectivity

Connect to live clusters and retrieve Secret data. Uses the `kubernetes` Python client, which works with vanilla k8s, OpenShift, GKE, EKS, and AKS through kubeconfig exec-based auth plugins.

### Authentication model

The tool does NOT store credentials. It relies on the user's existing auth context:

1. **Kubeconfig** (primary) — the user runs `oc login`, `gcloud container clusters get-credentials`, `aws eks update-kubeconfig`, etc. before using the tool. The `context` field in the YAML maps to a kubeconfig context.
2. **In-cluster ServiceAccount** — when running inside a pod, the tool picks up the mounted token automatically. The user is responsible for creating the ServiceAccount and RBAC.

### `cluster.py` module (stubs created, not yet implemented)

```python
connect(context=None)           # in-cluster first, then kubeconfig fallback
get_secret(namespace, name, key) -> bytes  # base64-decoded secret data
list_tls_secrets(namespace) -> list        # secrets with cert-like keys
```

### RBAC

The user creates a Role (or ClusterRole for cross-namespace) with `get`/`list` on Secrets. For cert rotation (Step 6), `update`/`patch` is also needed.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-asset-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]        # add "update", "patch" for rotation
```

The tool should detect permission errors and emit clear warnings per-namespace without blocking the entire run.

### CLI flags

- `--live` — opt-in to cluster connection (default is offline validation only)
- `--context` — override the kubeconfig context for all clusters
- `--kubeconfig` — path to a non-default kubeconfig file

### Security

- Never print or log secret data in full
- Passwords held in memory only during analysis, then discarded
- `--redact` flag (default on) masks secret values in output
- Never log ServiceAccount tokens

### Testing without a cluster

- **kind** — lightweight local cluster in Docker
- **Mock** — mock `client.CoreV1Api()` for unit tests

---

## Step 3: Search & query engine

Allow users to search the asset inventory by CN, secret name, namespace, or cluster. This is useful before running analysis, CSR generation, or rotation — the user needs to find the right asset(s) first.

### CLI

```bash
# Search by CN (substring match)
python main.py search assets.yaml --cn "energia"

# Search by secret name
python main.py search assets.yaml --secret tls-secret

# Search by namespace
python main.py search assets.yaml --namespace energia-prod

# Search by cluster
python main.py search assets.yaml --cluster prod-ocp

# Combine filters (AND logic)
python main.py search assets.yaml --namespace energia-prod --cn "api"
```

### With `--live` flag

When `--live` is set, the search also fetches the actual cert from the cluster and matches against the real CN/SANs (not just the YAML metadata). This is how the user validates that "the cert in the cluster matches what I expect."

### Search output

Print matching assets with key metadata: id, cluster, namespace, certType, and (if `--live`) the actual CN, SANs, expiration.

---

## Step 4: Cross-reference map

The most operationally valuable feature: show where the same certificate lives across the entire inventory, which CAs are present, and how keystores/truststores relate.

### Same-cert detection

Two certs are "the same" if they share the same serial number + issuer (or, more loosely, the same CN + SANs). This requires `--live` to fetch actual cert data.

Output example:

```text
Certificate: CN=energia-api.example.com
  Serial: 1234567890
  Issuer: CN=Internal CA
  Expires: 2026-09-15 (188 days)
  Found in:
    - prod-ocp / energia-prod / tls-secret (keystore.jks)
    - prod-ocp / energia-prod / tls-backup (keystore.p12)
    - staging-gke / energia-staging / tls-secret (tls.crt)
```

### CA inventory

List all unique CAs (issuers) found across the inventory, and which assets they signed.

Output example:

```text
CA: CN=Internal CA, O=MyOrg
  Signed 12 certificates across 3 clusters
  Assets: energia-api, billing-api, payments-api, ...

CA: CN=Let's Encrypt Authority X3
  Signed 4 certificates in prod-ocp
  Assets: public-web, api-gateway, ...
```

### Relationship mapping

For each asset, show:

- Keystore + truststore pairing (if both defined)
- CAs in the truststore vs CA that signed the keystore cert (do they match? if mTLS, the truststore should contain the peer's CA)
- CAs in the same namespace/secret that aren't referenced by any asset (orphan CA certs)

### Map CLI

```bash
# Full cross-reference report
python main.py map assets.yaml --live

# CA inventory only
python main.py map assets.yaml --live --ca-only

# Show where a specific CN lives
python main.py map assets.yaml --live --cn "energia-api.example.com"
```

---

## Step 5: CSR generation — PARTIAL

Generate a Certificate Signing Request for one or more assets, reusing the existing cert's subject, SANs, and key type as defaults.

### What's implemented

- `csr_generate(cert_data, cert_type, optional_password)` in `cert_analysis.py` — reads a cert (PEM, DER, PKCS12), generates a new key pair matching the original type/size, builds a CSR preserving the full subject and all extensions (SANs, EKU, Key Usage, etc.), skips CA-only extensions (AKI, CRL, AIA, SKI)
- `csr` subcommand in `main.py` — `python main.py csr <cert> [--password] [--output] [--key-output]`
- Supports RSA and EC key types

### Still to do

- Interactive subject overrides (change CN, OU, etc. before generating)
- `--live` mode: fetch cert from cluster via asset id
- Reuse existing private key for mTLS key continuity
- JKS support

### CSR CLI (current)

```bash
# Generate CSR from a local cert file
python main.py csr test_certs/full.pem

# Custom output paths
python main.py csr test_certs/full.pem --output my.csr --key-output my-key.pem

# PKCS12 with password
python main.py csr keystore.p12 --password mysecret
```

### CSR CLI (planned, requires cluster connectivity)

```bash
# Generate CSR for a specific asset
python main.py csr assets.yaml --id energia-api --live

# Non-interactive (accept all defaults)
python main.py csr assets.yaml --id energia-api --live --defaults
```

---

## Step 6: Cert rotation

Update a certificate across all secrets/namespaces where it appears. Supports direct apply and manifest generation.

### Rotation flow

1. User provides the new cert file (PEM, PKCS12, etc.)
2. Tool identifies all locations where the old cert lives (using the cross-reference map from Step 4)
3. Shows the user what will change:

   ```text
   Will update CN=energia-api.example.com in:
     - prod-ocp / energia-prod / tls-secret (keystore.jks)
     - prod-ocp / energia-prod / tls-backup (keystore.p12)
     - staging-gke / energia-staging / tls-secret (tls.crt)
   Proceed? [y/N]
   ```

4. Applies the update or generates manifests

### Rotation modes

- **Direct apply** (default) — `kubectl apply` / patch the Secret in-place. Requires `update`/`patch` RBAC.
- **Manifest output** (`--dry-run` or `--output-only`) — generates YAML patches or full Secret manifests for the user to apply manually or commit to a GitOps repo (ArgoCD, Flux).

### Rotation CLI

```bash
# Rotate a cert across all locations (interactive confirmation)
python main.py rotate assets.yaml --id energia-api --new-cert new-cert.pem --live

# Dry-run: show what would change without applying
python main.py rotate assets.yaml --id energia-api --new-cert new-cert.pem --live --dry-run

# Generate manifests instead of applying
python main.py rotate assets.yaml --id energia-api --new-cert new-cert.pem --live --output-only

# Rotate by CN (updates all assets with matching CN)
python main.py rotate assets.yaml --cn "energia-api.example.com" --new-cert new-cert.pem --live
```

### Password handling

For PKCS12/JKS targets, the tool needs the keystore password to repackage. It reads it from the `passwordRef` Secret in the cluster (`--live`), or prompts for it.

### Safety

- Always requires confirmation (unless `--yes` flag)
- Shows before/after diff (old CN, new CN, old expiry, new expiry)
- Validates the new cert before applying (format check, not expired, SANs match)

---

## Step 7: Auto-discovery from cluster state

Scan a cluster and automatically generate a YAML asset inventory by discovering TLS-related Secrets.

### Discovery logic

1. List all Secrets in target namespace(s)
2. Filter for TLS-relevant Secrets:
   - Type `kubernetes.io/tls` (contains `tls.crt` and `tls.key`)
   - Type `Opaque` with keys matching: `*.pem`, `*.crt`, `*.p12`, `*.pfx`, `*.jks`, `keystore*`, `truststore*`
3. For each cert Secret, build a YAML asset entry with inferred `certType`, secret references, and password refs
4. Group related Secrets into single assets:
   - Name prefix matching (`myapp-tls`, `myapp-tls-password`)
   - Labels/annotations (e.g. `cert-manager.io`)
   - Same Deployment/StatefulSet volume mounts (later)
5. Infer mTLS if both keystore + truststore found

### Discovery output

Generated YAML passes `validate_config()` immediately. Includes comments marking inferred values.

### Discovery CLI

```bash
python main.py discover --live --namespace energia-prod
python main.py discover --live --all-namespaces
python main.py discover --live --namespace energia-prod --output assets.yaml
```

---

## Incremental improvements (can be done alongside any step)

These are smaller enhancements to the existing `cert_analysis.py` that add value at any point:

- ~~**PEM chain handling**~~ — DONE: `cert_metadata_extract` uses `load_pem_x509_certificates` (plural) to handle concatenated PEM chains
- **Expiration warnings** — days remaining, flag if expired or expiring within 30 days
- **Self-signed detection** — Subject == Issuer check
- **JKS magic-byte check** — `0xFEEDFEED` pre-filter before full parse
- **Cross-validation** — detected format vs declared `certType`, EKU vs `mtls` flag

---

## Implementation order

1. **Step 1 (multi-cluster schema)** — foundation for everything; update validation + example config
2. **Step 2 (cluster connectivity)** — enables all live features; start with kubeconfig, test with kind
3. **Step 3 (search/query)** — quick win once schema + connectivity exist; makes the tool immediately useful for operators
4. **Step 4 (cross-reference map)** — the high-value feature; depends on connectivity
5. **Step 5 (CSR generation)** — depends on cert metadata extraction (already done) + connectivity
6. **Step 6 (cert rotation)** — depends on cross-reference map + connectivity; the most operationally impactful feature
7. **Step 7 (auto-discovery)** — nice bootstrapping tool; depends on connectivity

Steps 1-3 are the minimum viable product for daily use. Steps 4-5 make it genuinely valuable. Steps 6-7 make it a full lifecycle tool.

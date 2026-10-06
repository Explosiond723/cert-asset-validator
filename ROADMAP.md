# cert-asset-validator — Implementation Roadmap

A certificate lifecycle management tool for Kubernetes/OpenShift environments. Maintains a YAML inventory of certificate assets across one or more clusters, validates them, analyses the actual cert material, generates CSRs for renewal, maps where the same cert lives, and rotates certs across all locations.

---

## What's done

### Cert analysis library (`cert_analysis.py`) — DONE

- `cert_format(data, path, optional_password)` — probes raw bytes: PEM → DER → JKS/JCEKS (magic number) → PKCS12
- `cert_metadata_extract(data, cert_type, optional_password)` — returns subject, issuer, serial, validity, SANs, EKU
- `eku_inspect(metadata)` — flags mTLS candidates (serverAuth + clientAuth)
- `_extract_cert_metadata(cert, alias, now)` — shared helper for consistent extraction; SANs rendered openssl-style (`DNS:`, `IP:`, `email:`, `URI:`, ...; `otherName:UPN:user@example.com`, hex for non-text otherName values), EKUs by short name (dotted OID when unknown), plus expiry fields
- `expiry_warning(metadata, warn_days)` — one-line warning for expired, not-yet-valid, or soon-to-expire certs
- `pyjks` is imported lazily: PEM/DER/PKCS12 analysis works without it

### YAML validation (`main.py`) — DONE

- `load_config(path)` / `validate_config(cfg, cluster_names)` — validates required fields based on `certType`, validates cluster references
- `validate_cluster(cluster)` — validates cluster definitions (name + context)
- Argparse CLI with `validate`, `analyse`, `csr`, and `search` subcommands (`build_parser()` / `main(argv)`, testable without a subprocess)
- `cluster.py` / `live.py` are imported only when `--live` is used: offline commands do not need the `kubernetes` package.
- `--format list|table|csv` on `search` and `analyse` (`output.py`); named `--format` because `csr --output` is the CSR file path
- Top-level error handling with `sys.exit(1)` for clean CLI output
- Logging with `-v`/`--verbose` flag

### Test certificates — DONE

`test_certs/` contains PEM, DER, PKCS12 (with/without password), JKS, and intentionally invalid files. `withpass.p12` uses the password `secret`. The fixtures expire on 2027-02-27; date-dependent tests use generated certs instead.

### Test suite (pytest) — DONE

`tests/` covers format detection, metadata extraction, SAN/EKU formatting, expiry boundaries (with a fixed `now`), CSR generation (RSA + EC), JKS round-trip (generated with pyjks), and the CLI (`validate`, `search`, `analyse`, `csr`, exit codes, `--warn-days`, `-v` position). It also runs `validate`, `search`, `analyse` (PEM, DER, PKCS12) and `csr` in a subprocess with `kubernetes` and `pyjks` unavailable, and the suite itself passes without pyjks (JKS tests are skipped). Run with `python -m pytest` after `pip install -r requirements-dev.txt`.

`tests/test_live.py` covers live mode against a fake `CoreV1Api` (no cluster needed): password from Secret, wrong password, 403/404/missing key/empty Secret, unreachable context, cross-check warnings, CSV output, and that passwords never reach the output.

Not covered yet: a real API server. Next step: run `validate --live` / `search --live` against a local kind cluster.

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

## Step 2: Cluster connectivity — DONE

Connect to live clusters and retrieve Secret data. Uses the `kubernetes` Python client, which works with vanilla k8s, OpenShift, GKE, EKS, and AKS through kubeconfig exec-based auth plugins.

### Authentication model

The tool does NOT store credentials. It relies on the user's existing auth context:

1. **Kubeconfig** (primary) — the user runs `oc login`, `gcloud container clusters get-credentials`, `aws eks update-kubeconfig`, etc. before using the tool. The `context` field in the YAML maps to a kubeconfig context.
2. **In-cluster ServiceAccount** — when running inside a pod, the tool picks up the mounted token automatically. The user is responsible for creating the ServiceAccount and RBAC.

### `cluster.py` module

```python
connect(config_file=None, context=None)  # if config_file given, use it; otherwise in-cluster first, then kubeconfig fallback
get_secret_key(namespace, name, key) -> bytes  # base64-decoded single key from a Secret
get_tls_password(namespace, name, key) -> bytes  # same as get_secret_key, semantically for passwords
list_tls_secrets(namespace) -> list[dict]      # secrets with cert-like keys (kubernetes.io/tls + Opaque with *.pem, *.crt, etc.)
list_tls_passwords(namespace) -> list[dict]    # Opaque secrets with password-like keys
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

### CLI flags — DONE (`validate`, `search`)

- `--live` — opt-in to cluster connection (default is offline validation only)
- `--context` — override the kubeconfig context for all clusters (maps to `connect(context=...)`)
- `--kubeconfig` — path to a non-default kubeconfig file (maps to `connect(config_file=...)`)
- `--warn-days` — expiry threshold for live checks

`--context` / `--kubeconfig` without `--live` is a usage error.

### What was implemented

- `cluster.connect()` returns an independent `ApiClient` per context (no global config), so one run can cover several clusters; `get_secret_key(..., api)` maps 404 / 401-403 / missing key / empty Secret / network errors to `ClusterError` with messages that never contain secret data; every API call has a 15 s timeout
- `live.py`: `ClusterClients` (one connection per context, failures cached), `inspect_asset()` (fetch keystore + truststore + passwords, analyse, cross-check certType / cn / mtls / expiry), errors collected per asset instead of aborting the run

### Security

- Never print or log secret data in full
- Passwords held in memory only during analysis, then discarded
- `--redact` flag (default on) masks secret values in output — not needed so far: no command prints secret values
- Never log ServiceAccount tokens

### Testing without a cluster

- **kind** — lightweight local cluster in Docker
- **Mock** — mock `client.CoreV1Api()` for unit tests

---

## Step 3: Search & query engine — DONE

Offline search of the asset inventory by CN, secret name, namespace, or cluster. Validates all assets before filtering.

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

### Search implementation

- `cmd_search(args)` in `main.py` — loads config, validates all assets, then filters by namespace, cluster, secret name (checks both keystore and truststore), and CN (substring match). Multiple filters combine with AND logic.
- `cn` added as a required field in the asset schema to enable offline CN search
- Compact one-line-per-asset output format: `id | cluster | namespace | cn | certType`

### Search live mode — DONE

- `--live`: fetches the actual cert from the cluster and shows real CN/subject, SANs and expiry per asset
- `--cn` with `--live` matches the YAML cn, the real CN and the SANs

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

- `csr_generate(cert_data, cert_type, optional_password)` in `cert_analysis.py` — reads a cert (PEM, DER, PKCS12, JKS — leaf of the first private key entry, using `--password`), generates a new key pair matching the original type/size, builds a CSR preserving the full subject and all extensions (SANs, EKU, Key Usage, etc.), skips CA-only extensions (AKI, CRL, AIA, SKI)
- `csr` subcommand in `main.py` — `python main.py csr <cert> [--password] [--output] [--key-output]`
- Supports RSA and EC key types

### CSR still to do

- Interactive subject overrides (change CN, OU, etc. before generating)
- `--live` mode: fetch cert from cluster via asset id
- Reuse existing private key for mTLS key continuity

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

- ~~**JKS private key entries**~~ — DONE: `cert_metadata_extract` returns the cert chain of `PrivateKeyEntry` (leaf first, `entry_type: PrivateKeyEntry`) before `TrustedCertEntry` certs; metadata also carries `common_name`
- ~~**PEM chain handling**~~ — DONE: `cert_metadata_extract` uses `load_pem_x509_certificates` (plural) to handle concatenated PEM chains
- ~~**Expiration warnings**~~ — DONE (option A): `_extract_cert_metadata` adds `validity_status` (`valid` / `expired` / `not_yet_valid`), `days_remaining` (counted towards zero, negative once expired, always consistent with the label) and an `expiry` label to every cert's metadata, so `--live` and `map` get it for free. The threshold is applied separately by `expiry_warning(metadata, warn_days)`; `analyse --warn-days N` (default 30, inclusive) controls it. `analyse` still exits 0 on expired certs — a `--fail-on-expiry`-style exit code for pipelines is a possible follow-up.
- **Self-signed detection** — Subject == Issuer check
- ~~**JKS magic-byte check**~~ — DONE: `cert_format` matches `0xFEEDFEED` (JKS) / `0xCECECECE` (JCEKS) without needing pyjks or the password, so a missing or wrong password is reported as such instead of "unable to detect certificate format"
- **Cross-validation** — PARTIAL: with `--live`, detected format vs declared `certType`, YAML `cn` vs real CN/SANs, and `mtls` without truststore are checked; EKU vs `mtls` is not (a server cert in an mTLS setup legitimately has only serverAuth)

---

## Implementation order

1. **Step 1 (multi-cluster schema)** — DONE
2. **Step 2 (cluster connectivity)** — DONE (wired into `validate --live` and `search --live`; still to test against a real cluster, e.g. kind)
3. **Step 3 (search/query)** — DONE (offline and `--live`)
4. **Step 4 (cross-reference map)** — the high-value feature; depends on connectivity
5. **Step 5 (CSR generation)** — depends on cert metadata extraction (already done) + connectivity
6. **Step 6 (cert rotation)** — depends on cross-reference map + connectivity; the most operationally impactful feature
7. **Step 7 (auto-discovery)** — nice bootstrapping tool; depends on connectivity

Steps 1-3 are the minimum viable product for daily use. Steps 4-5 make it genuinely valuable. Steps 6-7 make it a full lifecycle tool.

# cert-asset-validator

Certificate lifecycle management for Kubernetes / OpenShift environments.

## Purpose

In real-world Kubernetes/OpenShift environments, certificates are often:

- spread across multiple namespaces and clusters
- stored in Secrets with non-standard layouts
- composed of keystores, truststores, and passwords stored separately
- duplicated across environments with no single source of truth

`cert-asset-validator` replaces fragile documentation with a **declarative, version-controlled YAML inventory** that can be validated offline, queried, and used to drive certificate operations across clusters.

## Quick start

```bash
# Install dependencies (Python 3.10+)
# On Fedora/RHEL, python3-devel is needed to build the twofish C extension (pyjks dependency):
#   sudo dnf install python3-devel
# On Debian/Ubuntu:
#   sudo apt install python3-dev
pip install -r requirements.txt
# pyjks is only needed for JKS keystores and kubernetes only for cluster access:
# validate/analyse/csr/search on PEM, DER and PKCS12 work without them.

# Validate a YAML asset definition
python main.py validate example-cfg.yaml

# Analyse a certificate file
python main.py analyse path/to/cert.pem

# Analyse a password-protected PKCS12/JKS keystore
python main.py analyse path/to/keystore.p12 --password mysecret

# Change the expiry warning threshold (default: 30 days)
python main.py analyse path/to/cert.pem --warn-days 60

# Generate a CSR from an existing certificate
python main.py csr path/to/cert.pem

# Search assets by CN, namespace, cluster, or secret name
python main.py search example-cfg.yaml --cn "energia"
python main.py search example-cfg.yaml --namespace energia-prod --cluster prod-ocp
```

Running `python main.py` with no arguments prints usage help.

## Features

### Available now

- **YAML validation** (`validate`) — parses single or multiple certificate asset definitions, validates required fields and structure based on `certType`, fails fast with human-readable errors
- **Certificate analysis** (`analyse`) — detects format from raw bytes (PEM, DER, PKCS12, JKS), extracts metadata (Subject, Issuer, Serial, Validity, SANs, EKU), handles password-protected keystores, flags mTLS candidates
- **Expiration warnings** — every analysed certificate reports `validity_status`, `days_remaining` and a readable `expiry` label; a `WARNING` line is printed for expired, not-yet-valid, or soon-to-expire certificates (`--warn-days`, default 30)
- **Multi-cluster inventory** — single YAML file covering assets across multiple clusters, each referencing a kubeconfig context
- **CSR generation** (`csr`) — generates a Certificate Signing Request from an existing certificate, preserving subject (CN, OU, O, etc.), SANs, EKU, and other extensions; generates a new key pair matching the original key type and size
- **Cluster connectivity** — connects to Kubernetes/OpenShift clusters via kubeconfig or in-cluster ServiceAccount, retrieves secrets, and discovers TLS-related secrets in a namespace. Works with any provider (OpenShift, GKE, EKS, AKS).
- **Search & query** (`search`) — filter assets by CN (substring match), secret name, namespace, or cluster; combine multiple filters with AND logic

### Planned

- **Cross-reference map** — show where the same cert lives across locations, CA inventory, keystore+truststore relationship analysis
- **Cert rotation** — update a cert across all secrets/namespaces where it appears, with direct apply or manifest generation for GitOps
- **Auto-discovery** — scan clusters and generate YAML inventory from existing Secrets
- **`--live` mode** — opt-in flag to connect to clusters for real-time cert analysis, search, and rotation

See `ROADMAP.md` for the detailed implementation plan.

## Sample output

```text
$ python main.py analyse test_certs/full.pem
  subject: CN=test.example.com,C=US
  issuer: CN=Test CA,C=US
  serial_number: 634829801381407007699990377129478153637635620168
  not_valid_before: 2026-02-27T15:29:02+00:00
  not_valid_after: 2027-02-27T15:29:02+00:00
  validity_status: valid
  days_remaining: 147
  expiry: expires in 147 days
  san: DNS:test.example.com, DNS:*.example.com
  eku: serverAuth, clientAuth
----
mTLS candidate: True
```

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Tests live in `tests/`. They use the fixtures in `test_certs/` for format detection, and generate certificates on the fly wherever the result depends on the current date (expiry), so they do not start failing when the fixtures expire.

## Configuration model

The YAML configuration describes **how certificate material is stored**, not the material itself.

- Secrets are **referenced**, never embedded
- Passwords are **located**, not stored
- Each cluster maps to a kubeconfig context — the tool never stores credentials

### Example

```yaml
clusters:
  - name: prod-ocp
    context: prod-ocp-admin

assets:
  - id: energia-api
    cluster: prod-ocp
    namespace: energia-prod
    cn: energia-api.example.com
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

See `example-cfg.yaml` for additional examples.

## Authentication

The tool relies on the user's existing Kubernetes auth context:

- **Kubeconfig** — run `oc login`, `gcloud container clusters get-credentials`, `aws eks update-kubeconfig`, etc. before using the tool. The `context` field in the YAML maps to a kubeconfig context.
- **In-cluster ServiceAccount** — when running inside a pod, the tool picks up the mounted token automatically. The user creates the ServiceAccount and RBAC.

All cluster operations are opt-in via the `--live` flag. Default behaviour is offline validation only.

## License

See `LICENSE`.

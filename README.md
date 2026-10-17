# cert-asset-validator

[![CI](https://github.com/Explosiond723/cert-asset-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/Explosiond723/cert-asset-validator/actions/workflows/ci.yml)

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

# For scripts/CI: exit 1 if a cert is expired, not yet valid, or expires within --warn-days
python main.py analyse path/to/cert.pem --warn-days 14 --fail-on-expiry
python main.py validate example-cfg.yaml --live --fail-on-expiry

# Generate a CSR from an existing certificate
python main.py csr path/to/cert.pem

# Renew with changes: new CN (a DNS SAN equal to the old CN follows it), SAN edits,
# and the existing private key instead of a new one
python main.py csr keystore.p12 --password mysecret --cn api-v2.example.com \
    --add-san DNS:api.example.com --remove-san DNS:legacy.example.com --reuse-key
python main.py csr tls.crt --key tls.key --subject "C=IT,O=Acme,CN=api.example.com"

# CSR for an inventory asset, reading keystore and password from the cluster
python main.py csr example-cfg.yaml --id energia-api --live

# Search assets by CN, namespace, cluster, or secret name
python main.py search example-cfg.yaml --cn "energia"
python main.py search example-cfg.yaml --namespace energia-prod --cluster prod-ocp

# Output as an aligned table or CSV instead of the default list
python main.py search example-cfg.yaml --format table
python main.py analyse path/to/keystore.p12 --password mysecret --format csv > certs.csv

# Live mode (read-only): fetch the real certificates from the clusters
python main.py validate example-cfg.yaml --live
python main.py validate example-cfg.yaml --live --format csv > inventory-report.csv
python main.py search example-cfg.yaml --live --cn "api" --format table
python main.py search example-cfg.yaml --live --context kind-test --kubeconfig ~/.kube/kind

# Bootstrap an inventory from an existing cluster (read-only), then check it
python main.py discover -n energia-prod -n billing-prod --output inventory.yaml
python main.py discover -A --context prod-ocp-admin --cluster-name prod-ocp --output inventory.yaml
python main.py validate inventory.yaml --live

# Later: add only the Secrets that are new, keeping every hand edit and comment
python main.py discover -A --update inventory.yaml

# Cross-reference map: where each certificate lives, which CAs signed what, chains and trust
python main.py map inventory.yaml
python main.py map inventory.yaml --view cas
python main.py map inventory.yaml --cn api.example.com --view certificates
python main.py map inventory.yaml --view assets --format csv > relationships.csv
```

Running `python main.py` with no arguments prints usage help.

## Features

### Available now

- **YAML validation** (`validate`) — parses single or multiple certificate asset definitions, validates required fields and structure based on `certType`, fails fast with human-readable errors
- **Certificate analysis** (`analyse`) — detects format from raw bytes (PEM, DER, PKCS12, JKS), extracts metadata (Subject, Issuer, Serial, Validity, SANs, EKU), handles password-protected keystores, flags mTLS candidates (from the leaf certificate's EKU only: `clientAuth` or no EKU at all; a hint, since mTLS is enforced by application config)
- **Expiration warnings** — every analysed certificate reports `validity_status`, `days_remaining` and a readable `expiry` label; a `WARNING` line is printed for expired, not-yet-valid, or soon-to-expire certificates (`--warn-days`, default 30). By default warnings do not change the exit code; `--fail-on-expiry` (on `analyse`, and on `validate`/`search` with `--live`) exits 1 when any certificate triggers one, with the reason on stderr so CSV output stays clean
- **Multi-cluster inventory** — single YAML file covering assets across multiple clusters, each referencing a kubeconfig context
- **CSR generation** (`csr`) — generates a Certificate Signing Request from an existing certificate (PEM, DER, PKCS12, JKS), preserving subject (CN, OU, O, etc.), SANs, EKU, and other extensions. By default it generates a new key pair matching the original key type and size (written with mode 0600). Options:
  - `--cn NAME` replaces only the CN, in place (RDN order kept); a DNS SAN equal to the old CN is renamed too. `--subject "C=IT,O=Acme,CN=..."` replaces the whole subject (RFC 4514)
  - `--add-san` / `--remove-san` (repeatable) edit the SANs, in the same notation `analyse` prints (`DNS:`, `IP:`, `email:`, `URI:`)
  - `--reuse-key` signs with the key already in the keystore (PKCS12, JKS, PEM bundle); `--key FILE [--key-password]` with a separate PEM key. The key must belong to the certificate, and no key file is written
  - `--live --id ASSET` takes the certificate from the inventory asset: keystore and password come from its Secrets; for `tls.crt` assets `--reuse-key` reads `tls.key` from the same Secret. Outputs default to `<asset-id>.csr` / `<asset-id>-key.pem`
- **Cluster connectivity** — connects to Kubernetes/OpenShift clusters via kubeconfig or in-cluster ServiceAccount, retrieves secrets, and discovers TLS-related secrets in a namespace. Works with any provider (OpenShift, GKE, EKS, AKS).
- **Search & query** (`search`) — filter assets by CN (substring match), secret name, namespace, or cluster; combine multiple filters with AND logic
- **Live mode** (`validate --live`, `search --live`) — read-only: fetches each asset's keystore/truststore and password from its Secrets, analyses the real certificates, and cross-checks them against the YAML (declared `certType` vs actual format, `cn` vs real CN/SANs, `mtls` without truststore, expiry). Each asset is checked independently: an unreachable cluster or a missing Secret is reported for that asset and the run continues; the exit code is 1 if any asset had errors. With `--live`, `search --cn` also matches the real CN and SANs.
- **Auto-discovery** (`discover`) — scans the Secrets of one or more namespaces (read-only) and writes a YAML inventory that passes `validate`:
  - finds `kubernetes.io/tls` Secrets and Opaque keys holding PEM, DER, PKCS12 or JKS material (detected by content, not only by key name); skips service-account tokens, registry credentials, Helm releases, private keys
  - pairs keystores with truststores in the same Secret, or in a Secret with the same base name (`myapp-tls` + `myapp-truststore`)
  - never sets `mtls`: whether a service requires client certificates is application or proxy configuration (`client-auth=need`, `ssl_verify_client`, Ingress `auth-tls-*`), and keystore + truststore is also the normal setup for outbound TLS. `notes.mtls` reports the hints that are available (truststore present, leaf EKU)
  - findings for people go in the asset's `notes` field (`mtls`, `keystore_password`, `truststore_password`, `cn`, `managed_by`, `content`), so they reach table/csv output; YAML comments only carry the subject and expiry
  - looks for the password, in this order: password-like keys of the same Secret; any key of a Secret related by name, i.e. the base name (`billing` for `billing-tls`) as prefix or suffix plus a password-like word (`billing-pwd`, `billing.password`, `billing-tls-pw`, `billing-keystore-pass`, `billing-creds`, `pwd-billing`, ...); keys named after the app in shared password Secrets (`app-passwords: {billing: ...}`); finally password-like keys of any other Secret in the namespace, flagged with a comment because a default password shared by several apps also matches. A `passwordRef` is written **only if that password actually opens the keystore**; otherwise `TODO` with a comment
  - reads `cn` from the certificate; notes cert-manager ownership and expiry as comments
  - `-A` skips `kube-*`, `openshift*` and `default` unless `--include-system`; a namespace that cannot be listed is reported and skipped (exit 1, partial inventory still written)
  - never writes secret values; `--output` refuses to overwrite an existing file without `--force`
  - `--update FILE` keeps an inventory up to date after you edited it by hand (filled TODOs, fixed a `passwordRef`, renamed ids, added notes and comments):
    - an asset is recognised by the Secrets it points to (cluster + namespace + Secret + key of keystore or truststore), not by its id, so renamed assets are not duplicated
    - only new assets are appended, as text, at the end of the `assets` list with the same indentation: the rest of the file stays byte for byte, comments included
    - the result is re-parsed before writing (it must contain exactly the old assets plus the new ones) and written atomically; if appending is not safe (e.g. `assets` is not the last section) nothing is written
    - the cluster must already be in the `clusters` section (matched by kubeconfig context, or `--cluster-name`); assets whose Secrets disappeared are listed, never removed
- **Cross-reference map** (`map`) — reads the real certificates (always connects, like `discover`) and shows three views (`--view certificates|cas|assets`, all by default; `table`/`csv` need one view):
  - **certificates**: each asset certificate with every place it lives (same SHA-256 fingerprint), and a warning when the **same name exists as different certificates** — typically a renewal applied in one place but not in another
  - **cas**: every CA in the inventory with the certificates it signed, who trusts it (truststores) and whose chain carries it; issuers that appear nowhere in the inventory are listed too. Certificates are linked to their CA by key identifier (AKI/SKI), with the DN as fallback, so a renewed CA with the same name is told apart (and flagged)
  - **assets**: per asset, whether the keystore chain contains the issuing CA, whether the truststore trusts the asset's own CA, which trusted CAs sign nothing in the inventory, and which other assets use the same certificate
  - `--cn` limits the map to assets whose YAML cn or real CN/SANs match; exit 1 if any asset could not be read
- **Notes** (`notes:` on an asset, optional) — free-form `key: text` pairs, written by `discover` and editable by hand (e.g. `owner: team-payments`). In `--format csv` every key becomes a `notes_<key>` column, ready for spreadsheet filtering; `table` shows a `notes` column listing the keys; `validate` (list) prints them
- **Output formats** (`--format list|table|csv` on `validate`, `search` and `analyse`) — `list` is the default human-readable layout; `table` is an aligned view; `csv` carries every field, one row per asset or certificate, multi-value cells joined with `; `

### Planned

- **Cert rotation** — update a cert across all secrets/namespaces where it appears, with direct apply or manifest generation for GitOps
- **Cert rotation** with `--live` — push a renewed certificate into every Secret where it lives

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


### Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to `main`:

| Job | What it checks |
|---|---|
| `tests` | `pytest` on Python 3.10, 3.12, 3.13, 3.14 |
| `minimal-deps` | `pytest` with only `pyyaml` and `cryptography` installed: offline commands must work without `kubernetes` and `pyjks` (their tests are skipped) |
| `e2e-kind` | `e2e/kind.sh up` + `run` on a kind cluster created inside the runner; the scenario log is kept as the `e2e-run-log` artifact for 14 days |

It can also be started by hand from the Actions tab (`Run workflow`).

### End-to-end test with kind

`e2e/kind.sh` runs `--live` against a real API server on a local [kind](https://kind.sigs.k8s.io/) cluster (requires docker or podman, kind, kubectl):

```bash
e2e/kind.sh up     # cluster, Secrets (PEM, JKS, PKCS12, expired, mismatched), RBAC, e2e/out/inventory.yaml
e2e/kind.sh run    # scenarios with expected exit codes; log in e2e/out/run.log
e2e/kind.sh down   # delete the cluster and e2e/out/
```

Each scenario checks the exit code **and** the output: the messages it must print (`expect`), those it must not (`reject`), and no Python traceback, so a crash cannot pass for an expected failure. Two scenarios also look inside the results: the subject and SANs of the generated CSRs, and the `passwordRef`s written by `discover`. The harness itself is tested in `tests/test_e2e_harness.py`.

It uses its own kubeconfig (`e2e/out/kubeconfig`), so `~/.kube/config` is not modified. The inventory covers OK assets, expiry warnings, YAML/cluster mismatches, a missing Secret, an RBAC denial through a limited ServiceAccount, and an unknown context.
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

Context selection with `--live`: each asset uses the `context` of its cluster from the YAML; `--context` overrides it for every asset (useful for a local kind cluster); `--kubeconfig` points to a non-default kubeconfig file. Without clusters in the YAML (legacy format) and without `--context`, the tool tries the in-cluster ServiceAccount first, then the kubeconfig current context.

Live mode only reads Secrets: the identity in use needs `get` on `secrets` in each asset's namespace (`discover` also needs `list` on `secrets`, and `list` on `namespaces` for `-A`). Passwords read from `passwordRef` are used in memory only and never printed (a trailing newline, as left by `echo pass | oc create secret ...`, is stripped).

## License

See `LICENSE`.

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

# Rotation: see what a renewed certificate would change everywhere the current one lives
# (nothing is written to the cluster), then write the manifests and the kubectl script
python main.py rotate inventory.yaml -i portal --cert portal-new.crt -k portal-new.key
python main.py rotate inventory.yaml -i portal --cert portal-new.crt -k portal-new.key -r -o rotation/
bash rotation/rotate.sh        # after reviewing it

# Short options: the same letter means the same thing in every command
python main.py search inventory.yaml -l -n energia-prod -f table
```

Running `python main.py` with no arguments prints usage help.

| Short | Long | Commands |
|---|---|---|
| `-n` | `--namespace` | search, discover |
| `-A` | `--all-namespaces` | discover |
| `-l` | `--live` | validate, search, csr |
| `-c` | `--context` | validate, search, csr, discover, map, rotate |
| `-f` | `--format` | validate, analyse, search, map |
| `-o` | `--output` | csr, discover, rotate |
| `-u` | `--update` | discover |
| `-p` | `--password` | analyse, csr |
| `-i` | `--id` | csr, rotate |
| `-k` | `--key` | csr, rotate |
| `-w` | `--warn-days` | validate, analyse, search, map, rotate |
| `-s` | `--secret` | search |
| `-C` | `--cluster` | search |
| `-r` | `--restart` | rotate |
| `-B` | `--no-backup` | rotate |
| `-v` | `--verbose` | all |

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
- **Live mode** (`validate --live`, `search --live`) — read-only: fetches each asset's keystore/truststore and password from its Secrets, analyses the real certificates, and cross-checks them against the YAML (declared `certType` vs actual format, `cn` vs real CN/SANs, `mtls` without truststore, expiry). It also reports:
  - **private key**: where the certificate's key is (`in the keystore` for JKS/PKCS12, `in the same file` for a PEM bundle, `in Secret key 'tls.key'` when another key of the same Secret holds it — found by name, its content is never read). This is a fact, not an mTLS verdict: every TLS server needs its key. Only `mtls: true` with no key found is a warning
  - **chain verified**: the leaf is checked **by signature** against the CA certificates in the keystore and in the asset's optional `chain` Secret (the `openssl verify -CAfile cacerts.pem tls.crt` of the renewal procedure, first hop). A CA with the right name but the wrong key fails the check Each asset is checked independently: an unreachable cluster or a missing Secret is reported for that asset and the run continues; the exit code is 1 if any asset had errors. With `--live`, `search --cn` also matches the real CN and SANs.
- **Auto-discovery** (`discover`) — scans the Secrets of one or more namespaces (read-only) and writes a YAML inventory that passes `validate`:
  - finds `kubernetes.io/tls` Secrets and Opaque keys holding PEM, DER, PKCS12 or JKS material (detected by content, not only by key name); skips service-account tokens, registry credentials, Helm releases, private keys
  - pairs keystores with truststores in the same Secret, or in a Secret with the same base name (`myapp-tls` + `myapp-truststore`)
  - CA chain keys next to a certificate (`cacerts.pem`, `ca.crt` — also in `kubernetes.io/tls` Secrets written by cert-manager — `chain.pem`, `ca-bundle.crt`, `intermediate.pem`, ...) become the asset's `chain` instead of a keystore of their own; `fullchain.pem` holds the leaf too and stays a keystore. A Secret holding only CA material is a truststore (CA bundle). Add your own names with `--chain-key KEY`
  - **backup copies** of other Secrets (`api-tls-bck`, `api-tls.backup`, `api-tls-bck-20240101`; words `bck`, `bkp`, `backup`, `bak`, `old`, more with `--backup-suffix WORD`) are left out and counted in the summary: they hold the previous certificate on purpose. A name only counts as a backup when the Secret it copies exists in the same namespace (`old-tls` alone is not one). `--include-backups` inventories them with a `notes.backup`
  - `notes.private_key` says where the private key is (or that none was found), as a fact: it does not imply mTLS
  - never sets `mtls`: whether a service requires client certificates is application or proxy configuration (`client-auth=need`, `ssl_verify_client`, Ingress `auth-tls-*`), and keystore + truststore is also the normal setup for outbound TLS. `notes.mtls` reports the hints that are available (truststore present, leaf EKU)
  - findings for people go in the asset's `notes` field (`mtls`, `private_key`, `keystore_password`, `truststore_password`, `chain`, `cn`, `backup`, `managed_by`, `content`), so they reach table/csv output; YAML comments only carry the subject and expiry
  - looks for the password, in this order: password-like keys of the same Secret; any key of a Secret related by name, i.e. the base name (`billing` for `billing-tls`) as prefix or suffix plus a password-like word (`billing-pwd`, `billing.password`, `billing-tls-pw`, `billing-keystore-pass`, `billing-creds`, `pwd-billing`, ...); keys named after the app in shared password Secrets (`app-passwords: {billing: ...}`); finally password-like keys of any other Secret in the namespace, flagged with a comment because a default password shared by several apps also matches. A `passwordRef` is written **only if that password actually opens the keystore**; otherwise `TODO` with a comment
  - reads `cn` from the certificate; notes cert-manager ownership and expiry as comments
  - `-A` skips `kube-*`, `openshift*` and `default` unless `--include-system`; a namespace that cannot be listed is reported and skipped (exit 1, partial inventory still written)
  - never writes secret values; `--output` refuses to overwrite an existing file without `--force`
  - `--update FILE` keeps an inventory up to date after you edited it by hand (filled TODOs, fixed a `passwordRef`, renamed ids, added notes and comments):
    - an asset is recognised by the Secrets it points to (cluster + namespace + Secret + key of keystore or truststore), not by its id, so renamed assets are not duplicated
    - only new assets are appended, as text, at the end of the `assets` list with the same indentation: the rest of the file stays byte for byte, comments included
    - the result is re-parsed before writing (it must contain exactly the old assets plus the new ones) and written atomically; if appending is not safe (e.g. `assets` is not the last section) nothing is written
    - the cluster must already be in the `clusters` section (matched by kubeconfig context, or `--cluster-name`); assets whose Secrets disappeared are listed, never removed (backup Secrets left out are not reported as gone)
- **Cross-reference map** (`map`) — reads the real certificates (always connects, like `discover`) and shows three views (`--view certificates|cas|assets`, all by default; `table`/`csv` need one view):
  - **certificates**: each asset certificate with every place it lives (same SHA-256 fingerprint), and a warning when the **same name exists as different certificates** — typically a renewal applied in one place but not in another. A version found only in backup Secrets (same rules as `discover`, or a `notes.backup`) is the expected leftover of a renewal: it is shown as a note, not as a missing renewal
  - **cas**: every CA in the inventory with the certificates it signed, who trusts it (truststores) and whose chain carries it; issuers that appear nowhere in the inventory are listed too. Certificates are linked to their CA by key identifier (AKI/SKI), with the DN as fallback, so a renewed CA with the same name is told apart (and flagged)
  - **assets**: per asset, whether the chain (keystore or `chain` Secret) contains the issuing CA — verified by signature —, where the private key is, whether it is a backup copy, whether the truststore trusts the asset's own CA, which trusted CAs sign nothing in the inventory, and which other assets use the same certificate
  - `--cn` limits the map to assets whose YAML cn or real CN/SANs match; exit 1 if any asset could not be read
- **Rotation plan** (`rotate`) — replaces one certificate everywhere it lives. **It never writes to the clusters**: it shows the plan and, with `-o DIR`, writes the files to apply after review:
  - targets: every asset whose current certificate has the same fingerprint as the one of `--id` (or of the assets matching `--cn`, which must all hold the same certificate), as in `map`. Backup copies are left alone and listed; unreadable assets and truststores pinning the old certificate are listed too
  - the new certificate (`--cert`, PEM or DER; a PEM can carry its chain) is checked first: not expired or not yet valid, no DNS/IP SAN of the current one dropped (`--allow-san-removal` to accept it), later expiry and CN change reported, key matching the certificate
  - the stored material is rebuilt **in the same layout**: PEM `tls.crt` with or without the chain in it, key in the same file or in `tls.key`, DER, PKCS12 and JKS with the same password (JKS keeps its other entries). The chain inside a store or in the `chain` Secret is kept when its CA signed the new certificate, replaced by `--chain` otherwise. Without `-k/--key` the stored key is kept when the new certificate uses it (CSR made with `--reuse-key`); a new key is required otherwise
  - backup **on by default**, as in the renewal procedure: a copy of each Secret as `<secret>-bck` (`-bck-YYYYMMDD` when that exists), created before the change, without the original labels/annotations so operators do not act on it. `-B/--no-backup` disables it
  - restart **off by default**: `-r/--restart` adds `kubectl rollout restart` for the Deployments, StatefulSets and DaemonSets whose pods mount or read the Secret (OpenShift DeploymentConfigs are not checked)
  - `-o DIR` writes `<cluster>/<namespace>/<secret>.patch.json` (merge patch with only the changed keys and the `resourceVersion` read at planning time: the API refuses it if the Secret changed meanwhile), `<secret>-bck-*.yaml` and `rotate.sh` (`set -euo pipefail`: a backup that cannot be created stops the patch after it). Files are `0600` in a `0700` directory with a `.gitignore` of `*`: they hold private keys and Secret values. For GitOps, encrypt them (SOPS, Sealed Secrets) before committing
  - a Secret managed by cert-manager is flagged: a manual change is overwritten at its next renewal
- **Notes** (`notes:` on an asset, optional) — free-form `key: text` pairs, written by `discover` and editable by hand (e.g. `owner: team-payments`). In `--format csv` every key becomes a `notes_<key>` column, ready for spreadsheet filtering; `table` shows a `notes` column listing the keys; `validate` (list) prints them
- **Output formats** (`--format list|table|csv` on `validate`, `search` and `analyse`) — `list` is the default human-readable layout; `table` is an aligned view; `csv` carries every field, one row per asset or certificate, multi-value cells joined with `; `

### Planned

- **Rotation apply** — `rotate --apply`: the same plan applied directly (backup, patch, restart, then a live check), with confirmation

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
e2e/kind.sh up     # cluster, Secrets (PEM, JKS, PKCS12, expired, mismatched, chain + -bck), a Deployment, RBAC, inventory
e2e/kind.sh run    # scenarios with expected exit codes; log in e2e/out/run.log
e2e/kind.sh down   # delete the cluster and e2e/out/
```

Each scenario checks the exit code **and** the output: the messages it must print (`expect`), those it must not (`reject`), and no Python traceback, so a crash cannot pass for an expected failure. Two scenarios also look inside the results: the subject and SANs of the generated CSRs, and the `passwordRef`s, `chain` and notes written by `discover`. The harness itself is tested in `tests/test_e2e_harness.py`.

It uses its own kubeconfig (`e2e/out/kubeconfig`), so `~/.kube/config` is not modified. The inventory covers OK assets, expiry warnings, YAML/cluster mismatches, a missing Secret, an RBAC denial through a limited ServiceAccount, an unknown context, and the renewal-guide layout (generic Secret with `tls.crt` + `tls.key` + `cacerts.pem`, plus its `-bck` copy holding the previous certificate). The last scenarios run `rotate` on it and execute the generated `rotate.sh` against the cluster: backup, patch, rollout restart, then a live check of the new certificate, and a second run that must stop on the existing backup.

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

  # The layout of a generic Secret with the CA chain in its own key (tls.crt + tls.key +
  # cacerts.pem). `chain` is optional: CA certificates used to verify the leaf, no password.
  - id: portal
    cluster: prod-ocp
    namespace: portal-prod
    cn: portal.example.com
    certType: pem
    keystore:
      secret: {name: portal-tls, key: tls.crt}
    chain:
      secret: {name: portal-tls, key: cacerts.pem}
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

# cert-asset-validator

Validate certificate asset definitions (YAML) and analyse certificate files (PEM, DER, PKCS12, JKS) for Kubernetes / OpenShift environments.

## Purpose

In real-world Kubernetes/OpenShift environments, certificates are often:

- spread across multiple namespaces
- stored in Secrets with non-standard layouts
- composed of keystores, truststores, and passwords stored separately
- documented manually (e.g. spreadsheets)

`cert-asset-validator` replaces fragile documentation with a **declarative, version-controlled YAML definition** that can be validated offline, reviewed safely (no secrets stored), and used as the foundation for future automation.

## Quick start

```bash
# Install dependencies (Python 3.9+)
pip install -r requirements.txt

# Validate a YAML asset definition
python main.py validate example-cfg.yaml

# Analyse a certificate file
python main.py analyse path/to/cert.pem

# Analyse a password-protected PKCS12/JKS keystore
python main.py analyse path/to/keystore.p12 --password mysecret
```

Running `python main.py` with no arguments prints usage help.

## Features

### YAML validation (`validate`)

- Parses single or multiple certificate asset definitions
- Validates required fields and structure based on `certType`
- Fails fast with explicit, human-readable errors

### Certificate analysis (`analyse`)

- Detects format from raw bytes: PEM, DER, PKCS12, JKS
- Extracts metadata: Subject, Issuer, Serial Number, Validity Period, SANs, EKU
- Handles password-protected PKCS12 and JKS keystores
- Inspects Extended Key Usage to flag mTLS candidates (`serverAuth` + `clientAuth`)

## Configuration model

The YAML configuration describes **how certificate material is stored**, not the material itself.

- Secrets are **referenced**, never embedded
- Passwords are **located**, not stored
- Configuration is separate from runtime cluster data

### Example

```yaml
- id: energia-api
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

See `example-cfg.yaml` for a complete reference with multiple assets.

## Roadmap

- Wire certificate analysis into the YAML validation loop
- Cross-validate declared `certType` against detected format
- Kubernetes/OpenShift Secret retrieval (`--live` mode)
- Auto-generate YAML definitions from cluster state (`discover` subcommand)

See `ROADMAP.md` for the detailed implementation plan.

## License

See `LICENSE`.

"""Certificate rotation plan (`main.py rotate`).

Given a renewed certificate (and its key / CA chain when needed), finds every inventory
asset that holds the current certificate (same SHA-256 fingerprint, as `map` does),
rebuilds the stored material in the same format and layout (PEM bundle or tls.crt +
tls.key, DER, PKCS12, JKS with its other entries, the `chain` Secret key), and shows what
would change. With an output directory it also writes, for review:

  <cluster>/<namespace>/<secret>.patch.json  merge patch with only the changed keys, and the
                                             resourceVersion read at planning time: the API
                                             rejects it if the Secret changed in between
  <cluster>/<namespace>/<secret>-bck.yaml    copy of the current Secret under a free name
                                             (<secret>-bck, else -bck-YYYYMMDD), created first
  rotate.sh                                  the kubectl commands, in order: backup, patch,
                                             optional rollout restart

Nothing is ever written to a cluster here. The files hold private keys and Secret values:
the directory is created 0700, files 0600, with a .gitignore that ignores everything.
"""
import base64
import json
import os
import shlex
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

import cluster
from cert_analysis import _load_jks, _same_public_key, cert_format, is_private_key_name

# The backup copy gets only these annotations, not the original labels/annotations: an
# operator selecting on them (cert-manager, reloaders) would act on the copy too.
BACKUP_ANNOTATION = "cert-asset-validator/backup-of"


class RotateError(ValueError):
    pass


# --- new material ---------------------------------------------------------------------

def _load_certs(data: bytes, path: str) -> list:
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificates(data)
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        raise RotateError(f"{path}: not a PEM or DER certificate")


# load_new_material reads the renewed certificate. The certificate file may carry its
# chain after the leaf (PEM); --chain gives it separately. The key is optional: without
# it, the key already stored is kept when it matches the new certificate.
def load_new_material(cert_path: str, key_path: str = None, chain_path: str = None, key_password: str = None) -> dict:
    with open(cert_path, "rb") as f:
        certs = _load_certs(f.read(), cert_path)
    chain = certs[1:]
    if chain_path:
        with open(chain_path, "rb") as f:
            chain = _load_certs(f.read(), chain_path)
    key = None
    if key_path:
        with open(key_path, "rb") as f:
            try:
                key = serialization.load_pem_private_key(f.read(), key_password.encode() if key_password else None)
            except (ValueError, TypeError) as e:
                raise RotateError(f"{key_path}: unable to load the private key: {e}")
        if not _same_public_key(key, certs[0]):
            raise RotateError(f"{key_path} is not the private key of {cert_path}")
    return {"leaf": certs[0], "chain": chain, "key": key, "chain_given": bool(chain_path) or len(certs) > 1}


def _fingerprint(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _sans(cert) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [f"DNS:{n}" for n in ext.get_values_for_type(x509.DNSName)] + \
           [f"IP:{ip}" for ip in ext.get_values_for_type(x509.IPAddress)]


def _cn(cert):
    attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def _issued_by(child, issuer) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def describe_new(new: dict) -> dict:
    leaf = new["leaf"]
    return {"subject": leaf.subject.rfc4514_string(), "issuer": leaf.issuer.rfc4514_string(),
            "not_valid_after": leaf.not_valid_after_utc.isoformat(), "fingerprint": _fingerprint(leaf),
            "san": _sans(leaf), "chain": len(new["chain"]), "key": "from --key" if new["key"] else None}


# check_new_cert compares the new certificate with the one it replaces. Returns
# (errors, warnings): errors block the rotation.
def check_new_cert(new: dict, old_leaf_meta: dict, warn_days: int, allow_san_removal: bool):
    leaf, errors, warnings = new["leaf"], [], []
    now = datetime.now(timezone.utc)
    if leaf.not_valid_after_utc <= now:
        errors.append("the new certificate is expired")
    elif leaf.not_valid_before_utc > now:
        errors.append(f"the new certificate is not valid yet (from {leaf.not_valid_before_utc.isoformat()})")
    elif (leaf.not_valid_after_utc - now).days <= warn_days:
        warnings.append(f"the new certificate expires within {warn_days} days")
    if leaf.not_valid_after_utc.isoformat() <= old_leaf_meta["not_valid_after"]:
        warnings.append("the new certificate does not expire later than the current one")
    # only DNS and IP SANs are compared: those are what clients check
    old_sans = {s for s in old_leaf_meta.get("san", []) if s.startswith(("DNS:", "IP:"))}
    removed = sorted(old_sans - set(_sans(leaf)))
    if removed:
        message = f"SANs of the current certificate missing from the new one: {', '.join(removed)}"
        if allow_san_removal:
            warnings.append(message)
        else:
            errors.append(message + " (use --allow-san-removal if intended)")
    if old_leaf_meta.get("common_name") and _cn(leaf) != old_leaf_meta["common_name"]:
        warnings.append(f"CN changes from '{old_leaf_meta['common_name']}' to '{_cn(leaf)}'")
    return errors, warnings


# --- rebuilding one store ----------------------------------------------------------------

def _pem(certs) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


# _pick_chain chooses the CA certificates stored with the new leaf. The layout is kept: no
# chain when the store had none (it lives elsewhere, e.g. cacerts.pem), else the new chain
# when one was given, else the old one when it still signs the new leaf (same CA).
def _pick_chain(new: dict, old_chain: list, where: str) -> list:
    if not old_chain:
        return []
    if new["chain_given"]:
        return new["chain"]
    if any(_issued_by(new["leaf"], ca) for ca in old_chain):
        return old_chain
    raise RotateError(f"{where} stores the CA chain with the certificate, and the current chain did not "
                      "sign the new certificate: pass --chain")


# _pick_key returns the key to store with the new leaf: --key, else the current key when it
# belongs to the new certificate (CSR made with --reuse-key).
def _pick_key(new: dict, old_key, where: str):
    if new["key"] is not None:
        return new["key"]
    if old_key is not None and _same_public_key(old_key, new["leaf"]):
        return old_key
    raise RotateError(f"{where} stores the private key and the new certificate has a new key: pass --key")


def _rebuild_pem(data: bytes, new: dict, where: str) -> tuple[bytes, object]:
    old = x509.load_pem_x509_certificates(data)
    out = _pem([new["leaf"]] + _pick_chain(new, old[1:], where))
    key = None
    if b"PRIVATE KEY-----" in data:
        if b"ENCRYPTED PRIVATE KEY" in data:
            raise RotateError(f"{where}: encrypted PEM keys are not supported by rotate")
        old_key = serialization.load_pem_private_key(data, None)
        key = _pick_key(new, old_key, where)
        out += _key_pem(key)
    return out, key


def _rebuild_pkcs12(data: bytes, password, new: dict, where: str) -> tuple[bytes, object]:
    pw = password.encode() if password else None
    old_key, old_cert, old_cas = pkcs12.load_key_and_certificates(data, pw)
    if old_key is None:
        raise RotateError(f"{where}: the PKCS12 holds no private key (a truststore is not rotated)")
    key = _pick_key(new, old_key, where)
    cas = _pick_chain(new, list(old_cas or []), where)
    name = None
    try:
        name = pkcs12.load_pkcs12(data, pw).cert.friendly_name
    except (ValueError, AttributeError):
        pass
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(name, key, new["leaf"], cas or None, enc), key


def _rebuild_jks(data: bytes, password, new: dict, where: str) -> tuple[bytes, object]:
    jks = _load_jks()
    ks = jks.KeyStore.loads(data, password)
    entries, key, replaced = [], None, False
    for alias, entry in ks.entries.items():
        if isinstance(entry, jks.PrivateKeyEntry) and not replaced:
            old_key = serialization.load_der_private_key(entry.pkey_pkcs8, password=None) \
                if entry.is_decrypted() else None
            if old_key is None:
                raise RotateError(f"{where}: the JKS private key has its own password, not supported")
            key = _pick_key(new, old_key, where)
            old_chain = [x509.load_der_x509_certificate(c[1]) for c in entry.cert_chain[1:]]
            chain = [new["leaf"]] + _pick_chain(new, old_chain, where)
            pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
            entries.append(jks.PrivateKeyEntry.new(alias, [c.public_bytes(serialization.Encoding.DER) for c in chain],
                                                   pkcs8))
            replaced = True
        else:
            entries.append(entry)
    if not replaced:
        raise RotateError(f"{where}: no private key entry in the JKS (a truststore is not rotated)")
    return jks.KeyStore.new(ks.store_type, entries).saves(password), key


# --- planning ----------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _decode(secret, key: str) -> bytes:
    return base64.b64decode((secret.data or {})[key])


class Planner:
    """Collects the changes per Secret: several assets (and keystore + chain) can share one."""

    def __init__(self, new: dict, clients, backup: bool, restart: bool):
        self.new, self.clients, self.backup, self.restart = new, clients, backup, restart
        self.secrets = {}  # (cluster, namespace, name) -> plan dict

    def _secret_plan(self, asset: dict, name: str) -> dict:
        ref = (asset.get("cluster"), asset["namespace"], name)
        if ref not in self.secrets:
            api = self.clients.api_for(asset)
            secret = cluster.read_secret(asset["namespace"], name, api)
            annotations = secret.metadata.annotations or {}
            self.secrets[ref] = {
                "cluster": asset.get("cluster"), "context": self.clients.context_for(asset),
                "namespace": asset["namespace"], "name": name, "secret": secret, "api": api,
                "type": secret.type or "Opaque", "resource_version": secret.metadata.resource_version,
                "assets": [], "changes": {}, "notes": [], "backup_name": None, "workloads": None,
                "managed_by": annotations.get("cert-manager.io/certificate-name"),
            }
        return self.secrets[ref]

    def _change(self, plan: dict, key: str, data: bytes, what: str) -> None:
        if _decode(plan["secret"], key) == data:
            plan["notes"].append(f"{key}: unchanged ({what})")
            return
        previous = plan["changes"].get(key)
        if previous and previous[0] != data:
            raise RotateError(f"Secret '{plan['namespace']}/{plan['name']}' key '{key}' would get two different "
                              "values from two assets")
        plan["changes"][key] = (data, what)

    # add_asset plans the changes for one asset holding the current certificate.
    def add_asset(self, asset: dict) -> None:
        from live import fetch_store_material
        store = asset["keystore"]
        name, key_name = store["secret"]["name"], store["secret"]["key"]
        plan = self._secret_plan(asset, name)
        plan["assets"].append(asset["id"])
        where = f"Secret '{asset['namespace']}/{name}' key '{key_name}'"
        data, password = fetch_store_material(plan["api"], asset["namespace"], store)
        fmt = cert_format(data, key_name, password)
        new = self.new

        if fmt == "PEM":
            out, key = _rebuild_pem(data, new, where)
            self._change(plan, key_name, out, f"certificate{' + chain' if out.count(b'BEGIN CERT') > 1 else ''}"
                         f"{' + private key' if key is not None else ''}, PEM")
        elif fmt == "DER":
            out, key = new["leaf"].public_bytes(serialization.Encoding.DER), None
            self._change(plan, key_name, out, "certificate, DER")
        elif fmt == "PKCS12":
            out, key = _rebuild_pkcs12(data, password, new, where)
            self._change(plan, key_name, out, "PKCS12 rebuilt with the same password")
        elif fmt == "JKS":
            out, key = _rebuild_jks(data, password, new, where)
            self._change(plan, key_name, out, "JKS rebuilt with the same password, other entries kept")
        else:
            raise RotateError(f"{where}: unsupported format {fmt}")

        if fmt in ("PEM", "DER") and key is None:
            self._plan_sidecar_key(plan, key_name, where)
        chain = asset.get("chain")
        if isinstance(chain, dict) and isinstance(chain.get("secret"), dict):
            self._plan_chain(asset, chain["secret"])

    # A key next to the certificate (tls.key): replaced by --key, kept when it matches.
    def _plan_sidecar_key(self, plan: dict, cert_key: str, where: str) -> None:
        sidecars = sorted(k for k in (plan["secret"].data or {}) if k != cert_key and is_private_key_name(k))
        if not sidecars:
            if self.new["key"] is not None:
                plan["notes"].append("no private key stored next to the certificate: --key not written")
            return
        key_name = sidecars[0]
        raw = _decode(plan["secret"], key_name)
        try:
            old_key = serialization.load_pem_private_key(raw, None)
        except (ValueError, TypeError):
            old_key = None
        key = _pick_key(self.new, old_key, f"{where} (private key in '{key_name}')")
        if old_key is not None and key is old_key:
            plan["notes"].append(f"{key_name}: unchanged (same key as the new certificate)")
        else:
            self._change(plan, key_name, _key_pem(key), "private key")

    def _plan_chain(self, asset: dict, ref: dict) -> None:
        plan = self._secret_plan(asset, ref["name"])
        if asset["id"] not in plan["assets"]:
            plan["assets"].append(asset["id"])
        current = _load_certs(_decode(plan["secret"], ref["key"]), ref["key"])
        if self.new["chain_given"]:
            self._change(plan, ref["key"], _pem(self.new["chain"]), "CA chain")
        elif not any(_issued_by(self.new["leaf"], ca) for ca in current):
            raise RotateError(f"the CA chain in Secret '{asset['namespace']}/{ref['name']}' key '{ref['key']}' "
                              "did not sign the new certificate: pass --chain")
        else:
            plan["notes"].append(f"{ref['key']}: unchanged (its CA signed the new certificate)")

    # finish picks backup names and the workloads to restart, for Secrets that change.
    # Returns warnings.
    def finish(self) -> list[str]:
        warnings = []
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        for plan in self.secrets.values():
            if not plan["changes"]:
                continue
            ns, name, api = plan["namespace"], plan["name"], plan["api"]
            if plan["managed_by"]:
                warnings.append(f"Secret '{ns}/{name}' is managed by cert-manager (Certificate "
                                f"'{plan['managed_by']}'): a manual change is overwritten at its next renewal")
            if self.backup:
                candidates = [f"{name}-bck", f"{name}-bck-{stamp}"] + [f"{name}-bck-{stamp}-{n}" for n in range(2, 10)]
                plan["backup_name"] = next((c for c in candidates if not cluster.secret_exists(ns, c, api)), None)
                if plan["backup_name"] is None:
                    raise RotateError(f"no free backup name for Secret '{ns}/{name}'")
            if self.restart:
                try:
                    plan["workloads"] = cluster.workloads_using_secret(ns, name, api)
                except cluster.ClusterError as e:
                    plan["workloads"] = []
                    warnings.append(f"restart: {e}; add the rollout restart by hand")
                if not plan["workloads"]:
                    warnings.append(f"no Deployment/StatefulSet/DaemonSet in '{ns}' uses Secret '{name}': "
                                    "nothing to restart (DeploymentConfigs and other controllers are not checked)")
        return warnings

    def changed(self) -> list[dict]:
        return [p for p in self.secrets.values() if p["changes"]]


# --- output ------------------------------------------------------------------------------

def _where(plan: dict) -> str:
    return " / ".join(p for p in (plan["cluster"], plan["namespace"], plan["name"]) if p)


def print_plan(new_desc: dict, old_meta: dict, targets: list[str], planner: Planner, checks: dict,
               skipped: dict) -> None:
    print("Rotation plan (nothing is written to the cluster)")
    print(f"New certificate: {new_desc['subject']}")
    print(f"  issuer: {new_desc['issuer']}")
    print(f"  expires: {new_desc['not_valid_after']}  fingerprint: {new_desc['fingerprint'][:16]}...")
    print(f"  san: {', '.join(new_desc['san']) or '(none)'}")
    print(f"  chain given: {new_desc['chain']} cert(s)  key: {new_desc['key'] or 'not given (stored key kept if it matches)'}")
    print(f"Replaces: {old_meta['subject']}  (expires {old_meta['not_valid_after']}, "
          f"fingerprint {old_meta['fingerprint_sha256'][:16]}...)")
    print(f"  held by: {', '.join(targets)}")
    for text in checks["warnings"]:
        print(f"WARNING: {text}")
    for text in checks["errors"]:
        print(f"ERROR: {text}")
    for plan in planner.secrets.values():
        print("----")
        print(f"Secret {_where(plan)}  (assets: {', '.join(plan['assets'])})")
        for key, (_data, what) in sorted(plan["changes"].items()):
            print(f"  {key}: replace ({what})")
        for note in plan["notes"]:
            print(f"  {note}")
        if not plan["changes"]:
            print("  nothing to change")
            continue
        if planner.backup:
            print(f"  backup: {plan['backup_name']} (created before the change)")
        else:
            print("  backup: disabled (--no-backup)")
        if plan["workloads"] is not None:
            print(f"  restart: {', '.join(plan['workloads']) or 'none found'}")
        else:
            print("  restart: not requested (-r/--restart)")
    for label, items in (("backup copies keep the current certificate (not changed)", skipped["backups"]),
                         ("could not be read, they may hold the current certificate", skipped["unreadable"]),
                         ("trust the current certificate in their truststore (update by hand)", skipped["pinned"])):
        if items:
            print("----")
            print(f"Assets that {label}: {', '.join(items)}")


def _backup_manifest(plan: dict) -> dict:
    secret = plan["secret"]
    return {"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": plan["backup_name"], "namespace": plan["namespace"],
                         "annotations": {BACKUP_ANNOTATION: plan["name"],
                                         "cert-asset-validator/backup-date": datetime.now(timezone.utc).isoformat(),
                                         "cert-asset-validator/backup-resource-version": plan["resource_version"]}},
            "type": plan["type"], "data": dict(secret.data or {})}


def _patch(plan: dict) -> dict:
    return {"metadata": {"resourceVersion": plan["resource_version"]},
            "data": {key: _b64(data) for key, (data, _what) in sorted(plan["changes"].items())}}


def _write(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


# write_manifests writes the patch/backup files and rotate.sh under out_dir. Returns the
# list of written paths (relative).
def write_manifests(out_dir: str, planner: Planner, header: list[str], kubeconfig: str = None) -> list[str]:
    import yaml
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    os.chmod(out_dir, 0o700)
    written = []
    _write(os.path.join(out_dir, ".gitignore"), "# Secret values and private keys: never commit\n*\n")
    lines = ["#!/usr/bin/env bash", *[f"# {h}" for h in header],
             "# Review before running. Uses $KUBECONFIG or ~/.kube/config; KUBECTL=oc to use oc.",
             "# Stops at the first failure: a backup that cannot be created stops the patch after it,",
             "# and a Secret changed since planning is rejected (resourceVersion conflict).",
             "set -euo pipefail", 'KUBECTL="${KUBECTL:-kubectl}"']
    if kubeconfig:
        lines.append(f'if [ -z "${{KUBECONFIG:-}}" ]; then export KUBECONFIG={shlex.quote(os.path.abspath(kubeconfig))}; fi')
    lines.append('cd "$(dirname "$0")"')
    for plan in planner.changed():
        rel_dir = os.path.join(*(p for p in (plan["cluster"], plan["namespace"]) if p))
        os.makedirs(os.path.join(out_dir, rel_dir), mode=0o700, exist_ok=True)
        kc = ['"$KUBECTL"'] + (["--context", shlex.quote(plan["context"])] if plan["context"] else []) + \
             ["-n", shlex.quote(plan["namespace"])]
        lines += ["", f"# --- {_where(plan)}  (assets: {', '.join(plan['assets'])})"]
        if plan["backup_name"]:
            rel = os.path.join(rel_dir, f"{plan['backup_name']}.yaml")
            _write(os.path.join(out_dir, rel), yaml.safe_dump(_backup_manifest(plan), sort_keys=False))
            written.append(rel)
            lines.append(" ".join(kc + ["create", "-f", shlex.quote(rel)]))
        rel = os.path.join(rel_dir, f"{plan['name']}.patch.json")
        _write(os.path.join(out_dir, rel), json.dumps(_patch(plan), indent=2) + "\n")
        written.append(rel)
        lines.append(" ".join(kc + ["patch", "secret", shlex.quote(plan["name"]), "--type", "merge",
                                    "--patch-file", shlex.quote(rel)]))
        for workload in plan["workloads"] or []:
            lines.append(" ".join(kc + ["rollout", "restart", shlex.quote(workload)]))
    lines += ["", 'echo "done: check with main.py validate INVENTORY --live"', ""]
    script = os.path.join(out_dir, "rotate.sh")
    _write(script, "\n".join(lines))
    os.chmod(script, 0o700)
    written.append("rotate.sh")
    return written

import base64
import json
import logging
import re

import yaml

from cert_analysis import JCEKS_MAGIC, JKS_MAGIC, _load_jks, cert_format, cert_metadata_extract

logger = logging.getLogger(__name__)

# Secret types that never hold certificate material worth inventorying.
SKIP_SECRET_TYPES = {
    "kubernetes.io/service-account-token",
    "kubernetes.io/dockerconfigjson",
    "kubernetes.io/dockercfg",
    "kubernetes.io/basic-auth",
    "kubernetes.io/ssh-auth",
    "bootstrap.kubernetes.io/token",
    "helm.sh/release.v1",
}

# Key names that look like certificate material. Content is always checked too:
# a key is only kept if cert_format() recognises it.
CERT_KEY_SUFFIXES = (".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".jceks")
CERT_KEY_WORDS = ("keystore", "truststore", "cert")
# Never treated as certificates even if they parse (private keys, CA bundle of a tls Secret).
NOT_CERT_KEYS = ("tls.key", "ca.crt")

# Substrings that make a Secret key look like a password (keystorePassword, storepass,
# KEYSTORE_PWD, ssl-passphrase, ...). Matching is generous on purpose: a candidate is only
# used if it actually opens the keystore.
PASSWORD_WORDS = ("password", "passwd", "pass", "pwd", "secret", "pin", "cred")
# Tokens (Secret names split on "-" and ".", the only separators Kubernetes allows) that
# make a Secret name look like a password holder: billing-pwd, billing.password,
# billing-tls-pw, billing-keystore-pass, billing-creds, pwd-billing, app-passwords, ...
PASSWORD_NAME_TOKENS = {
    "password", "passwords", "passwd", "pass", "pwd", "pw", "passphrase", "pin", "secret", "secrets",
    "cred", "creds", "credential", "credentials", "storepass", "keypass",
}

# Suffixes stripped from a Secret name to find related Secrets: api-tls -> api,
# billing-keystore -> billing. The password Secret is then looked up as <base>-pass, ...
NAME_SUFFIXES = ("-tls", "-ssl", "-cert", "-certs", "-certificate", "-keystore", "-truststore", "-jks", "-p12")

# certType written in the YAML for each detected format. JKS uses "keystore" so that
# validate requires a passwordRef for it.
FORMAT_CERT_TYPE = {"PEM": "pem", "DER": "der", "PKCS12": "pkcs12", "JKS": "keystore"}

MAX_PASSWORD_CANDIDATES = 20

# Password candidate tiers, best first. Only TIER_UNRELATED produces a warning note.
TIER_SAME_SECRET, TIER_RELATED_NAME, TIER_SHARED_SECRET, TIER_UNRELATED = range(4)


def _decode(value: str) -> bytes:
    return base64.b64decode(value)


def _base_name(secret_name: str) -> str:
    for suffix in NAME_SUFFIXES:
        if secret_name.endswith(suffix) and len(secret_name) > len(suffix):
            return secret_name[: -len(suffix)]
    return secret_name


def _is_password_key(key: str) -> bool:
    lower = key.lower()
    if any(word in lower for word in PASSWORD_WORDS):
        return True
    # short "pw" only as a whole token or suffix (keystore-pw, keystorePw, KS_PW)
    return lower.endswith("pw") or "pw" in re.split(r"[-._]", lower)


def _name_tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[-.]", name.lower()) if t]


def _is_password_name(name: str) -> bool:
    return any(t in PASSWORD_NAME_TOKENS or "pass" in t or "pwd" in t for t in _name_tokens(name))


# _related_by_name: `other` starts or ends with `base` and the rest of its name is
# password-like: billing -> billing-pwd, billing.password, billing-tls-pw,
# billing-keystore-pass, billing-creds, pwd-billing.
def _related_by_name(base: str, other_name: str) -> bool:
    base_tokens, tokens = _name_tokens(base), _name_tokens(other_name)
    n = len(base_tokens)
    if len(tokens) <= n:
        return False
    if tokens[:n] == base_tokens:
        rest = tokens[n:]
    elif tokens[-n:] == base_tokens:
        rest = tokens[:-n]
    else:
        return False
    return _is_password_name("-".join(rest))


def _is_truststore_key(key: str) -> bool:
    return "trust" in key.lower()


def _looks_like_cert_key(key: str, data: bytes) -> bool:
    lower = key.lower()
    if lower in NOT_CERT_KEYS or lower.endswith(".key") or _is_password_key(lower):
        return False
    if lower.endswith(CERT_KEY_SUFFIXES) or any(word in lower for word in CERT_KEY_WORDS):
        return True
    # keys with arbitrary names: accept only content that is unambiguous
    return b"-----BEGIN CERTIFICATE-----" in data or data[:4] in (JKS_MAGIC, JCEKS_MAGIC)


# _cert_stores returns the certificate stores of one Secret as dicts
# {key, data, format, role} (role: "keystore" or "truststore").
def _cert_stores(secret) -> list[dict]:
    data = secret.data or {}
    stores = []
    if secret.type == "kubernetes.io/tls":
        if "tls.crt" in data:
            raw = _decode(data["tls.crt"])
            fmt = cert_format(raw, "tls.crt")
            if fmt:
                stores.append({"key": "tls.crt", "data": raw, "format": fmt, "role": "keystore"})
        return stores

    for key in sorted(data):
        raw = _decode(data[key])
        if not raw or not _looks_like_cert_key(key, raw):
            continue
        fmt = cert_format(raw, key)
        if fmt is None:
            continue
        role = "truststore" if _is_truststore_key(key) else "keystore"
        stores.append({"key": key, "data": raw, "format": fmt, "role": role})
    return stores


# _password_candidates lists (secret name, key, value, tier) to try for a store, best first:
#   TIER_SAME_SECRET    password-like keys in the same Secret, those naming the store role or
#                       key stem first (keystorePassword for keystore.jks)
#   TIER_RELATED_NAME   every key of Secrets related by name (_related_by_name), role-matching
#                       and password-like keys first: a Secret named billing-pwd may store the
#                       password under any key (password, value, keystore.password, ...)
#   TIER_SHARED_SECRET  keys mentioning the base name in password-named Secrets shared by
#                       several apps (app-passwords: {billing: ..., api: ...})
#   TIER_UNRELATED      password-like keys of any other Secret in the namespace, last resort
def _password_candidates(secret, store: dict, by_name: dict) -> list[tuple[str, str, bytes, int]]:
    stem = store["key"].rsplit(".", 1)[0].lower()
    role = store["role"]
    name = secret.metadata.name
    base = _base_name(name)

    def ranked(keys):
        keys = sorted(keys)
        first = [k for k in keys if role in k.lower() or stem in k.lower()]
        second = [k for k in keys if k not in first and _is_password_key(k)]
        return first + second + [k for k in keys if k not in first and k not in second]

    ordered = [(name, k, TIER_SAME_SECRET)
               for k in ranked(k for k in (secret.data or {}) if _is_password_key(k))]

    others = [s for _n, s in sorted(by_name.items()) if s is not secret and s.data]
    for other in others:
        if _related_by_name(base, other.metadata.name) or _related_by_name(name, other.metadata.name):
            ordered += [(other.metadata.name, k, TIER_RELATED_NAME) for k in ranked(other.data)]
    for other in others:
        if _is_password_name(other.metadata.name):
            ordered += [(other.metadata.name, k, TIER_SHARED_SECRET)
                        for k in ranked(other.data) if base.lower() in k.lower()]
    for other in others:
        ordered += [(other.metadata.name, k, TIER_UNRELATED)
                    for k in ranked(other.data) if _is_password_key(k)]

    seen, result = set(), []
    for secret_name, key, tier in ordered:
        if (secret_name, key) in seen:
            continue
        seen.add((secret_name, key))
        result.append((secret_name, key, _decode(by_name[secret_name].data[key]), tier))
        if len(result) == MAX_PASSWORD_CANDIDATES:
            break
    return result


# _open_store parses a store, trying candidate passwords when the format needs one.
# Returns (metadata list or None, passwordRef dict or None, note or None). A password
# candidate is accepted only if it actually opens the store, so a wrong guess is never
# written to the inventory.
def _open_store(secret, store: dict, by_name: dict):
    fmt = store["format"]
    if fmt in ("PEM", "DER"):
        metas = cert_metadata_extract(store["data"], fmt)
        return (metas if isinstance(metas, list) else [metas]), None, None
    if fmt == "JKS":
        try:
            _load_jks()
        except ValueError:
            return None, None, "pyjks is not installed, the JKS store could not be opened to find its password"

    for name, key, raw, tier in _password_candidates(secret, store, by_name):
        try:
            password = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            continue
        try:
            metas = cert_metadata_extract(store["data"], fmt, password)
        except ValueError:
            continue
        if metas:
            note = None
            if tier == TIER_UNRELATED:
                # e.g. two apps both using "changeit": the reference works today but points
                # at another app's Secret and breaks when that one is rotated
                note = (f"password found in Secret '{name}', which is not related by name: "
                        "check it is the intended one (a default password shared by several apps matches too)")
            return metas, {"name": name, "key": key}, note

    if fmt == "PKCS12":
        try:
            metas = cert_metadata_extract(store["data"], fmt, None)
            return metas, None, "opens without a password, but certType pkcs12 requires a passwordRef: fill it in"
        except ValueError:
            pass
    return None, None, "password not found automatically: fill in passwordRef"


def _leaf(metas: list[dict]):
    for meta in metas or []:
        if meta.get("entry_type") != "TrustedCertEntry":
            return meta
    return (metas or [None])[0]


# _asset_id builds a readable, unique id: the Secret name, plus the store key when one
# Secret holds several keystores, plus the namespace on collision across namespaces.
def _asset_id(secret_name: str, namespace: str, key: str, multiple: bool, used: set) -> str:
    base = f"{secret_name}-{key}" if multiple else secret_name
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", base)
    candidate = base if base not in used else f"{base}.{namespace}"
    n = 2
    while candidate in used:
        candidate = f"{base}.{namespace}-{n}"
        n += 1
    used.add(candidate)
    return candidate


def _store_ref(secret_name: str, store: dict, password_ref) -> dict:
    ref = {"secret": {"name": secret_name, "key": store["key"]}}
    if store["format"] in ("PKCS12", "JKS"):
        ref["passwordRef"] = password_ref or {"name": "TODO", "key": "TODO"}
    return ref


# discover_namespace turns the Secrets of one namespace into inventory assets.
# Returns a list of (asset dict, notes list). Never includes secret values.
def discover_namespace(namespace: str, secrets: list, cluster_name: str, used_ids: set) -> list[tuple[dict, list[str]]]:
    by_name = {s.metadata.name: s for s in secrets}
    found = []  # (secret, stores)
    for secret in sorted(secrets, key=lambda s: s.metadata.name):
        if secret.type in SKIP_SECRET_TYPES:
            continue
        stores = _cert_stores(secret)
        if stores:
            found.append((secret, stores))

    # Standalone truststore Secrets (only truststore keys) are attached to the asset whose
    # Secret has the same base name (myapp-tls + myapp-truststore) when there is one.
    truststore_only = {}
    for secret, stores in found:
        if all(st["role"] == "truststore" for st in stores):
            truststore_only[_base_name(secret.metadata.name)] = (secret, stores[0])

    results = []
    attached = set()
    for secret, stores in found:
        name = secret.metadata.name
        keystores = [st for st in stores if st["role"] == "keystore"]
        truststores = [st for st in stores if st["role"] == "truststore"]
        if not keystores:
            continue  # handled below if it was not attached

        if not truststores and _base_name(name) in truststore_only:
            ts_secret, ts_store = truststore_only[_base_name(name)]
            truststores = [dict(ts_store, secret_name=ts_secret.metadata.name, secret=ts_secret)]
            attached.add(ts_secret.metadata.name)

        for ks in keystores:
            results.append(_build_asset(namespace, cluster_name, secret, ks, truststores[:1],
                                        len(keystores) > 1, by_name, used_ids))

    # truststore-only Secrets nobody claimed become assets of their own
    for secret, stores in found:
        name = secret.metadata.name
        if name in attached or any(st["role"] == "keystore" for st in stores):
            continue
        asset, notes = _build_asset(namespace, cluster_name, secret, stores[0], [], False, by_name, used_ids)
        notes.insert(0, "truststore only (CA bundle), no keystore found for it")
        results.append((asset, notes))
    return results


def _build_asset(namespace, cluster_name, secret, ks, truststores, multiple, by_name, used_ids):
    name = secret.metadata.name
    notes = []
    metas, ks_pass, note = _open_store(secret, ks, by_name)
    if note:
        notes.append(f"keystore: {note}")
    leaf = _leaf(metas)

    asset = {"id": _asset_id(name, namespace, ks["key"], multiple, used_ids)}
    if cluster_name:
        asset["cluster"] = cluster_name
    asset["namespace"] = namespace
    if leaf and leaf.get("common_name"):
        asset["cn"] = leaf["common_name"]
    else:
        asset["cn"] = "TODO"
        notes.append("cn: could not be read from the certificate, fill it in")
    asset["certType"] = FORMAT_CERT_TYPE[ks["format"]]
    asset["keystore"] = _store_ref(name, ks, ks_pass)

    if truststores:
        ts = truststores[0]
        ts_secret = ts.get("secret", secret)
        _ts_metas, ts_pass, ts_note = _open_store(ts_secret, ts, by_name)
        if ts_note:
            notes.append(f"truststore: {ts_note}")
        asset["truststore"] = _store_ref(ts_secret.metadata.name, ts, ts_pass)

    note = _mtls_note(leaf, bool(truststores))
    if note:
        notes.append(note)

    annotations = secret.metadata.annotations or {}
    if "cert-manager.io/certificate-name" in annotations:
        notes.append(f"managed by cert-manager (Certificate '{annotations['cert-manager.io/certificate-name']}')")
    if leaf:
        notes.append(f"{leaf['subject']}, {leaf['expiry']}")
    return asset, notes


# _mtls_note explains why `mtls` is not written. Whether a service requires client
# certificates is application/proxy configuration (Spring server.ssl.client-auth=need,
# Tomcat clientAuth, nginx ssl_verify_client, Ingress auth-tls-*), not something stored in
# a Secret. Keystore + truststore is also the normal setup for outbound TLS to a private
# CA. The certificate's EKU only gives a hint: an EKU without clientAuth cannot be used as
# an mTLS client certificate; clientAuth, or no EKU at all (RFC 5280: no restriction),
# makes mTLS possible but not proven (many CAs set clientAuth by default).
# Returns None when nothing suggests mTLS, to keep the YAML quiet.
def _mtls_note(leaf, has_truststore: bool):
    eku = (leaf or {}).get("eku", [])
    client_auth = "clientAuth" in eku
    if not has_truststore and not client_auth:
        return None
    hints = [f"EKU: {', '.join(eku)}" if eku else "no EKU (any usage allowed)"]
    if has_truststore:
        hints.append("truststore present")
    verdict = "possible" if client_auth or not eku else "unlikely as client (EKU without clientAuth)"
    return (f"mtls: not set, cannot be inferred from Secrets ({'; '.join(hints)}): {verdict}; "
            "set it from the application config, e.g. client-auth=need")


# render_inventory writes the discovered assets as YAML. PyYAML cannot emit comments,
# so each asset is dumped on its own and preceded by its notes as comments.
def render_inventory(cluster_name: str, context: str, discovered: list[tuple[dict, list[str]]],
                     header: list[str]) -> str:
    lines = [f"# {h}" for h in header]
    if cluster_name:
        # json.dumps quotes safely and a JSON string is valid YAML
        lines += ["clusters:", f"  - name: {json.dumps(cluster_name)}",
                  f"    context: {json.dumps(context)}", ""]
    lines.append("assets:" if discovered else "assets: []")
    for asset, notes in discovered:
        lines.append("")
        lines += [f"  # {note}" for note in notes]
        dumped = yaml.safe_dump([asset], sort_keys=False, default_flow_style=False)
        lines += ["  " + line if line else line for line in dumped.rstrip("\n").split("\n")]
    return "\n".join(lines) + "\n"

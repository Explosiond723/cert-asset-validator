import logging

import cluster
from cert_analysis import cert_format, cert_metadata_extract, expiry_warning, private_key_location, verify_issued_by

logger = logging.getLogger(__name__)

# Formats accepted for each declared certType. A mismatch is reported as a warning:
# the YAML says one thing, the Secret holds another.
CERT_TYPE_FORMATS = {
    "keystore": {"JKS", "PKCS12"},
    "jks": {"JKS"},
    "pkcs12": {"PKCS12"},
    "p12": {"PKCS12"},
    "pem": {"PEM"},
    "crt": {"PEM", "DER"},
    "der": {"DER"},
}


# ClusterClients hands out one CoreV1Api per kubeconfig context, connecting lazily
# and only once per context. A context that fails to connect is remembered, so its
# error is reported for every asset on that cluster without retrying each time.
#
# Context resolution for an asset: --context override > clusters[].context of the
# asset's cluster > None (in-cluster ServiceAccount, then kubeconfig current context).
class ClusterClients:
    def __init__(self, cluster_contexts: dict, kubeconfig: str = None, context_override: str = None):
        self.cluster_contexts = cluster_contexts
        self.kubeconfig = kubeconfig
        self.context_override = context_override
        self._cache = {}

    def context_for(self, asset: dict):
        if self.context_override:
            return self.context_override
        return self.cluster_contexts.get(asset.get("cluster"))

    def api_for(self, asset: dict):
        context = self.context_for(asset)
        if context not in self._cache:
            try:
                from kubernetes import client
                api_client = cluster.connect(config_file=self.kubeconfig, context=context)
                self._cache[context] = client.CoreV1Api(api_client)
            except cluster.ClusterError as e:
                self._cache[context] = e
        cached = self._cache[context]
        if isinstance(cached, Exception):
            raise cached
        return cached


# fetch_store_material reads one keystore/truststore reference from the cluster and
# returns (raw bytes, password or None). The password only lives in the caller's scope
# and is never logged or printed.
def fetch_store_material(api, namespace: str, store: dict) -> tuple[bytes, str | None]:
    secret = store["secret"]
    data = cluster.get_secret_key(namespace, secret["name"], secret["key"], api)

    password = None
    ref = store.get("passwordRef")
    if ref:
        raw = cluster.get_tls_password(namespace, ref["name"], ref["key"], api)
        try:
            # Secrets created with `echo pass | oc create secret ...` carry a trailing
            # newline that is not part of the password
            password = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            raise ValueError(f"password in Secret '{ref['name']}' key '{ref['key']}' is not valid UTF-8")
    return data, password


# _fetch_store fetches a store and parses it. Returns (format, list of cert metadata), plus
# where the private key is (cert_analysis.private_key_location) when with_key is set.
def _fetch_store(api, namespace: str, store: dict, with_key: bool = False):
    secret = store["secret"]
    data, password = fetch_store_material(api, namespace, store)

    fmt = cert_format(data, secret["key"], password)
    if fmt is None:
        raise ValueError(f"unable to detect certificate format of Secret '{secret['name']}' key '{secret['key']}'")
    metas = cert_metadata_extract(data, fmt, password)
    if isinstance(metas, dict):
        metas = [metas]
    if not metas:
        raise ValueError(f"no certificates found in Secret '{secret['name']}' key '{secret['key']}'")
    if with_key:
        location = private_key_location(data, fmt, password, metas, secret["key"],
                                        lambda: cluster.secret_keys(namespace, secret["name"], api))
        return fmt, metas, location
    return fmt, metas


# fetch_csr_material gets what `csr --live` needs for an asset: the keystore bytes, its
# detected format, the password, and (only when reuse_key is set and the cert is a PEM
# stored as tls.crt) the PEM private key from tls.key of the same Secret, the
# kubernetes.io/tls layout. Raises ClusterError / ValueError.
def fetch_csr_material(asset: dict, clients: ClusterClients, reuse_key: bool):
    store = asset.get("keystore")
    if not isinstance(store, dict) or not isinstance(store.get("secret"), dict):
        raise ValueError(f"asset '{asset['id']}' has no keystore.secret reference, nothing to renew")
    api = clients.api_for(asset)
    data, password = fetch_store_material(api, asset["namespace"], store)
    secret = store["secret"]
    fmt = cert_format(data, secret["key"], password)
    if fmt is None:
        raise ValueError(f"unable to detect certificate format of Secret '{secret['name']}' key '{secret['key']}'")

    key_pem = None
    if reuse_key and fmt in ("PEM", "DER") and secret["key"] == "tls.crt":
        key_pem = cluster.get_secret_key(asset["namespace"], secret["name"], "tls.key", api)
    return data, fmt, password, key_pem


# _leaf picks the certificate that identifies the asset: the first cert of a private
# key entry for JKS, the first cert for every other format (PEM chain order, PKCS12 leaf).
def _leaf(metas: list[dict]) -> dict:
    for meta in metas:
        if meta.get("entry_type") != "TrustedCertEntry":
            return meta
    return None


def _cn_matches(yaml_cn: str, leaf: dict) -> bool:
    wanted = yaml_cn.lower()
    if leaf.get("common_name") and leaf["common_name"].lower() == wanted:
        return True
    return any(san.lower() == f"dns:{wanted}" for san in leaf.get("san", []))


# inspect_asset fetches the asset's material from the cluster and cross-checks it
# against the YAML. Never raises: cluster and parsing problems are collected in
# result["errors"], inconsistencies and expiry in result["warnings"].
# result["expiring"] is True when any keystore or truststore cert triggered an expiry
# warning (expired, not yet valid, or within warn_days): used by --fail-on-expiry.
def inspect_asset(asset: dict, clients: ClusterClients, warn_days: int) -> dict:
    result = {"id": asset["id"], "context": clients.context_for(asset), "errors": [], "warnings": [],
              "expiring": False, "keystore": None, "truststore": None, "chain": None, "leaf": None,
              "private_key": None, "chain_verified": None}
    namespace = asset["namespace"]

    try:
        api = clients.api_for(asset)
    except cluster.ClusterError as e:
        result["errors"].append(str(e))
        return result

    for role in ("keystore", "truststore", "chain"):
        store = asset.get(role)
        if not isinstance(store, dict) or not isinstance(store.get("secret"), dict):
            continue
        try:
            if role == "keystore":
                fmt, metas, result["private_key"] = _fetch_store(api, namespace, store, with_key=True)
            else:
                fmt, metas = _fetch_store(api, namespace, store)
        except (cluster.ClusterError, ValueError) as e:
            result["errors"].append(f"{role}: {e}")
            continue
        result[role] = {"secret": store["secret"]["name"], "key": store["secret"]["key"],
                        "format": fmt, "certs": metas}
        for meta in metas:
            warning = expiry_warning(meta, warn_days)
            if warning:
                result["warnings"].append(f"{role}: {meta['subject']}: {warning}")
                result["expiring"] = True

    if result["keystore"] is None and not result["errors"]:
        result["errors"].append("no keystore.secret reference in the YAML, nothing to inspect")

    keystore = result["keystore"]
    if keystore:
        allowed = CERT_TYPE_FORMATS.get(str(asset["certType"]).lower())
        if allowed and keystore["format"] not in allowed:
            result["warnings"].append(
                f"certType '{asset['certType']}' declared, but the Secret contains {keystore['format']}"
            )
        leaf = _leaf(keystore["certs"])
        result["leaf"] = leaf
        if leaf is None:
            result["warnings"].append("keystore contains only trusted certificates, no private key entry")
        elif not _cn_matches(asset["cn"], leaf):
            result["warnings"].append(
                f"YAML cn '{asset['cn']}' does not match the certificate "
                f"(CN '{leaf.get('common_name')}', SAN: {', '.join(leaf['san']) or 'none'})"
            )

        if leaf is not None:
            _check_chain(asset, result, leaf)

    if asset.get("mtls") and "truststore" not in asset:
        result["warnings"].append("mtls: true but no truststore is defined (peer certificates cannot be verified)")
    if asset.get("mtls") and keystore and result["private_key"] is None:
        result["warnings"].append("mtls: true but no private key was found with the certificate "
                                  "(an mTLS endpoint needs its own key)")

    return result


# _check_chain verifies, by signature, that the leaf was issued by a CA found in the
# keystore itself or in the asset's separate `chain` Secret (the equivalent of
# `openssl verify -CAfile chain.pem leaf.pem` for the first hop). chain_verified is True
# when an issuer verifies, False when CA material exists but none signed the leaf, None
# when there is no CA material at all (nothing to check). A self-signed leaf verifies
# against itself.
def _check_chain(asset: dict, result: dict, leaf: dict) -> None:
    candidates = [m for m in result["keystore"]["certs"] if m is not leaf]
    if result["chain"]:
        candidates += result["chain"]["certs"]
    if verify_issued_by(leaf, leaf):
        result["chain_verified"] = True
        return
    if not candidates:
        return
    result["chain_verified"] = any(verify_issued_by(leaf, ca) for ca in candidates)
    if not result["chain_verified"]:
        where = (f"chain Secret '{result['chain']['secret']}/{result['chain']['key']}'"
                 if result["chain"] else "keystore")
        result["warnings"].append(f"the certificate is not signed by any CA in its {where} "
                                  f"(issuer: {leaf['issuer']})")


def print_inspection(result: dict) -> None:
    context = result["context"] or "(default)"
    print(f"Live: {result['id']}  (context: {context})")
    for role in ("keystore", "truststore", "chain"):
        store = result[role]
        if store:
            print(f"  {role}: {store['secret']}/{store['key']}  [{store['format']}, {len(store['certs'])} cert(s)]")
    if result["keystore"]:
        print(f"  private key: {result['private_key'] or 'not found'}")
    if result["chain_verified"] is not None:
        print(f"  chain verified: {'yes' if result['chain_verified'] else 'no'}")
    leaf = result["leaf"]
    if leaf:
        print(f"  leaf: {leaf['subject']}")
        print(f"  issuer: {leaf['issuer']}")
        print(f"  san: {', '.join(leaf['san']) or '(none)'}")
        print(f"  expiry: {leaf['expiry']} ({leaf['not_valid_after']})")
    for warning in result["warnings"]:
        print(f"  WARNING: {warning}")
    for error in result["errors"]:
        print(f"  ERROR: {error}")
    print("----")


# live_matches_cn implements `search --live --cn`: substring match against the YAML cn,
# the real CN and the SANs of the leaf certificate fetched from the cluster.
def live_matches_cn(asset: dict, result: dict, needle: str) -> bool:
    needle = needle.lower()
    if needle in asset["cn"].lower():
        return True
    leaf = result.get("leaf")
    if not leaf:
        return False
    if leaf.get("common_name") and needle in leaf["common_name"].lower():
        return True
    return any(needle in san.lower() for san in leaf.get("san", []))

import logging

import cluster
from cert_analysis import cert_format, cert_metadata_extract, expiry_warning

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


# _fetch_store reads one keystore/truststore reference from the cluster and parses it.
# Returns (format, list of cert metadata). The password, if any, only lives in this
# function's scope and is never logged or printed.
def _fetch_store(api, namespace: str, store: dict) -> tuple[str, list[dict]]:
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

    fmt = cert_format(data, secret["key"], password)
    if fmt is None:
        raise ValueError(f"unable to detect certificate format of Secret '{secret['name']}' key '{secret['key']}'")
    metas = cert_metadata_extract(data, fmt, password)
    if isinstance(metas, dict):
        metas = [metas]
    if not metas:
        raise ValueError(f"no certificates found in Secret '{secret['name']}' key '{secret['key']}'")
    return fmt, metas


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
def inspect_asset(asset: dict, clients: ClusterClients, warn_days: int) -> dict:
    result = {"id": asset["id"], "context": clients.context_for(asset), "errors": [], "warnings": [],
              "keystore": None, "truststore": None, "leaf": None}
    namespace = asset["namespace"]

    try:
        api = clients.api_for(asset)
    except cluster.ClusterError as e:
        result["errors"].append(str(e))
        return result

    for role in ("keystore", "truststore"):
        store = asset.get(role)
        if not isinstance(store, dict) or not isinstance(store.get("secret"), dict):
            continue
        try:
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

    if asset.get("mtls") and "truststore" not in asset:
        result["warnings"].append("mtls: true but no truststore is defined (peer certificates cannot be verified)")

    return result


def print_inspection(result: dict) -> None:
    context = result["context"] or "(default)"
    print(f"Live: {result['id']}  (context: {context})")
    for role in ("keystore", "truststore"):
        store = result[role]
        if store:
            print(f"  {role}: {store['secret']}/{store['key']}  [{store['format']}, {len(store['certs'])} cert(s)]")
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

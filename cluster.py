import base64

from kubernetes import config, client


# Timeout (seconds) for each API call, so an unreachable cluster fails fast
# instead of hanging the whole run.
REQUEST_TIMEOUT = 15


# ClusterError is raised for any cluster access problem (config, RBAC, missing
# Secret/key, network). Messages never contain secret data.
class ClusterError(Exception):
    pass


# connect builds a client for one Kubernetes/OpenShift cluster and returns it.
# Unlike the global kubernetes config, each call returns an independent ApiClient,
# so one run can talk to several clusters (one per kubeconfig context).
#
# - context and/or config_file given: load that kubeconfig context
#   (config_file=None means the default ~/.kube/config or $KUBECONFIG)
# - neither given: try in-cluster config first (ServiceAccount token mounted at
#   /var/run/secrets/kubernetes.io/serviceaccount/), then the kubeconfig current context
#
# Works with any provider (OpenShift, GKE, EKS, AKS, vanilla k8s) because
# they all write their auth config into ~/.kube/config when the user logs in
# (oc login, gcloud, aws eks, etc.). The kubernetes library reads those
# auth plugins transparently.
def connect(config_file: str = None, context: str = None) -> client.ApiClient:
    if config_file or context:
        try:
            return config.new_client_from_config(config_file=config_file, context=context, persist_config=False)
        except (config.ConfigException, OSError) as e:
            where = f"context '{context}'" if context else f"kubeconfig '{config_file}'"
            raise ClusterError(f"failed to load {where}: {e}")

    try:
        configuration = client.Configuration()
        config.load_incluster_config(client_configuration=configuration)
        return client.ApiClient(configuration)
    except config.ConfigException:
        pass
    try:
        return config.new_client_from_config(persist_config=False)
    except (config.ConfigException, OSError) as e:
        raise ClusterError(f"no in-cluster config and failed to load kubeconfig: {e}")


# get_secret_key retrieves a single data key from a Kubernetes Secret.
# The secret.data values in Kubernetes are base64-encoded strings; this function
# decodes them and returns the raw bytes, ready to be passed to cert_analysis
# functions (cert_format, cert_metadata_extract) which expect raw bytes.
# api is a CoreV1Api; when omitted the globally loaded config is used.
# Raises ClusterError if the Secret or key does not exist, or if the identity in use
# lacks `get` permission on secrets in the target namespace.
def get_secret_key(namespace: str, name: str, key: str, api=None) -> bytes:
    api = api or client.CoreV1Api()
    try:
        secret = api.read_namespaced_secret(name=name, namespace=namespace, _request_timeout=REQUEST_TIMEOUT)
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ClusterError(f"Secret '{namespace}/{name}' not found")
        if e.status in (401, 403):
            raise ClusterError(
                f"permission denied reading Secret '{namespace}/{name}' "
                "(RBAC needs 'get' on secrets in this namespace)"
            )
        raise ClusterError(f"failed to read Secret '{namespace}/{name}': HTTP {e.status} {e.reason}")
    except Exception as e:  # network errors, TLS errors, timeouts from urllib3
        raise ClusterError(f"failed to read Secret '{namespace}/{name}': {e}")

    # secret.data is None when the Secret has no data at all
    data = secret.data or {}
    if key not in data:
        raise ClusterError(f"Secret '{namespace}/{name}' does not contain key '{key}'")

    return base64.b64decode(data[key])

# secret_keys returns the key names of a Secret without decoding any value. Used to tell
# whether a private key sits next to a certificate (tls.key) without reading the key.
def secret_keys(namespace: str, name: str, api) -> list[str]:
    try:
        secret = api.read_namespaced_secret(name=name, namespace=namespace, _request_timeout=REQUEST_TIMEOUT)
    except client.exceptions.ApiException as e:
        raise ClusterError(f"failed to read Secret '{namespace}/{name}': HTTP {e.status} {e.reason}")
    except Exception as e:
        raise ClusterError(f"failed to read Secret '{namespace}/{name}': {e}")
    return sorted((secret.data or {}).keys())


# get_tls_password is a semantic alias for get_secret_key, named to make it
# clear in the code when we're retrieving a password vs a cert/key.
def get_tls_password(namespace: str, name: str, key: str, api=None) -> bytes:
    return get_secret_key(namespace, name, key, api)


def _api_error(what: str, e) -> ClusterError:
    if e.status in (401, 403):
        return ClusterError(f"permission denied listing {what} (RBAC needs 'list' on {what})")
    return ClusterError(f"failed to list {what}: HTTP {e.status} {e.reason}")


# list_secrets returns every Secret of a namespace (with data). Used by `discover`.
# Needs RBAC `list` on secrets in that namespace.
def list_secrets(namespace: str, api) -> list:
    try:
        return api.list_namespaced_secret(namespace=namespace, _request_timeout=REQUEST_TIMEOUT).items
    except client.exceptions.ApiException as e:
        raise _api_error(f"secrets in namespace '{namespace}'", e)
    except Exception as e:  # network errors, TLS errors, timeouts from urllib3
        raise ClusterError(f"failed to list secrets in namespace '{namespace}': {e}")


# list_namespaces returns the names of all namespaces (`discover --all-namespaces`).
# Needs cluster-wide RBAC `list` on namespaces.
def list_namespaces(api) -> list[str]:
    try:
        return [ns.metadata.name for ns in api.list_namespace(_request_timeout=REQUEST_TIMEOUT).items]
    except client.exceptions.ApiException as e:
        raise _api_error("namespaces", e)
    except Exception as e:
        raise ClusterError(f"failed to list namespaces: {e}")


# current_context returns the name of the kubeconfig current context, or None when there
# is no kubeconfig (e.g. running in-cluster with a ServiceAccount).
def current_context(config_file: str = None):
    try:
        _contexts, active = config.list_kube_config_contexts(config_file=config_file)
        return active["name"] if active else None
    except (config.ConfigException, OSError):
        return None

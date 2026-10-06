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

# get_tls_password is a semantic alias for get_secret_key, named to make it
# clear in the code when we're retrieving a password vs a cert/key.
def get_tls_password(namespace: str, name: str, key: str, api=None) -> bytes:
    return get_secret_key(namespace, name, key, api)


# list_tls_passwords lists all Secrets in a namespace that contain keys that look like passwords.
# This is used by the discover command to find any TLS-related secrets that might contain passwords,
# even if they don't follow the standard TLS secret format. It filters for Opaque secrets with keys
# that start with or end with common password patterns (password, pass, pwd).
def list_tls_passwords(namespace: str) -> list[dict]:

    client_api = client.CoreV1Api()
    try:
        secrets = client_api.list_namespaced_secret(namespace=namespace)
    except client.exceptions.ApiException as e:
        print(f"Error: Failed to list secrets in namespace '{namespace}': {e}")
        return []

    tls_passwords = []

    for secret in secrets.items:
        if secret.type == "Opaque":
            matching_keys = [key for key in secret.data.keys() if key.lower().endswith(('password', 'pass', 'pwd', 'truststorepassword', 'keystorepassword')) or key.lower().startswith(('password', 'pass', 'pwd', 'truststorepassword', 'keystorepassword'))]
            if matching_keys:
                tls_passwords.append({
                    "name": secret.metadata.name,
                    "type": secret.type,
                    "keys": matching_keys
                })
        
    return tls_passwords

# list_tls_secrets lists all Secrets in a namespace that contain TLS-related keys.
# They might not be of type kubernetes.io/tls, but if they have keys that look like certs/keys, we include them as well.
# This is default behavior. if we want to only include kubernetes.io/tls secrets, we can add a filter for that.
# 
# Used by the discover command to auto-generate YAML asset definitions from cluster state.
# Filters for:
#   - Type kubernetes.io/tls (contains tls.crt and tls.key)
#   - Type Opaque with keys matching common cert patterns:
#     *.pem, *.crt, *.p12, *.pfx, *.jks, keystore*, truststore*
# Returns a list of dicts with secret name, type, and matching key names.
# Skips Secrets the ServiceAccount cannot access (permission errors logged as warnings).
def list_tls_secrets(namespace: str) -> list[dict]:

    client_api = client.CoreV1Api()
    try:
        secrets = client_api.list_namespaced_secret(namespace=namespace)
    except client.exceptions.ApiException as e:
        print(f"Error: Failed to list secrets in namespace '{namespace}': {e}")
        return []

    tls_secrets = []

    for secret in secrets.items:
        if secret.type == "kubernetes.io/tls":
            if "tls.crt" in secret.data and "tls.key" in secret.data:
                tls_secrets.append({
                    "name": secret.metadata.name,
                    "type": secret.type,
                    "keys": ["tls.crt", "tls.key"]
                })
        elif secret.type == "Opaque":
            # non-standard secret, check for keys that look like certs/keys
            matching_keys = [key for key in secret.data.keys() if key.lower().endswith(('.pem', '.crt', '.der', '.p12', '.pfx', '.jks')) or key.lower().startswith(('keystore', 'truststore'))]
            if matching_keys:
                tls_secrets.append({
                    "name": secret.metadata.name,
                    "type": secret.type,
                    "keys": matching_keys
                })
        
    return tls_secrets

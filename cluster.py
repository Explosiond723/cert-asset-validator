import base64

from kubernetes import config, client


# connect establishes a connection to a Kubernetes/OpenShift cluster.
# It configures the kubernetes client globally — after calling connect(),
# all API calls (get_secret, list_tls_secrets) use the loaded config
# automatically. Nothing is returned; it just sets up the session.
#
# If config_file is provided, it loads that specific kubeconfig file.
# Otherwise it tries in-cluster config first (checks for the ServiceAccount
# token at /var/run/secrets/kubernetes.io/serviceaccount/token), then falls
# back to kubeconfig (~/.kube/config).
#
# Works with any provider (OpenShift, GKE, EKS, AKS, vanilla k8s) because
# they all write their auth config into ~/.kube/config when the user logs in
# (oc login, gcloud, aws eks, etc.). The kubernetes library reads those
# auth plugins transparently.
#
# Raises RuntimeError if no valid config is found.
def connect(config_file: str = None, context: str = None) -> None:

    if config_file:
        try:
            # try to load the specified kubeconfig file and context (if provided)
            config.load_kube_config(config_file=config_file, context=context)
        except config.ConfigException as e:
            raise RuntimeError(f"Failed to load kubeconfig: {e}")
    else:
        try:
            # first try in-cluster config (works if running inside a Pod with a ServiceAccount)
            config.load_incluster_config()
        except config.ConfigException as e:
            try:
                # if in-cluster config fails, try kubeconfig as fallback (works for local dev)
                config.load_kube_config(context=context)
            except config.ConfigException as e2:
                raise RuntimeError(f"Failed to load kubeconfig: {e2}")


# get_secret_key retrieves a single data key from a Kubernetes Secret.
# The secret.data values in Kubernetes are base64-encoded strings; this function
# decodes them and returns the raw bytes, ready to be passed to cert_analysis
# functions (cert_format, cert_metadata_extract) which expect raw bytes.
# Raises an error if the Secret or key does not exist, or if the ServiceAccount
# lacks get permissions on secrets in the target namespace.
def get_secret_key(namespace: str, name: str, key: str) -> bytes:

    secret = client.CoreV1Api().read_namespaced_secret(name=name, namespace=namespace)
    if key not in secret.data:
        raise KeyError(f"Secret '{name}' does not contain key '{key}'")
    
    return base64.b64decode(secret.data[key])

# get_tls_password is a semantic alias for get_secret_key, named to make it
# clear in the code when we're retrieving a password vs a cert/key.
def get_tls_password(namespace: str, name: str, key: str) -> bytes:
    return get_secret_key(namespace, name, key)


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

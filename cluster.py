# connect establishes a connection to a Kubernetes/OpenShift cluster.
# It tries in-cluster config first (checks for the ServiceAccount token at
# /var/run/secrets/kubernetes.io/serviceaccount/token), then falls back to
# kubeconfig (~/.kube/config). A specific kubeconfig context can be provided
# to target a particular cluster entry.
# Raises an error if neither in-cluster config nor kubeconfig is available.
def connect(context: str = None) -> None:
    pass


# get_secret retrieves a single data key from a Kubernetes Secret.
# The secret.data values in Kubernetes are base64-encoded strings; this function
# decodes them and returns the raw bytes, ready to be passed to cert_analysis
# functions (cert_format, cert_metadata_extract) which expect raw bytes.
# Raises an error if the Secret or key does not exist, or if the ServiceAccount
# lacks get permissions on secrets in the target namespace.
def get_secret(namespace: str, name: str, key: str) -> bytes:
    pass


# list_tls_secrets lists all Secrets in a namespace that contain TLS-related keys.
# Used by the discover command to auto-generate YAML asset definitions from cluster state.
# Filters for:
#   - Type kubernetes.io/tls (contains tls.crt and tls.key)
#   - Type Opaque with keys matching common cert patterns:
#     *.pem, *.crt, *.p12, *.pfx, *.jks, keystore*, truststore*
# Returns a list of dicts with secret name, type, and matching key names.
# Skips Secrets the ServiceAccount cannot access (permission errors logged as warnings).
def list_tls_secrets(namespace: str) -> list[dict]:
    pass

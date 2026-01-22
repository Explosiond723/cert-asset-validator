import yaml

def require_path(cfg: dict, path: str):
    cur = cfg
    for part in path.split("."):
        if not isinstance(cur, dict):
            raise ValueError(f"ERROR: Field '{path}' parent is not a dictionary")
        if part not in cur:
            raise ValueError(f"ERROR: Missing required field: {path}")
        cur = cur[part]
    return cur

def require_dict(cfg: dict, path: str) -> dict:
    val = require_path(cfg, path)
    if not isinstance(val, dict):
        raise ValueError(f"ERROR: Field '{path}' must be a dictionary")
    return val

def validate_config(cfg: dict) -> None:
    if cfg is None or not isinstance(cfg, dict):
        raise ValueError("ERROR: config file not found or not in the correct format")

    # top-level required
    for k in ("id", "namespace", "certType"):
        if k not in cfg:
            raise ValueError(f"ERROR: Missing required field: {k}")

    cert_type = cfg["certType"]
    needs_password = cert_type in ("keystore", "pkcs12")

    # keystore: required when certType implies it (your current model)
    if needs_password:
        require_dict(cfg, "keystore")
        require_dict(cfg, "keystore.secret")
        require_path(cfg, "keystore.secret.name")
        require_path(cfg, "keystore.secret.key")

        require_dict(cfg, "keystore.passwordRef")
        require_path(cfg, "keystore.passwordRef.name")
        require_path(cfg, "keystore.passwordRef.key")

    # truststore: optional, but if present validate it
    if "truststore" in cfg:
        require_dict(cfg, "truststore")
        require_dict(cfg, "truststore.secret")
        require_path(cfg, "truststore.secret.name")
        require_path(cfg, "truststore.secret.key")

        if needs_password:
            require_dict(cfg, "truststore.passwordRef")
            require_path(cfg, "truststore.passwordRef.name")
            require_path(cfg, "truststore.passwordRef.key")

    # mtls optional but if present must be boolean
    if "mtls" in cfg and not isinstance(cfg["mtls"], bool):
        raise ValueError("ERROR: Field 'mtls' must be boolean")

with open("example-cfg.yaml", "rt") as f:
    cfg = yaml.safe_load(f)

validate_config(cfg)

print("Asset ID: ", cfg["id"])
print("Namespace: ", cfg["namespace"])
print("certType: ", cfg["certType"])
print("mTLS: ", cfg.get("mtls", False))

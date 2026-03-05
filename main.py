import argparse
import yaml
from cert_analysis import cert_format, cert_metadata_extract, eku_inspect

def load_assets(path: str) -> list[dict]:
    with open(path, "rt") as cfg_file:
        data = yaml.safe_load(cfg_file)
    if data is None:
        raise ValueError(f"ERROR: config file is empty")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise ValueError(f"ERROR: config root must be a dict or a list of dicts")

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


def cmd_validate(args):
    assets = load_assets(args.config)
    for i, cfg in enumerate(assets):
        try:
            validate_config(cfg)
        except ValueError as VE:
            asset_id = cfg.get("id", f"asset[{i}]")
            raise ValueError(f"{asset_id}: {VE}")
        print("Asset ID: ", cfg["id"])
        print("Namespace: ", cfg["namespace"])
        print("certType: ", cfg["certType"])
        print("mTLS: ", cfg.get("mtls", False))
        print("----")


def cmd_analyse(args):
    with open(args.cert, "rb") as f:
        data = f.read()
    password = args.password if args.password else None
    detected_type = cert_format(data, args.cert, password)
    if detected_type is None:
        print("ERROR: Unable to detect certificate format")
        return
    metadata = cert_metadata_extract(data, detected_type, password)
    eku_inspect(metadata)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="cert-asset-validator")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate", help="Validate YAML asset definitions")
    validate_parser.add_argument("config", help="Path to YAML config file")

    analyse_parser = subparsers.add_parser("analyse", help="Analyse a certificate file")
    analyse_parser.add_argument("cert", help="Path to certificate file")
    analyse_parser.add_argument("--password", help="Password for PKCS12/JKS keystores")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "analyse":
        cmd_analyse(args)

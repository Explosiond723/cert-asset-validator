import argparse
import logging
import sys
import yaml
from cert_analysis import cert_format, cert_metadata_extract, eku_inspect

logger = logging.getLogger(__name__)


def load_config(path: str) -> dict:
    """Load and normalize the YAML config file.

    Returns a dict with 'clusters' (list of cluster defs) and 'assets' (list of asset defs).
    Supports both the new multi-cluster format and the legacy flat list format.
    """
    with open(path, "rt") as cfg_file:
        data = yaml.safe_load(cfg_file)
    if data is None:
        raise ValueError("config file is empty")

    # New format: dict with 'clusters' and 'assets' keys
    if isinstance(data, dict):
        if "assets" in data:
            clusters = data.get("clusters", [])
            assets = data["assets"]
            if not isinstance(assets, list):
                raise ValueError("'assets' must be a list")
            if not isinstance(clusters, list):
                raise ValueError("'clusters' must be a list")
            return {"clusters": clusters, "assets": assets}
        # Single asset dict (legacy)
        return {"clusters": [], "assets": [data]}

    # Legacy format: flat list of assets
    if isinstance(data, list):
        return {"clusters": [], "assets": data}

    raise ValueError("config root must be a dict or a list of dicts")


def require_path(cfg: dict, path: str):
    cur = cfg
    for part in path.split("."):
        if not isinstance(cur, dict):
            raise ValueError(f"field '{path}' parent is not a dictionary")
        if part not in cur:
            raise ValueError(f"missing required field: {path}")
        cur = cur[part]
    return cur


def require_dict(cfg: dict, path: str) -> dict:
    val = require_path(cfg, path)
    if not isinstance(val, dict):
        raise ValueError(f"field '{path}' must be a dictionary")
    return val


def validate_cluster(cluster: dict) -> None:
    """Validate a single cluster definition."""
    if not isinstance(cluster, dict):
        raise ValueError("each cluster entry must be a dictionary")
    for k in ("name", "context"):
        if k not in cluster:
            raise ValueError(f"missing required cluster field: {k}")


def validate_config(cfg: dict, cluster_names: list[str]) -> None:
    """Validate a single asset definition.

    cluster_names is the list of valid cluster names from the clusters section.
    If empty (legacy mode), the 'cluster' field on assets is not required.
    """
    if cfg is None or not isinstance(cfg, dict):
        raise ValueError("config file not found or not in the correct format")

    # top-level required
    for k in ("id", "namespace", "certType"):
        if k not in cfg:
            raise ValueError(f"missing required field: {k}")

    # cluster field: required when clusters are defined, must reference a valid name
    if cluster_names:
        if "cluster" not in cfg:
            raise ValueError("missing required field: cluster")
        if cfg["cluster"] not in cluster_names:
            raise ValueError(
                f"cluster '{cfg['cluster']}' is not defined in the clusters section"
            )

    cert_type = cfg["certType"]
    needs_password = cert_type in ("keystore", "pkcs12")

    # keystore: required when certType implies it
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
        raise ValueError("field 'mtls' must be boolean")


def cmd_validate(args):
    config = load_config(args.config)
    clusters = config["clusters"]
    assets = config["assets"]

    # Validate cluster definitions
    cluster_names = []
    for cluster in clusters:
        try:
            validate_cluster(cluster)
            cluster_names.append(cluster["name"])
        except ValueError as ve:
            raise ValueError(f"Cluster config error: {ve}")

    if clusters:
        print(f"Clusters defined: {', '.join(cluster_names)}")
        print("----")

    # Validate each asset
    for i, cfg in enumerate(assets):
        try:
            validate_config(cfg, cluster_names)
        except ValueError as ve:
            asset_id = cfg.get("id", f"asset[{i}]")
            raise ValueError(f"{asset_id}: {ve}")
        print("Asset ID: ", cfg["id"])
        if "cluster" in cfg:
            print("Cluster:  ", cfg["cluster"])
        print("Namespace:", cfg["namespace"])
        print("certType: ", cfg["certType"])
        print("mTLS:     ", cfg.get("mtls", False))
        print("----")


def cmd_analyse(args):
    with open(args.cert, "rb") as f:
        data = f.read()
    # argparse defaults to None when --password is not provided, no need to check
    password = args.password
    detected_type = cert_format(data, args.cert, password)
    if detected_type is None:
        print("error: unable to detect certificate format")
        return
    metadata = cert_metadata_extract(data, detected_type, password)

    # normalize to list so we handle both single cert and multi-cert the same way
    if isinstance(metadata, dict):
        metadata = [metadata]

    for cert_meta in metadata:
        for key, value in cert_meta.items():
            print(f"  {key}: {value}")
        print("----")

    is_mtls = eku_inspect(metadata)
    print(f"mTLS candidate: {is_mtls}")


if __name__ == "__main__":
    # Main parser — this is the root command: `python main.py`
    parser = argparse.ArgumentParser(description="cert-asset-validator")

    # Subparsers let us define subcommands (like `validate` and `analyse`).
    # dest="command" means args.command will hold whichever subcommand the user picked,
    # or None if they didn't pick one (in which case we show help).
    subparsers = parser.add_subparsers(dest="command")

    # `python main.py validate <config>` — takes one positional argument (the YAML path)
    validate_parser = subparsers.add_parser("validate", help="Validate YAML asset definitions")
    validate_parser.add_argument("config", help="Path to YAML config file")

    # `python main.py analyse <cert> [--password]` — takes the cert path as positional,
    # and an optional --password flag for PKCS12/JKS files that need one
    analyse_parser = subparsers.add_parser("analyse", help="Analyse a certificate file")
    analyse_parser.add_argument("cert", help="Path to certificate file")
    analyse_parser.add_argument("--password", help="Password for PKCS12/JKS keystores")

    # Global flag (applies to all subcommands): -v / --verbose
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output (show INFO-level log messages)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.INFO if args.verbose else logging.WARNING,
    )

    # Top-level error handling: catch ValueErrors raised by subcommands and
    # print a clean one-line message instead of a full Python traceback.
    # sys.exit(1) signals failure to the shell (useful in scripts/pipelines).
    if args.command is None:
        parser.print_help()
    elif args.command == "validate":
        try:
            cmd_validate(args)
        except ValueError as e:
            print(f"error: {e}")
            sys.exit(1)
    elif args.command == "analyse":
        try:
            cmd_analyse(args)
        except ValueError as e:
            print(f"error: {e}")
            sys.exit(1)
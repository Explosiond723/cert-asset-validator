import argparse
import logging
import sys
import yaml
from cert_analysis import cert_format, cert_metadata_extract, eku_inspect, csr_generate, expiry_warning
# cluster.py (and the kubernetes client it needs) is deliberately NOT imported here:
# all current subcommands work offline. Import it inside the command that needs it
# once --live is wired in, so offline use does not require the kubernetes package.

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
    for k in ("id", "namespace", "cn", "certType"):
        if k not in cfg:
            raise ValueError(f"missing required field: {k}")
        
    if not isinstance(cfg["cn"], str):
        raise ValueError("field 'cn' must be a string")
    if not isinstance(cfg["namespace"], str):
        raise ValueError("field 'namespace' must be a string")
    if not isinstance(cfg["certType"], str):
        raise ValueError("field 'certType' must be a string")

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

    # Validate each asset independently, all errors are reported before exiting
    had_error = False
    for i, cfg in enumerate(assets):
        asset_id = cfg.get("id", f"asset[{i}]") if isinstance(cfg, dict) else f"asset[{i}]"
        try:
            validate_config(cfg, cluster_names)
        except ValueError as ve:
            print(f"error: {asset_id}: {ve}")
            had_error = True
            continue
        print("Asset ID: ", cfg["id"])
        if "cluster" in cfg:
            print("Cluster:  ", cfg["cluster"])
        print("Namespace:", cfg["namespace"])
        print("CN:      ", cfg["cn"])
        print("certType: ", cfg["certType"])
        print("mTLS:     ", cfg.get("mtls", False))
        print("----")

    if had_error:
        sys.exit(1)


def cmd_analyse(args):
    with open(args.cert, "rb") as f:
        data = f.read()
    # argparse defaults to None when --password is not provided, no need to check
    password = args.password
    detected_type = cert_format(data, args.cert, password)
    if detected_type is None:
        print("error: unable to detect certificate format")
        sys.exit(1)
    metadata = cert_metadata_extract(data, detected_type, password)

    # normalize to list so we handle both single cert and multi-cert the same way
    if isinstance(metadata, dict):
        metadata = [metadata]

    for cert_meta in metadata:
        for key, value in cert_meta.items():
            # lists (SANs, EKUs) are printed comma-separated instead of as a Python list
            if isinstance(value, list):
                value = ", ".join(value) if value else "(none)"
            print(f"  {key}: {value}")
        warning = expiry_warning(cert_meta, args.warn_days)
        if warning:
            print(f"  WARNING: {warning}")
        print("----")

    is_mtls = eku_inspect(metadata)
    print(f"mTLS candidate: {is_mtls}")


def cmd_csr(args):
    with open(args.cert, "rb") as f:
        data = f.read()
    password = args.password
    detected_type = cert_format(data, args.cert, password)
    if detected_type is None:
        print("error: unable to detect certificate format")
        sys.exit(1)

    csr_pem, key_pem = csr_generate(data, detected_type, password)

    # Default output filenames based on the input cert name
    cert_base = args.cert.rsplit(".", 1)[0]
    csr_path = args.output or f"{cert_base}.csr"
    key_path = args.key_output or f"{cert_base}-key.pem"

    with open(csr_path, "wb") as f:
        f.write(csr_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)

    print(f"CSR written to: {csr_path}")
    print(f"Private key written to: {key_path}")

# cmd_search is a simple filter that loads the YAML config and prints assets that match the provided filters.
# This is useful for quickly finding assets in a large inventory without needing to use `kubectl` or query the cluster directly.
def cmd_search(args):
    cfg = load_config(args.config)
    clusters = cfg["clusters"]
    assets = cfg["assets"]
    cluster_names = [c["name"] for c in clusters]
    for i, asset in enumerate(assets):
        asset_id = asset.get("id", f"asset[{i}]") if isinstance(asset, dict) else f"asset[{i}]"
        try:
            validate_config(asset, cluster_names)
        except ValueError as ve:
            raise ValueError(f"{asset_id}: {ve}")
    
    if args.namespace:
        assets = [a for a in assets if a["namespace"] == args.namespace]
    if args.cluster:
        assets = [a for a in assets if a.get("cluster") == args.cluster]
    if args.secret:
        assets = [a for a in assets if a.get("keystore", {}).get("secret", {}).get("name") == args.secret or a.get("truststore", {}).get("secret", {}).get("name") == args.secret]
    if args.cn:
        assets = [a for a in assets if args.cn in a["cn"]]
    
    print(f"Found {len(assets)} matching assets:")
    print("----")

    for asset in assets:
        print(f"  {asset['id']}  |  {asset.get('cluster', 'N/A')}  |  {asset['namespace']}  |  {asset['cn']}  |  {asset['certType']}")
        print("----")
    




# non_negative_int is an argparse type: rejects negative values for day thresholds.
def non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer value: '{value}'")
    if number < 0:
        raise argparse.ArgumentTypeError(f"must be zero or positive, got {number}")
    return number


def build_parser() -> argparse.ArgumentParser:
    # Main parser — this is the root command: `python main.py`
    parser = argparse.ArgumentParser(description="cert-asset-validator")

    # Subparsers let us define subcommands (like `validate` and `analyse`).
    # dest="command" means args.command will hold whichever subcommand the user picked,
    # or None if they didn't pick one (in which case we show help).
    subparsers = parser.add_subparsers(dest="command")

    # `python main.py validate <config>` — takes one positional argument (the YAML path)
    validate_parser = subparsers.add_parser("validate", help="Validate YAML asset definitions")
    validate_parser.add_argument("config", metavar="CONFIGFILE", help="Path to YAML config file")
    validate_parser.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Enable verbose output (show INFO-level log messages)")

    # `python main.py analyse <cert> [--password] [--warn-days]` — takes the cert path as positional,
    # an optional --password flag for PKCS12/JKS files that need one, and the expiry warning threshold
    analyse_parser = subparsers.add_parser("analyse", help="Analyse a certificate file")
    analyse_parser.add_argument("cert", metavar="FILE", help="Path to certificate file")
    analyse_parser.add_argument("--password", help="Password for PKCS12/JKS keystores")
    analyse_parser.add_argument(
        "--warn-days", type=non_negative_int, default=30, metavar="DAYS",
        help="Warn when a certificate expires within DAYS days (default: 30)",
    )
    analyse_parser.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Enable verbose output (show INFO-level log messages)")


    # `python main.py csr <cert> [--password] [--output] [--key-output]`
    # Generates a CSR from an existing certificate, reusing its subject, SANs, and extensions
    csr_parser = subparsers.add_parser("csr", help="Generate a CSR from an existing certificate")
    csr_parser.add_argument("cert", metavar="FILE", help="Path to certificate file")
    csr_parser.add_argument("--password", help="Password for PKCS12/JKS keystores")
    csr_parser.add_argument("--output", help="Output path for the CSR file (default: <cert>.csr)")
    csr_parser.add_argument("--key-output", help="Output path for the private key (default: <cert>-key.pem)")
    csr_parser.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Enable verbose output (show INFO-level log messages)")

    # `python main.py search <config> [--namespace] [--cluster] [--secret] [--cn]`
    # Filters assets from the YAML inventory by namespace, cluster, secret name, or CN.
    # Multiple filters can be combined (AND logic). Prints matching assets.
    search_parser = subparsers.add_parser("search", help="Search the YAML asset inventory by namespace, cluster, secret, or CN")
    search_parser.add_argument("config", metavar="CONFIGFILE", help="Path to YAML config file")
    search_parser.add_argument("--namespace", help="Filter assets by namespace")
    search_parser.add_argument("--cluster", help="Filter assets by cluster name")
    search_parser.add_argument("--secret", help="Filter assets by secret name")
    search_parser.add_argument("--cn", help="Filter assets by Common Name (substring match)")
    search_parser.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Enable verbose output (show INFO-level log messages)")

    # Global flag (applies to all subcommands): -v / --verbose
    # The subcommand copies of -v use default=argparse.SUPPRESS: otherwise their default
    # (False) would overwrite a -v given before the subcommand (`main.py -v analyse ...`).
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output (show INFO-level log messages)",
    )
    return parser


COMMANDS = {
    "validate": cmd_validate,
    "analyse": cmd_analyse,
    "csr": cmd_csr,
    "search": cmd_search,
}


# main is the CLI entry point. argv defaults to sys.argv[1:]; tests pass it explicitly.
def main(argv: list[str] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.INFO if args.verbose else logging.WARNING,
    )

    if args.command is None:
        parser.print_help()
        return

    # Top-level error handling: catch ValueErrors raised by subcommands and
    # print a clean one-line message instead of a full Python traceback.
    # sys.exit(1) signals failure to the shell (useful in scripts/pipelines).
    try:
        COMMANDS[args.command](args)
    except (ValueError, OSError) as e:
        print(f"error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

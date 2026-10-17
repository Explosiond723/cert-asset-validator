"""Cross-reference map of the certificates behind an inventory (`main.py map`).

Built from the results of live.inspect_asset (the certificates actually stored in the
Secrets), it answers three questions:
  - certificates: where does the same certificate live, and does the same name exist as
    different certificates (a renewal applied in one place but not in another)?
  - CAs: which CAs are present, which certificates did each sign, who trusts them?
  - assets: is each keystore chain complete, does its truststore trust its own CA, which
    trusted CAs sign nothing in the inventory?
"""
from cert_analysis import expiry_warning

LEAF, CHAIN, TRUSTED = "leaf", "chain", "trusted"


def _location(result: dict, asset: dict, role: str) -> dict:
    store = result[role]
    return {"asset": asset["id"], "cluster": asset.get("cluster"), "namespace": asset["namespace"],
            "secret": store["secret"], "key": store["key"], "role": role}


def _where(loc: dict) -> str:
    parts = [p for p in (loc["cluster"], loc["namespace"]) if p]
    return " / ".join(parts + [f"{loc['secret']} ({loc['key']})"])


def _short(fingerprint: str) -> str:
    return fingerprint[:16]


# _ca_key identifies a CA: its Subject Key Identifier when present, else its subject DN.
def _ca_key(meta: dict) -> str:
    return f"ski:{meta['subject_key_id']}" if meta.get("subject_key_id") else f"dn:{meta['subject']}"


# _issuer_key is the _ca_key a certificate's issuer must have: the Authority Key Identifier
# when present (exact even across a CA renewal that keeps the same DN), else the issuer DN.
def _issuer_key(meta: dict) -> str:
    return f"ski:{meta['authority_key_id']}" if meta.get("authority_key_id") else f"dn:{meta['issuer']}"


def _self_signed(meta: dict) -> bool:
    if meta.get("authority_key_id") and meta.get("subject_key_id"):
        return meta["authority_key_id"] == meta["subject_key_id"]
    return meta["subject"] == meta["issuer"]


# build_map turns inspection results into the three views. `pairs` is a list of
# (asset dict, inspect_asset result). Assets whose inspection failed are kept in the
# assets view with their errors and contribute nothing else.
def build_map(pairs: list[tuple[dict, dict]], warn_days: int) -> dict:
    certs = {}  # fingerprint -> {"meta", "positions": set, "locations": [...]}

    def add(meta, position, loc):
        entry = certs.setdefault(meta["fingerprint_sha256"], {"meta": meta, "positions": set(), "locations": []})
        entry["positions"].add(position)
        entry["locations"].append(dict(loc, position=position))

    leaves = {}  # asset id -> leaf meta
    for asset, result in pairs:
        ks = result.get("keystore")
        if ks:
            loc = _location(result, asset, "keystore")
            leaf = result.get("leaf")
            for meta in ks["certs"]:
                trusted = meta.get("entry_type") == "TrustedCertEntry"
                is_leaf = leaf is not None and meta is leaf
                add(meta, LEAF if is_leaf else (TRUSTED if trusted else CHAIN), loc)
            if leaf is not None:
                leaves[asset["id"]] = leaf
        ts = result.get("truststore")
        if ts:
            loc = _location(result, asset, "truststore")
            for meta in ts["certs"]:
                add(meta, TRUSTED, loc)

    # --- CAs: every CA certificate seen anywhere, keyed so that issuers can be matched
    cas = {}
    for fp, entry in certs.items():
        meta = entry["meta"]
        # a CA by Basic Constraints, or a self-signed cert that is not an asset's own
        # certificate (old roots without the extension). A self-signed server certificate and
        # a leaf pinned in a truststore are not CAs.
        if meta.get("is_ca") or (_self_signed(meta) and LEAF not in entry["positions"]):
            ca = cas.setdefault(_ca_key(meta), {"meta": meta, "fingerprints": set(), "signs": [],
                                                "trusted_by": set(), "in_chain_of": set()})
            ca["fingerprints"].add(fp)
            for loc in entry["locations"]:
                if loc["position"] == TRUSTED:
                    ca["trusted_by"].add(loc["asset"])
                elif loc["position"] == CHAIN:
                    ca["in_chain_of"].add(loc["asset"])

    missing_issuers = {}  # issuer key -> {"issuer": DN, "signs": [asset ids]}
    for asset_id, leaf in leaves.items():
        if _self_signed(leaf):
            continue
        key = _issuer_key(leaf)
        if key not in cas and key.startswith("ski:"):
            # CA without SKI in the inventory: fall back to its DN
            key = f"dn:{leaf['issuer']}" if f"dn:{leaf['issuer']}" in cas else key
        if key in cas:
            cas[key]["signs"].append(asset_id)
        else:
            missing_issuers.setdefault(leaf["issuer"], []).append(asset_id)

    # --- certificates view: the identity certs (leaves), with the other places they live
    by_cn = {}
    for fp, entry in certs.items():
        if LEAF in entry["positions"] and entry["meta"].get("common_name"):
            by_cn.setdefault(entry["meta"]["common_name"].lower(), set()).add(fp)

    cert_rows = []
    for fp, entry in certs.items():
        if LEAF not in entry["positions"]:
            continue
        meta = entry["meta"]
        versions = by_cn.get((meta.get("common_name") or "").lower(), {fp})
        cert_rows.append({
            "fingerprint": fp, "subject": meta["subject"], "common_name": meta.get("common_name"),
            "issuer": meta["issuer"], "serial_number": meta["serial_number"],
            "not_valid_after": meta["not_valid_after"], "expiry": meta["expiry"],
            "days_remaining": meta["days_remaining"], "san": meta.get("san", []),
            "warning": expiry_warning(meta, warn_days),
            "locations": entry["locations"],
            "assets": sorted({loc["asset"] for loc in entry["locations"]}),
            "other_versions": sorted(versions - {fp}),
        })
    cert_rows.sort(key=lambda r: ((r["common_name"] or "").lower(), r["not_valid_after"]))

    ca_rows = []
    for key, ca in cas.items():
        meta = ca["meta"]
        ca_rows.append({
            "subject": meta["subject"], "fingerprint": meta["fingerprint_sha256"],
            "subject_key_id": meta.get("subject_key_id"), "not_valid_after": meta["not_valid_after"],
            "expiry": meta["expiry"], "warning": expiry_warning(meta, warn_days),
            "signs": sorted(set(ca["signs"])), "trusted_by": sorted(ca["trusted_by"]),
            "in_chain_of": sorted(ca["in_chain_of"]), "found_in_inventory": True,
        })
    for issuer, signs in missing_issuers.items():
        ca_rows.append({
            "subject": issuer, "fingerprint": None, "subject_key_id": None, "not_valid_after": None,
            "expiry": None, "warning": None, "signs": sorted(set(signs)), "trusted_by": [],
            "in_chain_of": [], "found_in_inventory": False,
        })
    ca_rows.sort(key=lambda r: (not r["found_in_inventory"], r["subject"]))
    # Same DN, different key: usually a CA renewal (rollover). Certificates are linked to the
    # right one by key identifier, but people reading the report need to tell them apart.
    dn_count = {}
    for row in ca_rows:
        if row["found_in_inventory"]:
            dn_count[row["subject"]] = dn_count.get(row["subject"], 0) + 1
    for row in ca_rows:
        row["same_name_as_other_ca"] = dn_count.get(row["subject"], 0) > 1

    # --- assets view: chain and trust relationships per asset
    asset_rows = []
    for asset, result in pairs:
        leaf = result.get("leaf")
        row = {"id": asset["id"], "cluster": asset.get("cluster"), "namespace": asset["namespace"],
               "leaf": leaf["subject"] if leaf else None, "issuer": leaf["issuer"] if leaf else None,
               "issuer_in_inventory": None, "chain_complete": None, "truststore_trusts_own_ca": None,
               "unused_trusted_cas": [], "shared_with": [], "errors": list(result.get("errors", []))}
        if leaf:
            fp = leaf["fingerprint_sha256"]
            row["shared_with"] = sorted({loc["asset"] for loc in certs[fp]["locations"]
                                         if loc["position"] == LEAF} - {asset["id"]})
            if _self_signed(leaf):
                row["issuer_in_inventory"] = "self-signed"
                row["chain_complete"] = True
            else:
                issuer_ca = _find_ca(cas, leaf)
                row["issuer_in_inventory"] = "yes" if issuer_ca else "no"
                chain = result["keystore"]["certs"]
                row["chain_complete"] = bool(issuer_ca) and any(
                    m["fingerprint_sha256"] in issuer_ca["fingerprints"] for m in chain if m is not leaf)
            ts = result.get("truststore")
            if ts:
                trusted_keys = {_ca_key(m) for m in ts["certs"]}
                issuer_ca = _find_ca(cas, leaf)
                row["truststore_trusts_own_ca"] = (
                    "yes" if issuer_ca and _ca_key(issuer_ca["meta"]) in trusted_keys else "no")
                row["unused_trusted_cas"] = sorted(
                    m["subject"] for m in ts["certs"]
                    if not cas.get(_ca_key(m), {}).get("signs"))
        asset_rows.append(row)

    return {"certificates": cert_rows, "cas": ca_rows, "assets": asset_rows}


def _find_ca(cas: dict, leaf: dict):
    key = _issuer_key(leaf)
    if key in cas:
        return cas[key]
    return cas.get(f"dn:{leaf['issuer']}")


def _join(values) -> str:
    return ", ".join(values) if values else "-"


# print_map renders the default human-readable report for the selected views.
def print_map(report: dict, views: list[str]) -> None:
    if "certificates" in views:
        print("== Certificates ==")
        for row in report["certificates"]:
            print(f"Certificate: {row['subject']}")
            print(f"  fingerprint: {_short(row['fingerprint'])}...  serial: {row['serial_number']}")
            print(f"  issuer: {row['issuer']}")
            print(f"  expiry: {row['expiry']} ({row['not_valid_after']})")
            if row["san"]:
                print(f"  san: {', '.join(row['san'])}")
            print(f"  found in {len(row['locations'])} place(s):")
            for loc in row["locations"]:
                print(f"    - {_where(loc)}  [asset {loc['asset']}, {loc['role']}]")
            if row["warning"]:
                print(f"  WARNING: {row['warning']}")
            if row["other_versions"]:
                others = ", ".join(_short(f) for f in row["other_versions"])
                print(f"  WARNING: same name, different certificate(s) elsewhere: {others}")
            print("----")
    if "cas" in views:
        print("== CAs ==")
        for row in report["cas"]:
            if row["found_in_inventory"]:
                print(f"CA: {row['subject']}")
                key_id = f"  key id: {row['subject_key_id'][:16]}..." if row["subject_key_id"] else ""
                print(f"  fingerprint: {_short(row['fingerprint'])}...{key_id}  expiry: {row['expiry']}")
                if row["same_name_as_other_ca"]:
                    print("  NOTE: another CA has the same name with a different key (renewed CA?)")
            else:
                print(f"CA (not in the inventory): {row['subject']}")
            print(f"  signs: {_join(row['signs'])}")
            print(f"  trusted by: {_join(row['trusted_by'])}")
            if row["in_chain_of"]:
                print(f"  in the chain of: {_join(row['in_chain_of'])}")
            if row["warning"]:
                print(f"  WARNING: {row['warning']}")
            print("----")
    if "assets" in views:
        print("== Assets ==")
        for row in report["assets"]:
            print(f"Asset: {row['id']}")
            if row["errors"]:
                for error in row["errors"]:
                    print(f"  ERROR: {error}")
                print("----")
                continue
            if row["leaf"]:
                print(f"  leaf: {row['leaf']}")
                print(f"  issuer: {row['issuer']} (in inventory: {row['issuer_in_inventory']})")
                print(f"  chain complete: {'yes' if row['chain_complete'] else 'no'}")
            if row["truststore_trusts_own_ca"] is not None:
                print(f"  truststore trusts its own CA: {row['truststore_trusts_own_ca']}")
            if row["unused_trusted_cas"]:
                print(f"  trusted CAs signing nothing in the inventory: {_join(row['unused_trusted_cas'])}")
            if row["shared_with"]:
                print(f"  same certificate also used by: {_join(row['shared_with'])}")
            print("----")


# table_rows flattens one view for --format table/csv: (rows, columns).
def table_rows(report: dict, view: str) -> tuple[list[dict], list[str]]:
    if view == "certificates":
        rows = [dict(r, locations=[_where(loc) for loc in r["locations"]], places=len(r["locations"]),
                     other_versions=[_short(f) for f in r["other_versions"]])
                for r in report["certificates"]]
        cols = ["common_name", "fingerprint", "not_valid_after", "days_remaining", "places", "assets",
                "locations", "other_versions", "issuer", "san", "warning"]
        return rows, cols
    if view == "cas":
        cols = ["subject", "found_in_inventory", "not_valid_after", "expiry", "signs", "trusted_by",
                "in_chain_of", "same_name_as_other_ca", "subject_key_id", "fingerprint", "warning"]
        return report["cas"], cols
    cols = ["id", "cluster", "namespace", "leaf", "issuer", "issuer_in_inventory", "chain_complete",
            "truststore_trusts_own_ca", "unused_trusted_cas", "shared_with", "errors"]
    return report["assets"], cols

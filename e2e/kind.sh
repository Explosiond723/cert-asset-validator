#!/usr/bin/env bash
# End-to-end test of `--live` against a local kind cluster.
#
#   e2e/kind.sh up     create the cluster, Secrets, RBAC and e2e/out/inventory.yaml
#   e2e/kind.sh run    run the scenarios, print EXPECTED vs actual, save e2e/out/run.log
#   e2e/kind.sh down   delete the cluster and e2e/out/
#
# Requirements: docker (or podman), kind, kubectl, python3 with `pip install -r requirements.txt`.
# Everything uses its own kubeconfig (e2e/out/kubeconfig): ~/.kube/config is never touched.
set -euo pipefail

CLUSTER_NAME="cert-validator-e2e"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/e2e/out"
KCFG="$OUT/kubeconfig"
ADMIN_CTX="kind-$CLUSTER_NAME"
LIMITED_CTX="$CLUSTER_NAME-limited"
PY="${PYTHON:-python3}"

kc() { kubectl --kubeconfig "$KCFG" --context "$ADMIN_CTX" "$@"; }

require() {
    local missing=0
    for bin in kind kubectl "$PY"; do
        command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; missing=1; }
    done
    "$PY" -c "import cryptography, yaml, kubernetes, jks" 2>/dev/null \
        || { echo "missing Python deps: pip install -r $REPO_ROOT/requirements.txt" >&2; missing=1; }
    [ "$missing" -eq 0 ] || exit 1
}

up() {
    require
    mkdir -p "$OUT"
    if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
        kind create cluster --name "$CLUSTER_NAME" --kubeconfig "$KCFG" --wait 120s
    else
        kind get kubeconfig --name "$CLUSTER_NAME" > "$KCFG"
    fi

    "$PY" "$REPO_ROOT/e2e/make_fixtures.py" "$OUT/certs"
    local c="$OUT/certs"

    for ns in web-prod api-prod billing-prod portal-prod restricted cert-validator; do
        kc create namespace "$ns" --dry-run=client -o yaml | kc apply -f - >/dev/null
    done

    # apply = idempotent re-runs of `up`
    apply_secret() { kc create secret "$@" --dry-run=client -o yaml | kc apply -f - >/dev/null; }

    # web-prod: standard kubernetes.io/tls, plus an expired cert and a cert that does not match the inventory
    apply_secret tls web-tls -n web-prod --cert "$c/web.crt" --key "$c/web.key"
    apply_secret generic old-tls -n web-prod --from-file=tls.crt="$c/legacy.crt"
    apply_secret generic mismatch-tls -n web-prod --from-file=tls.crt="$c/mismatch.crt"

    # api-prod: JKS keystore + truststore; keystore password in a separate Secret,
    # written with a trailing newline like `echo changeit | ...` would do
    printf 'changeit\n' > "$c/keystore-password"
    printf 'trustpass' > "$c/truststore-password"
    apply_secret generic api-tls -n api-prod \
        --from-file=keystore.jks="$c/api-keystore.jks" \
        --from-file=truststore.jks="$c/api-truststore.jks" \
        --from-file=truststorePassword="$c/truststore-password"
    apply_secret generic api-pass -n api-prod --from-file=keystorePassword="$c/keystore-password"

    # billing-prod: PKCS12 expiring in 10 days
    printf 'p12pass' > "$c/p12-password"
    apply_secret generic billing-tls -n billing-prod --from-file=keystore.p12="$c/billing.p12"
    apply_secret generic billing-tls-pass -n billing-prod --from-file=keystorePassword="$c/p12-password"

    # portal-prod: the layout of the renewal guide (infrastructure-guides, TLS/mTLS renewal on
    # OpenShift): generic Secret with tls.crt + tls.key + cacerts.pem, and the <secret>-bck copy
    # taken before the renewal, still holding the previous certificate
    cp "$c/ca.pem" "$c/cacerts.pem"
    apply_secret generic portal-tls -n portal-prod \
        --from-file=tls.crt="$c/portal.crt" --from-file=tls.key="$c/portal.key" --from-file=cacerts.pem="$c/cacerts.pem"
    apply_secret generic portal-tls-bck -n portal-prod \
        --from-file=tls.crt="$c/portal-old.crt" --from-file=tls.key="$c/portal-old.key" \
        --from-file=cacerts.pem="$c/cacerts.pem"

    # a workload using portal-tls, for `rotate --restart` (0 replicas: nothing to pull or run)
    kc apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: portal, namespace: portal-prod}
spec:
  replicas: 0
  selector: {matchLabels: {app: portal}}
  template:
    metadata: {labels: {app: portal}}
    spec:
      containers: [{name: portal, image: registry.k8s.io/pause:3.9,
                    volumeMounts: [{name: tls, mountPath: /tls}]}]
      volumes: [{name: tls, secret: {secretName: portal-tls}}]
EOF

    # restricted: readable by the admin context only
    apply_secret tls restricted-tls -n restricted --cert "$c/web.crt" --key "$c/web.key"

    # Limited identity: ServiceAccount allowed to `get`/`list` secrets in web-prod only
    kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: cert-reader, namespace: cert-validator}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: cert-reader, namespace: web-prod}
rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: cert-reader, namespace: web-prod}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: cert-reader}
subjects: [{kind: ServiceAccount, name: cert-reader, namespace: cert-validator}]
EOF
    local token
    token="$(kc create token cert-reader -n cert-validator --duration=24h)"
    kubectl --kubeconfig "$KCFG" config set-credentials cert-reader --token="$token" >/dev/null
    kubectl --kubeconfig "$KCFG" config set-context "$LIMITED_CTX" \
        --cluster "$ADMIN_CTX" --user cert-reader >/dev/null

    cat > "$OUT/inventory.yaml" <<EOF
# Generated by e2e/kind.sh up. Expected result per asset is in the comment.
clusters:
  - name: kind-admin
    context: $ADMIN_CTX
  - name: kind-limited
    context: $LIMITED_CTX
  - name: ghost
    context: context-that-does-not-exist

assets:
  - id: web                 # OK (kubernetes.io/tls, PEM chain, EC key)
    cluster: kind-admin
    namespace: web-prod
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: web-tls, key: tls.crt}}

  - id: api                 # OK (JKS + truststore, password with trailing newline, mtls)
    cluster: kind-admin
    namespace: api-prod
    cn: api.example.com
    certType: keystore
    mtls: true
    keystore:
      secret: {name: api-tls, key: keystore.jks}
      passwordRef: {name: api-pass, key: keystorePassword}
    truststore:
      secret: {name: api-tls, key: truststore.jks}
      passwordRef: {name: api-tls, key: truststorePassword}

  - id: billing             # WARNING: expires in 10 days
    cluster: kind-admin
    namespace: billing-prod
    cn: billing.internal.example.com
    certType: pkcs12
    keystore:
      secret: {name: billing-tls, key: keystore.p12}
      passwordRef: {name: billing-tls-pass, key: keystorePassword}

  - id: legacy              # WARNING: expired 5 days ago
    cluster: kind-admin
    namespace: web-prod
    cn: old.example.com
    certType: pem
    keystore: {secret: {name: old-tls, key: tls.crt}}

  - id: mismatch            # WARNING x2: certType der vs PEM, cn vs real CN
    cluster: kind-admin
    namespace: web-prod
    cn: www2.example.com
    certType: der
    keystore: {secret: {name: mismatch-tls, key: tls.crt}}

  - id: portal              # OK (leaf + chain in cacerts.pem, verified by signature; key in tls.key)
    cluster: kind-admin
    namespace: portal-prod
    cn: portal.example.com
    certType: pem
    mtls: true
    keystore: {secret: {name: portal-tls, key: tls.crt}}
    chain: {secret: {name: portal-tls, key: cacerts.pem}}

  - id: portal-bck          # OK (backup copy, previous certificate)
    cluster: kind-admin
    namespace: portal-prod
    cn: portal.example.com
    certType: pem
    keystore: {secret: {name: portal-tls-bck, key: tls.crt}}
    chain: {secret: {name: portal-tls-bck, key: cacerts.pem}}

  - id: missing             # ERROR: Secret not found
    cluster: kind-admin
    namespace: web-prod
    cn: missing.example.com
    certType: pem
    keystore: {secret: {name: does-not-exist, key: tls.crt}}

  - id: web-limited         # OK through the limited ServiceAccount
    cluster: kind-limited
    namespace: web-prod
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: web-tls, key: tls.crt}}

  - id: restricted          # ERROR: permission denied (RBAC)
    cluster: kind-limited
    namespace: restricted
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: restricted-tls, key: tls.crt}}

  - id: ghost               # ERROR: kubeconfig context does not exist
    cluster: ghost
    namespace: web-prod
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: web-tls, key: tls.crt}}
EOF

    # the portal asset alone, to check it after `rotate` with a clean exit code
    cat > "$OUT/portal-only.yaml" <<EOF
clusters:
  - name: kind-admin
    context: $ADMIN_CTX
assets:
  - id: portal
    cluster: kind-admin
    namespace: portal-prod
    cn: portal.example.com
    certType: pem
    keystore: {secret: {name: portal-tls, key: tls.crt}}
    chain: {secret: {name: portal-tls, key: cacerts.pem}}
EOF

    echo
    echo "Ready. Inventory: $OUT/inventory.yaml"
    echo "Next: e2e/kind.sh run"
}

# scenario EXPECTED_RC "description" cmd...: runs one command, prints its output and checks it.
# An exit code alone is not enough: a crash also exits 1, so a scenario that expects a
# failure would pass on a traceback. Before calling scenario, `expect` lists strings that
# must appear in the output and `reject` strings that must not; both are reset after each
# scenario. A Python traceback always fails the scenario.
PASS=0
FAIL=0
EXPECT=()
REJECT=()
expect() { EXPECT=("$@"); }
reject() { REJECT=("$@"); }

scenario() {
    local expected_rc="$1" description="$2"
    shift 2
    echo
    echo "=================================================================="
    echo "SCENARIO: $description"
    echo "COMMAND:  $*"
    echo "EXPECTED: exit $expected_rc"
    local text
    for text in ${EXPECT[@]+"${EXPECT[@]}"}; do echo "          + output contains: $text"; done
    for text in ${REJECT[@]+"${REJECT[@]}"}; do echo "          - output lacks:    $text"; done
    echo "------------------------------------------------------------------"

    local output rc
    output="$(mktemp)"
    set +e
    (cd "$OUT" && "$@") 2>&1 | tee "$output"
    rc=${PIPESTATUS[0]}
    set -e

    local problems=()
    [ "$rc" -eq "$expected_rc" ] || problems+=("exit $rc, wanted $expected_rc")
    if grep -q "Traceback (most recent call last)" "$output"; then
        problems+=("Python traceback in the output")
    fi
    for text in ${EXPECT[@]+"${EXPECT[@]}"}; do
        grep -qF -- "$text" "$output" || problems+=("missing from output: $text")
    done
    for text in ${REJECT[@]+"${REJECT[@]}"}; do
        if grep -qF -- "$text" "$output"; then problems+=("unexpected in output: $text"); fi
    done
    rm -f "$output"
    EXPECT=()
    REJECT=()

    if [ "${#problems[@]}" -eq 0 ]; then
        echo "RESULT:   exit $rc  [OK]"
        PASS=$((PASS + 1))
    else
        echo "RESULT:   exit $rc  [UNEXPECTED]"
        for text in "${problems[@]}"; do echo "          * $text"; done
        FAIL=$((FAIL + 1))
    fi
}

# Small Python checks used by `run` to look inside the produced files.
CSR_SUMMARY='
import sys
from cryptography import x509
for path in sys.argv[1:]:
    csr = x509.load_pem_x509_csr(open(path, "rb").read())
    cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    print(path + ": CN=" + cn + " SAN=" + ",".join(sans.get_values_for_type(x509.DNSName)))
'
INVENTORY_REFS='
import sys, yaml
for asset in yaml.safe_load(open(sys.argv[1]))["assets"]:
    for role in ("keystore", "truststore"):
        ref = (asset.get(role) or {}).get("passwordRef")
        if ref:
            print(asset["id"] + " " + role + " -> " + ref["name"] + "/" + ref["key"])
    if "chain" in asset:
        print(asset["id"] + " chain -> " + asset["chain"]["secret"]["name"] + "/" + asset["chain"]["secret"]["key"])
    for key, text in (asset.get("notes") or {}).items():
        if key in ("private_key", "backup"):
            print(asset["id"] + " " + key + ": " + text)
'

run() {
    require
    [ -f "$OUT/inventory.yaml" ] || { echo "run 'e2e/kind.sh up' first" >&2; exit 1; }
    local main=("$PY" "$REPO_ROOT/main.py")
    local inv="$OUT/inventory.yaml"
    local live=(--live --kubeconfig "$KCFG")

    {
        echo "cert-asset-validator e2e run - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "git: $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo n/a)"
        echo "kind: $(kind version 2>/dev/null)  kubectl: $(kubectl version --client 2>/dev/null | head -1)"

        expect "keystore: web-tls/tls.crt  [PEM, 2 cert(s)]" \
            "keystore: api-tls/keystore.jks  [JKS, 2 cert(s)]" \
            "truststore: api-tls/truststore.jks  [JKS, 1 cert(s)]" \
            "keystore: billing-tls/keystore.p12  [PKCS12, 2 cert(s)]" \
            "CN=billing.internal.example.com: certificate expires in" \
            "CN=old.example.com: certificate expired" \
            "certType 'der' declared, but the Secret contains PEM" \
            "YAML cn 'www2.example.com' does not match the certificate" \
            "ERROR: keystore: Secret 'web-prod/does-not-exist' not found" \
            "ERROR: keystore: permission denied reading Secret 'restricted/restricted-tls'" \
            "ERROR: failed to load context 'context-that-does-not-exist'" \
            "Live: web-limited  (context: $LIMITED_CTX)" \
            "chain: portal-tls/cacerts.pem  [PEM, 1 cert(s)]" "private key: in Secret key 'tls.key'" \
            "private key: in the keystore" "chain verified: yes" \
            "mtls: true but no truststore is defined"
        reject "wrong password" "not valid UTF-8" "unable to detect certificate format" "chain verified: no" \
            "not signed by any CA" "but no private key"
        scenario 1 "validate --live: 5 OK, 4 warnings, 3 errors (see inventory comments)" \
            "${main[@]}" validate "$inv" "${live[@]}"
        expect "LIVE_SUBJECT" "keystore: Secret 'web-prod/does-not-exist' not found" "expires in"
        scenario 1 "validate --live as table" \
            "${main[@]}" validate "$inv" "${live[@]}" --format table
        expect "id,cluster,namespace,cn,certType,live_subject" \
            "api,kind-admin,api-prod,api.example.com,keystore" "DNS:api.example.com"
        scenario 0 "search --live, real SAN match, admin cluster only, csv" \
            "${main[@]}" search "$inv" "${live[@]}" --cluster kind-admin --namespace api-prod --cn "DNS:api" --format csv
        expect "Found 1 matching assets" "certificate expires in" "(threshold: 30 days)"
        reject "error:"
        scenario 0 "search --live billing: warning only, exit 0 without --fail-on-expiry" \
            "${main[@]}" search "$inv" "${live[@]}" --namespace billing-prod
        expect "error: 1 asset(s) with certificates expired, not yet valid, or expiring within 30 days"
        scenario 1 "search --live billing --fail-on-expiry (10 days < 30)" \
            "${main[@]}" search "$inv" "${live[@]}" --namespace billing-prod --fail-on-expiry
        expect "Found 1 matching assets" "live: O=cert-asset-validator e2e,CN=billing.internal.example.com"
        reject "WARNING" "error:"
        scenario 0 "search --live billing --fail-on-expiry --warn-days 5" \
            "${main[@]}" search "$inv" "${live[@]}" --namespace billing-prod --fail-on-expiry --warn-days 5
        expect "Found 1 matching assets" "live: O=cert-asset-validator e2e,CN=www.example.com"
        reject "permission denied"
        scenario 0 "search --live with --context override (every asset via the admin context)" \
            "${main[@]}" search "$inv" "${live[@]}" --context "$ADMIN_CTX" --namespace restricted
        expect "CSR written to: api.csr" "Private key written to: api-key.pem"
        scenario 0 "csr --live from JKS (password from Secret), new CN and extra SAN" \
            "${main[@]}" csr "$inv" --id api "${live[@]}" --cn api-v2.example.com --add-san DNS:api.example.com
        expect "CSR written to: web.csr" "existing key reused, no new key written"
        scenario 0 "csr --live from kubernetes.io/tls, reusing tls.key" \
            "${main[@]}" csr "$inv" --id web "${live[@]}" --reuse-key
        expect "CSR written to: billing.csr" "existing key reused, no new key written"
        scenario 0 "csr --live from PKCS12, reusing the key inside the keystore" \
            "${main[@]}" csr "$inv" --id billing "${live[@]}" --reuse-key
        # the CSRs must carry what was asked: new CN + SANs for api, the same subject for web
        expect "api.csr: CN=api-v2.example.com SAN=api-v2.example.com,api.example.com" \
            "web.csr: CN=www.example.com SAN=www.example.com" \
            "billing.csr: CN=billing.internal.example.com SAN=billing.internal.example.com"
        scenario 0 "CSR contents: subject and SANs" "$PY" -c "$CSR_SUMMARY" api.csr web.csr billing.csr
        expect "error: restricted: permission denied reading Secret 'restricted/restricted-tls'"
        scenario 1 "csr --live on an asset the limited identity cannot read" \
            "${main[@]}" csr "$inv" --id restricted "${live[@]}"
        expect "discovered 6 asset(s) in 4 namespace(s)" \
            "1 backup Secret(s) left out (portal-tls-bck; see --include-backups)"
        reject "TODO values"
        scenario 0 "discover: scan the test namespaces and write an inventory (backup left out)" \
            "${main[@]}" discover -n web-prod -n api-prod -n billing-prod -n portal-prod \
            --kubeconfig "$KCFG" --context "$ADMIN_CTX" --cluster-name kind-admin --output discovered.yaml --force
        # the passwords must have been found in the right Secrets (and verified by discover)
        expect "api-tls keystore -> api-pass/keystorePassword" \
            "api-tls truststore -> api-tls/truststorePassword" \
            "billing-tls keystore -> billing-tls-pass/keystorePassword" \
            "portal-tls chain -> portal-tls/cacerts.pem" \
            "portal-tls private_key: in Secret key 'tls.key'" "web-tls private_key: in Secret key 'tls.key'" \
            "api-tls private_key: in the keystore" "old-tls private_key: not found next to the certificate"
        reject "TODO" "cacerts.pem-" "portal-tls-bck"
        scenario 0 "discovered inventory: passwordRefs, chain, private key" "$PY" -c "$INVENTORY_REFS" discovered.yaml
        expect "api-tls" "billing-tls" "web-tls" "portal-tls" "certificate expires in"
        reject "not found" "permission denied" "wrong password" "not signed by any CA"
        scenario 0 "validate --live on the discovered inventory (passwords found and verified, warnings only)" \
            "${main[@]}" validate "$OUT/discovered.yaml" "${live[@]}" --format table
        expect "no new assets, discovered.yaml unchanged, 6 already in the inventory"
        reject "not found in the cluster any more"
        scenario 0 "discover --update on the same namespaces: nothing new, file unchanged" \
            "${main[@]}" discover -n web-prod -n api-prod -n billing-prod -n portal-prod \
            --kubeconfig "$KCFG" --context "$ADMIN_CTX" --cluster-name kind-admin --update discovered.yaml
        expect "1 new asset(s) appended to discovered.yaml, 1 already in the inventory"
        scenario 0 "discover --update --include-backups: the -bck Secret is added, marked as backup" \
            "${main[@]}" discover -n portal-prod --include-backups \
            --kubeconfig "$KCFG" --context "$ADMIN_CTX" --cluster-name kind-admin --update discovered.yaml
        expect "portal-tls-bck backup: backup copy of Secret 'portal-tls'" "portal-tls-bck chain -> portal-tls-bck/cacerts.pem"
        scenario 0 "discovered inventory: backup note" "$PY" -c "$INVENTORY_REFS" discovered.yaml
        expect "warning: permission denied listing secrets in namespace 'api-prod'" \
            "discovered 3 asset(s) in 1 namespace(s), 1 namespace(s) skipped"
        scenario 1 "discover with the limited identity: web-prod readable, api-prod denied" \
            "${main[@]}" discover -n web-prod -n api-prod --kubeconfig "$KCFG" --context "$LIMITED_CTX"
        # map: the fixture certs have no key identifiers, so CA linkage uses the DN fallback
        expect "CA: O=cert-asset-validator e2e,CN=e2e Test CA" \
            "signs: api, billing, legacy, mismatch, portal, portal-bck, web, web-limited" \
            "trusted by: api"
        reject "CA (not in the inventory)"
        scenario 1 "map --view cas: one CA signs every leaf (errors from the 3 broken assets)" \
            "${main[@]}" map "$inv" --kubeconfig "$KCFG" --view cas
        # with the admin context everywhere, the www certificate is readable in 4 assets
        expect "Certificate: O=cert-asset-validator e2e,CN=www.example.com" "found in 4 place(s):" \
            "kind-limited / restricted / restricted-tls (tls.crt)  [asset restricted, keystore]"
        reject "same name, different certificate"
        scenario 0 "map --view certificates --cn www: same certificate in 4 places" \
            "${main[@]}" map "$inv" --kubeconfig "$KCFG" --context "$ADMIN_CTX" --view certificates --cn www
        expect "truststore trusts its own CA: yes" "chain complete: no" "chain complete: yes (from keystore)" \
            "same certificate also used by: ghost, restricted, web-limited" \
            "chain complete: yes (from Secret portal-tls (cacerts.pem))" "backup of: portal-tls" \
            "private key: in Secret key 'tls.key'" "private key: in the keystore"
        scenario 1 "map --view assets: chains, truststore, shared certificates" \
            "${main[@]}" map "$inv" --kubeconfig "$KCFG" --context "$ADMIN_CTX" --view assets
        # the old portal certificate lives only in the backup: not a renewal missing somewhere
        expect "found in 1 place(s):" "[asset portal-tls-bck, keystore, backup]" \
            "NOTE: found only in backups; current version(s):"
        reject "same name, different certificate"
        scenario 0 "map --view certificates --cn portal on the discovered inventory: backup recognised" \
            "${main[@]}" map "$OUT/discovered.yaml" --kubeconfig "$KCFG" --view certificates --cn portal
        # rotate: plan, write the manifests, run the generated script against the real API
        # server (this is a throw-away cluster), then check the result. Kept last: it changes
        # portal-tls for good.
        local stamp
        stamp="$(date -u +%Y%m%d)"
        expect "held by: portal" "tls.crt: replace (certificate, PEM)" "tls.key: replace (private key)" \
            "cacerts.pem: unchanged (its CA signed the new certificate)" \
            "backup: portal-tls-bck-$stamp (created before the change)" "restart: deployment/portal" \
            "Dry run: add -o DIR"
        reject "PRIVATE KEY" "ERROR"
        scenario 0 "rotate --id portal (dry run): -bck exists, so the backup gets a dated name; restart found" \
            "${main[@]}" rotate "$inv" -i portal --cert "$OUT/certs/portal-new.crt" -k "$OUT/certs/portal-new.key" -r \
            --kubeconfig "$KCFG"
        expect "Written to rotation:" "rotate.sh" "do not commit them"
        scenario 0 "rotate -o rotation: patch, backup manifest and rotate.sh written" \
            "${main[@]}" rotate "$inv" -i portal --cert "$OUT/certs/portal-new.crt" -k "$OUT/certs/portal-new.key" -r \
            --kubeconfig "$KCFG" -o rotation
        expect "portal-tls-bck-$stamp created" "secret/portal-tls patched" "deployment.apps/portal restarted"
        scenario 0 "rotate.sh against the cluster: backup, patch (resourceVersion checked), rollout restart" \
            bash rotation/rotate.sh
        expect "DNS:portal2.example.com" "chain verified: yes" "private key: in Secret key 'tls.key'"
        reject "ERROR" "not signed"
        scenario 0 "after rotate: portal serves the new certificate, chain and key still consistent" \
            "${main[@]}" validate "$OUT/portal-only.yaml" "${live[@]}"
        expect "kubectl.kubernetes.io/restartedAt"
        scenario 0 "after rotate: the Deployment was restarted" \
            kc get deployment portal -n portal-prod -o jsonpath='{.spec.template.metadata.annotations}'
        expect "already exists"
        reject "patched"
        scenario 1 "rotate.sh run twice: the backup already exists, so it stops before patching" \
            bash rotation/rotate.sh
        expect "already in place"
        scenario 1 "rotate again with the same certificate: refused" \
            "${main[@]}" rotate "$inv" -i portal --cert "$OUT/certs/portal-new.crt" --kubeconfig "$KCFG"
        expect "PrivateKeyEntry" "CN=api.example.com" "DNS:api.example.com"
        scenario 0 "analyse the generated CSR inputs: JKS keystore from disk" \
            "${main[@]}" analyse "$OUT/certs/api-keystore.jks" --password changeit --format table

        if command -v openssl >/dev/null; then
            for f in api.csr web.csr billing.csr; do
                echo
                echo "--- openssl req -in $f -noout -subject -verify"
                (cd "$OUT" && openssl req -in "$f" -noout -subject -verify 2>&1 || true)
                (cd "$OUT" && openssl req -in "$f" -noout -text 2>/dev/null | grep -A1 "Alternative Name" || true)
            done
        fi

        echo
        echo "=================================================================="
        echo "SUMMARY: $PASS scenario(s) as expected, $FAIL unexpected"
    } 2>&1 | tee "$OUT/run.log"
    echo
    echo "Log saved to $OUT/run.log"
    # The counters live in the piped subshell above, so the verdict is read back from
    # the log: exit 1 when any scenario did not behave as expected (needed for CI).
    grep -q "^SUMMARY: .*, 0 unexpected$" "$OUT/run.log"
}

down() {
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    rm -rf "$OUT"
    echo "cluster $CLUSTER_NAME and $OUT removed"
}

# Dispatch only when executed: sourcing the file (tests/test_e2e_harness.py) just
# defines the functions.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        up) up ;;
        run) run ;;
        down) down ;;
        *) echo "usage: $0 up|run|down" >&2; exit 2 ;;
    esac
fi

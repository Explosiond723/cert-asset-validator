from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.primitives.serialization import pkcs12
import jks

# cert_format takes raw cert bytes and identifies which type of TLS cert it is.
# Also verifies if path contains multiple certificates concatenated in a single file (certificate chain)
# Types of certificates:
#   - PEM
#   - PKCS12
#   - DER
#   - JKS
def cert_format(data: bytes, path: str = "", optional_password: str = None) -> str:
    if data is None or len(data) == 0:
        raise ValueError("ERROR: certificate file is empty")

    # Try PEM
    try:
        x509.load_pem_x509_certificate(data)
        print("Certificate format: PEM")
        return "PEM"
    except Exception:  # broad catch: we're probing format, not handling a known error
        pass

    # Try DER
    try:
        x509.load_der_x509_certificate(data)
        print("Certificate format: DER")
        return "DER"
    except Exception:
        pass

    # Try PKCS12
    # We attempt with an empty password first. If it succeeds, no password is needed.
    # If it raises ValueError, it could be password-protected PKCS12 or not PKCS12 at all.
    # Since PEM and DER were already tried above, a ValueError here on data starting with
    # ASN.1 SEQUENCE (0x30) most likely means password-protected PKCS12.
    try:
        _key, _cert, _ca_certs = pkcs12.load_key_and_certificates(data, b"")
        print("Certificate format: PKCS12 (password not required to extract metadata)")
        return "PKCS12"
    except ValueError:
        # PEM/DER already failed above. If the data starts with an ASN.1 SEQUENCE tag,
        # it's very likely a password-protected PKCS12 (DER certs would have matched earlier).
        if len(data) > 0 and data[0] == 0x30:
            print("Certificate format: PKCS12 (password required to extract metadata)")
            return "PKCS12"
    except Exception:
        pass

    # Try JKS — first check the extension, then try PKCS12 (some .jks files are PKCS12 underneath),
    # then fall back to the jks library.
    if path.endswith(".jks"):
        try:
            pkcs12.load_key_and_certificates(data, b"")
            print("Certificate format: JKS (PKCS12 underneath)")
            return "JKS"
        except Exception:
            # Now try to load it as a JKS with the 'jks' library.
            if optional_password is not None:
                try:
                    jks.KeyStore.loads(data, optional_password)
                    print("Certificate format: JKS")
                    return "JKS"
                except Exception:
                    pass

    return None


def _extract_cert_metadata(cert, alias: str = None) -> dict:
    """Extract common metadata from a cryptography x509.Certificate object."""
    metadata = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
    }
    if alias is not None:
        metadata["alias"] = alias

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        metadata["san"] = [str(san) for san in san_ext.value]
    except ExtensionNotFound:
        metadata["san"] = []

    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        metadata["eku"] = [str(eku) for eku in eku_ext.value]
    except ExtensionNotFound:
        metadata["eku"] = []

    return metadata


# cert_metadata_extract looks for common metadata (CN, SANs, Issuer, Validity Period, Serial Number).
# for PKCS12 and JKS you need a password to deserialize. The `cryptography` library's PKCS12 loader returns the key, the leaf cert, and any additional CA certs separately.
def cert_metadata_extract(data: bytes, cert_type: str, optional_password: str = None) -> dict | list[dict]:
    if cert_type in ("PEM", "DER"):
        if cert_type == "PEM":
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
        print("Certificate metadata extracted successfully")
        return _extract_cert_metadata(cert)

    if cert_type == "PKCS12":
        _key, cert, additional_certs = pkcs12.load_key_and_certificates(
            data, optional_password.encode() if optional_password is not None else None
        )
        if cert is None:
            raise ValueError("ERROR: Unable to extract metadata from PKCS12 certificate, check if the password is correct and if the file is a valid PKCS12 keystore")
        metadata_list = [_extract_cert_metadata(cert)]
        if additional_certs:
            for ca_cert in additional_certs:
                metadata_list.append(_extract_cert_metadata(ca_cert))
        print("Certificate metadata extracted successfully")
        return metadata_list

    if cert_type == "JKS":
        if optional_password is None:
            raise ValueError("ERROR: JKS keystores require a password")
        try:
            ks = jks.KeyStore.loads(data, optional_password)
            metadata_list = []
            for alias, entry in ks.entries.items():
                if isinstance(entry, jks.TrustedCertEntry):
                    # jks gives raw DER bytes, parse into a cryptography cert object
                    cert = x509.load_der_x509_certificate(entry.cert)
                    metadata_list.append(_extract_cert_metadata(cert, alias=alias))
            print("Certificate metadata extracted successfully")
            return metadata_list
        except Exception:
            raise ValueError("ERROR: Unable to extract metadata from JKS certificate, check if the password is correct and if the file is a valid JKS keystore")

    return None


# eku_inspect inspects the TLS Certificate Extended Key Usage extension for Server Authentication and Client Authentication. If both are present the cert will most likely be mTLS.
# Also verifies if the PrivateKey is present, if it's present this could also be mTLS (BEWARE! it's not definitive).
# The presence of a Truststore is another mTLS indicator. In a typical mTLS setup the truststore holds the CA certificates used to verify the **peer's** certificate. If `mtls: true` is set but no truststore is defined, that could be worth a warning too.
def eku_inspect(metadata: dict | list[dict]) -> bool:
    if metadata is None:
        return False
    if isinstance(metadata, dict):
        metadata = [metadata]  # normalize to list for easier processing
    if len(metadata) == 0:
        return False
    has_server_auth = False
    has_client_auth = False
    for cert_meta in metadata:
        eku = cert_meta.get("eku", [])
        if any("serverAuth" in usage for usage in eku):
            has_server_auth = True
        if any("clientAuth" in usage for usage in eku):
            has_client_auth = True
        if "alias" in cert_meta:  # JKS entries with alias are likely to be trusted certs, not private keys
            continue
        # if "private_key" in cert_meta:
        #    has_private_key = True

        # Note: We cannot reliably detect private key presence from cert metadata alone
        # unless we parse the key file separately. 
        # For now, mTLS detection relies on EKU + Truststore presence (checked in main.py)

        # Check results AFTER looping through all certs
    is_mtls_candidate = has_server_auth and has_client_auth

    print(f"EKU inspection results: Server Auth={has_server_auth}, Client Auth={has_client_auth}")
    return is_mtls_candidate

import logging

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.primitives.serialization import pkcs12
import jks

logger = logging.getLogger(__name__)

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
        logger.info("Certificate format: PEM")
        return "PEM"
    except Exception:  # broad catch: we're probing format, not handling a known error
        pass

    # Try DER
    try:
        x509.load_der_x509_certificate(data)
        logger.info("Certificate format: DER")
        return "DER"
    except Exception:
        pass

    # Try PKCS12
    # We attempt with an empty password first. If it succeeds, no password is needed.
    # If a password was provided, we also try that — this gives a definitive answer
    # instead of falling back to the 0x30 heuristic below.
    try:
        _key, _cert, _ca_certs = pkcs12.load_key_and_certificates(data, b"")
        logger.info("Certificate format: PKCS12 (password not required to extract metadata)")
        return "PKCS12"
    except ValueError:
        # Empty password failed — try the user-provided password if available
        if optional_password is not None:
            try:
                pkcs12.load_key_and_certificates(data, optional_password.encode())
                logger.info("Certificate format: PKCS12 (verified with provided password)")
                return "PKCS12"
            except Exception:
                pass
        # 0x30 is the ASN.1 SEQUENCE tag, the first byte in any DER-encoded structure.
        # This includes PKCS12 but also other binary formats, so this is a best-guess
        # heuristic, not a definitive check. It only runs when PEM, DER, and password
        # verification all failed above, so false positives are unlikely in practice.
        if len(data) > 0 and data[0] == 0x30:
            logger.info("Certificate format: PKCS12 (password required to extract metadata)")
            return "PKCS12"
    except Exception:
        pass

    # Try JKS — first check the extension, then try PKCS12 (some .jks files are PKCS12 underneath),
    # then fall back to the jks library.
    if path.endswith(".jks"):
        try:
            pkcs12.load_key_and_certificates(data, b"")
            logger.info("Certificate format: JKS (PKCS12 underneath)")
            return "JKS"
        except Exception:
            # Now try to load it as a JKS with the 'jks' library.
            if optional_password is not None:
                try:
                    jks.KeyStore.loads(data, optional_password)
                    logger.info("Certificate format: JKS")
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
    if cert_type == "PEM":
        # load_pem_x509_certificates (plural) handles PEM files with multiple
        # certs concatenated (e.g. leaf + intermediate + root chain)
        certs = x509.load_pem_x509_certificates(data)
        logger.info("Certificate metadata extracted successfully (%d cert(s))", len(certs))
        if len(certs) == 1:
            return _extract_cert_metadata(certs[0])
        return [_extract_cert_metadata(cert) for cert in certs]

    if cert_type == "DER":
        cert = x509.load_der_x509_certificate(data)
        logger.info("Certificate metadata extracted successfully")
        return _extract_cert_metadata(cert)

    if cert_type == "PKCS12":
        try:
            _key, cert, additional_certs = pkcs12.load_key_and_certificates(
                data, optional_password.encode() if optional_password is not None else None
            )
        except ValueError:
            raise ValueError("ERROR: Unable to decrypt PKCS12 file, try providing a password with --password")
        except Exception as e:
            raise ValueError(f"ERROR: Failed to load PKCS12 file: {e}")
        if cert is None:
            raise ValueError("ERROR: Unable to extract metadata from PKCS12 certificate, check if the password is correct and if the file is a valid PKCS12 keystore")
        metadata_list = [_extract_cert_metadata(cert)]
        if additional_certs:
            for ca_cert in additional_certs:
                metadata_list.append(_extract_cert_metadata(ca_cert))
        logger.info("Certificate metadata extracted successfully")
        return metadata_list

    if cert_type == "JKS":
        if optional_password is None:
            raise ValueError("ERROR: JKS keystores require a password")
        try:
            ks = jks.KeyStore.loads(data, optional_password)
        except jks.util.BadKeystoreFormatException:
            raise ValueError("ERROR: Not a valid JKS keystore file")
        except jks.util.DecryptionFailureException:
            raise ValueError("ERROR: Wrong password for JKS keystore")
        except jks.util.UnsupportedKeystoreVersionException:
            raise ValueError("ERROR: Unsupported JKS keystore version")
        metadata_list = []
        for alias, entry in ks.entries.items():
            if isinstance(entry, jks.TrustedCertEntry):
                # jks gives raw DER bytes, parse into a cryptography cert object
                cert = x509.load_der_x509_certificate(entry.cert)
                metadata_list.append(_extract_cert_metadata(cert, alias=alias))
        logger.info("Certificate metadata extracted successfully")
        return metadata_list

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

    logger.info("EKU inspection results: Server Auth=%s, Client Auth=%s", has_server_auth, has_client_auth)
    return is_mtls_candidate

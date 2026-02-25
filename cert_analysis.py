from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.primitives.serialization import pkcs12
import jks
import sys

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
    try:
        # PKCS12 requires a password, but we can try with an empty password to see if it loads.
        _key, cert, _ca_certs = pkcs12.load_key_and_certificates(data, b"")
        if cert is not None:
            print("Certificate format: PKCS12 (password not required to extract metadata)")
            return "PKCS12NP"  # PKCS12 No Password
        else:
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
            try:
                jks.KeyStore.load(path, optional_password)
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

    if cert_type in ("PKCS12NP", "PKCS12"):
        _key, cert, additional_certs = pkcs12.load_key_and_certificates(
            data, optional_password.encode() if optional_password else None
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
def eku_inspect(metadata: dict | list[dict]) -> None:
    # TODO: implement EKU inspection
    pass


# only for testing purposes, in the final version the input will be taken from command line arguments or from a configuration file,
# and the output will be a report with all the metadata extracted and any potential issues found.
if __name__ == "__main__":
    cert_path = input("insert certificate path:")
    password = input("Insert additional password if present (leave empty if not needed): ")
    with open(cert_path, "rb") as f:
        data = f.read()
    cert_type = cert_format(data, cert_path, password)
    metadata = cert_metadata_extract(data, cert_type, password)
    eku_inspect(metadata)

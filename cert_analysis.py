import cryptography
import jks
import yaml
import sys

# cert_format takes a file/path in, opens it, and verify wich type of TLS cert is given. Also verifies if path contains multiple certificates cocatenated in a single file (certificate chain)
# Types of certificates:
#   - PEM
#   - PKCS12
#   - DER
#   - JKS (not implemented yet, usually it's PKCS12 with extension ".jks", Have to verify if the extension is valid or if it's a PKCS12 underneath)
def cert_format(path: str, optional_password: str = None) -> str:
    with open(path, "rb") as f:
        data = f.read()
    if data is None or len(data) == 0:
        raise ValueError(f"ERROR: certificate file is empty")
    # Try PEM
    try:
        certs = cryptography.x509.load_pem_x509_certificate(data)
        print("Certificate format: PEM")
        return "PEM"
    except Exception:
        pass

    # Try DER
    try:
        certs = cryptography.x509.load_der_x509_certificate(data)
        print("Certificate format: DER")
        return "DER"
    except Exception:
        pass

    # Try PKCS12
    try:
        # PKCS12 requires a password, but we can try with an empty password to see if it loads.
        certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(data, b"")
        # We verify if the password is actually needed, if the certs variable is None, it means that the password is needed to extract the metadata, 
        # if it's not None, it means that the password is not needed to extract the metadata.
        if certs is not None:
            print("Certificate format: PKCS12 (password not required to extract metadata)")
            return "PKCS12NP" # PKCS12 No Password  
        else:
            print("Certificate format: PKCS12 (password required to extract metadata)")
            return "PKCS12" # PKCS12 
    except Exception:
        pass

    # Try JKS (not implemented yet, usually it's PKCS12 with extension ".jks", Have to verify if the extension is valid or if it's a PKCS12 underneath)
    # Fist i'll verify if the extension is .jks, if it is, i'll try to load it as a PKCS12, if it loads, then it's a JKS, if it doesn't load, then it's an invalid certificate file or it needs to be open as a JKS.
    if path.endswith(".jks"):
        try:
            certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(data, b"")
            print("Certificate format: JKS (password required to extract metadata)")
            return "JKS"
        except Exception:
            # Now try to load it as a JKS with the 'jks' lybrary.
            try:
                certs = jks.KeyStore.load(path, optional_password)
                print("Certificate format: JKS (password required to extract metadata)")
                return "JKS"
            except Exception:
                pass
        
    return None
    

# cert_metadata_extract looks for common metadata (CN, SANs, Issuer, Validity Period, Serial Number).
# for PKCS12 and JKS you need a password  to deserialize. The `cryptography` library's PKCS12 loader returns the key, the leaf cert, and any additional CA certs separately.
def cert_metadata_extract(path: str, cert_type: str, optional_password: str = None) -> dict:
    # if cert_type is PEM or DER, we can extract metadata without a password
    if cert_type in ("PEM", "DER"):
        with open(path, "rb") as f:
            data = f.read()
        if cert_type == "PEM":
            cert = cryptography.x509.load_pem_x509_certificate(data)
        else:
            cert = cryptography.x509.load_der_x509_certificate(data)
        metadata = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": cert.serial_number,
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
            "san": [str(san) for san in cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value],
        }
        print("Certificate metadata extracted successfully")
        return metadata

    # if cert_type is PKCS12NP or PKCS12
    if cert_type == "PKCS12NP" or cert_type == "PKCS12":
        with open(path, "rb") as f:
            data = f.read()
        # if optional_password is provided, we can use it to extract the metadata, 
        # if it's not provided, we can try with an empty password, if it doesn't work, then we can't extract the metadata.
        # Also, if it's provided we need to encode it since the load_key_and_certificates function expects a bytes-like object for the password.
        certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(data, optional_password.encode() if optional_password else None)
        if certs is None:
            raise ValueError(f"ERROR: Unable to extract metadata from PKCS12 certificate, check if the password is correct and if the file is a valid PKCS12 keystore")
        # i'll cycle through the certs variable and take metadata for each one
        metadata_list = []
        for cert in certs[:]: # if the first element is the private key, we skip it
            if isinstance(cert, cryptography.x509.Certificate):
                metadata = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": cert.serial_number,
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                    "eku": [str(eku) for eku in cert.extensions.get_extension_for_class(cryptography.x509.ExtendedKeyUsage).value],
                    "san": [str(san) for san in cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value],
                }
            metadata_list.append(metadata)
        print("Certificate metadata extracted successfully")
        return metadata_list

    # if cert_type is JKS, we need a password to extract the metadata
    if cert_type == "JKS":
        with open(path, "rb") as f:
            data = f.read()
        try:            
            certs = jks.KeyStore.load(path, optional_password)
            # JKS can contain multiple entries, we will extract metadata from all that are certificates
            metadata_list = []
            for alias, entry in certs.entries.items():
                if isinstance(entry, jks.TrustedCertEntry):
                    cert = entry.cert
                    metadata = {
                        "alias": alias,
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial_number": cert.serial_number,
                        "not_valid_before": cert.not_valid_before.isoformat(),
                        "not_valid_after": cert.not_valid_after.isoformat(),
                        "eku": [str(eku) for eku in cert.extensions.get_extension_for_class(cryptography.x509.ExtendedKeyUsage).value],
                        "san": [str(san) for san in cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value],
                    }
                    print("Certificate metadata extracted successfully")
                    return metadata
        except Exception:
            raise ValueError(f"ERROR: Unable to extract metadata from JKS certificate, check if the password is correct and if the file is a valid JKS keystore")
    return None


# eku_inspect inpects the TLS Certificate Extended Key Usage extension for Server Authentication and Client Authentication. If both are present the cert will most likely be mTLS. 
# Also verifies if the PrivateKey is present, if it's present this could also be mTLS (BEWARE! it's not definitive).
# The presence of a Truststore is another mTLS indicator. In a typical mTLS setup the truststore holds the CA certificates used to verify the **peer's** certificate. If `mtls: true` is set but no truststore is defined, that could be worth a warning too.
def eku_inspect():
    # we search for the 
    return None

# only for testing purposes, in the final version the input will be taken from command line arguments or from a configuration file, 
# and the output will be a report with all the metadata extracted and any potential issues found.
cert = input("insert certificate path:")
password = input("Insert additional password if present (leave empty if not needed): ")
cert_type = cert_format(cert, password)
metadata = cert_metadata_extract(cert, cert_type, password)
eku_inspect()

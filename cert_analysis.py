import logging
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)

# First 4 bytes of a Java KeyStore (JKS) and of a JCEKS store.
JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"


# _load_jks imports pyjks only when a real JKS keystore has to be parsed.
# pyjks pulls in the twofish C extension, which needs python3-devel to build;
# importing it lazily keeps PEM/DER/PKCS12 analysis working without it.
def _load_jks():
    try:
        import jks
    except ImportError:
        raise ValueError("JKS support requires the 'pyjks' package, install it with: pip install pyjks")
    return jks

# cert_format takes raw cert bytes and identifies which type of TLS cert it is.
# Also verifies if path contains multiple certificates concatenated in a single file (certificate chain)
# Types of certificates:
#   - PEM
#   - PKCS12
#   - DER
#   - JKS
def cert_format(data: bytes, path: str = "", optional_password: str = None) -> str:
    if data is None or len(data) == 0:
        raise ValueError("certificate file is empty")

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

    # Try JKS / JCEKS by magic number. This is the same check pyjks performs before
    # anything else, but it needs neither pyjks nor the password: a missing or wrong
    # password is then reported by cert_metadata_extract instead of "unknown format".
    if data[:4] in (JKS_MAGIC, JCEKS_MAGIC):
        logger.info("Certificate format: JKS")
        return "JKS"

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

    # Some .jks files are PKCS12 underneath (the keytool default since Java 9).
    # Real JKS/JCEKS stores were already matched by their magic number above.
    if path.endswith(".jks"):
        try:
            pkcs12.load_key_and_certificates(data, b"")
            logger.info("Certificate format: JKS (PKCS12 underneath)")
            return "JKS"
        except Exception:
            pass

    return None


# _format_general_name renders a SAN entry the way openssl does ("DNS:example.com",
# "IP:10.0.0.1", ...) instead of the repr of the cryptography object.
def _format_general_name(name) -> str:
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName:{name.value.rfc4514_string()}"
    if isinstance(name, x509.RegisteredID):
        return f"RID:{name.value.dotted_string}"
    if isinstance(name, x509.OtherName):
        return _format_other_name(name)
    return str(name)


# Microsoft User Principal Name, the most common otherName (smartcard / AD client certs).
_UPN_OID = "1.3.6.1.4.1.311.20.2.3"
# DER string tags whose content is plain text: UTF8String, PrintableString, IA5String.
_DER_TEXT_TAGS = (0x0C, 0x13, 0x16)


# _format_other_name renders an otherName SAN as "otherName:<type>:<value>". The value is
# the DER encoding of an arbitrary ASN.1 type: simple text strings are decoded, anything
# else is shown as hex so that the identity is never silently dropped.
def _format_other_name(name) -> str:
    type_id = name.type_id.dotted_string
    label = "UPN" if type_id == _UPN_OID else type_id
    value = name.value
    # short-form DER length (< 128 bytes) is enough for any realistic name
    if len(value) >= 2 and value[0] in _DER_TEXT_TAGS and value[1] == len(value) - 2:
        try:
            return f"otherName:{label}:{value[2:].decode('utf-8')}"
        except UnicodeDecodeError:
            pass
    return f"otherName:{label}:{value.hex()}"


# _format_oid returns the short name of an OID (e.g. "serverAuth"), or its dotted
# string when cryptography does not know it (custom/private EKUs).
def _format_oid(oid) -> str:
    name = getattr(oid, "_name", "Unknown OID")
    return oid.dotted_string if name == "Unknown OID" else name


def _plural_days(n: int) -> str:
    return f"{n} day" if n == 1 else f"{n} days"


# _expiry_fields computes how long a certificate is still valid, relative to `now`.
# The "expiring soon" threshold is NOT applied here: callers pick it (see expiry_warning).
#   validity_status: "valid", "expired" or "not_yet_valid"
#   days_remaining:  whole days until not_valid_after, counted towards zero: a cert expiring
#                    in 23 hours gives 0, one that expired 3 days and 2 hours ago gives -3.
#                    0 is ambiguous on purpose ("today"); validity_status tells the two apart.
#   expiry:          human-readable label ("expires in 12 days", "expired 3 days ago"),
#                    always consistent with days_remaining
def _expiry_fields(cert, now: datetime) -> dict:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if now < not_before:
        status = "not_yet_valid"
    elif now > not_after:
        status = "expired"
    else:
        status = "valid"

    if status == "expired":
        days_ago = (now - not_after).days
        days_remaining = -days_ago
        label = "expired today" if days_ago == 0 else f"expired {_plural_days(days_ago)} ago"
    else:
        days_remaining = (not_after - now).days
        label = "expires today" if days_remaining == 0 else f"expires in {_plural_days(days_remaining)}"

    return {"validity_status": status, "days_remaining": days_remaining, "expiry": label}


def _extract_cert_metadata(cert, alias: str = None, now: datetime = None) -> dict:
    # Extract common metadata from a cryptography x509.Certificate object.
    # `now` is only overridden by tests; it defaults to the current UTC time.
    if now is None:
        now = datetime.now(timezone.utc)
    metadata = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
    }
    metadata.update(_expiry_fields(cert, now))
    if alias is not None:
        metadata["alias"] = alias

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        metadata["san"] = [_format_general_name(san) for san in san_ext.value]
    except ExtensionNotFound:
        metadata["san"] = []

    try:
        eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        metadata["eku"] = [_format_oid(eku) for eku in eku_ext.value]
    except ExtensionNotFound:
        metadata["eku"] = []

    return metadata


# expiry_warning returns a one-line warning for a single cert's metadata, or None when the
# cert is valid and has more than warn_days left. "Within N days" is inclusive: with
# warn_days=30, a cert with exactly 30 days remaining is flagged.
def expiry_warning(metadata: dict, warn_days: int) -> str | None:
    status = metadata.get("validity_status")
    if status == "expired":
        return f"certificate {metadata['expiry']}"
    if status == "not_yet_valid":
        return f"certificate is not valid before {metadata['not_valid_before']}"
    if status == "valid" and metadata["days_remaining"] <= warn_days:
        return f"certificate {metadata['expiry']} (threshold: {_plural_days(warn_days)})"
    return None


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
            try:
                # If the initial load failed, try with an empty password as a fallback.
                _key, cert, additional_certs = pkcs12.load_key_and_certificates(data, b"")
            except Exception:
                raise ValueError("unable to decrypt PKCS12 file, wrong password or no password provided, try providing a password with --password")
        except Exception as e:
            raise ValueError(f"failed to load PKCS12 file: {e}")
        if cert is None:
            raise ValueError("unable to extract metadata from PKCS12 certificate, check if the password is correct and if the file is a valid PKCS12 keystore")
        metadata_list = [_extract_cert_metadata(cert)]
        if additional_certs:
            for ca_cert in additional_certs:
                metadata_list.append(_extract_cert_metadata(ca_cert))
        logger.info("Certificate metadata extracted successfully")
        return metadata_list

    if cert_type == "JKS":
        if optional_password is None:
            raise ValueError("JKS keystores require a password")
        jks = _load_jks()
        try:
            ks = jks.KeyStore.loads(data, optional_password)
        except jks.util.BadKeystoreFormatException:
            raise ValueError("not a valid JKS keystore file")
        except jks.util.KeystoreSignatureException:
            # pyjks verifies the store integrity hash (keyed with the password) before
            # decrypting anything: a mismatch means a wrong password OR a damaged file,
            # the two cannot be told apart (keytool reports it the same way).
            raise ValueError("wrong password for JKS keystore, or keystore is corrupted (integrity check failed)")
        except jks.util.DecryptionFailureException:
            raise ValueError("wrong password for JKS keystore")
        except jks.util.UnsupportedKeystoreVersionException:
            raise ValueError("unsupported JKS keystore version")
        except jks.util.KeystoreException as e:
            raise ValueError(f"failed to load JKS keystore: {e}")
        metadata_list = []
        for alias, entry in ks.entries.items():
            if isinstance(entry, jks.TrustedCertEntry):
                # jks gives raw DER bytes, parse into a cryptography cert object
                cert = x509.load_der_x509_certificate(entry.cert)
                metadata_list.append(_extract_cert_metadata(cert, alias=alias))
        logger.info("Certificate metadata extracted successfully")
        return metadata_list

    raise ValueError(f"unsupported certificate type: {cert_type}")


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


# csr_generate builds a Certificate Signing Request from an existing certificate.
# It extracts the subject (CN, OU, O, C, etc.), SANs, and all relevant extensions
# (EKU, Key Usage, etc.) from the cert, generates a new key pair matching the original
# key type (RSA or EC), and signs the CSR.
# Returns a tuple of (csr_pem_bytes, key_pem_bytes).
def csr_generate(cert_data: bytes, cert_type: str, optional_password: str = None) -> tuple[bytes, bytes]:
    # Load the first/leaf certificate depending on format
    if cert_type == "PEM":
        cert = x509.load_pem_x509_certificates(cert_data)[0]
    elif cert_type == "DER":
        cert = x509.load_der_x509_certificate(cert_data)
    elif cert_type == "PKCS12":
        try:
            _key, cert, _ca_certs = pkcs12.load_key_and_certificates(
                cert_data, optional_password.encode() if optional_password else None
            )
        except ValueError:
            raise ValueError("unable to decrypt PKCS12 file, try providing a password with --password")
        if cert is None:
            raise ValueError("no certificate found in PKCS12 file")
    else:
        raise ValueError(f"CSR generation is not supported for {cert_type} format")

    # Detect original key type and size to generate a matching key
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        logger.info("Generated new RSA-%d key", key_size)
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve = pub_key.curve
        private_key = ec.generate_private_key(curve)
        logger.info("Generated new EC key (curve: %s)", curve.name)
    else:
        raise ValueError(f"unsupported key type: {type(pub_key).__name__}")

    # Build the CSR with the same subject as the original cert.
    # subject_name() copies the full subject including CN, OU, O, C, ST, L, etc.
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(cert.subject)

    # Copy all extensions from the original cert into the CSR.
    # This preserves SANs, EKU (serverAuth/clientAuth for mTLS), Key Usage,
    # Basic Constraints, and any other extensions the CA included.
    # We skip Authority-related extensions (AKI, CRL, AIA, SKI) since those are
    # set by the CA when it signs, not by the CSR requestor.
    ca_only_extensions = (
        x509.AuthorityKeyIdentifier,
        x509.CRLDistributionPoints,
        x509.AuthorityInformationAccess,
        x509.SubjectKeyIdentifier,
    )
    for ext in cert.extensions:
        if isinstance(ext.value, ca_only_extensions):
            continue
        builder = builder.add_extension(ext.value, critical=ext.critical)
        logger.info("Copied extension: %s (critical=%s)", ext.oid._name, ext.critical)

    csr = builder.sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    logger.info("CSR generated successfully")
    return csr_pem, key_pem

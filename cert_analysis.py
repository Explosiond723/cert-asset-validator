import cryptography
import yaml

# cert_format takes a file/path in, opens it, and verify wich type of TLS cert is given. Also verifies if path contains multiple certificates cocatenated in a single file (certificate chain)
# Types of certificates:
#   - PEM
#   - PKCS12
#   - DER
#   - JKS (not implemented yet, usually it's PKCS12 with extension ".jks", Have to verify if the extension is valid or if it's a PKCS12 underneath)
def cert_format(path -> str):

# cert_metadata_extract looks for common metadata (CN, SANs, Issuer, Validity Period, Serial Number).
# for PKCS12 and JKS you need a password  to deserialize. The `cryptography` library's PKCS12 loader returns the key, the leaf cert, and any additional CA certs separately.
def cert_metadata_extract():

# eku_inspect inpects the TLS Certificate Extended Key Usage extension for Server Authentication and Client Authentication. If both are present the cert will most likely be mTLS. 
# Also verifies if the PrivateKey is present, if it's present this could also be mTLS (BEWARE! it's not definitive).
# The presence of a Truststore is another mTLS indicator. In a typical mTLS setup the truststore holds the CA certificates used to verify the **peer's** certificate. If `mtls: true` is set but no truststore is defined, that could be worth a warning too.
def eku_inspect():


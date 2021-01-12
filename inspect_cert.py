import binascii
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography import x509
import sys
import datetime

# Certificate content
FULL_SUBJECT = None
ISSUER = None
NOT_VALID_AFTER = None
PUBLIC_KEY_ALGORITHM = None
PUBLIC_KEY_HASH = None
PUBLIC_KEY_LENGTH = None
SERIAL_NO = None
SUBJECT_COMMON_NAME = None
VERIFIABLE = None

def print_cert_content():
    print("Issuer: {}".format(ISSUER))
    print("Subject: {}".format(FULL_SUBJECT))
    print("Subject Common Name: {}".format(SUBJECT_COMMON_NAME))
    print("Serial number: {}".format(SERIAL_NO))
    print("Expiry date: {}".format(NOT_VALID_AFTER))
    print("Public key algorithm: {}".format(PUBLIC_KEY_ALGORITHM))
    print("Public key length: {}".format(PUBLIC_KEY_LENGTH))
    print("Public Key Info hash: {}".format(PUBLIC_KEY_HASH.decode()))
    print("Signature validated: {}".format(VERIFIABLE))

# Reads the certificate from a file and returns a Certificate object.
def open_cert(filename):
    cert_data = open(filename).read()
    cert = x509.load_pem_x509_certificate(str.encode(cert_data), default_backend())
    return cert

# Returns the SHA256 of a public key as a hex string
def hash_public_key(pk):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str.encode(str(pk)))
    d = digest.finalize()
    return binascii.hexlify(d)

# Inspects a certificate passed in as a Certificate object.
def inspect_cert(cert):
    global FULL_SUBJECT, ISSUER, NOT_VALID_AFTER, PUBLIC_KEY_ALGORITHM, PUBLIC_KEY_HASH, PUBLIC_KEY_LENGTH, SERIAL_NO, SUBJECT_COMMON_NAME

    # Populate global variables

    # SUBJECT:
    # Get full subject as RFC4514-formatted string
    FULL_SUBJECT = cert.subject.rfc4514_string()
    # Get the Common Name via x509.NameOID.COMMON_NAME
    SUBJECT_COMMON_NAME = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    # ISSUER:
    # Get issuer as RFC4515-formatted string
    ISSUER = cert.issuer.rfc4514_string()

    # EXPIRY:
    # Date must be formatted as YYYY-MM-DD.
    year = str(cert.not_valid_after.year)
    month = str(cert.not_valid_after.month)
    day = str(cert.not_valid_after.day)
    NOT_VALID_AFTER = year + '-' + month + '-' + day
    
    # PUBLIC KEY ALGORITHM:
    p = cert.public_key()
    if isinstance(p, rsa.RSAPublicKey):
        PUBLIC_KEY_ALGORITHM = "RSA"
    elif isinstance(p, dsa.DSAPublicKey):
        PUBLIC_KEY_ALGORITHM = "DSA"
    elif isinstance(p, ec.EllipticCurvePublicKey):
        PUBLIC_KEY_ALGORITHM = p.curve.name
    elif isinstance(p, ed25519.Ed25519PublicKey):
        PUBLIC_KEY_ALGORITHM = "Ed25519"
    elif isinstance(p, ed448.Ed448PublicKey):
        PUBLIC_KEY_ALGORITHM = "Ed448"
    else:
        PUBLIC_KEY_ALGORITHM = "UNKNOWN"

    # PUBLIC KEY HASH:
    PUBLIC_KEY_HASH = hash_public_key(p)

    # PUBLIC KEY LENGTH:
    if PUBLIC_KEY_ALGORITHM == "Ed25519":
        PUBLIC_KEY_LENGTH = 256
    elif PUBLIC_KEY_ALGORITHM == "Ed448":
        PUBLIC_KEY_LENGTH = 456
    else:
        PUBLIC_KEY_LENGTH = p.key_size

    # SERIAL NUMBER:
    SERIAL_NO = cert.serial_number

def verify_cert(cert, issuer_cert):
    global VERIFIABLE
    # CHECKING THE SIGNATURE:
    p = issuer_cert.public_key()
    if isinstance(p, rsa.RSAPublicKey):
        try:
            issuer_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            VERIFIABLE = True
        except InvalidSignature:
            VERIFIABLE = False
        except Exception as e:
            print("Unknown exception when verifying certificate signature. Are you trying to verify a cert that wasn't signed with RSA?")
            sys.exit(-1)
    if isinstance(p, ec.EllipticCurvePublicKey):
        try:
            issuer_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
            VERIFIABLE = True
        except InvalidSignature:
            VERIFIABLE = False
        except Exception as e:
            print("Unknown exception when verifying certificate signature. Are you trying to verify a cert that wasn't signed with RSA?")
            sys.exit(-1)

# Eg run commands:
# python inspect_cert.py intermediate_cert.crt ca.crt
# >> VERIFIABLE == true as intermediate_cert signed by ca cert
# python inspect_cert.py student_cert.crt intermediate_cert.crt
# >> VERIFIABLE == true as student_cert signed by intermediate_cert
# python inspect_cert.py student_cert.crt ca.crt
# >> VERIFIABLE == false as student_cert not signed by ca cert

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 {} CERT ISSUER_CERT".format(sys.argv[0]))
        sys.exit(-1)
    cert = open_cert(sys.argv[1])
    issuer_cert = open_cert(sys.argv[2])
    inspect_cert(cert)
    verify_cert(cert, issuer_cert)
    print_cert_content()


if __name__ == "__main__":
    main()

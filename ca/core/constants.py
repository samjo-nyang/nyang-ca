from collections import OrderedDict

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


# Subject Section
SUBJECT_KEYS = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress']

SUBJECT_KEY_TEXT_MAP = OrderedDict([
    ('C', 'Country'),
    ('ST', 'State'),
    ('L', 'Location'),
    ('O', 'Organization'),
    ('OU', 'Organizational Unit'),
    ('CN', 'Common Name'),
    ('emailAddress', 'Email'),
])

SUBJECT_KEY_OID_MAP = {
    'C': NameOID.COUNTRY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'L': NameOID.LOCALITY_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'CN': NameOID.COMMON_NAME,
    'emailAddress': NameOID.EMAIL_ADDRESS,
}

SUBJECT_OID_KEY_MAP = {v: k for k, v in SUBJECT_KEY_OID_MAP.items()}

SUBJECT_TEXT_UPPER_MAP = {
    v.upper(): v for _, v in SUBJECT_KEY_TEXT_MAP.items()
}

SAN_NAME_TEXT_MAP = {
    x509.UniformResourceIdentifier: 'URI',
    x509.DNSName: 'DNS',
    x509.RFC822Name: 'EMAIL',
    x509.RegisteredID: 'RID',
    x509.DirectoryName: 'DIRNAME',
    x509.IPAddress: 'IP',
    x509.OtherName: 'OTHER',
}

# Key and Algorithm Section
CA_KEY_SIZE = 4096

HASH_SHA512 = hashes.SHA512()


# ENCODING FORMAT
PEM_ENCODING = Encoding.PEM


# Key Usage Section
KEY_USAGES_OID_TEXT_MAP = {
    '2.5.29.15.0': 'digital_signature',
    '2.5.29.15.1': 'content_commitment',
    '2.5.29.15.2': 'key_encipherment',
    '2.5.29.15.3': 'data_encipherment',
    '2.5.29.15.4': 'key_agreement',
    '2.5.29.15.5': 'key_cert_sign',
    '2.5.29.15.6': 'crl_sign',
    '2.5.29.15.7': 'encipher_only',
    '2.5.29.15.8': 'decipher_only',
}

# Revocation Section
REVOCATION_REASONS = (
    ('', 'No Reason'),
    ('aa_compromise', 'Attribute Authority Compromised'),
    ('affiliation_changed', 'Affiliation Changed'),
    ('ca_compromise', 'CA Compromised'),
    ('certificate_hold', 'On Hold'),
    ('cessation_of_operation', 'Cessation of Operation'),
    ('key_compromise', 'Key Compromised'),
    ('privilege_withdrawn', 'Privilege Withdrawn'),
    ('remove_from_crl', 'Removed from CRL'),
    ('superseded', 'Superseded'),
    ('unspecified', 'Unspecified'),
)

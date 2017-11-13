from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

from ca.core.constants import HASH_SHA512
from .crypto import decrypt_privkey


def build_revoked_cert(cert):
    builder = x509.RevokedCertificateBuilder()
    builder = builder.serial_number(cert.x509.serial)
    builder = builder.revocation_date(cert.revoked_at)
    if cert.revoked_reason:
        reason_flag = getattr(x509.ReasonFlags, cert.revoked_reason)
        builder = builder.add_extension(
            x509.CRLReason(reason_flag), critical=False,
        )
    return builder.build(default_backend())


def build_crl(ca, ca_password, cert_revoked, expire_days):
    now = datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca.x509.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=expire_days))

    for cert in cert_revoked:
        builder = builder.add_revoked_certificate(build_revoked_cert(cert))

    private_key = decrypt_privkey(ca.private_key, ca_password)
    crl = builder.sign(
        private_key=private_key,
        algorithm=HASH_SHA512,
        backend=default_backend(),
    )
    return crl.public_bytes(Encoding.PEM)

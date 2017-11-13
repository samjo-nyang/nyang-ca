from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtensionOID, ObjectIdentifier
)

from ca.core.constants import (
    CA_KEY_SIZE, HASH_SHA512, KEY_USAGES_OID_TEXT_MAP,
)
from ca.core.utils import parse_general_name, parse_subj_name
from .crypto import decrypt_passwd, decrypt_privkey, generate_privkey


def issue_cert(subject, subject_alt_name, profile,
               ca, ca_password, extension_info, *,
               path_length=None):
    privkey = generate_privkey(CA_KEY_SIZE)
    pubkey = privkey.public_key()

    # calc expire date
    now = datetime.utcnow().replace(second=0, microsecond=0)
    expires = now + timedelta(days=profile.expire_days)

    # append subject key
    subj = parse_subj_name(subject)
    subj_key_id = x509.SubjectKeyIdentifier.from_public_key(pubkey)
    extension_info.append((subj_key_id, False))

    # append subject alt name
    if subject_alt_name:
        extension_info.append((x509.SubjectAlternativeName([
            parse_general_name(san) for san in subject_alt_name.splitlines()
        ]), False))

    # append issuer alt name and auth key id
    if not ca:
        issuer = subj
        issuer_alt_name = subject_alt_name
        sign_privkey = privkey
        auth_key_id = x509.AuthorityKeyIdentifier(
            key_identifier=subj_key_id.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    else:
        issuer = ca.x509.subject
        issuer_alt_name = ca.child_issuer_alt_name
        if not ca_password:
            ca_password = decrypt_passwd(ca.saved_password)
        sign_privkey = decrypt_privkey(ca.private_key, ca_password)
        auth_key_id = ca.x509.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value

    extension_info.append((auth_key_id, False))
    if issuer_alt_name:
        extension_info.append((x509.IssuerAlternativeName(
            [parse_general_name(issuer_alt_name)]
        ), False))

    # append basic constraints
    if path_length == -1:
        path_length = None
    extension_info.append((x509.BasicConstraints(
        ca=path_length is not None, path_length=path_length
    ), True))

    # append key usages
    key_usages = [k.oid for k in profile.key_usage_values.all()]
    extension_info.append((
        x509.KeyUsage(**{
            v: k in key_usages for k, v in KEY_USAGES_OID_TEXT_MAP.items()
        }), profile.key_usage_critical,
    ))

    # append extended key usages if exists
    extended_key_usage = [
        ObjectIdentifier(e.oid)
        for e in profile.extended_key_usage_values.all()
    ]
    if extended_key_usage:
        extension_info.append((
            x509.ExtendedKeyUsage(extended_key_usage),
            profile.extended_key_usage_critical,
        ))

    # append crl url if exists
    if ca and ca.child_crl_url:
        crl_urls = [url.strip() for url in ca.child_crl_url.splitlines()]
        crl_distributions = [
            x509.DistributionPoint(full_name=[
                x509.UniformResourceIdentifier(url),
            ], relative_name=None, crl_issuer=None, reasons=None)
            for url in crl_urls if url
        ]
        extension_info.append((
            x509.CRLDistributionPoints(crl_distributions), False,
        ))

    # append ocsp url and issuer url if exists
    auth_info_access = []
    if ca and ca.child_ocsp_url:
        auth_info_access.append(x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.OCSP,
            access_location=x509.UniformResourceIdentifier(ca.child_ocsp_url),
        ))
    if ca and ca.child_issuer_url:
        auth_info_access.append(x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
            access_location=x509.UniformResourceIdentifier(
                ca.child_issuer_url
            ),
        ))
    if auth_info_access:
        extension_info.append((
            x509.AuthorityInformationAccess(auth_info_access), False,
        ))

    # then build it!
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subj)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(expires)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pubkey)
    for extension, critical in extension_info:
        builder = builder.add_extension(extension, critical)

    return pubkey, privkey, builder.sign(
        private_key=sign_privkey,
        algorithm=HASH_SHA512,
        backend=default_backend(),
    )

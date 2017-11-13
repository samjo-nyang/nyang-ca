from datetime import datetime
from os import path

from cryptography import x509
from django.conf import settings
from django.db import models
from django.utils import timezone

from ca.core.internals import (
    build_crl, decrypt_passwd, encrypt_passwd,
    encrypt_privkey, issue_cert,
)
from ca.core.utils import parse_general_name, setattrs


class CertificateAuthorityManager(models.Manager):
    def issue(self, name, description, profile, ca, ca_password,
              subject, password, password_save, path_length, subject_alt_name,
              name_constraints_permitted, name_constraints_excluded,
              child_issuer_alt_name, child_issuer_url, child_crl_url,
              child_ocsp_url, obj=None):
        extension_info = []
        if name_constraints_permitted or name_constraints_excluded:
            def to_subtrees(lines):
                return [
                    parse_general_name(line)
                    for line in lines.splitlines()
                    if line.strip()
                ]
            extension_info.append((x509.NameConstraints(
                permitted_subtrees=to_subtrees(name_constraints_permitted),
                excluded_subtrees=to_subtrees(name_constraints_excluded),
            ), True))

        pubkey, privkey, cert = issue_cert(
            subject, subject_alt_name, profile,
            ca, ca_password, extension_info,
            path_length=path_length,
        )

        if obj is None:
            obj = self.model()
        setattrs(
            obj, name=name, description=description, profile=profile, ca=ca,
            child_issuer_alt_name=child_issuer_alt_name,
            child_issuer_url=child_issuer_url, child_crl_url=child_crl_url,
            child_ocsp_url=child_ocsp_url, x509=cert,
            private_key=encrypt_privkey(privkey, password),
            saved_password=encrypt_passwd(password) if password_save else None,
        )
        return obj

    def refresh_crl(self, ca, password=None):
        ca_password, expire_days = password, 365
        if ca.saved_password:
            ca_password = decrypt_passwd(ca.saved_password)
            expire_days = 10

        certs = sum([list(qs.filter(
            revoked_at__isnull=False,
            expired_at__gte=timezone.now(),
        )) for qs in [ca.children_ca, ca.children]], [])
        crl = build_crl(ca, ca_password, certs, expire_days)

        timestamp = int(datetime.utcnow().timestamp())
        crls_file_path = [
            path.join(
                settings.STORAGE_CRL_ARCHIVE_DIR,
                f'{ca.id}.{timestamp}.crl',
            ),
            path.join(
                settings.STORAGE_CRL_LIVE_DIR, f'{ca.name}.crl',
            ),
        ]
        for crl_file_path in crls_file_path:
            with open(crl_file_path, 'wb') as f:
                f.write(crl)
        return crl


class CertificateManager(models.Manager):
    def issue(self, ca, profile, subject, subject_alt_name,
              password, ca_password, privkey_save,
              password_save=False, obj=None):
        pubkey, privkey, cert = issue_cert(
            subject, subject_alt_name, profile,
            ca, ca_password, [],
        )

        private_key = None
        if privkey_save:
            private_key = encrypt_privkey(privkey, password)

        if obj is None:
            obj = self.model()

        setattrs(
            obj, ca=ca, profile=profile, x509=cert,
            private_key=private_key, private_key_plain=privkey,
            saved_password=encrypt_passwd(password) if password_save else None,
        )
        return obj

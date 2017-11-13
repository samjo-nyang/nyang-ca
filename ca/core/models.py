from collections import OrderedDict

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtensionOID,
)
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

from ca.core.constants import (
    KEY_USAGES_OID_TEXT_MAP, PEM_ENCODING, REVOCATION_REASONS,
    SUBJECT_OID_KEY_MAP,
)
from ca.core.managers import (
    CertificateAuthorityManager, CertificateManager,
)
from ca.core.utils import (
    format_general_name, format_general_names, format_serial,
    format_subj_name, safe_getattr, utc_to_local,
)
from ca.core.validators import (
    validate_ca_name, validate_general_name_multiline,
    validate_key_size, validate_url_multiline,
)


class KeyUsage(models.Model):
    oid = models.CharField(max_length=32, unique=True, verbose_name='OID')
    name = models.CharField(max_length=32, unique=True)
    description = models.TextField()

    class Meta:
        verbose_name = 'Key Usage'

    def __str__(self):
        return self.name


class ExtendedKeyUsage(models.Model):
    oid = models.CharField(max_length=32, unique=True, verbose_name='OID')
    name = models.CharField(max_length=32, unique=True)
    description = models.TextField()

    class Meta:
        verbose_name = 'Extended Key Usage'

    def __str__(self):
        return self.name


class Profile(models.Model):
    name = models.CharField(max_length=16, unique=True)
    description = models.TextField()
    key_usage_values = models.ManyToManyField(
        KeyUsage, verbose_name='KeyUsage Values',
    )
    key_usage_critical = models.BooleanField(
        default=True, verbose_name='KeyUsage Critical',
    )
    extended_key_usage_values = models.ManyToManyField(
        ExtendedKeyUsage, verbose_name='ExtendedKeyUsage Values',
    )
    extended_key_usage_critical = models.BooleanField(
        default=False, verbose_name='ExtendedKeyUsage Critical',
    )
    cn_in_san = models.BooleanField(default=True, verbose_name='CN in SAN')
    key_size = models.IntegerField(
        default=4096, validators=[validate_key_size], verbose_name='Key Size',
    )
    expire_days = models.IntegerField(default=375, validators=[
        MinValueValidator(30),
        MaxValueValidator(365 * 3 + 10),
    ], verbose_name='Expire Days')

    def __str__(self):
        return self.name


class X509MixIn(models.Model):
    public_key = models.TextField(verbose_name='Public Key')
    private_key = models.TextField(
        null=True, blank=True, verbose_name='Private Key',
    )
    saved_password = models.TextField(null=True, blank=True)
    profile = models.ForeignKey(
        Profile, null=True, blank=True, on_delete=models.SET_NULL,
    )
    common_name = models.CharField(max_length=128, verbose_name='Common Name')
    serial = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now=True, verbose_name='Created At')
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    expired_at = models.DateTimeField(db_index=True)
    revoked_reason = models.CharField(
        max_length=32, null=True, blank=True, choices=REVOCATION_REASONS,
    )

    x509_obj = None

    @property
    def x509(self):
        if not self.x509_obj:
            self.load()
        return self.x509_obj

    @x509.setter
    def x509(self, value):
        self.x509_obj = value
        self.public_key = value.public_bytes(PEM_ENCODING)
        self.common_name = self.subject['CN']
        self.serial = format_serial(value.serial_number)
        self.expired_at = timezone.make_aware(
            value.not_valid_after, timezone.utc,
        )

    @property
    def subject(self):
        return OrderedDict([
            (SUBJECT_OID_KEY_MAP[s.oid], s.value) for s in self.x509.subject
        ])

    @property
    def issuer(self):
        return OrderedDict([
            (SUBJECT_OID_KEY_MAP[s.oid], s.value) for s in self.x509.issuer
        ])

    def status(self):
        if self.revoked_at:
            return 'revoked'
        elif self.expired_at < timezone.now():
            return 'expired'
        return 'valid'

    def status_ocsp(self):
        if self.revoked_at:
            return self.revoked_reason or 'revoked'
        return 'good'

    def load(self):
        self.x509_obj = x509.load_pem_x509_certificate(
            self.public_key.encode('utf-8'), default_backend()
        )
        return self

    def extension_to_str(self, oid, handler):
        try:
            ext = self.x509_obj.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return ''

        value = handler(ext.value)
        if ext.critical:
            value += ' (critical)'
        return value

    def not_before(self):
        return utc_to_local(self.x509.not_valid_before)
    not_before.short_description = 'Not Before'

    def not_after(self):
        return utc_to_local(self.x509.not_valid_after)
    not_after.short_description = 'Not After'

    def subject_str(self):
        return format_subj_name(self.subject)
    subject_str.short_description = 'Subject'

    def issuer_str(self):
        return format_subj_name(self.issuer)
    issuer_str.short_description = 'Issuer'

    def subject_alt_name(self):
        return self.extension_to_str(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            lambda ev: format_general_names(ev),
        )
    subject_alt_name.short_description = 'Subject AltName'

    def issuer_alt_name(self):
        return self.extension_to_str(
            ExtensionOID.ISSUER_ALTERNATIVE_NAME,
            lambda ev: format_general_names(ev)
        )
    issuer_alt_name.short_description = 'Issuer AltName'

    def subject_key_identifier(self):
        return self.extension_to_str(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            lambda ev: format_serial(ev.digest)
        )
    subject_key_identifier.short_description = 'Subject Key Identifier'

    def authority_key_identifier(self):
        return self.extension_to_str(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            lambda ev: format_serial(ev.key_identifier)
        )
    authority_key_identifier.short_description = 'Authority Key Identifier'

    def basic_constraints(self):
        return self.extension_to_str(
            ExtensionOID.BASIC_CONSTRAINTS,
            lambda ev: f'CA: {str(ev.ca).upper()}, Path Len: {ev.path_length}',
        )
    basic_constraints.short_description = 'Basic Constraints'

    def key_usage(self):
        key_usage_names = {
            v: KeyUsage.objects.get(oid=k).description
            for k, v in KEY_USAGES_OID_TEXT_MAP.items()
        }
        return self.extension_to_str(
            ExtensionOID.KEY_USAGE,
            lambda ev: ', '.join([
                name for text, name in key_usage_names.items()
                if safe_getattr(ev, text)
            ]),
        )
    key_usage.short_description = 'Key Usage'

    def extended_key_usage(self):
        return self.extension_to_str(
            ExtensionOID.EXTENDED_KEY_USAGE,
            lambda ev: ', '.join([
                ExtendedKeyUsage.objects.get(oid=e.dotted_string).name
                for e in ev
            ]),
        )
    extended_key_usage.short_description = 'Extended Key Usage'

    def crl_distribution_points(self):
        def dp_to_str(dp):
            if dp.full_name:
                return f'Full Name: {format_general_names(dp.full_name)}'
            return f'Relative Name: {format_subj_name(dp.relative_name.value)}'
        return self.extension_to_str(
            ExtensionOID.CRL_DISTRIBUTION_POINTS,
            lambda ev: '\n'.join([dp_to_str(dp) for dp in ev])
        )
    crl_distribution_points.short_description = 'CRL Distribution Points'

    def authority_info_access(self):
        def aia_to_str(aia):
            if aia.access_method == AuthorityInformationAccessOID.OCSP:
                return f'OCSP: {format_general_name(aia.access_location)}'
            elif aia.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                return f'Issuers: {format_general_name(aia.access_location)}'
            return ''

        return self.extension_to_str(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            lambda ev: '\n'.join([aia_to_str(aia) for aia in ev])
        )
    authority_info_access.short_description = 'Authority Info Access'

    class Meta:
        abstract = True


class CertificateAuthority(X509MixIn):
    objects = CertificateAuthorityManager()

    name = models.CharField(
        max_length=32, unique=True, validators=[validate_ca_name],
    )
    description = models.TextField()
    ca = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL,
        verbose_name='CA (Parent)', related_name='children_ca',
    )
    child_issuer_alt_name = models.TextField(
        null=True, blank=True,
        validators=[validate_general_name_multiline],
        verbose_name='Issuer AltName',
    )
    child_issuer_url = models.URLField(
        null=True, blank=True, verbose_name='Issuer URL',
    )
    child_crl_url = models.TextField(
        null=True, blank=True, validators=[validate_url_multiline],
        verbose_name='CRL URLs',
    )
    child_ocsp_url = models.URLField(
        null=True, blank=True, verbose_name='OCSP URL',
    )
    ocsp_certificate = models.ForeignKey(
        'Certificate', null=True, blank=True, on_delete=models.SET_NULL,
        verbose_name='OCSP Certificate', related_name='ocsp_parent',
    )

    def name_constraints(self):
        def nc_to_str(nc):
            subtrees = [{
                'name': 'Permitted',
                'values': nc.permitted_subtrees,
            }, {
                'name': 'Excluded',
                'values': nc.excluded_subtrees,
            }]
            return '\n'.join(sum([
                [tree['name']] + [
                    f'- {format_general_name(name)}'
                    for name in tree['values']
                ] for tree in subtrees
            ], []))

        return self.extension_to_str(
            ExtensionOID.NAME_CONSTRAINTS, nc_to_str,
        )
    name_constraints.short_description = 'Name Constraints'

    class Meta:
        verbose_name = 'Certificate Authority'
        verbose_name_plural = 'Certificate Authorities'

    def __str__(self):
        return self.name


class Certificate(X509MixIn):
    objects = CertificateManager()

    ca = models.ForeignKey(
        CertificateAuthority, on_delete=models.CASCADE,
        verbose_name='Certificate Authority', related_name='children',
    )
    managers = models.ManyToManyField(User, related_name='certificates')

    def __str__(self):
        return self.common_name

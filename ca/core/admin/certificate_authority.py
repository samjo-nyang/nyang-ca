from django.contrib import admin

from ca.core.forms import CertificateAuthorityCreationForm
from ca.core.models import CertificateAuthority
from .utils import get_admin_urls
from .views import (
    CertificateAuthorityCRLView,
    CertificateAuthorityOCSPView,
    CertificateAuthorityRevocationView,
)
from .x509_mixin import X509MixInAdmin


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(X509MixInAdmin):
    list_display = [
        'id', 'name', 'subject_str', 'ca', 'serial',
        'created_at', 'expired_at', 'revoked_at',
    ]
    list_display_links = ['name']
    search_fields = ['name', 'common_name', 'subject_str', 'serial']

    fieldsets_create = [
        ('General', {
            'fields': [
                'name', 'description', 'profile', 'ca', 'ca_password',
            ],
        }),
        ('X509 Basic', {
            'fields': [
                'subject', 'subject_alt_name', 'password', 'password_save',
            ],
        }),
        ('X509 Extensions (CA)', {
            'fields': [
                'path_length', 'name_constraints_permitted',
                'name_constraints_excluded',
            ],
        }),
        ('X509 Extensions (Child)', {
            'fields': [
                'child_issuer_alt_name', 'child_issuer_url',
                'child_crl_url', 'child_ocsp_url',
            ],
        }),
    ]

    def __init__(self, *args, **kwargs):
        kwargs['fields_update_general'] = ['name', 'description']
        kwargs['fieldsets_update'] = [('X509 - Child', {
            'fields': [
                'child_issuer_alt_name', 'child_issuer_url',
                'child_crl_url', 'child_ocsp_url',
            ],
        })]
        kwargs['fields_x509_extra'] = ['name_constraints']
        kwargs['fields_readonly_extra'] = ['name']
        super().__init__(*args, **kwargs)

    def get_urls(self):
        urls_add = get_admin_urls(self.model._meta, self.admin_site, [
            ('crl', CertificateAuthorityCRLView),
            ('ocsp', CertificateAuthorityOCSPView),
            ('revoke', CertificateAuthorityRevocationView),
        ])
        return urls_add + super().get_urls()

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return CertificateAuthorityCreationForm
        return super().get_form(request, obj, **kwargs)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:
            self.model.objects.issue(**form.cleaned_data)

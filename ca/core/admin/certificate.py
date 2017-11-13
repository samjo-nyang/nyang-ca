from django.contrib import admin
from django.template.response import TemplateResponse

from ca.core.forms import CertificateCreationForm
from ca.core.internals import encrypt_privkey, get_plain_privkey
from ca.core.models import Certificate
from .utils import get_admin_urls
from .views import CertificateRevocationView
from .x509_mixin import X509MixInAdmin


@admin.register(Certificate)
class CertificateAdmin(X509MixInAdmin):
    list_display = [
        'id', 'subject_str', 'ca', 'serial',
        'created_at', 'expired_at', 'revoked_at',
    ]
    list_display_links = ['subject_str']
    search_fields = ['common_name', 'subject_str', 'serial']

    fieldsets_create = [
        ('General', {
            'fields': ['profile', 'ca', 'ca_password'],
        }),
        ('X509 Basic', {
            'fields': [
                'subject', 'subject_alt_name', 'password', 'privkey_save',
            ],
        }),
    ]

    def get_urls(self):
        urls_add = get_admin_urls(self.model._meta, self.admin_site, [
            ('revoke', CertificateRevocationView),
        ])
        return urls_add + super().get_urls()

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return CertificateCreationForm
        return super().get_form(request, obj, **kwargs)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if not change:
            obj = self.model.objects.issue(**form.cleaned_data)
            if not form.cleaned_data['privkey_save']:
                request.session['privkey'] = obj.private_key_plain
                request.session['passwd'] = form.cleaned_data['password']

    def response_add(self, request, obj, post_url_continue=None):
        privkey = request.session.pop('privkey', None)
        passwd = request.session.pop('passwd', None)
        if privkey:
            return TemplateResponse(request, 'admin/privkey.html', {
                'opts': self.model._meta,
                'object': obj,
                'subject_str': obj.subject_str,
                'privkey': get_plain_privkey(privkey),
                'privkey_encrypted': encrypt_privkey(privkey, passwd),
                'title': 'View private key',
                'media': self.media,
            })
        return super().response_add(request, obj, post_url_continue)

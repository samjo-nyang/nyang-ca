from django import forms
from django.conf import settings

from ca.core.models import CertificateAuthority
from ca.core.validators import validate_general_name_multiline
from .x509_create_mixin import X509CreationFormMixIn


class CertificateAuthorityCreationForm(X509CreationFormMixIn):
    path_length = forms.IntegerField(
        initial=-1, min_value=-1, label='Path Length',
        help_text='Hint: set -1 to NONE',
    )
    name_constraints_permitted = forms.CharField(
        required=False, widget=forms.Textarea,
        validators=[validate_general_name_multiline],
        label='Name Constraints (Permitted)',
    )
    name_constraints_excluded = forms.CharField(
        required=False, widget=forms.Textarea,
        validators=[validate_general_name_multiline],
        label='Name Constraints (Excluded)',
    )
    password_save = forms.BooleanField(
        required=False, initial=False, label='Save Password',
    )

    def __init__(self, *args, **kwargs):
        kwargs['ca_required'] = False
        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()

        ca = self.cleaned_data.get('ca', None)
        password_save = self.cleaned_data['password_save']
        if not ca and password_save:
            self.add_error(
                'password_save',
                'Saving root password is forbidden',
            )

    class Meta:
        model = CertificateAuthority
        fields = [
            'name', 'description', 'child_issuer_alt_name',
            'child_issuer_url', 'child_crl_url', 'child_ocsp_url',
        ]
        help_texts = {
            'child_crl_url': f'Hint: {settings.SITE_URL}crl/name.crl',
            'child_ocsp_url': f'Hint: {settings.SITE_URL}ocsp/name',
        }

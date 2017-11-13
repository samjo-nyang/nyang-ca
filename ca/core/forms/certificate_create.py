from django import forms

from ca.core.models import Certificate
from .x509_create_mixin import X509CreationFormMixIn


class CertificateCreationForm(X509CreationFormMixIn):
    privkey_save = forms.BooleanField(
        required=False, initial=False, label='Save Private Key',
    )

    class Meta:
        model = Certificate
        fields = ['ca']

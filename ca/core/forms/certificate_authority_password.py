from django import forms

from ca.core.internals import decrypt_privkey
from ca.core.models import CertificateAuthority


class CertificateAuthorityPasswordForm(forms.ModelForm):
    required_css_class = 'required'
    password = forms.CharField(widget=forms.PasswordInput())

    def clean_password(self):
        return self.cleaned_data['password'].encode('utf-8')

    def clean(self):
        super().clean()

        password = self.cleaned_data['password']
        if not password:
            self.add_error('password', 'You MUST provide the password')
        else:
            try:
                decrypt_privkey(self.instance.private_key, password)
            except ValueError:
                self.add_error('password', 'WRONG password')

    class Meta:
        model = CertificateAuthority
        fields = []

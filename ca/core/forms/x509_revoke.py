from django import forms

from ca.core.models import X509MixIn


class X509RevocationForm(forms.ModelForm):
    required_css_class = 'required'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['revoked_reason'].required = True

    class Meta:
        model = X509MixIn
        fields = ['revoked_reason']

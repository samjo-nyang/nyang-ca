from django import forms
from django.utils import timezone

from ca.core.fields import SubjectField
from ca.core.internals import decrypt_privkey
from ca.core.models import CertificateAuthority, Profile
from ca.core.validators import validate_general_name_multiline


class X509CreationFormMixIn(forms.ModelForm):
    ca = forms.ModelChoiceField(
        queryset=CertificateAuthority.objects.filter(
            revoked_at__isnull=True, expired_at__gte=timezone.now(),
        ), required=True, label='CA',
    )
    profile = forms.ModelChoiceField(
        queryset=Profile.objects.all(), label='Profile',
    )
    subject = SubjectField(label='Subject')
    subject_alt_name = forms.CharField(
        required=False, widget=forms.Textarea,
        validators=[validate_general_name_multiline],
        label='Subject AltName',
    )
    password = forms.CharField(required=True, widget=forms.PasswordInput)
    ca_password = forms.CharField(
        required=False, widget=forms.PasswordInput, label='CA Password',
        help_text='Ignored when CA have saved password',
    )

    def __init__(self, *args, **kwargs):
        ca_required = kwargs.pop('ca_required', True)

        super().__init__(*args, **kwargs)
        self.fields['ca'].required = ca_required

    def clean_password(self):
        return self.cleaned_data['password'].encode('utf-8')

    def clean_ca_password(self):
        return self.cleaned_data['ca_password'].encode('utf-8')

    def clean(self):
        super().clean()

        ca = self.cleaned_data.get('ca', None)
        ca_password = self.cleaned_data.get('ca_password', None)
        if not ca or ca.saved_password:
            pass
        elif not ca_password:
            self.add_error(
                'ca_password',
                'You MUST provide the ca password',
            )
        else:
            try:
                decrypt_privkey(ca.private_key, ca_password)
            except ValueError:
                self.add_error(
                    'ca_password', 'WRONG ca password',
                )

    def save(self, commit=True):
        obj = super().save(commit=False)
        self._meta.model.objects.issue(**self.cleaned_data, obj=obj)
        if commit:
            obj.save()
        return obj

import secrets

from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.views.generic.edit import UpdateView

from ca.core.forms import CertificateAuthorityPasswordForm
from ca.core.internals import decrypt_passwd
from ca.core.models import Certificate, CertificateAuthority, Profile


class CertificateAuthorityOCSPView(UpdateView):
    admin_site = None
    form_class = CertificateAuthorityPasswordForm
    model = CertificateAuthority
    template_name = 'admin/password.html'

    def get(self, request, *args, **kwargs):
        if self.get_object().saved_password:
            return self.form_valid(None)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(self.admin_site.each_context(self.request))
        context['opts'] = self.model._meta
        context['title'] = 'Re-issue OCSP Certificate'
        context['name'] = 'ocsp'
        context['action'] = 'Re-issue'
        return context

    def form_valid(self, form):
        ca = self.get_object().load()
        profile = Profile.objects.get(name='ocsp')
        if ca.saved_password:
            ca_password = decrypt_passwd(ca.saved_password)
        else:
            ca_password = form.cleaned_data['password']
        password = secrets.token_bytes(32)

        ocsp_cert = Certificate.objects.issue(
            ca=ca, profile=profile, subject=ca.subject,
            subject_alt_name=ca.subject_alt_name(),
            password=password, ca_password=ca_password,
            privkey_save=True, password_save=True,
        )
        ocsp_cert.save()

        if ca.ocsp_certificate:
            ca.ocsp_certificate.revoked_at = timezone.now()
            ca.ocsp_certificate.revoked_reason = 'superseded'
            ca.ocsp_certificate.save()

        ca.ocsp_certificate = ocsp_cert
        ca.save()
        return redirect(self.get_success_url())

    def get_success_url(self):
        meta = self.model._meta
        messages.add_message(
            self.request, messages.SUCCESS,
            'The OCSP certificate is successfully generated',
        )
        return reverse(
            f'admin:{meta.app_label}_{meta.model_name}_change',
            args=[self.get_object().pk],
        )

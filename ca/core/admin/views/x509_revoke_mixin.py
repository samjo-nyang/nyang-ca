from django.contrib import messages
from django.urls import reverse
from django.utils import timezone
from django.views.generic.edit import UpdateView

from ca.core.forms import X509RevocationForm


class X509RevocationViewMixIn(UpdateView):
    admin_site = None
    form_class = X509RevocationForm
    template_name = 'admin/revoke.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(self.admin_site.each_context(self.request))
        context['opts'] = self.model._meta
        return context

    def form_valid(self, form):
        data, instance = form.cleaned_data, form.instance
        instance.revoked_at = timezone.now()
        instance.revoked_reason = data['revoked_reason']
        instance.save()
        return super().form_valid(form)

    def get_success_url(self):
        meta = self.model._meta
        messages.add_message(
            self.request, messages.SUCCESS,
            'This certificate is successfully revoked',
        )
        return reverse(
            f'admin:{meta.app_label}_{meta.model_name}_change',
            args=[self.object.pk],
        )

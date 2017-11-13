from django.contrib import admin
from django.utils import timezone

from ca.core.models import Profile


class StatusFilter(admin.SimpleListFilter):
    title = 'status'
    parameter_name = 'status'

    def lookups(self, request, model_admin):
        return [
            ('valid', 'Valid'),
            ('expired', 'Expired'),
            ('revoked', 'Revoked'),
        ]

    def queryset(self, request, queryset):
        if self.value() == 'revoked':
            return queryset.filter(revoked_at__isnull=False)
        elif self.value() == 'expired':
            return queryset.filter(
                expired_at__lt=timezone.now(),
                revoked_at__isnull=True,
            )
        elif self.value() == 'valid':
            return queryset.filter(
                expired_at__gte=timezone.now(),
                revoked_at__isnull=True,
            )
        return queryset


class ProfileFilter(admin.SimpleListFilter):
    title = 'profile'
    parameter_name = 'profile'

    def lookups(self, request, model_admin):
        profiles = Profile.objects.all()
        return [('_deleted', 'Deleted')] + [
            (profile.name, profile.name.upper())
            for profile in profiles
        ]

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        elif self.value() == '_deleted':
            return queryset.filter(profile__isnull=True)
        return queryset.filter(profile__name=self.value())

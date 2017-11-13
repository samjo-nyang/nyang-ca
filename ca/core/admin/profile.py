from django.contrib import admin

from ca.core.models import Profile


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'key_size', 'expire_days', 'description']
    list_display_links = ['name']
    search_fields = ['name', 'description']
    ordering = ('id', )
    actions = None

    readonly_fields = [
        'name', 'description', 'key_usage_values', 'key_usage_critical',
        'extended_key_usage_values', 'extended_key_usage_critical',
        'cn_in_san', 'key_size', 'expire_days',
    ]

    def get_readonly_fields(self, request, obj=None):
        return [] if obj is None or obj.id > 6 else self.readonly_fields

    def has_delete_permission(self, request, obj=None):
        return obj is None or obj.id > 6

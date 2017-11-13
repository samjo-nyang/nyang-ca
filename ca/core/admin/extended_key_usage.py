from django.contrib import admin

from ca.core.models import ExtendedKeyUsage


@admin.register(ExtendedKeyUsage)
class ExtendedKeyUsageAdmin(admin.ModelAdmin):
    list_display = ['id', 'oid', 'name', 'description']
    list_display_links = ['oid']
    search_fields = ['oid', 'name', 'description']
    ordering = ('id', )
    actions = None

    readonly_fields = ['oid']
    fieldsets = [(None, {
        'fields': ['oid', 'name', 'description'],
    })]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

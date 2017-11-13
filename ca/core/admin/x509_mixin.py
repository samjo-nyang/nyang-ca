from django.contrib import admin

from .filters import ProfileFilter, StatusFilter


class X509MixInAdmin(admin.ModelAdmin):
    actions = None

    list_filter = [StatusFilter, ProfileFilter]
    fields_update_general_common = ['ca', 'profile', 'created_at', 'status']
    fields_x509_basic = [
        'subject_str', 'issuer_str', 'serial', 'not_before', 'not_after',
        'basic_constraints', 'key_usage', 'extended_key_usage',
        'subject_alt_name', 'issuer_alt_name', 'subject_key_identifier',
        'authority_key_identifier', 'crl_distribution_points',
        'authority_info_access',
    ]
    fields_revoked = ['revoked_at', 'revoked_reason']

    def __init__(self, *args, **kwargs):
        fields_update_general = kwargs.pop('fields_update_general', [])
        fieldsets_update = kwargs.pop('fieldsets_update', [])
        fields_x509_extra = kwargs.pop('fields_x509_extra', [])
        fields_readonly_extra = kwargs.pop('fields_readonly_extra', [])

        self.fieldsets_update = [
            ('General', {
                'fields': (
                    fields_update_general
                    + self.fields_update_general_common
                ),
            }),
            ('Certificate', {
                'fields': ['public_key', 'private_key'],
                'classes': ('collapse', 'code'),
            }),
            ('X509', {
                'fields': self.fields_x509_basic + fields_x509_extra
            }),
        ] + fieldsets_update
        self.readonly_fields = (
            ['public_key', 'private_key']
            + self.fields_update_general_common
            + self.fields_x509_basic + fields_x509_extra
            + self.fields_revoked + fields_readonly_extra
        )
        super().__init__(*args, **kwargs)

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return self.fieldsets_create

        if obj.ca and obj.revoked_at:
            fieldsets = self.fieldsets_update
            return fieldsets[:1] + [('Revoked Detail', {
                'fields': self.fields_revoked,
            })] + fieldsets[1:3]
        return self.fieldsets_update

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return []
        return self.readonly_fields

    def save_model(self, request, obj, form, change):
        if change:
            return obj.save()
        return form.save()

    def has_delete_permission(self, request, obj=None):
        return False

    class Media:
        css = {
            'all': {
                'admin/css/ca.css',
            },
        }

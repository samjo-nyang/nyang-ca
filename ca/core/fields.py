from collections import OrderedDict

from django import forms
from django.core.validators import validate_email

from ca.core.constants import SUBJECT_KEYS
from ca.core.validators import validate_country
from ca.core.widgets import SubjectWidget


class SubjectField(forms.MultiValueField):
    def __init__(self, *args, **kwargs):
        fields = (
            forms.CharField(validators=[validate_country]),
            forms.CharField(required=False),
            forms.CharField(required=False),
            forms.CharField(required=False),
            forms.CharField(required=False),
            forms.CharField(max_length=128),
            forms.CharField(required=False, validators=[validate_email]),
        )
        kwargs.setdefault('initial', {})
        kwargs.setdefault('widget', SubjectWidget)
        super().__init__(fields, require_all_fields=False, **kwargs)

    def compress(self, values):
        return OrderedDict([
            (k, v.strip()) for k, v in zip(SUBJECT_KEYS, values)
        ])

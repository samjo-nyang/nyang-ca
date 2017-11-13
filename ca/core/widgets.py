from django.forms import widgets

from ca.core.constants import SUBJECT_KEYS


class LabeledTextInput(widgets.TextInput):
    template_name = 'admin/widgets/labeled_text_input.html'

    def __init__(self, label, *args, **kwargs):
        self.label = label
        super().__init__(*args, **kwargs)

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        context['widget']['label'] = self.label
        context['widget']['required'] = self.attrs.get('required', False)
        return context


class MultiRowWidget(widgets.MultiWidget):
    template_name = 'admin/widgets/multi_row_widget.html'

    class Media:
        css = {
            'all': ('admin/css/multi_row_widget.css', ),
        }


class SubjectWidget(MultiRowWidget):
    def __init__(self, attrs=None):
        super().__init__((
            LabeledTextInput('Country', attrs={'required': True}),
            LabeledTextInput('State'),
            LabeledTextInput('Location'),
            LabeledTextInput('Organization'),
            LabeledTextInput('Organizational Unit'),
            LabeledTextInput('Common Name', attrs={'required': True}),
            LabeledTextInput('Email'),
        ), attrs)

    def decompress(self, value):
        if not value:
            return ['' * 6]
        return [value.get(name, '') for name in SUBJECT_KEYS]

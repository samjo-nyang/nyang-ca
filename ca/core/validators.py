from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from ca.core.utils import parse_general_name


def validate_ca_name(value):
    if not all([x.isalnum() or x in '-_' for x in value]):
        raise ValidationError('CA Name should be alphanumeric or -_')


def validate_country(value):
    if len(value) != 2:
        raise ValidationError('Country should be 2-char code')


def validate_general_name(value):
    value = value.strip()
    if not value:
        return

    try:
        parse_general_name(value)
    except ValueError as e:
        raise ValidationError(str(e))


def validate_general_name_multiline(value):
    for line in value.splitlines():
        validate_general_name(line)


def validate_key_size(value):
    if value < 2048:
        raise ValidationError('Key size should be at least 2048b')
    elif value & (value - 1) != 0:
        raise ValidationError('Key size should be multiple of 2')


def validate_url_multiline(value):
    validator = URLValidator()
    for line in value.splitlines():
        validator(line)

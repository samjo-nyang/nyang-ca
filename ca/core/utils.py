import binascii
from collections import OrderedDict
from ipaddress import ip_address, ip_network

import pytz
from cryptography import x509
from django.utils import timezone

from ca.core.constants import (
    SAN_NAME_TEXT_MAP, SUBJECT_KEY_OID_MAP, SUBJECT_KEYS,
    SUBJECT_TEXT_UPPER_MAP,
)


def safe_getattr(obj, prop):
    try:
        return getattr(obj, prop)
    except ValueError:
        return None


def setattrs(obj, **kwargs):
    for k, v in kwargs.items():
        setattr(obj, k, v)


def sort_subj_dict(subj):
    return sorted(subj.items(), key=lambda x: SUBJECT_KEYS.index(x[0]))


def utc_to_local(dt):
    return dt.replace(tzinfo=pytz.utc).astimezone(
        timezone.get_current_timezone()
    )


def parse_subj_name_str(subj):
    subj_data, key, value = {}, '', ''
    for component in subj.split('/'):
        fragments = component.split('=', 1)
        if len(fragments) > 1:
            if key:
                subj_data[key] = value.strip()
            key = SUBJECT_TEXT_UPPER_MAP[fragments[0].strip()]
            value = fragments[1]
        else:
            value += fragments[0]
    subj_data[key] = value.strip()
    return sort_subj_dict(subj_data)


def parse_subj_name(subj):
    subj_data = {}
    if isinstance(subj, str):
        subj_data = parse_subj_name_str(subj.strip())
    elif isinstance(subj, dict):
        subj_data = sort_subj_dict(subj)
    elif isinstance(subj, OrderedDict):
        subj_data = subj.items()

    return x509.Name([
        x509.NameAttribute(SUBJECT_KEY_OID_MAP[k], v)
        for k, v in subj_data if v
    ])


def format_subj_name(subj):
    return '/' + '/'.join([f'{k}={v}' for k, v in subj.items()])


def parse_general_name(name):
    error_msg = 'Invalid; should be (uri|dns|email|rid|dirname|ip|other):.*'
    if not name or ':' not in name:
        raise ValueError(error_msg)

    typ, name = name.split(':', 1)
    typ, name = typ.lower(), name.strip()
    if typ == 'uri':
        return x509.UniformResourceIdentifier(name)
    elif typ == 'dns':
        return x509.DNSName(name)
    elif typ == 'email':
        return x509.RFC822Name(name)
    elif typ == 'rid':
        return x509.RegisteredID(x509.ObjectIdentifier(name))
    elif typ == 'dirname':
        return x509.DirectoryName(parse_subj_name(name))
    elif typ == 'ip':
        try:
            return x509.IPAddress(ip_address(name))
        except ValueError:
            pass

        try:
            return x509.IPAddress(ip_network(name))
        except ValueError:
            pass

        raise ValueError('Could not parse IP address.')
    elif typ == 'other':
        type_id, value = name.split(',', 1)
        return x509.OtherName(x509.ObjectIdentifier(type_id), value)
    raise ValueError(error_msg)


def format_general_name(name):
    value = name.value
    if isinstance(name, x509.DirectoryName):
        value = format_subj_name(value)
    return f'{SAN_NAME_TEXT_MAP[type(name)]}:{value}'


def format_general_names(names):
    return '\n'.join([format_general_name(name) for name in names])


def format_serial(serial):
    if isinstance(serial, int):
        s = hex(serial)[2:].upper()
    elif isinstance(serial, bytes):
        s = binascii.hexlify(serial).upper().decode('utf-8')
    else:
        s = str(serial)
    return ':'.join(a + b for a, b in zip(s[::2], s[1::2]))

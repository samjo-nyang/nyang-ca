import base64
import time
import urllib
from collections import namedtuple
from datetime import datetime, timedelta

from asn1crypto.ocsp import OCSPRequest
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from ocspbuilder import OCSPResponseBuilder
from oscrypto.asymmetric import load_certificate, load_private_key
from oscrypto.keys import parse_certificate, parse_private

from ca.core.internals import decrypt_passwd
from ca.core.models import Certificate, CertificateAuthority
from ca.core.utils import format_serial


OCSPBuilderData = namedtuple('OCSPBuilderData', [
    'ca_public_key', 'ocsp_public_key', 'ocsp_private_key',
    'ocsp_private_key_passwd', 'expires',
])


def public_key_to_obj(pem_str):
    return load_certificate(parse_certificate(pem_str.encode('utf8')))


def private_key_to_obj(pem_str, passwd):
    return load_private_key(parse_private(
        pem_str.encode('utf8'), decrypt_passwd(passwd),
    ))


class OCSPView(View):
    _BUILDER_DATA_CACHE = {}
    _BUILDER_DATA_CACHE_TIME = 600
    _RESPONSE_CACHE_TIME = 600

    http_method_names = ['get', 'post', 'head', 'options']

    def load_builder_data(self, name):
        try:
            ca = CertificateAuthority.objects.get(name=name)
        except:
            return None

        ocsp_cert = ca.ocsp_certificate
        if not ocsp_cert or ocsp_cert.status() != 'valid':
            return None

        builder_data = OCSPBuilderData(
            ca_public_key=ca.public_key,
            ocsp_public_key=ocsp_cert.public_key,
            ocsp_private_key=ocsp_cert.private_key,
            ocsp_private_key_passwd=ocsp_cert.saved_password,
            expires=time.time() + self._BUILDER_DATA_CACHE_TIME,
        )
        self._BUILDER_DATA_CACHE[name] = builder_data
        return builder_data

    def get_builder_data(self, name):
        builder_data = self._BUILDER_DATA_CACHE.get(name, None)
        if not builder_data or time.time() > builder_data.expires:
            return self.load_builder_data(name)
        return builder_data

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, **kwargs):
        try:
            data = base64.base64decode(
                urllib.parse.unquote(kwargs.pop('data'))
            )
        except:
            data = ''
        return self.process_ocsp_request(kwargs.pop('name'), data)

    def post(self, request, **kwargs):
        return self.process_ocsp_request(kwargs.pop('name'), request.body)

    def process_ocsp_request(self, name, data):
        status = 200
        try:
            response = self.get_ocsp_response(name, data)
        except Exception as e:
            import traceback
            print(traceback.print_exc())
            status = 500
            response = self.fail('internal_error')

        return HttpResponse(
            response.dump(), status=status,
            content_type='application/ocsp-response',
        )

    def fail(self, reason):
        builder = OCSPResponseBuilder(response_status=reason)
        return builder.build()

    def get_ocsp_response(self, name, data):
        builder_data = self.get_builder_data(name)
        if not builder_data:
            return self.fail('unauthorized')

        try:
            ocsp_request = OCSPRequest.load(data)
            tbs_request = ocsp_request['tbs_request']
            extensions = tbs_request['request_extensions']
            request_list = tbs_request['request_list']
            if len(request_list) != 1:
                raise NotImplemented
            req_cert = request_list[0]['req_cert']
            serial = format_serial(req_cert['serial_number'].native)
        except:
            return self.fail('malformed_request')

        cert = Certificate.objects.filter(serial=serial).first()
        if not cert or cert.ca.name != name:
            return self.fail('unauthorized')

        builder = OCSPResponseBuilder(
            response_status='successful',
            certificate=public_key_to_obj(cert.public_key),
            certificate_status=cert.status_ocsp(),
            revocation_date=cert.revoked_at,
        )
        builder.next_update = (
            datetime.utcnow()
            + timedelta(seconds=self._RESPONSE_CACHE_TIME)
        )

        for extension in extensions:
            key = extension['extn_id'].native
            value = extension['extn_value'].parsed
            critical = extension['critical'].native

            unknown = False
            if key == 'nonce':
                builder.nonce = value.native
            else:
                unknown = True

            if unknown and critical:
                return self.fail('malformed_request')

        ca_cert = public_key_to_obj(builder_data.ca_public_key)
        ocsp_cert = public_key_to_obj(builder_data.ocsp_public_key)
        ocsp_key = private_key_to_obj(
            builder_data.ocsp_private_key,
            builder_data.ocsp_private_key_passwd,
        )

        builder.certificate_issuer = ca_cert
        return builder.build(ocsp_key, ocsp_cert)

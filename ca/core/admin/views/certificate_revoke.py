from ca.core.models import Certificate
from .x509_revoke_mixin import X509RevocationViewMixIn


class CertificateRevocationView(X509RevocationViewMixIn):
    model = Certificate

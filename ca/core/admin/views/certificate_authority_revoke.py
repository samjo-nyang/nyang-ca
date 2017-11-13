from ca.core.models import CertificateAuthority
from .x509_revoke_mixin import X509RevocationViewMixIn


class CertificateAuthorityRevocationView(X509RevocationViewMixIn):
    model = CertificateAuthority

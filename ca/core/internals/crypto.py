import base64
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat,
)
from django.conf import settings


def b64enc(b):
    return base64.b64encode(b)


def b64dec(b):
    return base64.b64decode(b)


def get_fernet(salt):
    kdf = Scrypt(
        salt=salt,
        backend=default_backend(),
        **settings.MASTER_PASSWORD_ARGS,
    )
    return Fernet(b64enc(
        kdf.derive(settings.MASTER_PASSWORD)
    ))


def encrypt_passwd(passwd):
    salt = secrets.token_bytes(16)
    passwd_enc = get_fernet(salt).encrypt(passwd)
    return b64enc(salt) + b'$' + b64enc(passwd_enc)


def decrypt_passwd(passwd_stored):
    salt, passwd_enc = passwd_stored.encode('utf-8').split(b'$')
    return get_fernet(b64dec(salt)).decrypt(b64dec(passwd_enc))


def generate_privkey(key_size):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )


def get_plain_privkey(privkey):
    return privkey.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def encrypt_privkey(privkey, passwd):
    algorithm = serialization.BestAvailableEncryption(passwd)
    return privkey.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=algorithm,
    )


def decrypt_privkey(privkey, passwd):
    return serialization.load_pem_private_key(
        privkey.encode('utf-8'), password=passwd,
        backend=default_backend(),
    )

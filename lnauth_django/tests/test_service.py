import binascii

import bech32
import django
from coincurve import PrivateKey
from django.conf import settings
from django.core.cache import cache
from django.urls import include, path

from .. import lnauth

settings.configure(
    DEBUG=True,
    ROOT_URLCONF=__name__,
    LNURL_AUTH_ROOT_DOMAIN="localhost:8000",
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "django.contrib.messages",
        "lnauth_django",
    ],
)

# Reconfigure Django's global settings object
django.setup()


urlpatterns = [
    path("lnauth_django/", include("lnauth_django.urls", namespace="lnauth_django")),
]


def test_ln_auth_flow():

    # Step 1: Generate a new private key and corresponding public key
    private_key = PrivateKey()
    public_key = private_key.public_key.format(compressed=False).hex()

    # Step 2: Get auth URL
    action = "test"
    auth_url_bech32 = lnauth.get_auth_url(action)

    # Step 3: Extract the k1 challenge from the URL
    _, auth_url_bytes = bech32.bech32_decode(auth_url_bech32)
    auth_url = bytes(bech32.convertbits(auth_url_bytes, 5, 8)).decode()
    k1 = auth_url.split("&")[1].split("=")[1]

    # Step 4: Sign the challenge with the private key
    signature = private_key.sign(binascii.unhexlify(k1), hasher=None)
    sig = signature.hex()

    # Step 5: Verify the signature
    lnauth.verify_ln_auth(k1, sig, public_key)

    # Cache should be empty at this point
    assert len(cache._cache) == 0

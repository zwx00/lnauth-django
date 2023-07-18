import binascii
import os

import bech32
from django.conf import settings
from django.core.cache import cache
from django.urls import reverse
from secp256k1 import PublicKey

from . import exceptions


def generate_k1():
    return os.urandom(32)


def get_auth_url(k1: str, action: str):
    reverse_url = reverse("lnauth_django:ln_auth_url")

    cache.set(
        f"lnauth-k1-{k1.hex()}:{action}",
        action,
        timeout=getattr(settings, "LNURL_AUTH_K1_TIMEOUT", 60 * 60),
    )

    url = f"{settings.LNURL_AUTH_ROOT_DOMAIN}{reverse_url}?tag=login&k1={k1.hex()}&action={action}"

    bech32_url = bech32.bech32_encode(
        "lnurl",
        bech32.convertbits(url.encode("utf-8"), 8, 5),
    )

    return bech32_url


def verify_ln_auth(k1: str, sig: str, linking_key: str, action: str):

    try:
        k1_bytes = binascii.unhexlify(k1)
        sig_bytes = binascii.unhexlify(sig)
        linking_key_bytes = binascii.unhexlify(linking_key)
    except binascii.Error:
        raise exceptions.LnAuthException("Invalid hex.")

    if not cache.delete(f"lnauth-k1-{k1_bytes.hex()}:{action}"):
        raise exceptions.LnAuthException("K1 does not exist.")

    linking_key_pubkey = PublicKey(linking_key_bytes, raw=True)

    sig_raw = linking_key_pubkey.ecdsa_deserialize(sig_bytes)

    if not linking_key_pubkey.ecdsa_verify(k1_bytes, sig_raw, raw=True):
        raise exceptions.InvalidSigException("Invalid signature.")

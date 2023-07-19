import binascii

import bech32
from coincurve import PrivateKey
from django.core.cache import cache

from .. import lnauth


def test_ln_auth_flow():

    # Step 1: Generate a new private key and corresponding public key
    private_key = PrivateKey()
    public_key = private_key.public_key.format(compressed=False).hex()

    # Step 2: Generate k1

    k1 = lnauth.generate_k1()

    # Step 3: Get auth URL
    action = "test"
    auth_url_bech32 = lnauth.get_auth_url(k1, action)

    # Step 4: Extract the k1 challenge from the URL
    _, auth_url_bytes = bech32.bech32_decode(auth_url_bech32)
    auth_url = bytes(bech32.convertbits(auth_url_bytes, 5, 8)).decode()
    k1 = auth_url.split("&")[1].split("=")[1]

    # Step 5: Sign the challenge with the private key
    signature = private_key.sign(binascii.unhexlify(k1), hasher=None)
    sig = signature.hex()

    # Step 6: Verify the signature
    lnauth.verify_ln_auth(k1, sig, public_key, action)

    # Cache should be empty at this point
    assert len(cache._cache) == 0

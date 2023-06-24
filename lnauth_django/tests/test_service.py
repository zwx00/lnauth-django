import binascii
from coincurve import PrivateKey
from django.core.cache import cache
from django.urls import reverse
from .. import service

def test_ln_auth_flow():

    # Step 1: Generate a new private key and corresponding public key
    private_key = PrivateKey()
    public_key = private_key.public_key.format(compressed=False).hex()

    # Step 2: Get auth URL
    action = 'test'
    auth_url = service.get_auth_url(action)

    # Step 3: Extract the k1 challenge from the URL
    k1 = auth_url.split('&')[1].split('=')[1]

    # Step 4: Sign the challenge with the private key
    signature = private_key.sign(binascii.unhexlify(k1), hasher=None)
    sig = signature.hex()

    # Step 5: Verify the signature
    service.verify_ln_auth(k1, sig, public_key)

    # Cache should be empty at this point
    assert len(cache._cache) == 0
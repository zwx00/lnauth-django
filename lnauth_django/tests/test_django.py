import binascii

import bech32
import pytest
from coincurve import PrivateKey
from django.test import Client
from django.urls import reverse


@pytest.fixture
def browser_client():
    return Client()


@pytest.fixture
def wallet_client():
    return Client()


def test_ln_auth_flow(browser_client, wallet_client):
    # Generate a new private key and corresponding public key
    private_key = PrivateKey()
    public_key = private_key.public_key.format(compressed=False).hex()

    # Browser generates a LNURL to be used for authentication
    response = browser_client.get(
        reverse("lnauth_django:ln_auth_url_provider"), {"action": "register"}
    )
    assert response.status_code == 200
    auth_url_bech32 = response.json()["url"]

    # Extract the k1 challenge from the URL
    _, auth_url_bytes = bech32.bech32_decode(auth_url_bech32)
    auth_url = bytes(bech32.convertbits(auth_url_bytes, 5, 8)).decode()
    k1 = auth_url.split("&")[1].split("=")[1]
    # Sign the challenge with the private key
    signature = private_key.sign(binascii.unhexlify(k1), hasher=None)
    sig = signature.hex()

    # Verify the signatur
    # Get the session ID
    session_id = browser_client.cookies["sessionid"].value

    # The authenticating wallet calls the ln-auth endpoint
    test_data = {
        "tag": "login",
        "k1": k1,
        "sig": sig,
        "key": public_key,
        "action": "register",
    }
    response = wallet_client.get(reverse("lnauth_django:ln_auth_url"), test_data)

    assert response.status_code == 200

    # Call another endpoint that requires authentication

    # import pdb; pdb.set_trace()
    response = browser_client.get(reverse("auth_view"))

    # Check the session ID is still the same (i.e., the session persisted)
    assert browser_client.cookies["sessionid"].value == session_id
    # Check that the response indicates that the user is authenticated
    assert response.status_code == 200  # Or whatever status code indicates success

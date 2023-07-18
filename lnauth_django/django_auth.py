import random
from importlib import import_module
from logging import getLogger

from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    get_user_model,
)
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.db import IntegrityError, transaction

from . import exceptions, models

logger = getLogger(__name__)
User = get_user_model()


def _perform_callback(callback_path, *args, **kwargs):
    module_path, function_name = callback_path.rsplit(".", 1)
    module = import_module(module_path)
    callback_function = getattr(module, function_name)

    # Call the callback function
    callback_function(*args, **kwargs)


def app_register(request):
    try:
        with transaction.atomic():
            temp_username = f"lnauth_{random.randint(0, 1000000)}"
            user = User.objects.create_user(username=temp_username, password=None)
            lnauthkey = models.LnAuthKey.objects.create(
                user=user, linking_key=request.GET["key"]
            )
            lnauthkey.save()
            user.save()
    except IntegrityError as e:
        logger.info(e)
        raise exceptions.DjangoAuthException("User already registered.")

    callback_path = getattr(settings, "LNURL_AUTH_REGISTER_CALLBACK", False)

    if callback_path:
        _perform_callback(callback_path, request, user)

    if getattr(settings, "LNURL_AUTH_LOGIN_AFTER_REGISTER", True):
        login_after_action(request.GET["k1"], user, request)


def app_login(request):
    try:
        user = User.objects.get(lnauthkey__linking_key=request.GET["key"])
    except User.DoesNotExist as e:
        logger.info(e)
        raise exceptions.DjangoAuthException("User not registered.")

    callback_path = getattr(settings, "LNURL_AUTH_LOGIN_CALLBACK", False)

    if callback_path:
        _perform_callback(callback_path, request, user)

    login_after_action(request.GET["k1"], user, request)


def login_after_action(k1, user, request):

    session_key = cache.get(f"lnauth-k1-{k1}:session_key")

    cache.delete(f"lnauth-k1-{k1}:session_key")

    try:
        Session.objects.get(session_key=session_key)
    except Session.DoesNotExist:
        raise exceptions.DjangoAuthException("Session does not exist.")

    # Update the session with the authenticated user's details
    session_data = SessionStore(session_key=session_key)
    session_data[SESSION_KEY] = user.pk
    session_data[BACKEND_SESSION_KEY] = getattr(settings, "LNURL_AUTH_BACKEND", None)
    session_data[HASH_SESSION_KEY] = user.get_session_auth_hash()

    session_data.save()


def create_and_save_session(k1: str, request):
    timeout = getattr(settings, "LNURL_AUTH_K1_TIMEOUT", 60 * 60)
    request.session["init"] = True
    request.session.save()

    cache.set(
        f"lnauth-k1-{k1.hex()}:session_key",
        request.session.session_key,
        timeout=timeout,
    )

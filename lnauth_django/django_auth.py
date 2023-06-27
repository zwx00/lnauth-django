from importlib import import_module
from logging import getLogger

from django.conf import settings
from django.contrib.auth import get_user_model, login
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

            user = User.objects.create_user(username="LNURL User", password=None)
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
        login(request, user, backend=getattr(settings, "LNURL_AUTH_BACKEND", None))


def app_login(request):
    try:
        user = User.objects.get(lnauthkey__linking_key=request.GET["key"])
    except User.DoesNotExist as e:
        logger.info(e)
        raise exceptions.DjangoAuthException("User not registered.")

    callback_path = getattr(settings, "LNURL_AUTH_LOGIN_CALLBACK", False)

    if callback_path:
        _perform_callback(callback_path, request, user)

    login(request, user, backend=getattr(settings, "LNURL_AUTH_BACKEND", None))

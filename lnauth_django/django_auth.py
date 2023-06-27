from django.conf import settings
from django.contrib.auth import login
from django.db import IntegrityError, transaction

from . import exceptions


def app_register(request):
    try:
        with transaction.atomic():

            user = settings.AUTH_USER_MODEL.objects.create_user(
                username=request.GET["key"], password=request.GET["key"]
            )
            user.lnauthkey.linking_key = request.GET["key"]
            user.lnauthkey.save()
            user.save()
    except IntegrityError:
        raise exceptions.DjangoAuthException("User already registered.")

    login(request, user)


def app_login(request):
    try:
        user = settings.AUTH_USER_MODEL.objects.get(
            lnauthkey__linking_key=request.GET["key"]
        )
    except settings.AUTH_USER_MODEL.DoesNotExist:
        raise exceptions.DjangoAuthException("User not registered.")

    login(request, user)

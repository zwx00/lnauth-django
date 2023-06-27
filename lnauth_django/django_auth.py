from django.contrib.auth import get_user_model, login
from django.db import IntegrityError, transaction

from . import exceptions, models

User = get_user_model()


def app_register(request):
    try:
        with transaction.atomic():

            user = User.objects.create_user(
                username=request.GET["key"], password=request.GET["key"]
            )
            lnauthkey = models.LnAuthKey.objects.create(
                user=user, linking_key=request.GET["key"]
            )
            lnauthkey.save()
            user.save()
    except IntegrityError:
        raise exceptions.DjangoAuthException("User already registered.")

    login(request, user)


def app_login(request):
    try:
        user = User.objects.get(lnauthkey__linking_key=request.GET["key"])
    except User.DoesNotExist:
        raise exceptions.DjangoAuthException("User not registered.")

    login(request, user)

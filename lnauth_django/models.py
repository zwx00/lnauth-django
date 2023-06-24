from django.conf import settings
from django.db import models


class LnAuthKey(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    linking_key = models.CharField(max_length=255, null=True, blank=True, unique=True)

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class LnAuthConfig(AppConfig):
    name = "lnauth_django"

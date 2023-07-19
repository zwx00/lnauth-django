import django
from django.conf import settings
from django.core.management import call_command
from django.http import HttpResponse
from django.urls import include, path

settings.configure(
    DEBUG=True,
    ROOT_URLCONF=__name__,
    LNURL_AUTH_ROOT_DOMAIN="localhost:8000",
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "django.contrib.messages",
        "lnauth_django",
    ],
    USER_MODEL="auth.User",
    SECRET_KEY="test",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
    ],
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
    ALLOWED_HOSTS=["testserver"],
)

# Reconfigure Django's global settings object
django.setup()
call_command("migrate")


def auth_view(request):
    return HttpResponse("Authenticated")


urlpatterns = [
    path("lnauth_django/", include("lnauth_django.urls", namespace="lnauth_django")),
    path("auth-api/", auth_view, name="auth_view"),
]

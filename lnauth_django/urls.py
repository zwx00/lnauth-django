from django.urls import path

from .views import AuthURLProviderView, AuthURLView

app_name = "lnauth_django"
urlpatterns = [
    path(
        "ln-auth-get-url/", AuthURLProviderView.as_view(), name="ln_auth_url_provider"
    ),
    path("ln-auth/", AuthURLView.as_view(), name="ln_auth_url"),
]

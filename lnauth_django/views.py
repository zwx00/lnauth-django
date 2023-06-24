import logging

from django.conf import settings
from django.http import JsonResponse
from django.views import generic

from . import exceptions, service

logger = logging.getLogger(__name__)


class AuthURLProviderView(generic.View):
    def get(self, request):
        if request.GET and "action" in request.GET:
            return JsonResponse(
                {"url": service.get_auth_url(request.GET["action"])}, status=200
            )
        else:
            return JsonResponse({"message": "Invalid request."}, status=400)


class AuthURLView(generic.View):
    def get(self, request):
        if not request.GET:
            return JsonResponse({"message": "Invalid request."}, status=400)

        for key in ["tag", "k1", "action", "sig", "key"]:
            if key not in request.GET:
                return JsonResponse(
                    {"status": "ERROR", "reason": f"Invalid request. Missing '{key}'."},
                    status=400,
                )
        if request.GET["tag"] != "login":
            return JsonResponse(
                {"status": "ERROR", "reason": "Invalid request. Invalid tag."},
                status=400,
            )

        if request.GET["action"] not in getattr(
            settings, "LNURL_AUTH_ALLOWED_ACTIONS", ["login", "register"]
        ):
            return JsonResponse(
                {"status": "ERROR", "reason": "Invalid request. Invalid action."},
                status=400,
            )

        try:
            service.verify_ln_auth(
                request.GET["k1"], request.GET["sig"], request.GET["key"]
            )
        except exceptions.LnAuthException as e:
            return JsonResponse(
                {"status": "ERROR", "reason": f"Invalid request. {e}"}, status=400
            )

        return JsonResponse({"status": "OK"}, status=200)

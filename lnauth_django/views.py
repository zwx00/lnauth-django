import logging

from django.http import JsonResponse
from django.views import generic

from . import django, exceptions, lnauth

logger = logging.getLogger(__name__)


class AuthURLProviderView(generic.View):
    def get(self, request):
        if request.GET and "action" in request.GET:
            return JsonResponse(
                {"url": lnauth.get_auth_url(request.GET["action"])}, status=200
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

        try:
            lnauth.verify_ln_auth(
                request.GET["k1"], request.GET["sig"], request.GET["key"]
            )
        except exceptions.LnAuthException as e:
            return JsonResponse(
                {"status": "ERROR", "reason": f"Invalid request. {e}"}, status=400
            )

        if request.GET["action"] == "login":

            try:
                django.login(request)
            except exceptions.DjangoAuthException as e:
                return JsonResponse(
                    {"status": "ERROR", "reason": f"Unauthorized. {e}"}, status=401
                )

        elif request.GET["action"] == "register":
            try:
                django.register(request)
            except exceptions.DjangoAuthException as e:
                return JsonResponse(
                    {"status": "ERROR", "reason": f"Unauthorized. {e}"}, status=401
                )
        else:
            return JsonResponse(
                {"status": "ERROR", "reason": "Invalid request. Invalid action."},
                status=400,
            )

        return JsonResponse({"status": "OK"}, status=200)

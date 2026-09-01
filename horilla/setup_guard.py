"""
SKOPAQ hardening: close Horilla's first-run setup wizard in production.

WHY THIS FILE EXISTS
--------------------
Upstream guards only the wizard's ENTRY view. `base.views.initialize_database`
opens with::

    if not settings.DEBUG:
        raise Http404

The steps it hands off to carry no such check. `base.views.initialize_database_user`
is decorated only with `@hx_request_required` -- that asks for an `HX-Request`
header, which any client can send -- then reads `username`, `email` and
`password` straight out of POST and calls::

    HorillaUser.objects.create_superuser(...)

Every one of those steps is registered unconditionally in `base/urls.py`. So a
stock production deploy, even with `DEBUG=False`, still answers on
`/initialize-database-user/` and will mint a superuser for whoever asks. The
entry view being closed hides the front door while the side door stands open.

This middleware closes the whole family, and it is deliberately the ONLY thing
standing between the public internet and `create_superuser`, so it fails CLOSED:
any one of three independent signals is enough to 404 a request. If a future
upstream release renames the views, moves them to another module, or changes the
URL prefix, at most one signal goes quiet and the other two still hold.

OPENING IT FOR FIRST-RUN SETUP
------------------------------
Set `HORILLA_ENABLE_SETUP_WIZARD=true`, complete the wizard, then remove the
variable. Do this only while the instance is behind network-level authentication
(for this deployment, Cloudflare Access): the wizard is unauthenticated by
design, because it exists to create the very first account.
"""

import os

from django.http import Http404

#: Values that count as "on". Anything else -- unset, empty, "false", "0" -- is off,
#: because the safe state has to be the one you get by doing nothing.
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: The env var that opens the wizard. Named for the product, not the middleware,
#: so it reads sensibly in a Railway variables list.
ENABLE_FLAG = "HORILLA_ENABLE_SETUP_WIZARD"

#: Signal 1 -- URL names, as registered in base/urls.py ("initialize-database",
#: "initialize-database-user", "initialize-department-edit", ...).
_URL_NAME_PREFIX = "initialize-"

#: Signal 2 -- view callable names ("initialize_database_user", ...).
_VIEW_NAME_PREFIX = "initialize_"

#: Signal 3 -- the request path itself.
_PATH_PREFIX = "/initialize-"


def setup_wizard_enabled() -> bool:
    """True only when the operator has explicitly switched the wizard on."""
    return os.environ.get(ENABLE_FLAG, "").strip().lower() in _TRUTHY


class SetupWizardGuardMiddleware:
    """Return 404 for the database-initialisation views unless explicitly enabled.

    A 404 rather than a 403: an attacker probing for this endpoint learns nothing
    from a response that is indistinguishable from the route not existing, and it
    matches what the guarded upstream entry view already does.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Runs after URL resolution, so `request.resolver_match` is populated.

        Returning ``None`` lets the request continue; raising ``Http404`` hands
        Django its normal not-found path.
        """
        if setup_wizard_enabled():
            return None

        resolver_match = getattr(request, "resolver_match", None)
        url_name = getattr(resolver_match, "url_name", "") or ""
        view_name = getattr(view_func, "__name__", "") or ""
        path = request.path or ""

        if (
            url_name.startswith(_URL_NAME_PREFIX)
            or view_name.startswith(_VIEW_NAME_PREFIX)
            or path.startswith(_PATH_PREFIX)
        ):
            raise Http404

        return None

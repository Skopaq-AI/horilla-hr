"""
SKOPAQ settings overrides, layered on top of upstream's base settings.

`horilla/settings/__init__.py` does `from .base import *` and then imports this
module if it exists. That makes this the supported seam for local changes, and
using it means NO upstream file is modified -- so upstream security releases
merge without conflict, which is the whole reason this deployment runs from our
own fork.

(The sibling `local_settings.py` seam is gitignored upstream, so it cannot carry
anything that has to ship with the image. This file is tracked.)

Keep this file small. Anything substantial belongs in its own module, imported
here -- see `horilla.setup_guard`.
"""

import os

from django.core.exceptions import ImproperlyConfigured

from .base import MIDDLEWARE as _UPSTREAM_MIDDLEWARE

#: Closes the unauthenticated first-run setup wizard. See horilla/setup_guard.py
#: for what upstream leaves open and why this is not optional in production.
_SETUP_WIZARD_GUARD = "horilla.setup_guard.SetupWizardGuardMiddleware"

#: Signs in the visitor Cloudflare Access has already verified, removing the
#: second password prompt. Inert unless CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD
#: are both set -- see horilla/cf_access.py.
_CF_ACCESS_SSO = "horilla.cf_access.CloudflareAccessMiddleware"

#: Django's session/user attachment. The SSO middleware is positioned relative to
#: this NAME rather than to an index, because upstream adds and removes entries
#: from the list above it and an index would silently drift to the wrong slot.
_DJANGO_AUTH = "django.contrib.auth.middleware.AuthenticationMiddleware"

#: Rebuilt as a new list rather than mutated in place: `from .base import *` has
#: already bound the upstream list, and appending to it would edit that same
#: object, which makes the override invisible to anyone reading base.py.
MIDDLEWARE = list(_UPSTREAM_MIDDLEWARE)

#: First in the chain, so a probe for the wizard is refused before any other
#: middleware does work on its behalf.
if _SETUP_WIZARD_GUARD not in MIDDLEWARE:
    MIDDLEWARE.insert(0, _SETUP_WIZARD_GUARD)

#: Immediately AFTER Django's AuthenticationMiddleware and therefore BEFORE
#: Horilla's own (CompanyMiddleware, ForcePasswordChangeMiddleware,
#: TwoFactorAuthMiddleware, ...). Both halves of that matter:
#:
#:   * after, because the SSO middleware needs `request.session` and
#:     `request.user` to exist before it can call `login()`;
#:   * before, because Horilla's middlewares read `request.user` and would
#:     otherwise see AnonymousUser on the very request that signs the visitor in,
#:     bouncing them to /login once before anything worked.
#:
#: Raises rather than guessing if the anchor is gone: a silent append would put
#: SSO at the end of the chain, where it still "works" but only from the second
#: request onward -- the kind of bug that reads as flakiness.
if _CF_ACCESS_SSO not in MIDDLEWARE:
    try:
        _anchor = MIDDLEWARE.index(_DJANGO_AUTH)
    except ValueError as exc:  # pragma: no cover - upstream restructure
        raise ImproperlyConfigured(
            f"{_DJANGO_AUTH} is not in MIDDLEWARE, so {_CF_ACCESS_SSO} cannot be "
            "ordered against it. Upstream has restructured the middleware list; "
            "re-read horilla/cf_access.py for the ordering this depends on."
        ) from exc
    MIDDLEWARE.insert(_anchor + 1, _CF_ACCESS_SSO)


# ---------------------------------------------------------------------------
# CF_ACCESS_ONLY: Cloudflare Access as the SOLE authenticator.
#
# Closing password authentication at the BACKEND rather than by hiding /login/
# is what makes it complete: Django's admin, DRF and any future view that calls
# authenticate() all go through this list, so there is no second door left to
# remember. See horilla/cf_access.py for the reasoning and the break-glass.
#
# The upstream backend is SUBCLASSED, not replaced, so per-company permission
# resolution is untouched -- swapping CompanyScopedBackend out would silently
# change what every user is allowed to do, which is not what "turn off passwords"
# should mean.
#
# Read from the environment here rather than importing horilla.cf_access: this
# module is evaluated while settings are still being assembled, and importing an
# application module that itself imports base.auth_backends would be a circular
# import. The backend is named as a STRING for the same reason -- Django resolves
# it lazily, long after the app registry is ready.
# ---------------------------------------------------------------------------
if (os.environ.get("CF_ACCESS_ONLY") or "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}:
    AUTHENTICATION_BACKENDS = ["horilla.cf_access_backend.AccessOnlyBackend"]

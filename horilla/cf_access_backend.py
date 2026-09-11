"""
SKOPAQ: the authentication backend that makes Cloudflare Access the only door.

Split out of ``horilla/cf_access.py`` ON PURPOSE, and the reason is not tidiness.
Importing ``base.auth_backends`` pulls in the whole ``base`` package, and
``base/__init__.py`` does ``from . import scheduler``, which constructs an
APScheduler ``BackgroundScheduler`` at import time. The middleware in
``cf_access.py`` is named in ``MIDDLEWARE`` and is therefore imported on every
boot, so putting the backend beside it would drag a background scheduler into
that import for every deployment — including ones that never switch this on.

This module is named in ``AUTHENTICATION_BACKENDS`` only when ``CF_ACCESS_ONLY``
is set, and Django resolves that string lazily, so the cost lands only where the
feature is actually in use.
"""

from base.auth_backends import CompanyScopedBackend


class AccessOnlyBackend(CompanyScopedBackend):
    """Refuse every password authentication; Cloudflare Access is the only way in.

    WHY A BACKEND RATHER THAN BLOCKING /login/. Hiding the login page closes one
    door and leaves the others: Django's admin has its own form, DRF has its own
    authenticators, and any future view that calls ``authenticate()`` opens a new
    one. Refusing at the mechanism closes all of them at once, so there is nothing
    to remember to block later.

    WHY IT SUBCLASSES RATHER THAN REPLACES. ``CompanyScopedBackend`` is not only
    an authenticator — it resolves per-company group permissions, and this
    deployment replaces Django's ``ModelBackend`` with it precisely so those
    grants are not unioned with global ones (see the comment above
    ``AUTHENTICATION_BACKENDS`` in settings/base.py). Swapping it out to stop
    password logins would quietly change what every user is allowed to do.
    Subclassing keeps ``_get_group_permissions``, ``get_user`` and ``has_perm``
    exactly as they were and overrides only the method that trades a password for
    a session.

    EXISTING PASSWORDS ARE NOT DELETED, AND THAT IS DELIBERATE. They stop being
    accepted, but nothing is migrated or rewritten — so setting
    ``CF_ACCESS_ONLY=false`` restores the previous behaviour exactly. That is what
    makes the switch safe to try, and it is the break-glass documented in
    ``horilla/cf_access.py``.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Always ``None``: no password is ever exchanged for a session.

        Returning ``None`` rather than raising is what Django expects from a
        backend that declines — it moves on to the next backend, and there is no
        next backend here, so the login form reports ordinary bad credentials
        rather than leaking that password auth has been disabled entirely.
        """
        return None

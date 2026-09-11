"""
SKOPAQ: sign in to Horilla with the identity Cloudflare Access has already verified.

WHY THIS FILE EXISTS
--------------------
hr.skopaq.com sits behind Cloudflare Access, which already proves who the visitor
is before a single byte reaches this application. Horilla then asks them to prove
it a second time with a Django username and password. Two credentials for one
door is not merely irritating: the second one is a password that has to exist, be
rotated and be recovered, for an account whose identity Cloudflare is already
vouching for. This middleware removes it.

THE ONE WAY TO GET THIS CATASTROPHICALLY WRONG
----------------------------------------------
Access forwards two things. `Cf-Access-Jwt-Assertion` is a signed JWT. It also
sets a convenience header, `Cf-Access-Authenticated-User-Email`, which is a plain
string.

**Never authenticate from that second header, and never from an unverified copy
of the first.** Headers are attacker-controlled on any request that reaches the
origin without passing through Access. A single `curl -H
'Cf-Access-Authenticated-User-Email: ceo@skopaq.com'` would then be a complete
authentication bypass of an HR system — salaries, addresses, contracts. The whole
value of this file is the verification below; the convenience header is read
nowhere in it.

That risk is not hypothetical for this deployment. A second Horilla service in
the same Railway project was reachable on a public `*.up.railway.app` domain with
no Access in front of it. The `hr-portal` service has no such domain today — its
only route is the Access-protected custom domain — but "today" is a deployment
detail one dashboard click can change, whereas signature verification holds
whatever the network does. So this middleware is written to be safe even if the
origin becomes publicly reachable.

WHAT IS ACTUALLY CHECKED
------------------------
The token must carry an RS256 signature made by a key Cloudflare currently
publishes for THIS team, and must name THIS application:

* signature   — verified against the team's JWKS at /cdn-cgi/access/certs
* ``aud``     — must equal ``CF_ACCESS_AUD``, the Application Audience tag. This
                is the check people skip, and it is the one that stops a valid
                token minted for a DIFFERENT application on the same Access team
                from being replayed here. A token is only as narrow as its
                audience.
* ``iss``     — must be the team domain
* ``exp`` / ``nbf`` — enforced by PyJWT

FAIL CLOSED, IN BOTH DIRECTIONS
-------------------------------
* Not configured (either env var missing) → this middleware does nothing at all
  and the ordinary Horilla login page still works. Installing the file changes no
  behaviour; setting the variables is the deliberate opt-in.
* Configured but the token is missing, malformed, expired or signed by the wrong
  key → the request simply continues as anonymous. It is never an error and never
  a partial login. Access should already have refused such a request; if one
  arrives anyway, the correct response is to ignore it, not to trust it.

MAKING ACCESS THE ONLY DOOR
---------------------------
Set ``CF_ACCESS_ONLY=true`` and password authentication stops working everywhere
(see ``horilla/cf_access_backend.py``). This is the stronger posture and it is the intended
end state: one credential, verified at the edge by Cloudflare with whatever MFA
the Access policy requires, instead of that PLUS a Django password that has to be
chosen, stored, rotated and recovered.

Turn it on only AFTER a real browser sign-in through Access has been observed to
work. The two switches are separate precisely so SSO can be proven first; turning
both on at once means a failure locks everyone out with no way to tell which half
broke.

BREAKING GLASS
--------------
With ``CF_ACCESS_ONLY=true`` there is no password login, so an Access outage or a
policy mistake locks everyone out, administrators included. Two ways back in, in
order of preference:

1. Set ``CF_ACCESS_ONLY=false`` in the Railway service variables. The service
   redeploys and ordinary password login works again immediately. Nothing was
   migrated or deleted, so this is a true revert.
2. ``manage.py shell`` in the Railway console, which needs no HTTP path at all.

Note that this middleware never removes or rewrites a stored password. That is
what makes (1) an instant revert rather than a recovery exercise.

NO NEW DEPENDENCY
-----------------
PyJWT arrives via ``djangorestframework-simplejwt==5.5.0`` and ``cryptography``
is pinned directly, both already in requirements.txt. ``RSAAlgorithm.from_jwk``
is used rather than ``PyJWKClient`` because it has existed since PyJWT 1.7, so
this does not quietly require a floor that requirements.txt does not state.
"""

import json
import logging
import os
import threading
import time

import requests
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.db import IntegrityError, transaction

import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)

#: Values that count as "on". Anything else — unset, empty, "false", "0" — is off,
#: matching `horilla.setup_guard` so the two read the same way in a variables list.
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Your Access team domain, e.g. "raphaenterprises.cloudflareaccess.com".
ENV_TEAM_DOMAIN = "CF_ACCESS_TEAM_DOMAIN"

#: The Application Audience (AUD) tag from the Access application. NOT optional:
#: without it a token minted for any other app on the same team would be accepted.
ENV_AUD = "CF_ACCESS_AUD"

#: Create a HorillaUser (and link or create an Employee) the first time someone
#: Access has vouched for arrives. Default ON: Access is configured to admit one
#: email domain, so anyone reaching here is already an authorised colleague, and
#: the alternative is an administrator hand-creating a row before each new joiner
#: can log in. Set to "false" to restrict sign-in to accounts that already exist.
ENV_AUTO_PROVISION = "CF_ACCESS_AUTO_PROVISION"

#: Make Cloudflare Access the ONLY way in: password authentication stops working
#: everywhere. Default OFF, because switching it on without SSO already proven to
#: work locks everyone out. See `horilla/cf_access_backend.py` for what it closes
#: "BREAKING GLASS" below for how to get back in.
ENV_ACCESS_ONLY = "CF_ACCESS_ONLY"

#: How long a fetched JWKS is reused. Cloudflare rotates these keys regularly, and
#: a miss is cheap (one HTTPS GET) while a fetch per request would put a network
#: round trip in front of every page load.
_JWKS_TTL_SECONDS = 600

#: A short timeout matters: this fetch sits in the request path on a cache miss,
#: so a hung connection to Cloudflare must not hold a worker thread open.
_JWKS_TIMEOUT_SECONDS = 5

#: Cache of team domain -> (fetched_at, {kid: public_key}).
_jwks_cache: dict = {}
_jwks_lock = threading.Lock()


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def team_domain() -> str:
    """The Access team domain, with any scheme the operator pasted in removed."""
    raw = _env(ENV_TEAM_DOMAIN)
    return raw.replace("https://", "").replace("http://", "").rstrip("/")


def is_configured() -> bool:
    """True only when BOTH the team domain and the audience tag are set.

    Both, because either alone is a misconfiguration that would be worse than
    doing nothing: a team domain without an audience would accept tokens minted
    for any other application on the team.
    """
    return bool(team_domain()) and bool(_env(ENV_AUD))


def auto_provision_enabled() -> bool:
    value = _env(ENV_AUTO_PROVISION).lower()
    return value in _TRUTHY if value else True


def access_only_enabled() -> bool:
    """True when password authentication should be refused everywhere."""
    return _env(ENV_ACCESS_ONLY).lower() in _TRUTHY


def _load_jwks(domain: str, force: bool = False) -> dict:
    """Return ``{kid: public_key}`` for the team, fetching if stale.

    ``force`` bypasses the TTL and is used exactly once per unknown ``kid``, which
    is what makes key rotation invisible: Cloudflare starts signing with a new key
    before the cached set expires, and without this the deployment would reject
    every token for up to the TTL.
    """
    now = time.monotonic()
    with _jwks_lock:
        cached = _jwks_cache.get(domain)
        if cached and not force and (now - cached[0]) < _JWKS_TTL_SECONDS:
            return cached[1]

    # Fetched outside the lock: a slow network call must not block every other
    # worker thread, and the worst case is two threads fetching the same document.
    url = f"https://{domain}/cdn-cgi/access/certs"
    response = requests.get(url, timeout=_JWKS_TIMEOUT_SECONDS)
    response.raise_for_status()
    document = response.json()

    keys = {}
    for key_data in document.get("keys", []):
        kid = key_data.get("kid")
        if not kid:
            continue
        try:
            keys[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))
        except (ValueError, TypeError, KeyError):
            # One unusable key in the set must not discard the usable ones.
            logger.warning("cf_access: skipping unparseable JWKS key kid=%s", kid)

    with _jwks_lock:
        _jwks_cache[domain] = (time.monotonic(), keys)
    return keys


def verified_claims(token: str):
    """Return the token's claims, or ``None`` if it is not trustworthy.

    Every failure path returns ``None`` rather than raising: this runs on every
    request, and an exception here would turn a malformed header into a 500 for a
    visitor who could otherwise simply have been shown the login page.
    """
    domain = team_domain()
    audience = _env(ENV_AUD)
    if not token or not domain or not audience:
        return None

    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        return None
    if not kid:
        return None

    try:
        keys = _load_jwks(domain)
        key = keys.get(kid)
        if key is None:
            # Unknown kid: Cloudflare has probably rotated. Refetch once.
            key = _load_jwks(domain, force=True).get(kid)
    except (requests.RequestException, ValueError) as exc:
        # Cloudflare unreachable. Refuse to authenticate rather than fall back to
        # anything weaker — the visitor still gets the ordinary login page.
        logger.warning("cf_access: could not load JWKS: %s", exc)
        return None

    if key is None:
        return None

    try:
        return jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],  # Pinned: never let the token choose its own.
            audience=audience,
            issuer=f"https://{domain}",
        )
    except jwt.PyJWTError as exc:
        logger.info("cf_access: rejected token: %s", exc)
        return None


def _token_from(request) -> str:
    """The assertion, from the header Access sets or the cookie it drops.

    The cookie is the fallback for a request Cloudflare served from cache or a
    redirect that dropped the header. Both carry the SAME signed JWT, so reading
    either is safe — it is the signature that is trusted, never the transport.
    """
    header = request.META.get("HTTP_CF_ACCESS_JWT_ASSERTION")
    if header:
        return header.strip()
    return (request.COOKIES.get("CF_Authorization") or "").strip()


def _username_for(email: str) -> str:
    """A free username derived from the email's local part.

    HorillaUser inherits AbstractUser, whose ``username`` is unique and required,
    so the local part alone collides as soon as two domains share one. The email
    itself is the identity; this is only a label.
    """
    User = get_user_model()
    base = (email.split("@")[0] or "user")[:140]
    candidate = base
    suffix = 1
    while User.objects.filter(username__iexact=candidate).exists():
        suffix += 1
        candidate = f"{base}{suffix}"[:150]
    return candidate


def _ensure_employee(user, email: str) -> None:
    """Give ``user`` an Employee record, linking an existing one where it exists.

    THIS IS NOT OPTIONAL, AND ITS ABSENCE IS INVISIBLE. Horilla's post-login path
    reads ``request.user.employee_get``; a user without an Employee authenticates
    perfectly and is then redirected straight back to ``/login/``. In a browser
    that is indistinguishable from a rejected password, so SSO would look broken
    while working exactly as designed.

    LINKING MATTERS AS MUCH AS CREATING. ``Employee.email`` is ``unique=True``, so
    when HR has already onboarded someone, creating a second row raises
    IntegrityError and the person can never log in. The normal path for an
    established company is therefore to ADOPT the existing record, not to make one.
    """
    Employee = user._meta.apps.get_model("employee", "Employee")

    if Employee.objects.filter(employee_user_id=user).exists():
        return

    existing = Employee.objects.filter(email__iexact=email).first()
    if existing is not None:
        if existing.employee_user_id_id is None:
            existing.employee_user_id = user
            existing.save()
        else:
            # Someone else already owns this employee row. Do not steal it and do
            # not create a duplicate; leave it for a human to reconcile.
            logger.warning(
                "cf_access: employee %s is already linked to another user; "
                "not reassigning",
                email,
            )
        return

    local_part = email.split("@")[0]
    # Fields are set and then saved explicitly rather than through
    # `get_or_create(defaults=...)`: Employee.save() fires a signal that creates an
    # empty EmployeeWorkInformation, and defaults passed to get_or_create are
    # silently dropped on the branch where that signal has already run.
    employee = Employee(
        employee_user_id=user,
        employee_first_name=(local_part or email)[:200],
        employee_last_name="",
        email=email,
        # Required by the column but unknown to us. Left empty rather than
        # invented — an HR record is exactly the wrong place for a placeholder.
        phone="",
    )
    employee.save()


def _resolve_user(email: str):
    """Find, or optionally create, the account for a verified email address."""
    User = get_user_model()

    user = User.objects.filter(email__iexact=email).first()
    if user is None:
        employee = (
            User._meta.apps.get_model("employee", "Employee")
            .objects.filter(email__iexact=email)
            .exclude(employee_user_id__isnull=True)
            .first()
        )
        if employee is not None:
            user = employee.employee_user_id

    if user is None:
        if not auto_provision_enabled():
            logger.info("cf_access: no account for %s and provisioning is off", email)
            return None
        try:
            with transaction.atomic():
                user = User.objects.create(
                    username=_username_for(email),
                    email=email,
                    # NEVER a privilege grant. An SSO login is proof of identity,
                    # not of authority; staff and superuser stay off until a human
                    # grants them.
                    is_staff=False,
                    is_superuser=False,
                )
                # No password is ever valid for this account. Without this the row
                # carries an empty hash, and any future code path that checks a
                # password would be comparing against something nobody set.
                user.set_unusable_password()
                user.save()
        except IntegrityError as exc:
            logger.warning("cf_access: could not provision %s: %s", email, exc)
            return None

    if not user.is_active:
        # A deactivated account must stay out even with a perfect Access token.
        # Access governs who reaches the door; Horilla governs who still works here.
        logger.info("cf_access: refusing inactive account %s", email)
        return None

    # `base.middleware.ForcePasswordChangeMiddleware` runs AFTER this one and
    # redirects any user carrying `is_new_employee` to /change-password/. For an
    # account that signs in through Access there is no password to change, so that
    # redirect is a dead end the visitor cannot leave. Cleared ONLY for accounts
    # with an unusable password -- a colleague who still has a real Horilla
    # password keeps the normal onboarding flow, because for them the prompt is
    # answerable and meaningful.
    if user.is_new_employee and not user.has_usable_password():
        user.is_new_employee = False
        user.save(update_fields=["is_new_employee"])

    try:
        with transaction.atomic():
            _ensure_employee(user, email)
    except IntegrityError as exc:
        # Log the user in anyway: Horilla will bounce them to /login, which is
        # visible and diagnosable, whereas swallowing the login is not.
        logger.warning("cf_access: could not attach employee for %s: %s", email, exc)

    return user


class CloudflareAccessMiddleware:
    """Log in the visitor Cloudflare Access has already authenticated.

    ORDERING: this must run AFTER ``AuthenticationMiddleware`` (it needs a session
    and ``request.user``) and BEFORE Horilla's own middlewares, which read
    ``request.user`` and would otherwise see an anonymous visitor on the very
    request that signs them in. ``horilla/settings/addons.py`` places it there by
    anchoring on AuthenticationMiddleware rather than by index.

    COST: one RSA signature verification per request once the JWKS is cached —
    tens of microseconds. Deliberately not optimised with a "already logged in,
    skip the check" shortcut: that shortcut is how a session outlives the access
    it was granted under, and re-checking is what makes a revoked Access session
    take effect here on the next request rather than whenever Django's session
    happens to expire.
    """

    def __init__(self, get_response):
        self.get_response = get_response

        # THE ONE COMBINATION THAT LOCKS EVERYBODY OUT: passwords refused, and no
        # working SSO to replace them. The service would boot, serve, and admit
        # nobody -- which looks exactly like "Cloudflare is broken" and costs an
        # hour of looking in the wrong place.
        #
        # Raising here rather than logging is deliberate. Railway keeps the
        # PREVIOUS deployment serving when a new one fails to boot, so this turns
        # a silent lockout into a named error in the deploy log with the old,
        # working version still up. A warning would scroll past.
        if access_only_enabled() and not is_configured():
            from django.core.exceptions import ImproperlyConfigured

            raise ImproperlyConfigured(
                f"{ENV_ACCESS_ONLY} is on, which refuses all password logins, but "
                f"{ENV_TEAM_DOMAIN} and {ENV_AUD} are not both set, so Cloudflare "
                "Access SSO cannot sign anyone in either. Set both, or unset "
                f"{ENV_ACCESS_ONLY}."
            )

    def __call__(self, request):
        if is_configured():
            try:
                self._apply(request)
            except Exception:  # noqa: BLE001
                # An authentication convenience must never take the site down. If
                # anything unforeseen happens, fall through to the normal login
                # page with the traceback in the deploy log.
                logger.exception("cf_access: unexpected failure; ignoring assertion")
        return self.get_response(request)

    def _apply(self, request) -> None:
        claims = verified_claims(_token_from(request))
        email = (claims or {}).get("email", "").strip().lower()

        if not email:
            # No usable assertion. Anything already signed in stays signed in —
            # this middleware's job is to start sessions, not to police the ones
            # Horilla's own login created.
            return

        if request.user.is_authenticated:
            if (request.user.email or "").strip().lower() == email:
                return
            # The verified identity is not the one holding this session. Discard
            # it before adopting the new one, so a shared browser cannot leave one
            # colleague operating inside another's session.
            logout(request)

        user = _resolve_user(email)
        if user is None:
            return

        # `authenticate()` is deliberately not called: there is no password to
        # check, and the identity has already been proven cryptographically. That
        # means `user.backend` is unset, so `login()` needs the backend named.
        # Read from settings rather than hardcoded — this deployment REPLACES
        # ModelBackend with CompanyScopedBackend (see base.py), so a hardcoded
        # "ModelBackend" would raise here.
        backend = settings.AUTHENTICATION_BACKENDS[0]
        login(request, user, backend=backend)
        logger.info("cf_access: signed in %s via Cloudflare Access", email)

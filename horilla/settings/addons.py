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

from .base import MIDDLEWARE as _UPSTREAM_MIDDLEWARE

#: Closes the unauthenticated first-run setup wizard. See horilla/setup_guard.py
#: for what upstream leaves open and why this is not optional in production.
_SETUP_WIZARD_GUARD = "horilla.setup_guard.SetupWizardGuardMiddleware"

#: Rebuilt as a new list rather than mutated in place: `from .base import *` has
#: already bound the upstream list, and appending to it would edit that same
#: object, which makes the override invisible to anyone reading base.py.
MIDDLEWARE = list(_UPSTREAM_MIDDLEWARE)

#: First in the chain, so a probe for the wizard is refused before any other
#: middleware does work on its behalf.
if _SETUP_WIZARD_GUARD not in MIDDLEWARE:
    MIDDLEWARE.insert(0, _SETUP_WIZARD_GUARD)

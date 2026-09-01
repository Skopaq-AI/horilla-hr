#!/bin/sh
#
# SKOPAQ deployment wrapper for Railway.
#
# THE PROBLEM. Railway mounts a volume owned by root:root. This image runs as
# `appuser` (uid 1000, set by the Dockerfile), so with the volume mounted at
# /app/media the first write upstream's entrypoint attempts --
#
#     /entrypoint.sh: line 37: /app/media/.generated_secret_key: Permission denied
#
# -- kills the container, and it restart-loops. Employee document uploads would
# fail identically once the app was running.
#
# WHAT WAS REJECTED. Setting RAILWAY_RUN_UID=0 runs the entire container as
# root; that fixes the write and silently discards the image's non-root
# hardening on the machine holding employee personal data. RAILWAY_RUN_UID=1000
# does not work at all -- Railway does not chown the volume to the run UID
# (tried, identical error).
#
# WHAT THIS DOES. Runs as root only long enough to take ownership of the mount,
# then drops privileges for the process that actually listens on the network.
# Upstream's entrypoint still runs as root, because it has to write to a volume
# nobody owns yet (SECRET_KEY, migrations, collectstatic); by the time gunicorn
# starts we are back to uid 1000.
#
# USAGE (Railway service settings):
#   RAILWAY_RUN_UID = 0
#   Custom Start Command =
#     /app/docker/railway-start.sh gunicorn horilla.wsgi:application \
#       --config docker/gunicorn.conf.py
#
# Railway passes that as arguments to the image's ENTRYPOINT (/entrypoint.sh),
# so the order at runtime is: entrypoint.sh (root) -> this wrapper (root) ->
# gunicorn (appuser).

set -e

APP_USER="${APP_USER:-appuser}"
APP_UID="${APP_UID:-1000}"

# Every path the app must be able to write to at runtime. Add to this list
# rather than chowning /app wholesale: a recursive chown of the entire
# application tree is slow on every boot and hides mistakes.
WRITABLE_PATHS="/app/media /app/staticfiles"

if [ "$(id -u)" = "0" ]; then
  for path in $WRITABLE_PATHS; do
    [ -d "$path" ] || mkdir -p "$path"
    # Only chown when it is not already correct: on a volume with many uploaded
    # files this is the difference between a fast boot and a slow one.
    if [ "$(stat -c '%u' "$path" 2>/dev/null || echo -1)" != "$APP_UID" ]; then
      echo "[railway-start] taking ownership of $path for uid $APP_UID"
      chown -R "$APP_UID:$APP_UID" "$path"
    fi
  done

  # Drop privileges for the long-running process. Three mechanisms, because
  # which of them a slim base image ships varies; failing to drop is NOT
  # acceptable, so if none is present we stop rather than silently serving as
  # root -- that would be the exact outcome this file exists to prevent.
  if command -v runuser >/dev/null 2>&1; then
    echo "[railway-start] dropping to $APP_USER via runuser"
    exec runuser -u "$APP_USER" -- "$@"
  elif command -v setpriv >/dev/null 2>&1; then
    echo "[railway-start] dropping to uid $APP_UID via setpriv"
    exec setpriv --reuid="$APP_UID" --regid="$APP_UID" --init-groups -- "$@"
  elif command -v su >/dev/null 2>&1; then
    echo "[railway-start] dropping to $APP_USER via su"
    exec su -s /bin/sh "$APP_USER" -c 'exec "$0" "$@"' -- "$@"
  else
    echo "[railway-start] FATAL: no runuser/setpriv/su available to drop privileges" >&2
    exit 1
  fi
fi

# Already unprivileged (local docker-compose, or Railway without the root UID):
# nothing to fix, just run.
exec "$@"

#!/bin/sh
# Auto-enrolls on first boot when running the default `victor run`
# command, using VICTOR_ENROLL_TOKEN/VICTOR_CONTROL_PLANE - the env
# vars docs/collector-design.md §11's documented `docker run` example
# already sets. Without this, an operator would have to `docker exec`
# in and run `victor enroll` by hand before the container did anything
# useful, which defeats the point of a one-line `docker run`.
#
# Anything other than the exact `victor run` command (e.g. `victor ui`
# for Standalone Mode, per the other documented example) passes through
# untouched - this script only ever intercepts the one case it needs to.
set -e

if [ "$1" = "victor" ] && [ "$2" = "run" ] && [ ! -f "$HOME/.victor/credentials.json" ]; then
    if [ -n "$VICTOR_ENROLL_TOKEN" ] && [ -n "$VICTOR_CONTROL_PLANE" ]; then
        victor enroll --token "$VICTOR_ENROLL_TOKEN" --control-plane "$VICTOR_CONTROL_PLANE"
    else
        echo "Not enrolled, and VICTOR_ENROLL_TOKEN/VICTOR_CONTROL_PLANE aren't both set." >&2
        echo "Set both for cloud-connected mode, or run this image with 'victor ui' instead for Standalone Mode." >&2
        exit 1
    fi
fi

exec "$@"

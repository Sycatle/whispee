#!/usr/bin/env bash
#
# Runs the web client on the port this branch owns, pointed at this branch's server.
#
# `scripts/dev-env.sh` decides both and explains why they travel together: `WHISPEE_API` is
# read by `apps/web/src/lib/api.ts` *and* computed into the page's CSP, and `WEB_PORT` has to
# match the `ALLOWED_ORIGINS` the server was started with. Starting the client any other way —
# `pnpm run dev` in `apps/web` — reverts to the defaults and reaches the wrong server, or none.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
eval "$(scripts/dev-env.sh)"

echo "dev-web: $WHISPEE_DEV_BRANCH -> port $WEB_PORT, api $WHISPEE_API" >&2
cd apps/web
exec pnpm run dev "$@"

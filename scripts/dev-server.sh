#!/usr/bin/env bash
#
# Runs the delivery service on the database and port this branch owns.
#
# Everything about *which* database and *which* port is in `scripts/dev-env.sh`, including why
# the split exists at all. This script is the half that acts on it: it creates the database if
# this is the branch's first run, and starts the server.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
eval "$(scripts/dev-env.sh)"

# `-d postgres`: connecting to the database being created is not an option, and `whispee` might
# itself be gone after a `down -v`. The `postgres` database is the one that always exists.
psql=(docker exec whispee_pg psql -U whispee -d postgres -tAc)
if ! "${psql[@]}" "select 1 from pg_database where datname = '$WHISPEE_DEV_DATABASE'" | grep -q 1; then
  "${psql[@]}" "create database \"$WHISPEE_DEV_DATABASE\" owner whispee" >/dev/null
  echo "dev-server: created database $WHISPEE_DEV_DATABASE" >&2
fi

echo "dev-server: $WHISPEE_DEV_BRANCH -> $WHISPEE_DEV_DATABASE on $SERVER_ADDR" >&2
exec cargo run -p server "$@"

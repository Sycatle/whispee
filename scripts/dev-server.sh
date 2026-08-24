#!/usr/bin/env bash
#
# Runs the delivery service against a database of its own, named after the branch checked out.
#
# # Why a branch gets its own database
#
# One development Postgres serves every checkout — `docker-compose.yml` publishes a single
# container on 55432, and the worktrees under `.worktrees/` all point at it. Migrations, though,
# are per branch: two branches in flight add `0018_` and `0019_` independently, and neither knows
# about the other's. Whichever one runs first leaves its version row behind, and sqlx then
# refuses to start the other — `Migrate(VersionMissing(18))`, because the database is ahead of
# the code in a direction the code cannot undo.
#
# The recovery for that was to drop the volume, which is destructive to whoever else was using
# it: it took one such drop, on a colleague's branch, to make this script worth writing. Giving
# each branch its own database inside the same container costs a `CREATE DATABASE` and removes
# the conflict entirely. `main` keeps the default `whispee`, so a plain checkout behaves as it
# always did.
#
# # Why it loads .env itself
#
# `crates/server/src/main.rs` reads `DATABASE_URL` from the environment and nothing loads the
# file — `cargo run -p server` on a fresh clone fails with `DATABASE_URL missing`. A worktree is
# worse: `.env` is gitignored, so a newly created one has no file at all. Falling back to
# `.env.example` is safe here because its defaults point at that same throwaway container, and it
# says so on stderr rather than pretending a configuration was found.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

env_file=.env
if [ ! -f "$env_file" ]; then
  env_file=.env.example
  echo "dev-server: no .env, falling back to $env_file" >&2
fi
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

: "${DATABASE_URL:?DATABASE_URL missing from $env_file}"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = HEAD ] && branch=$(git rev-parse --short HEAD)

if [ "$branch" = main ]; then
  database=whispee
else
  # Postgres truncates identifiers at 63 bytes, silently: two long branch names sharing a prefix
  # would collide on the same database without a word about it. Cut it here instead.
  slug=$(printf '%s' "$branch" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_')
  database=$(printf 'whispee_%s' "$slug" | cut -c1-63)
fi

# The DSN's last path segment is the database name. Everything after `?` is left alone — a query
# string can carry `sslmode` and friends, which have nothing to do with which database this is.
base_url=${DATABASE_URL%%\?*}
query=${DATABASE_URL#"$base_url"}
DATABASE_URL="${base_url%/*}/${database}${query}"
export DATABASE_URL

# `-d postgres`: connecting to the database being created is not an option, and `whispee` might
# itself be gone after a `down -v`. The `postgres` database is the one that always exists.
psql=(docker exec whispee_pg psql -U whispee -d postgres -tAc)
if ! "${psql[@]}" "select 1 from pg_database where datname = '$database'" | grep -q 1; then
  "${psql[@]}" "create database \"$database\" owner whispee" >/dev/null
  echo "dev-server: created database $database" >&2
fi

echo "dev-server: $branch -> $database" >&2
exec cargo run -p server "$@"

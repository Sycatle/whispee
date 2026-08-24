#!/usr/bin/env bash
#
# Prints the development environment for the branch checked out, as shell `export` lines:
#
#     eval "$(scripts/dev-env.sh)"
#
# `scripts/dev-server.sh` and `scripts/dev-web.sh` do exactly that. Run it by hand to see what a
# branch resolves to, or to configure a shell for `cargo run -p server` directly.
#
# # Why it prints rather than being sourced
#
# A sourced script sets `-euo pipefail` in the caller's shell, and leaves it set: one typo later
# and an interactive shell exits on a failed `grep`. Printing assignments keeps the strictness
# inside this process, which is where it belongs.
#
# # What a branch gets, and why every value moves together
#
# One development machine runs several checkouts at once — `.worktrees/` exists for that — and
# they used to share one database, one server port and one Vite port. The database was split off
# first; the ports are the same problem. The second server to start fails on `Address already in
# use`, and the second Vite *does not fail*: it slides to the next free port and then talks to
# whichever server is up, which is not the one its branch built.
#
# Four values have to agree for a client to reach a server at all, so all four are derived here
# from one index:
#
#   - `SERVER_ADDR`, where the server listens.
#   - `VITE_API_URL`, where the client looks. It also determines the CSP computed into
#     `index.html` (`apps/web/vite.config.ts`), and a `connect-src` that omits the port blocks
#     the request in the browser before it is sent — no server log, no cause named. See the
#     header of `apps/web/src/lib/csp.ts`.
#   - `ALLOWED_ORIGINS`, the server's CORS list, which defaults to port 5173 alone
#     (`crates/server/src/lib.rs`). A client on another port is refused.
#   - `WEB_PORT`, which `apps/web/vite.config.ts` reads with `strictPort`.
#
# Getting one of the four wrong produces "Failed to fetch" and nothing else. That is the whole
# reason they are computed in one place instead of documented in four.
#
# # Why an index registry and not a hash of the branch name
#
# A hash is three lines and collides silently: two branches land on the same port, and the
# failure is precisely the one this removes. The registry — `whispee-dev-ports` next to the
# shared `.git`, so every worktree sees the same one — records `branch index` and hands out the
# lowest free index. `main` keeps index 0, meaning the ports every document already names.
#
# Delete that file to start the numbering over; nothing else reads it.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

env_file=.env
if [ ! -f "$env_file" ]; then
  env_file=.env.example
  echo "dev-env: no .env, falling back to $env_file" >&2
fi
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

: "${DATABASE_URL:?DATABASE_URL missing from $env_file}"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = HEAD ] && branch=$(git rev-parse --short HEAD)

if [ "$branch" = main ]; then
  index=0
else
  registry="$(git rev-parse --path-format=absolute --git-common-dir)/whispee-dev-ports"
  touch "$registry"

  # The lock, and why it is not paranoia: two agents starting on two worktrees at the same
  # moment is the situation this whole file exists for. Without it both read the same free index
  # and both write it.
  exec 9>"$registry.lock"
  flock 9

  index=$(awk -v b="$branch" '$1 == b { print $2 }' "$registry" | head -n1)
  if [ -z "$index" ]; then
    index=1
    while awk -v i="$index" '$2 == i { found = 1 } END { exit !found }' "$registry"; do
      index=$((index + 1))
    done
    printf '%s %s\n' "$branch" "$index" >> "$registry"
    echo "dev-env: $branch takes index $index" >&2
  fi

  exec 9>&-
fi

# Postgres truncates identifiers at 63 bytes, silently: two long branch names sharing a prefix
# would collide on one database without a word about it. Cut it here instead.
if [ "$index" = 0 ]; then
  database=whispee
else
  slug=$(printf '%s' "$branch" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_')
  database=$(printf 'whispee_%s' "$slug" | cut -c1-63)
fi

# The DSN's last path segment is the database name. Everything after `?` is left alone — a query
# string can carry `sslmode` and friends, which have nothing to do with which database this is.
base_url=${DATABASE_URL%%\?*}
query=${DATABASE_URL#"$base_url"}

server_port=$((8787 + index))
web_port=$((5173 + index))

printf "export DATABASE_URL='%s'\n" "${base_url%/*}/${database}${query}"
printf "export SERVER_ADDR='127.0.0.1:%s'\n" "$server_port"
printf "export VITE_API_URL='http://127.0.0.1:%s'\n" "$server_port"
printf "export ALLOWED_ORIGINS='http://127.0.0.1:%s,http://localhost:%s'\n" "$web_port" "$web_port"
printf "export WEB_PORT='%s'\n" "$web_port"
printf "export WHISPEE_DEV_DATABASE='%s'\n" "$database"
printf "export WHISPEE_DEV_BRANCH='%s'\n" "$branch"

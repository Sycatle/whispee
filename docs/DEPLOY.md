# Deploying Whispee

This document is for putting Whispee on a host other people can reach. It says what to run, what
the deployment learns about the people using it, and what it still does not do — the last section
being the one that matters, because a deployment that only reads the first two would be presented
to users as something it is not.

Read [`../README.md`](../README.md) first, and specifically its status section. Nothing below
changes it: this project has had no external audit and will not receive one.

## What this deployment is

One host, three containers, one domain.

| Container | What it is |
|---|---|
| `postgres` | Postgres 17. Everything the server keeps is here. Not published on any port |
| `server` | The delivery service. Not published on any port either — only the proxy reaches it |
| `web` | Caddy: TLS, the static client on `/`, and everything under `/v1` proxied to `server` |

The client and the API share one origin. The delivery service serves no static file, so the two
*could* live on separate hosts with CORS between them; putting them on one origin removes the
preflight entirely, and with it a failure this repository has already hit twice — a browser that
refuses **before** sending, so the server logs nothing and the message names no cause.

## Before the first start

**The DNS record has to exist and point here.** Caddy obtains the certificate over ACME, which
verifies by connecting back to the domain. A domain that does not resolve yet fails in a way no
retry fixes, and failed attempts are rate-limited — five an hour per domain.

Ports 80 and 443 must reach the host. Port 80 is not decoration: it carries the ACME challenge
and the redirect to HTTPS.

## Starting it

```sh
cd deploy
cp .env.example .env && chmod 600 .env
$EDITOR .env            # WHISPEE_DOMAIN, WHISPEE_ACME_EMAIL, POSTGRES_PASSWORD
docker compose up -d --build
```

Three variables are required, and the compose file enforces them: an unset one stops the stack
with a sentence naming it rather than starting something that half works.

`POSTGRES_PASSWORD` should be generated, not chosen — `openssl rand -base64 32`. It is read by
two containers on a private network and by nothing else, which is what makes a random string with
no mnemonic value the right answer.

Migrations need no step of their own: `server::connect` runs `sqlx::migrate!` on startup, so the
schema and the binary cannot disagree.

## After the first start: the log pin

The server generates the transparency log's signing key on its first boot and prints its public
half on every start:

```sh
docker compose logs server | grep log_key
```

It is printed rather than fetched because the only route carrying it, `/v1/log/sth`, requires a
signed request — an operator has no signing device yet at this point.

Put it in `.env` as `VITE_LOG_PUBKEY` and rebuild the client:

```sh
docker compose up -d --build web
```

What this buys, precisely: a client with the pin refuses any log head signed by a different key.
That is the only check that works on a **first** contact with a server — every other one compares
the server against its own past. In the desktop binary, whose interface is packaged in a signed
artefact, it closes the substitution hole. On the web it does not: this deployment serves both
the pin and the code the pin constrains. There it turns a silent substitution into one that
breaks every client at once, which is worth having and is not a defence.

## Changing the domain means rebuilding the client

The Content-Security-Policy is computed into `index.html` at build time
(`apps/web/src/lib/csp.ts`), and its `connect-src` has to name this deployment's exact origin —
both the `https://` form and the `wss://` one, which it does not infer. `VITE_API_URL` is
therefore a build argument, not an environment variable. Change the domain and run
`docker compose build web`.

The same applies to `VITE_LOG_PUBKEY` and `VITE_MEDIA_URL`.

## Updating

```sh
git pull
cd deploy && docker compose up -d --build
```

The build is `--release`, and there is no way to ask this Dockerfile for anything else. That is
deliberate: OpenMLS 0.8.1 runs a `debug_assert!(false)` before returning its decryption error, so
in a debug build one altered byte in transit panics the process — a denial of service any remote
party can trigger. `CONTRIBUTING.md` states it as an invariant; `deploy/Dockerfile.server` is
where it stops being advice.

## Backups

**The only thing worth backing up is the Postgres volume, and it is the only thing here that
cannot be rebuilt.** Both images are reproducible from the repository; `pgdata` holds every
account, every envelope, every vault page, and the transparency log's signing key.

Losing that key is not the same as losing a database. Clients that have gossiped about this log
will see a new key as a **fork** — which is what the gossip is there to detect — and restoring
from a backup that predates entries clients have already seen looks like a log that shrank, which
is exactly what an attack looks like. Back up the volume, and treat a restore as an incident to
explain rather than a routine operation.

```sh
docker compose exec -T postgres pg_dump -U whispee whispee | zstd > whispee-$(date +%F).sql.zst
```

`caddy_data` holds the certificates and the ACME account key. Losing it is survivable, but a
deployment that rebuilds often and forgets its volume re-issues every time — and Let's Encrypt
counts those: fifty certificates a week per domain, after which the domain is unusable for a
week.

## Turning on push, and what it costs

One variable, `VAPID_SUBJECT` — a `mailto:` or `https:` URL a push service can use to reach
whoever runs this deployment. There is no private key to generate: the pair belongs to the server
and is created on its first start.

```sh
$EDITOR .env            # VAPID_SUBJECT=mailto:ops@example.test
docker compose up -d
```

Left empty, subscriptions still register and nobody is woken — the key route answers 503 and the
client hides the control. A deployment that wants to talk to no push service keeps a fully working
messenger.

**What it discloses, and the settings screen says this before offering the switch.** The browser's
push service — Google for Chrome, Mozilla for Firefox — learns each time a message arrives for one
of your users and can tie that to an address. And this server learns which devices to wake, which
is what sealed sender was arranged to remove: a server that stops waking four members of five can
tell who wrote the next message. Nothing cryptographic answers that. The wake-up itself carries no
text, no sender and no group id.

### Checking it actually works

The suites check the token against RFC 8292 and against the key advertised beside it, against a
fake push service. What they cannot check is that Google and Mozilla agree with that reading, so
one pass through a browser is part of standing a deployment up rather than optional:

1. Open the deployment, create an account, allow notifications, then turn on **Wake this browser
   when a message arrives** in Settings → Notifications.
2. Close every tab of the site.
3. From another account — a second browser profile does — send a message.
4. A notification saying "New message" should appear. Clicking it opens the application.

If nothing arrives, `docker compose logs server | grep -i push` is where the refusal appears: a
`401` means the service rejected the token, a `403` usually means the subscription was minted
against a different key than the one now advertised.

## Calls are not set up here

`MEDIA_URL` and the four variables beside it are for a deployment that already runs a media
server. This compose file runs none, and a deployment that leaves them empty keeps a fully
working messenger: the call route answers 503 — not 404 — and the client hides the button.

Standing LiveKit and coturn up on a public host is its own piece of work: both terminate WebRTC
and want a port range, which is why the development compose gives them `network_mode: host`.
Before doing it, read `crates/server/src/call.rs`. A call leaks more than a message does — the
delivery service sees that somebody is joining a call and towards which group, and the media
server sees who shares a room with whom, and for how long. Neither can hear anything: every frame
is encrypted under a key derived from the MLS epoch, which is never sent anywhere.

## What this deployment does not do

Written here rather than discovered later.

- **No push to the packaged mobile application.** Web Push covers the web client and an Android
  browser; FCM and APNs do not exist, so the Tauri build is only notified while it is open. See
  [`./ROADMAP.md`](./ROADMAP.md) for why, and for what push costs sealed sender.
- **No health endpoint.** The server exposes no route for a load balancer or an uptime check to
  call; `docker compose ps` and the logs are what there is. Adding one means adding a route, and
  it has not been done.
- **No account deletion and no export.** The transparency log is append-only, so an account
  cannot simply be dropped from it. For a deployment inside the EU this is a GDPR gap, not a
  missing convenience — see the roadmap.
- **No monitoring, no alerting, no log shipping.** `RUST_LOG` writes to the container's stdout
  and stops there.
- **One host, no replication.** The server supports several instances — fan-out goes through
  Postgres `LISTEN/NOTIFY` — but nothing here starts more than one, and Postgres has no standby.
- **The rate limit sees the proxy, not the peer — so there is effectively no rate limit.** The
  limit on the open routes reads the address from `ConnectInfo`, which behind Caddy is always
  Caddy's, and it deliberately refuses to read `X-Forwarded-For`: that header is freely forged,
  and trusting it would turn the limit into a header somebody writes in order to bypass it. The
  server's own comment names the consequence — it is then up to the proxy to carry the limit, and
  this one does not, because Caddy's standard build has no rate limiter. One client can exhaust
  the account-creation quota for everybody.
- **The web ships its own weakness.** This host serves the JavaScript and can serve a hostile
  version. No browser policy stands in the way; only the packaged desktop binary closes that path,
  and it moves the trust to the distribution channel — which is what the verifiable release in
  [`./BUILD.md`](./BUILD.md) answers.

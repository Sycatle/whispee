/**
 * Which delivery service this installation talks to.
 *
 * # Why the shell has to be told, and the web does not
 *
 * On the web the answer is the page's own origin: `deploy/` puts one reverse proxy in front of
 * the client and the API, and the development server proxies `/v1`. The empty string means
 * exactly that, and it is a configured value rather than a missing one — see `api.ts`.
 *
 * The packaged shell is loaded from `tauri://`, which names nothing reachable. It used to carry a
 * compiled-in `http://127.0.0.1:8787`, so every build that was installed anywhere could only talk
 * to a server on the same machine. This module is what replaces that constant.
 *
 * # Why nothing here validates
 *
 * The address is parsed and refused in Rust, by `apps/desktop/src/server.rs`, before it is
 * stored. Repeating the rules here would put a second copy of a security decision in the one
 * place that cannot enforce it — the page. What this module does instead is *ask*, and report
 * what the native side answered, message included.
 *
 * The one thing it does on its own is [`reachable`], which is not validation: it is the
 * difference between an address that is well formed and an address where something is listening.
 */
import { invoke } from "@tauri-apps/api/core";

import { isTauri } from "./platform";

/**
 * The address this installation is pointed at, or `null` if it has not been pointed anywhere.
 *
 * `""` on the web — this page's own origin, which is an answer. `null` only ever comes back from
 * a packaged shell on first launch, and it is what puts `app/ServerSetup.tsx` on screen.
 */
export async function configuredServer(): Promise<string | null> {
  if (!isTauri()) return "";

  return (await invoke<string | null>("server_url")) ?? null;
}

/**
 * Records the address, and answers with the form that was stored.
 *
 * The answer is the *normalised* address, not the string that was typed: the two differ by a
 * trailing slash or a default port, and building URLs from a spelling the next launch does not
 * agree with is the kind of difference that shows up as one broken request in ten.
 *
 * Throws with the native side's own message when the address is refused. That message is written
 * to be read by the person typing — see `server.rs`.
 */
export async function chooseServer(raw: string): Promise<string> {
  return invoke<string>("server_set", { url: raw });
}

/**
 * Whether a delivery service answers at this address.
 *
 * # Why `/v1/push/vapid` and not a health route
 *
 * Because it is public (`crates/server/src/routes.rs`), and because both of its answers are
 * informative: 200 when a deployment has configured Web Push, 503 when it has not. Either proves
 * a Whispee server is there. There is no `/v1/health`, and adding a public route for one caller
 * would be adding public surface to answer a question an existing route already answers.
 *
 * A 404 is the useful failure: something is listening, and it is not this. Telling that apart
 * from "nothing is listening" is worth the extra branch, because the two have different fixes —
 * one is a typo in the host, the other a typo in the port.
 */
export type Reach = "ok" | "not-whispee" | "unreachable";

export async function reachable(origin: string): Promise<Reach> {
  try {
    const response = await fetch(`${origin}/v1/push/vapid`, { method: "GET" });

    // 503 is "push is off here", which only a server that has the route can say.
    return response.ok || response.status === 503 ? "ok" : "not-whispee";
  } catch {
    // `fetch` rejects for DNS, TLS, connection refused and a policy refusal alike, and the browser
    // deliberately does not say which — so neither does this.
    return "unreachable";
  }
}

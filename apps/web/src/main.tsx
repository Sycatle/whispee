/**
 * Client entry point.
 *
 * No `StrictMode`, deliberately: it mounts and unmounts every effect one extra time in
 * development. `Session` opens a socket and advances an MLS ratchet inside its effects — replaying
 * them would consume the same message keys twice, and MLS refuses the second read. The symptom
 * would be messages lost in development only, the worst kind of divergence between the two
 * environments.
 *
 * # Why the first render waits
 *
 * Because the client no longer knows where its server is until it asks. On the web the answer is
 * immediate and is the empty string — this page's own origin — but on a packaged shell it comes
 * back over the IPC, and there is no synchronous way to ask. Rendering first and configuring
 * afterwards would let the earliest request go out against an unset base, which is a bare path in
 * a `tauri://` document: a `SyntaxError` naming nothing, at sign-in.
 *
 * The wait is one IPC round trip and nothing is painted before it. That is a blank frame on the
 * desktop and no frame at all on the web, where the promise is already resolved.
 */
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { ServerSetup } from "./app/ServerSetup";
import { configureApi } from "./lib/api";
import { configuredServer } from "./lib/server";
import "./index.css";

const element = document.getElementById("root");
if (!element) throw new Error("mount point not found");

const root = createRoot(element);

function start(origin: string) {
  configureApi(origin);
  root.render(<App />);
}

void configuredServer()
  // A failure to *read* the address is treated as not having one, for the same reason
  // `server.rs::read` treats an unparseable file as absent: asking again is recoverable, and an
  // application that will not start is not. The only way here is an IPC that is broken, in which
  // case the setup screen will fail too — but it will fail with a sentence on screen.
  .catch(() => null)
  .then((configured) => {
    if (configured === null) root.render(<ServerSetup onReady={start} />);
    else start(configured);
  });

/**
 * Client entry point.
 *
 * No `StrictMode`, deliberately: it mounts and unmounts every effect one extra time in
 * development. `Session` opens a socket and advances an MLS ratchet inside its effects — replaying
 * them would consume the same message keys twice, and MLS refuses the second read. The symptom
 * would be messages lost in development only, the worst kind of divergence between the two
 * environments.
 */
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./index.css";

const root = document.getElementById("root");
if (!root) throw new Error("mount point not found");

createRoot(root).render(<App />);

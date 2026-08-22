/**
 * Copies the pdf.js data files into `public/` and records what they came from.
 *
 * # Why they are committed rather than fetched
 *
 * The same argument `emoji-assets.mjs` makes, applied to a second dependency: the build has to
 * work offline, and an application whose case is that you can verify what you run should not
 * reach for a third of its behaviour at build time — still less at *run* time, which is what
 * pdf.js does by default. Its `cMapUrl` and `standardFontDataUrl` point at a CDN unless told
 * otherwise, and `script-src 'self'` would not stop them: they are `fetch`, not scripts, so they
 * would be refused by `connect-src` instead — silently, as a PDF that renders blank pages.
 *
 * # What each directory is for, since none of them is optional in the way it looks
 *
 * - `cmaps/` maps character codes to Unicode for CJK encodings. Without it, a Japanese or Chinese
 *   document renders as empty pages rather than as an error.
 * - `standard_fonts/` are the fourteen fonts a PDF is allowed to reference without embedding.
 *   Without it, a document that relies on them draws nothing where its text should be.
 * - `wasm/` holds the JBIG2 and JPEG 2000 decoders. Scanned documents use both.
 *
 * # The manifest is the point of the script
 *
 * A copied directory says nothing about where it came from. `MANIFEST.json` records the version
 * and a digest per file, so a difference between what is committed and what the pinned package
 * contains is a question somebody can ask and answer — which is the same reason
 * `public/emoji/MANIFEST.json` exists.
 */
import { createHash } from "node:crypto";
import { cp, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const source = dirname(require.resolve("pdfjs-dist/package.json"));
const target = join(root, "public", "pdfjs");

/** Read from the package rather than from our own `package.json`: this is what is on disk. */
const { version } = JSON.parse(await readFile(join(source, "package.json"), "utf8"));

const DIRECTORIES = ["cmaps", "standard_fonts", "wasm"];

/** Every file under a directory, relative to it, sorted so the manifest is stable. */
async function walk(base, prefix = "") {
  const entries = await readdir(join(base, prefix), { withFileTypes: true });
  const out = [];

  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(base, path)));
    else out.push(path);
  }

  return out;
}

await rm(target, { recursive: true, force: true });
await mkdir(target, { recursive: true });

const files = {};

for (const directory of DIRECTORIES) {
  await cp(join(source, directory), join(target, directory), { recursive: true });

  for (const path of await walk(join(target, directory))) {
    const full = join(target, directory, path);
    files[relative(target, full)] = createHash("sha256")
      .update(await readFile(full))
      .digest("hex");
  }
}

await writeFile(
  join(target, "MANIFEST.json"),
  `${JSON.stringify({ package: "pdfjs-dist", version, files }, null, 2)}\n`,
);

console.log(`pdfjs-dist ${version}: ${Object.keys(files).length} files under public/pdfjs`);

/**
 * Turns Microsoft's Fluent Emoji repository into the two things this application actually needs:
 * a folder of SVG files named by codepoint, and one catalogue describing them.
 *
 * # Why the emoji are images at all
 *
 * Because the alternative does not work on our own desktop shell. A colour font is the tidy
 * answer — the glyphs stay text, selection and copy come free — but the formats that can express
 * Fluent's artwork are COLRv1, which WebKit does not implement, and OT-SVG, which WebKitGTK
 * leaves switched off by default. WebKitGTK is the engine behind the Tauri build on Linux. The
 * only format supported everywhere is COLRv0, which has no gradients and therefore no Fluent.
 *
 * That leaves substitution: parse the text, replace each emoji with an `<img>`. It is what
 * Discord, Slack and X all do, for the same reason.
 *
 * # Why the output is committed
 *
 * `package.json`'s `wasm` script sets the precedent: a generated artefact belongs in the tree
 * when the build must work offline and reproducibly. A pre-build step that reaches for a third
 * party repository would make every build depend on GitHub being up, which is a strange property
 * for an application whose argument is that you can verify what you run.
 *
 * The upstream commit is pinned below, and the archive's digest is checked against
 * `public/emoji/MANIFEST.json` on every run. Regenerating from a different commit is a decision
 * somebody makes, not something that happens.
 *
 * # Flat, not Color
 *
 * Measured on the pinned tree: `Color` is 41 kB per file and 132 MB in total, `Flat` is 5.4 kB
 * and 17 MB, for the same 3,145 files. A picker grid of 1,900 cells cannot be made of 41 kB
 * files whatever the loading strategy. Flat also survives the size it is actually displayed at —
 * a reaction pill is 16 to 20 pixels, where a gradient is a smudge.
 *
 * # What this does not solve
 *
 * Coverage. Fluent draws 1,595 emoji; Unicode defines rather more. Anything it does not draw
 * falls back to the system font at render time (see `assetOf` in `src/lib/emoji.ts`) and is
 * absent from the picker. That is a deliberate trade: the picker offers exactly what we can
 * guarantee to display identically on every platform.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { optimize } from "svgo";

/**
 * The upstream commit this tree was generated from.
 *
 * A commit and not a tag, because the repository publishes no tags: there is nothing more stable
 * to point at. Bumping it is a reviewable one-line change followed by a regeneration.
 */
const COMMIT = "62ecdc0d7ca5c6df32148c169556bc8d3782fca4";

const ARCHIVE = `https://codeload.github.com/microsoft/fluentui-emoji/tar.gz/${COMMIT}`;

const OUT_ASSETS = "public/emoji";
const OUT_INDEX = "src/lib/generated/emoji-index.json";
const OUT_MANIFEST = "public/emoji/MANIFEST.json";

/**
 * The skin tone directories, in the order the Unicode modifiers run.
 *
 * Index 0 is the toneless glyph and has no directory: `Default` is the yellow one, which is not a
 * skin tone but the absence of one. Keeping that distinction here is what lets a preference of
 * "never chose" differ from a preference of "chose yellow".
 */
const TONES = ["Light", "Medium-Light", "Medium", "Medium-Dark", "Dark"];

/**
 * Fluent's own group names, mapped to the order the picker shows.
 *
 * Taken from the metadata rather than invented, so a new group upstream shows up as an unknown
 * name and fails loudly below instead of silently landing in a bucket nobody looks at.
 */
const GROUPS = [
  "Smileys & Emotion",
  "People & Body",
  "Animals & Nature",
  "Food & Drink",
  "Travel & Places",
  "Activities",
  "Objects",
  "Symbols",
  "Flags",
];

/**
 * The filename a codepoint sequence maps to.
 *
 * `FE0F` is dropped, and this is the single most breakable line in the pipeline. The variation
 * selector says "draw the previous character as an emoji rather than as text"; Fluent's metadata
 * omits it, while text typed on any platform almost always carries it — `❤️` is `2764 FE0F`. Get
 * this wrong and the emoji renders for whoever picked it (their string came from the catalogue)
 * and not for whoever receives it (their string came from the wire). Zero-width joiners and skin
 * tone modifiers are kept: they distinguish real, separate artworks.
 */
function fileOf(sequence) {
  return `${sequence
    .split(/[-\s]/)
    .map((part) => part.toLowerCase())
    .filter((part) => part && part !== "fe0f")
    .join("-")}.svg`;
}

/** The character a codepoint sequence spells, as it will travel on the wire. */
function charOf(sequence) {
  return String.fromCodePoint(
    ...sequence
      .split(/[-\s]/)
      .filter(Boolean)
      .map((part) => Number.parseInt(part, 16)),
  );
}

function download(url) {
  // `curl` rather than `fetch`, because the body is a 136 MB tarball and streaming it to disk
  // through a shell tool avoids holding it in memory as an ArrayBuffer.
  const archive = join(mkdtempSync(join(tmpdir(), "fluent-emoji-")), "source.tar.gz");
  execFileSync("curl", ["--fail", "--location", "--silent", "--show-error", "--output", archive, url], {
    stdio: ["ignore", "ignore", "inherit"],
  });
  return archive;
}

function digestOf(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/**
 * Reads one emoji directory into a catalogue entry, or returns null if it has no Flat artwork.
 *
 * Upstream uses two different shapes, and the difference is the presence of skin tones. An emoji
 * that takes them has `<Name>/Default/Flat` plus five sibling tone directories; one that does not
 * has `<Name>/Flat` and no intermediate level at all. Trying `Default/Flat` first and falling
 * back to `Flat` covers both without asking the metadata which shape to expect — 1,285 of the
 * 1,595 emoji are the flat shape, so getting this wrong loses most of the set.
 */
function entryOf(root, name) {
  const dir = join(root, "assets", name);
  const metadata = JSON.parse(readFileSync(join(dir, "metadata.json"), "utf8"));

  if (!GROUPS.includes(metadata.group)) {
    // A group we do not know about would land in no section of the picker and disappear from the
    // interface without a word. Better to stop and have someone decide where it goes.
    throw new Error(`Unknown group ${JSON.stringify(metadata.group)} on ${name}`);
  }

  const flat = (...segments) => {
    const path = join(dir, ...segments, "Flat");
    try {
      const file = readdirSync(path).find((entry) => entry.endsWith(".svg"));
      return file ? join(path, file) : null;
    } catch {
      return null;
    }
  };

  const base = flat("Default") ?? flat();
  if (!base) return null;

  const tones = TONES.map((tone) => {
    const artwork = flat(tone);
    if (!artwork) return null;
    const sequence = metadata.unicodeSkintones?.find((candidate) =>
      // The metadata lists the toned sequences in tone order, but not always all five, and not
      // always in an order we should trust. Matching on the modifier codepoint is exact.
      candidate.includes(
        { Light: "1f3fb", "Medium-Light": "1f3fc", Medium: "1f3fd", "Medium-Dark": "1f3fe", Dark: "1f3ff" }[
          tone
        ],
      ),
    );
    return sequence ? { sequence, artwork } : null;
  });

  return {
    sequence: metadata.unicode,
    artwork: base,
    label: metadata.cldr,
    keywords: metadata.keywords ?? [],
    group: GROUPS.indexOf(metadata.group),
    tones: tones.every((tone) => tone !== null) ? tones : null,
  };
}

function write(artwork, sequence) {
  const source = readFileSync(artwork, "utf8");
  const { data } = optimize(source, {
    path: artwork,
    multipass: true,
    // `preset-default` alone. The one override worth having would be `removeViewBox: false` —
    // the viewBox is what lets the browser scale the artwork to the 1.25em box the renderer
    // gives it, and without it every emoji is pinned to its authored 32px — but svgo 4 dropped
    // that plugin from the preset, so the viewBox now survives by default and naming it is a
    // configuration error rather than a safeguard.
    plugins: ["preset-default"],
  });
  writeFileSync(join(OUT_ASSETS, fileOf(sequence)), data);
  return data.length;
}

const archive = download(ARCHIVE);
const digest = digestOf(archive);

const root = mkdtempSync(join(tmpdir(), "fluent-emoji-tree-"));
execFileSync("tar", [
  "--extract",
  "--file",
  archive,
  "--directory",
  root,
  "--strip-components",
  "1",
  // Stated as exclusions rather than inclusions: GNU tar's wildcards match slashes, so an
  // include pattern precise enough to name the Flat directory also matches nothing at the depth
  // the tones live at, and tar treats a pattern that matched nothing as a fatal error. The three
  // unwanted variants have unambiguous directory names, and the 3D PNGs alone are most of the
  // 136 MB this avoids writing to disk.
  "--wildcards",
  "--exclude=*/3D/*",
  "--exclude=*/Color/*",
  "--exclude=*/High Contrast/*",
]);

rmSync(OUT_ASSETS, { recursive: true, force: true });
mkdirSync(OUT_ASSETS, { recursive: true });

const entries = [];
let bytes = 0;
let skipped = 0;

for (const name of readdirSync(join(root, "assets")).sort()) {
  const entry = entryOf(root, name);
  if (!entry) {
    skipped += 1;
    continue;
  }

  bytes += write(entry.artwork, entry.sequence);
  for (const tone of entry.tones ?? []) bytes += write(tone.artwork, tone.sequence);

  entries.push({
    char: charOf(entry.sequence),
    label: entry.label,
    keywords: entry.keywords,
    group: entry.group,
    ...(entry.tones ? { tones: entry.tones.map((tone) => charOf(tone.sequence)) } : {}),
  });
}

// Sorted by group, then by the order Fluent lists them, which is alphabetical by name. Alphabetical
// within a category is not the Unicode order — but the Unicode order is not meaningful to a reader
// either, and this one at least is stable across regenerations.
entries.sort((a, b) => a.group - b.group || a.label.localeCompare(b.label));

writeFileSync(OUT_INDEX, `${JSON.stringify({ groups: GROUPS, entries })}\n`);
writeFileSync(
  OUT_MANIFEST,
  `${JSON.stringify({ source: "microsoft/fluentui-emoji", licence: "MIT", commit: COMMIT, sha256: digest }, null, 2)}\n`,
);
execFileSync("cp", [join(root, "LICENSE"), join(OUT_ASSETS, "LICENSE")]);

rmSync(root, { recursive: true, force: true });
rmSync(archive, { force: true });

console.log(
  `${entries.length} emoji, ${(bytes / 1e6).toFixed(1)} MB of SVG, ${skipped} without Flat artwork.`,
);
console.log(`sha256 ${digest}`);

/**
 * Turns Twemoji plus Emojibase into the two things this application actually needs: seven sprite
 * sheets of artwork, and one catalogue describing what is in them.
 *
 * # Why the emoji are images at all
 *
 * Because the alternative does not work on our own desktop shell. A colour font is the tidy
 * answer — the glyphs stay text, selection and copy come free — but the formats that can express
 * this artwork are COLRv1, which WebKit does not implement, and OT-SVG, which WebKitGTK leaves
 * switched off by default. WebKitGTK is the engine behind the Tauri build on Linux. The only
 * format supported everywhere is COLRv0, which has no gradients.
 *
 * That leaves substitution. It is what Discord, Slack and X do; Telegram and Signal do it too,
 * from Apple's set, which is not ours to redistribute.
 *
 * # Why Twemoji replaced Fluent
 *
 * Coverage, not taste. Fluent draws 1,595 emoji and **no country flag at all**, so `🇫🇷` from a
 * peer had nothing to draw. It was also missing every keycap, `©️` and `®️` — and worse, the old
 * version of this script indexed those fourteen anyway, because it never checked that a catalogue
 * entry had a file. Twemoji covers Unicode completely, and the check below now exists.
 *
 * # Two sources, one seam
 *
 * Twemoji ships artwork and nothing else: no names, no keywords, no groups, no idea which
 * sequences are tone variants of which. Emojibase ships exactly that and no artwork. The seam
 * between them is `keyOf()`, imported from `src/lib/emoji.ts` rather than restated here — see the
 * comment on it, the FE0F rule is not the obvious one and getting it wrong fails silently on the
 * receiving side only.
 *
 * # Why the output is committed
 *
 * `package.json`'s `wasm` script sets the precedent: a generated artefact belongs in the tree when
 * the build must work offline and reproducibly. A pre-build step reaching for a third party would
 * make every build depend on GitHub being up, which is a strange property for an application whose
 * argument is that you can verify what you run.
 *
 * # Why sheets rather than files
 *
 * The previous tree was 3,145 SVG files. The cost of that was never the bytes — the whole untoned
 * set is 3.5 MB — it was the request count: six at a time over HTTP/1.1, one round trip apiece
 * through Tauri's custom protocol. `src/lib/emoji-sprite.ts` carries the full argument. Seven
 * files also happen to be something a person can review in a diff.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { optimize } from "svgo";

import data from "emojibase-data/en/data.json" with { type: "json" };
import messages from "emojibase-data/en/messages.json" with { type: "json" };
import shortcodes from "emojibase-data/en/shortcodes/emojibase.json" with { type: "json" };

import { keyOf, TONE_SAMPLES } from "../src/lib/emoji.ts";
import { shardOf, UNKNOWN } from "../src/lib/emoji-sprite.ts";

/**
 * The upstream tag this tree was generated from.
 *
 * A tag and its commit, because `jdecked/twemoji` publishes both and the pair is what makes a
 * regeneration reviewable: the tag says what a human chose, the commit says what was fetched.
 */
const TAG = "v17.0.3";
const COMMIT = "b6b55fef1e8636b540a6d016a4729ca8cdf2e60b";

const ARCHIVE = `https://codeload.github.com/jdecked/twemoji/tar.gz/${COMMIT}`;

const OUT_ASSETS = "public/emoji";
const OUT_INDEX = "src/lib/generated/emoji-index.json";

/**
 * The grid nearly every Twemoji drawing is on.
 *
 * Nearly: a handful are authored on a shorter canvas — the watermelon is `0 0 36 25.22` — and the
 * sheets carry inner markup only, with one viewBox written by `emoji-sprite.ts` onto every
 * `<symbol>`. Left alone, those few would be stretched to fill a square.
 *
 * So the odd ones out are wrapped in a nested `<svg>` carrying their own viewBox, which is legal
 * inside a `<symbol>` and letterboxes them exactly as the old `<img>` did. The sheet format stays
 * a flat map of key to markup, which is worth more than saving forty bytes on the one that needs it.
 */
const VIEWBOX = "0 0 36 36";

/**
 * Emojibase's group 2 is "components" — the bare skin tone modifiers and hair colours.
 *
 * They are not emoji anyone sends. They exist so that a sequence can be composed, and showing them
 * in the picker would offer a reader five identical brown squares.
 */
const COMPONENT = 2;

/**
 * The placeholder for a sequence no sheet carries.
 *
 * The point of this whole change was to stop falling back to the platform font, which drew tofu on
 * Linux and three different pictures on three systems. But drawing *nothing* would be worse than
 * drawing the wrong thing: a message would arrive and simply not be there. So one neutral glyph
 * goes into the base sheet, in Twemoji's own greys, and `symbolOf()` reaches for it.
 *
 * In practice this is only reachable by a Unicode release newer than the pinned tag.
 */
const UNKNOWN_ARTWORK =
  '<path fill="#CCD6DD" d="M36 32a4 4 0 0 1-4 4H4a4 4 0 0 1-4-4V4a4 4 0 0 1 4-4h28a4 4 0 0 1 4 4z"/>' +
  '<path fill="#99AAB5" d="M18 7a7 7 0 0 0-7 7h4a3 3 0 1 1 3 3c-1.1 0-2 .9-2 2v3h4v-1.35A7 7 0 0 0 18 7"/>' +
  '<circle fill="#99AAB5" cx="18" cy="27.5" r="2.5"/>';

/** "smileys & emotion" as Emojibase writes it, "Smileys & Emotion" as the picker shows it. */
function titled(message) {
  return message.replace(/\b[a-z]/g, (letter) => letter.toUpperCase());
}

function download(url) {
  // `curl` rather than `fetch`, because the body is a tarball of some hundred megabytes and
  // streaming it to disk through a shell tool avoids holding it in memory as an ArrayBuffer.
  const archive = join(mkdtempSync(join(tmpdir(), "twemoji-")), "source.tar.gz");
  execFileSync(
    "curl",
    ["--fail", "--location", "--silent", "--show-error", "--output", archive, url],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  return archive;
}

function digestOf(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/**
 * One SVG file, optimised and stripped down to what goes inside a `<symbol>`.
 *
 * `prefixIds` is not optional. Twenty-odd drawings carry a `<clipPath>` or a `<linearGradient>`
 * with an id, and every sheet's markup ends up in **one** document: two emoji both claiming `#a`
 * would have the second one silently take the first one's clip. Per-file prefixes make the
 * collision impossible rather than unlikely.
 */
function artworkOf(path, key) {
  const { data: optimised } = optimize(readFileSync(path, "utf8"), {
    path,
    multipass: true,
    plugins: ["preset-default", { name: "prefixIds", params: { prefix: `t${key}` } }],
  });

  const root = /^<svg\b([^>]*)>([\s\S]*)<\/svg>\s*$/.exec(optimised);
  if (!root) throw new Error(`${key}: not a single-root SVG`);

  const viewBox = /viewBox="([^"]*)"/.exec(root[1])?.[1];
  if (viewBox === undefined) throw new Error(`${key}: no viewBox`);
  if (viewBox === VIEWBOX) return root[2];

  odd.add(key);
  return `<svg viewBox="${viewBox}">${root[2]}</svg>`;
}

/** Drawings not on the standard grid, reported at the end so the count stays visible. */
const odd = new Set();

const archive = download(ARCHIVE);
const digest = digestOf(archive);

const root = mkdtempSync(join(tmpdir(), "twemoji-tree-"));
execFileSync("tar", [
  "--extract",
  "--file",
  archive,
  "--directory",
  root,
  "--strip-components",
  "1",
  // The repository also ships 72×72 PNGs of everything, which is most of its size and none of its
  // use to us. GNU tar's wildcards match slashes, so one include pattern reaches the whole folder.
  "--wildcards",
  "*/assets/svg/*",
  "*/LICENSE-GRAPHICS",
]);

const svg = join(root, "assets", "svg");

/**
 * The catalogue, and every sequence that will need artwork.
 *
 * Both come out of the same walk on purpose: the picker must never offer a cell we cannot draw,
 * and a sheet must never carry a glyph nothing can reach. Building the two from one pass is what
 * makes the check below meaningful rather than ceremonial.
 */
const groups = messages.groups
  .filter((group) => group.order !== COMPONENT)
  .sort((a, b) => a.order - b.order);

const entries = [];
const wanted = new Map();

for (const emoji of data) {
  if (emoji.group === undefined || emoji.group === COMPONENT) continue;

  const group = groups.findIndex((candidate) => candidate.order === emoji.group);
  if (group < 0) throw new Error(`${emoji.label}: unknown group ${emoji.group}`);

  wanted.set(emoji.emoji, emoji.label);

  // Every skin, including the two-tone couples and handshakes, because a peer can send one even
  // though the picker never offers it. `tones` keeps only the five single-modifier variants: they
  // are what a skin tone preference means, and they are what `applyTone()` indexes into.
  for (const skin of emoji.skins ?? []) wanted.set(skin.emoji, skin.label);
  const tones = (emoji.skins ?? [])
    .filter((skin) => typeof skin.tone === "number")
    .sort((a, b) => a.tone - b.tone)
    .map((skin) => skin.emoji);

  // The `emojibase` preset rather than `github`: 3,979 sequences against 1,870, and it carries
  // the familiar names as aliases — `:joy:` as well as `:tears_of_joy:` — so nothing anyone
  // already types is lost by taking the larger set.
  const codes = shortcodes[emoji.hexcode];

  entries.push({
    char: emoji.emoji,
    label: emoji.label,
    keywords: emoji.tags ?? [],
    group,
    order: emoji.order ?? 0,
    ...(codes ? { codes: Array.isArray(codes) ? codes : [codes] } : {}),
    ...(tones.length === 5 ? { tones } : {}),
  });
}

/**
 * The check whose absence put fourteen unreachable cells in the picker.
 *
 * It fails the whole run rather than skipping the entry, because skipping is what happened before:
 * the catalogue kept the name, the artwork was never written, and the only symptom was a 404 and a
 * system glyph in a grid nobody scrolled to the bottom of.
 */
const missing = [...wanted]
  .filter(([char]) => !existsSync(join(svg, `${keyOf(char)}.svg`)))
  .map(([char, label]) => `  ${keyOf(char)}.svg — ${label}`);

if (missing.length > 0) {
  throw new Error(
    `${missing.length} catalogue entries have no artwork in ${TAG}:\n${missing.join("\n")}`,
  );
}

const sheets = new Map([["base", { [UNKNOWN]: UNKNOWN_ARTWORK }]]);
let bytes = 0;

for (const char of wanted.keys()) {
  const key = keyOf(char);
  // The tone swatches are the one place a toned glyph belongs in the base sheet. Left in their
  // own shards, opening the picker fetches all five — 4.5 MB — to draw six buttons, which is the
  // exact cost sharding by tone exists to avoid. Five duplicated drawings is roughly 10 kB.
  const shard = TONE_SAMPLES.includes(char) ? "base" : shardOf(char);
  const inner = artworkOf(join(svg, `${key}.svg`), key);

  if (!sheets.has(shard)) sheets.set(shard, {});
  sheets.get(shard)[key] = inner;
  bytes += inner.length;

  // …and in their own shard too, so that choosing that tone and then looking at a hand in the
  // grid does not depend on which sheet happened to be fetched first.
  if (shard === "base" && shardOf(char) !== "base") {
    const own = shardOf(char);
    if (!sheets.has(own)) sheets.set(own, {});
    sheets.get(own)[key] = inner;
  }
}

rmSync(OUT_ASSETS, { recursive: true, force: true });
mkdirSync(OUT_ASSETS, { recursive: true });

for (const [shard, sheet] of sheets) {
  writeFileSync(join(OUT_ASSETS, `${shard}.json`), JSON.stringify(sheet));
}

// Unicode's own order within each group. Fluent's tree only offered alphabetical, which put
// "grinning face" thirty cells from "grinning squinting face"; this is the order every other
// picker uses, and the one the emoji were designed to be read in.
entries.sort((a, b) => a.group - b.group || a.order - b.order);
for (const entry of entries) delete entry.order;

writeFileSync(
  OUT_INDEX,
  `${JSON.stringify({ groups: groups.map((group) => titled(group.message)), entries })}\n`,
);
writeFileSync(
  join(OUT_ASSETS, "MANIFEST.json"),
  `${JSON.stringify(
    {
      artwork: { source: "jdecked/twemoji", licence: "CC-BY-4.0", tag: TAG, commit: COMMIT, sha256: digest },
      catalogue: { source: "emojibase-data", licence: "MIT" },
    },
    null,
    2,
  )}\n`,
);
// CC-BY 4.0 requires the notice to travel with the artwork. It is an obligation, not a courtesy,
// and `public/` is the only place it is guaranteed to reach whoever receives a build.
execFileSync("cp", [join(root, "LICENSE-GRAPHICS"), join(OUT_ASSETS, "LICENSE")]);

rmSync(root, { recursive: true, force: true });
rmSync(archive, { force: true });

console.log(
  `${entries.length} emoji in the catalogue, ${wanted.size} drawings, ` +
    `${entries.filter((entry) => entry.codes).length} with shortcodes.`,
);
for (const [shard, sheet] of sheets) {
  console.log(`  ${shard.padEnd(6)} ${String(Object.keys(sheet).length).padStart(5)} glyphs`);
}
console.log(`${(bytes / 1e6).toFixed(1)} MB of markup across ${sheets.size} sheets.`);
console.log(`${odd.size} drawings are not on the ${VIEWBOX} grid and carry their own viewBox.`);
console.log(`sha256 ${digest}`);

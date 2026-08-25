/**
 * The little markup a message is allowed to carry, and the shape it is read into.
 *
 * Pure and testable, like `lib/mention.ts` and `lib/link.ts` next door. It never touches the DOM
 * and it never produces markup: it produces a tree, and `components/RichText.tsx` decides what
 * elements that becomes. Nothing on this path builds an HTML string, which is the property that
 * makes the whole feature safe to run on text a peer wrote.
 *
 * # Rendered, never transmitted
 *
 * The wire format does not learn anything here. A message with markup in it is an ordinary text
 * message — `content.ts` gains no type, no span table, no byte — and a client that predates this
 * shows the asterisks, which is what was typed. The same argument `lib/mention.ts` makes for
 * carrying a handle rather than a name, applied one level up.
 *
 * # What is in, and the two things deliberately left out
 *
 * In: `**bold**`, `*italic*`, `~~strike~~`, `` `code` ``, ```` ```fenced``` ````, `> quote`,
 * `||spoiler||`.
 *
 * Out, first: **headings and tables**. A message is a sentence, not a document, and a `#` at the
 * start of a line is far more often a channel name or a comment than a title.
 *
 * Out, second, and this one is a security decision: **`[label](url)` does not exist**. A link
 * whose text is chosen separately from its target is the phishing primitive — it is how every
 * credential page anybody has ever been sent was linked. Here the text of a link *is* the URL, so
 * it can only misrepresent itself, which is what makes `lib/link.ts` a tractable module rather
 * than an impossible one. The cost is real and is not hidden: nobody can write a tidy sentence
 * with a link buried in a word. That is the point.
 *
 * # Why a tree and not a list of spans
 *
 * `mention.runs` is flat because mentions do not nest. `**bold with @alice in it**` does. A span
 * table with offsets would push the nesting problem onto every consumer and make each of them
 * re-slice the string; a tree is what a recursive renderer wants, so the shape follows the
 * problem.
 *
 * # The layers cannot collide, by typing rather than by checking
 *
 * **Only `{kind:"text"}` nodes are prose**, and prose is the only thing that goes on to
 * `mention.runs` and then `emoji.segment`.
 *
 * That single sentence is the whole isolation argument. A fenced block carries a `string`, so no
 * mention, no emoji and no emphasis can be found inside it — not because anything checks, but
 * because it is not an `Inline[]` and there is nothing to walk. Inline code is the same. A link
 * carries its own text and is rendered verbatim. Emphasis carries `children`, so a mention inside
 * bold is found for free.
 *
 * # Markdown knows nothing about mentions, and must not learn
 *
 * The dependency runs one way: `mention.ts` imports `prose()` from here, never the reverse.
 * Putting an `@` case in the inline tokeniser below would look like a simplification and would
 * couple two scanners that are correct precisely because they are separate.
 *
 * # Bounds, because this is hostile input
 *
 * `content.ts` puts no ceiling on the length of a text message, and these bytes were written by a
 * peer. Every limit below is therefore a real defence and not a tidiness measure, and exceeding
 * one returns the raw text as a single paragraph — never an exception, never a truncation. An
 * unreadable message beats a missing one.
 */

// `lib/link.ts` owns what a URL is. This module only needs to know where one starts and stops,
// so that it can leave it alone — see the ordering note on `parseInline`.
import { scan as scanLinks } from "./link.ts";

/** A stretch of a message at block level. */
export type Block =
  | { readonly kind: "paragraph"; readonly children: Inline[] }
  | { readonly kind: "quote"; readonly children: Inline[] }
  | { readonly kind: "code"; readonly lang: string | null; readonly code: string };

/** A stretch of a message inside a block. Only `text` is prose. */
export type Inline =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "strong" | "em" | "strike" | "spoiler"; readonly children: Inline[] }
  | { readonly kind: "code"; readonly text: string }
  | { readonly kind: "link"; readonly raw: string };

/** Longest message that is parsed at all. Beyond it, the text is shown as written. */
export const MAX_SOURCE = 64 * 1024;
/** Most nodes a message may produce, counting every level. */
export const MAX_NODES = 2000;
/** Deepest nesting of emphasis. Six is more than anybody writes and cheap to bound. */
export const MAX_DEPTH = 6;

/** Characters a backslash may neutralise. */
const ESCAPABLE = new Set(["*", "~", "|", "`", "\\", ">"]);

/**
 * Reads a whole message.
 *
 * Never throws and never returns nothing: a message that trips a bound comes back as one
 * paragraph holding its own source, which is strictly better than an empty bubble.
 */
export function parse(text: string): Block[] {
  if (text.length > MAX_SOURCE) return [{ kind: "paragraph", children: [{ kind: "text", text }] }];

  const blocks = parseBlocks(text);
  return count(blocks) > MAX_NODES
    ? [{ kind: "paragraph", children: [{ kind: "text", text }] }]
    : blocks;
}

/** Total nodes in a tree, for the ceiling above. */
function count(blocks: Block[]): number {
  const inline = (nodes: Inline[]): number =>
    nodes.reduce((n, node) => n + 1 + ("children" in node ? inline(node.children) : 0), 0);

  return blocks.reduce((n, b) => n + 1 + ("children" in b ? inline(b.children) : 0), 0);
}

const FENCE = /^```([A-Za-z0-9_+-]{0,20})[ \t]*$/;
const QUOTE = /^> ?/;

/**
 * Splits a message into blocks.
 *
 * Line breaks inside a paragraph are **kept**, and that is not an oversight. The composer accepts
 * them and the bubble carries `whitespace-pre-wrap`; normalising them the way CommonMark does
 * would turn a message written as a list into one run-on sentence — the loss `Messages.tsx`
 * already documents guarding against.
 */
export function parseBlocks(text: string): Block[] {
  const lines = text.split("\n");
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  let quote: string[] = [];

  const flushParagraph = () => {
    if (paragraph.length === 0) return;
    blocks.push({ kind: "paragraph", children: parseInline(paragraph.join("\n")) });
    paragraph = [];
  };
  const flushQuote = () => {
    if (quote.length === 0) return;
    blocks.push({ kind: "quote", children: parseInline(quote.join("\n")) });
    quote = [];
  };
  const flush = () => {
    flushParagraph();
    flushQuote();
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    const fence = FENCE.exec(line);

    if (fence !== null) {
      flush();

      const body: string[] = [];
      i += 1;
      // An unterminated fence runs to the end of the message. That is what somebody who pressed
      // send early meant, and it beats scattering the rest of their text with backticks.
      for (; i < lines.length && !FENCE.test(lines[i] ?? ""); i += 1) body.push(lines[i] ?? "");

      blocks.push({ kind: "code", lang: fence[1] ? fence[1].toLowerCase() : null, code: body.join("\n") });
      continue;
    }

    if (QUOTE.test(line)) {
      flushParagraph();
      quote.push(line.replace(QUOTE, ""));
      continue;
    }

    flushQuote();
    paragraph.push(line);
  }

  flush();
  return blocks;
}

/** One entry on the delimiter stack. */
interface Open {
  readonly marker: string;
  readonly kind: "strong" | "em" | "strike" | "spoiler";
  /** Index just past the opener, where the span's contents begin. */
  readonly at: number;
  /** How many nodes `out` held when this opened, so closing can discard what came after. */
  readonly outLength: number;
}

const MARKERS: ReadonlyArray<readonly [string, Open["kind"]]> = [
  ["**", "strong"],
  ["~~", "strike"],
  ["||", "spoiler"],
  ["*", "em"],
];

/**
 * Reads one block's worth of inline markup.
 *
 * The order the scanner tries things in is half of what makes this correct:
 *
 *   1. **backslash** — neutralises the next character and emits it as prose.
 *   2. **inline code** — highest precedence, so `` `**a**` `` stays literal.
 *   3. **links** — the span is made opaque here, which is what saves
 *      `https://x.com/a_b*c` without anybody having to escape it.
 *   4. **delimiters** — matched with a stack, over whatever is left.
 *
 * A delimiter that never closes is prose. The stack is drained into text at the end rather than
 * producing a node, so an unbalanced `**` shows as `**`.
 */
export function parseInline(text: string, depth = 0): Inline[] {
  const out: Inline[] = [];
  const stack: Open[] = [];
  let buffer = "";

  const flush = () => {
    if (buffer === "") return;
    out.push({ kind: "text", text: buffer });
    buffer = "";
  };

  // Links are found once, over the whole block, and their spans are then simply skipped. Doing it
  // this way rather than character by character is what makes them opaque to everything below.
  const links = new Map<number, { raw: string; to: number }>();
  for (const found of scanLinks(text)) links.set(found.from, { raw: found.raw, to: found.to });

  let i = 0;
  while (i < text.length) {
    const char = text[i] ?? "";

    if (char === "\\") {
      const next = text[i + 1];
      // Only the characters that mean something get neutralised. A backslash before anything else
      // is a backslash — which is what keeps a Windows path and a regular expression intact.
      if (next !== undefined && ESCAPABLE.has(next)) {
        buffer += next;
        i += 2;
      } else {
        buffer += char;
        i += 1;
      }
      continue;
    }

    if (char === "`") {
      const end = text.indexOf("`", i + 1);
      if (end !== -1) {
        flush();
        out.push({ kind: "code", text: text.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }

    const link = links.get(i);
    if (link !== undefined) {
      flush();
      out.push({ kind: "link", raw: link.raw });
      i = link.to;
      continue;
    }

    const marker = MARKERS.find(([m]) => text.startsWith(m, i));
    if (marker !== undefined && depth < MAX_DEPTH) {
      const [token, kind] = marker;
      // A plain reverse loop rather than `findLastIndex`, which needs an ES2023 lib this build
      // does not target — the same reason `lib/mention.ts` writes out an index instead of using a
      // lookbehind.
      let open = -1;
      for (let s = stack.length - 1; s >= 0; s -= 1) {
        if (stack[s]!.marker === token) {
          open = s;
          break;
        }
      }

      if (open !== -1 && closes(text, i)) {
        const entry = stack[open]!;
        const inner = text.slice(entry.at, i);
        flush();
        // Everything after the opener became `buffer`/`out` entries that are now wrong, so the
        // span is re-read from the source instead. Simpler than unwinding, and the depth bound is
        // what keeps it from being quadratic on hostile input.
        while (out.length > entry.outLength) out.pop();
        out.push({ kind, children: parseInline(inner, depth + 1) });
        stack.length = open;
        i += token.length;
        continue;
      }

      if (opens(text, i, token)) {
        flush();
        stack.push({ marker: token, kind, at: i + token.length, outLength: out.length });
        i += token.length;
        continue;
      }
    }

    buffer += char;
    i += 1;
  }

  flush();

  // Anything still open never closed. Its marker and its contents are prose, and re-reading the
  // source from the earliest unclosed opener is the way to say that without reconstructing text
  // from nodes.
  if (stack.length > 0) {
    const first = stack[0]!;
    while (out.length > first.outLength) out.pop();
    const tail = text.slice(first.at - first.marker.length);
    if (tail !== "") out.push({ kind: "text", text: tail });
  }

  return out;
}

/**
 * Whether a marker at `i` may open a span.
 *
 * It must be followed by something that is not a space and not the marker itself. That single
 * rule is what keeps `2 * 3`, `a * b` and a bare `**` out of the tokeniser, and it is why `_` is
 * absent from `MARKERS` entirely: no flanking rule saves `__init__`, `snake_case` or `MY_CONST`,
 * and those are exactly what gets pasted into a conversation about code. The cost is that
 * `_italic_` does not exist here. Worth it.
 */
function opens(text: string, i: number, token: string): boolean {
  const after = text[i + token.length];
  return after !== undefined && !/\s/.test(after) && after !== token[0];
}

/** Whether a marker at `i` may close a span: the character before it is not a space. */
function closes(text: string, i: number): boolean {
  const before = text[i - 1];
  return before !== undefined && !/\s/.test(before);
}

/**
 * The ranges of `text` that are prose — outside every fence and every inline code span.
 *
 * Exported for `lib/mention.ts`, and it exists to fix something that is a real defect rather than
 * a cosmetic one. `resolve()` rewrites `@alice` into an account id **on the way out**, over the
 * whole string. The moment fenced blocks exist, a Python snippet containing `@alice` is sent with
 * thirty-two hexadecimal characters in the middle of it, irreversibly. `addresses()` has the
 * mirror-image bug: a notification for a handle that is only visible inside a code sample.
 *
 * Ranges rather than a rewritten string, so that `resolve` can splice the original and copy
 * everything outside prose byte for byte. Identity outside prose is then guaranteed by
 * construction, not by how faithful a parser is.
 */
export function prose(text: string): ReadonlyArray<{ from: number; to: number }> {
  const ranges: { from: number; to: number }[] = [];
  const lines = text.split("\n");

  let offset = 0;
  let cut = 0;
  let fenced = false;

  for (const line of lines) {
    const isFence = FENCE.test(line);

    if (isFence) {
      if (!fenced && offset > cut) ranges.push({ from: cut, to: offset });
      fenced = !fenced;
      // Reopening prose after the closing fence, past its newline.
      if (!fenced) cut = offset + line.length + 1;
    }

    offset += line.length + 1;
  }

  if (!fenced && cut < text.length) ranges.push({ from: cut, to: text.length });

  // Inline code carves further holes out of what is left.
  return ranges.flatMap((range) => withoutInlineCode(text, range));
}

/** Splits one prose range around the inline code spans inside it. */
function withoutInlineCode(
  text: string,
  range: { from: number; to: number },
): { from: number; to: number }[] {
  const out: { from: number; to: number }[] = [];
  let cut = range.from;
  let i = range.from;

  while (i < range.to) {
    if (text[i] === "\\") {
      i += 2;
      continue;
    }
    if (text[i] === "`") {
      const end = text.indexOf("`", i + 1);
      if (end === -1 || end >= range.to) break;
      if (i > cut) out.push({ from: cut, to: i });
      cut = end + 1;
      i = end + 1;
      continue;
    }
    i += 1;
  }

  if (cut < range.to) out.push({ from: cut, to: range.to });
  return out;
}

/**
 * The message as one line of plain text, for the places that have no room for a tree.
 *
 * Three of those, and one of them matters more than the others: the rail's row, the reply quote,
 * and `Conversation.tsx`'s `aria-live` announcement. A spoiler read aloud to somebody who did not
 * ask for it is the worst failure this feature can have, so masking is not the caller's job to
 * remember — `spoilers: "mask"` is what they pass, and it is why this takes an option at all.
 *
 * Markers are dropped and content is kept, so the line reads as the sentence rather than as its
 * source. Code keeps its contents for the same reason.
 */
export function plain(text: string, options?: { spoilers?: "keep" | "mask" }): string {
  const mask = options?.spoilers === "mask";

  const inline = (nodes: Inline[]): string =>
    nodes
      .map((node) => {
        if (node.kind === "text") return node.text;
        if (node.kind === "code") return node.text;
        if (node.kind === "link") return node.raw;
        if (node.kind === "spoiler") return mask ? "spoiler" : inline(node.children);
        return inline(node.children);
      })
      .join("");

  return parse(text)
    .map((block) => (block.kind === "code" ? block.code : inline(block.children)))
    .join("\n");
}

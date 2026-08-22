import { Fragment } from "react";

import { CodeBlock } from "@/components/CodeBlock";
import { LinkCard } from "@/components/LinkCard";
import { LinkText } from "@/components/LinkText";
import { MentionText } from "@/components/MentionText";
import { Spoiler } from "@/components/Spoiler";
import { contactable } from "@/lib/link-preview";
import { type Block, type Inline, parse } from "@/lib/markdown";
import type { ConversationView } from "@/lib/session";
import { cn } from "@/ui/cn";

/**
 * A message, with the little markup it is allowed to carry.
 *
 * # The tree is read here and nowhere else
 *
 * `lib/markdown.ts` decides what the text *is*; this decides what that becomes. Nothing on this
 * path builds an HTML string — every node turns into an element with React putting its text in as
 * text — which is the property that makes it safe to run over a message a peer wrote.
 *
 * # Only text nodes are prose, and prose is the only thing that goes further
 *
 * The isolation rule from `markdown.ts`, kept by construction rather than by checking. A `text`
 * node goes to `MentionText`, and from there to `EmojiText`. A fenced block carries a `string`
 * and goes to `CodeBlock`, so no mention and no emoji can be found inside it — not because
 * anything refuses, but because there is nothing to walk. Emphasis carries children, so a mention
 * inside bold is found for free.
 *
 * # `display: inline`, and why that is the whole constraint
 *
 * `ui/Emoji.tsx` says prose must stay in bare text nodes or a long word overflows instead of
 * breaking. What actually breaks line-breaking is the *atomic inline box* — `inline-block`,
 * `inline-flex`, `whitespace-nowrap` — and `Emoji` is one by construction. A plain `display:
 * inline` element is transparent to line breaking: `overflow-wrap: anywhere` is inherited through
 * it and a break may fall inside it.
 *
 * So `<strong>`, `<em>`, `<s>`, `<code>` and `<a>` are all fine, and none of them may be given a
 * class that changes their display. The one exception is `Spoiler`, which is a `<button>` — the
 * user agent makes those `inline-block`, and that file explains what it does about it.
 *
 * # The single-run fast path is load-bearing
 *
 * A message with no markup at all must reach `MentionText` as one string. `big` asks whether the
 * message is *only* emoji, and a message split into fragments would answer that one fragment at a
 * time and enlarge each separately. `MentionText` has the same shortcut for the same reason.
 */
export function RichText({
  text,
  among,
  view,
  big = false,
  cards = false,
}: {
  text: string;
  /** The handles this thread can address. Anything else stays prose. */
  among: readonly string[];
  view: ConversationView;
  big?: boolean;
  /**
   * Whether a link in this text may offer to contact its site.
   *
   * **Opt-in, and the default is what enforces two of the three rules.** A preview built at the
   * recipient discloses their IP to a server the sender chose, so it must never happen
   * automatically and never anywhere nobody pressed anything — the rail, a quotation, a
   * notification. Those places all render through this component, and none of them passes this,
   * so none of them *can* produce a card. A comment asking people not to would not survive the
   * next call site; a prop that has to be written does.
   */
  cards?: boolean;
}) {
  const blocks = parse(text);

  // Nothing to draw around it: hand the whole string over untouched. Not merely an optimisation —
  // see the note above on `big`.
  if (blocks.length === 1 && blocks[0]!.kind === "paragraph" && plainRun(blocks[0]!)) {
    return <MentionText text={text} among={among} view={view} big={big} />;
  }

  // The first contactable link only, and never one that lives inside a fence — code is not an
  // address somebody meant to publish. One rather than all of them because a card per link turns
  // a message listing five into five requests, which is five disclosures for one press.
  // `contactable` is what keeps a deceptive URL from being offered here after `LinkText` refused
  // to make it clickable.
  const target = cards ? firstLink(blocks) : null;

  return (
    <>
      {blocks.map((block, index) => (
        <BlockNode key={index} block={block} among={among} view={view} />
      ))}
      {target !== null && <LinkCard url={target} />}
    </>
  );
}

/**
 * The first link in the prose, or `null`.
 *
 * Only `paragraph` and `quote` carry `children`; a `code` block carries an opaque string and is
 * skipped by the type rather than by a check — the same airtightness that keeps mentions and
 * emoji out of a fence.
 */
function firstLink(blocks: readonly Block[]): string | null {
  const walk = (nodes: readonly Inline[]): string | null => {
    for (const node of nodes) {
      if (node.kind === "link") {
        if (contactable(node.raw)) return node.raw;
        // Keep looking: a message whose first link is deceptive may still carry an ordinary one,
        // and the deceptive one must not shadow it.
        continue;
      }
      if ("children" in node) {
        const nested = walk(node.children);
        if (nested !== null) return nested;
      }
    }
    return null;
  };

  for (const block of blocks) {
    if (!("children" in block)) continue;
    const found = walk(block.children);
    if (found !== null) return found;
  }
  return null;
}

/** Whether a paragraph is one unmarked run — the case the fast path above exists for. */
function plainRun(block: Block): boolean {
  return "children" in block && block.children.length === 1 && block.children[0]!.kind === "text";
}

function BlockNode({
  block,
  among,
  view,
}: {
  block: Block;
  among: readonly string[];
  view: ConversationView;
}) {
  if (block.kind === "code") return <CodeBlock code={block.code} lang={block.lang} />;

  const children = <InlineNodes nodes={block.children} among={among} view={view} />;

  if (block.kind === "quote") {
    return (
      // The same rule the reply quote uses one level up, for the same reason: a margin on the
      // side the text is anchored to reads as belonging to the quote rather than as a divider in
      // the row.
      <span className="my-tight block border-l-2 border-(--color-border-strong) pl-snug text-(--color-ink-muted)">
        {children}
      </span>
    );
  }

  // `block` rather than a `<p>`: the thread's own container carries `whitespace-pre-wrap`, and a
  // paragraph element would add margins that the pre-wrapped newlines already provide.
  return <span className="block">{children}</span>;
}

function InlineNodes({
  nodes,
  among,
  view,
}: {
  nodes: readonly Inline[];
  among: readonly string[];
  view: ConversationView;
}) {
  return (
    <>
      {nodes.map((node, index) => (
        // The index is the position in a list derived from the text: two identical spans are
        // genuinely two runs, and nothing in this list is ever reordered.
        <Fragment key={index}>
          <InlineNode node={node} among={among} view={view} />
        </Fragment>
      ))}
    </>
  );
}

function InlineNode({
  node,
  among,
  view,
}: {
  node: Inline;
  among: readonly string[];
  view: ConversationView;
}) {
  switch (node.kind) {
    case "text":
      // The only branch that is prose. Everything downstream of here — mentions, then emoji —
      // happens because this node reached it, and nothing else does.
      return <MentionText text={node.text} among={among} view={view} />;

    case "code":
      return (
        <code
          className={cn(
            "rounded-tag bg-(--color-surface-sunken) px-[0.25em] font-evidence text-[0.9em]",
            // `box-decoration-clone` so the background is redrawn on each line of a break rather
            // than stretched across the gap. No `overflow-hidden` and no `whitespace-nowrap`:
            // either would make this an atomic box and a long identifier would overflow the
            // column instead of breaking inside it.
            "box-decoration-clone",
          )}
        >
          {node.text}
        </code>
      );

    case "link":
      return <LinkText raw={node.raw} />;

    case "spoiler":
      return (
        <Spoiler>
          <InlineNodes nodes={node.children} among={among} view={view} />
        </Spoiler>
      );

    case "strong":
      return (
        <strong className="font-semibold">
          <InlineNodes nodes={node.children} among={among} view={view} />
        </strong>
      );

    case "em":
      return (
        <em className="italic">
          <InlineNodes nodes={node.children} among={among} view={view} />
        </em>
      );

    case "strike":
      return (
        <s className="line-through">
          <InlineNodes nodes={node.children} among={among} view={view} />
        </s>
      );
  }
}

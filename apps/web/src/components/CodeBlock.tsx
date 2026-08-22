import { type Kind, tokenize } from "@/lib/highlight";
import { cn } from "@/ui/cn";

/**
 * A fenced block, coloured.
 *
 * # The mapping from meaning to colour lives here, and only here
 *
 * `lib/highlight.ts` returns semantic kinds and knows nothing about CSS — the same split as
 * `lib/emoji.ts` and `ui/Emoji.tsx`. This table is the whole of the other half, and it names
 * tokens rather than colours so that both themes and the two explicit `[data-theme]` overrides
 * are served by one line each.
 *
 * # It renders text nodes, never markup
 *
 * One `<span>` per token, with React putting the text in as text. Nothing here builds an HTML
 * string, which is the property that makes it safe to run over a code sample a peer wrote — the
 * same rule `lib/preview.ts` states for bytes, applied to characters.
 *
 * # Why it scrolls sideways instead of wrapping
 *
 * Code is one of the few things where a line break inserted by the layout changes the meaning of
 * what is written. The column around it is already `min-w-0`, which is what lets this overflow
 * rather than stretching the thread — and the thread's own measure is what would otherwise be
 * destroyed by one long line.
 */

/** What each kind is drawn with. See `--color-syntax-*` in `index.css`. */
const COLOURS: Record<Kind, string> = {
  comment: "text-(--color-syntax-comment) italic",
  string: "text-(--color-syntax-string)",
  keyword: "text-(--color-syntax-keyword)",
  number: "text-(--color-syntax-number)",
  punct: "text-(--color-syntax-punct)",
  // Identifiers and whitespace: the body colour, so the coloured tokens are what stands out
  // rather than everything being tinted something.
  plain: "",
};

export function CodeBlock({ code, lang }: { code: string; lang: string | null }) {
  const tokens = tokenize(code, lang);

  return (
    <div className="my-tight">
      {/* The language is shown when the sender named one, and never guessed. It is their label
          for their own snippet — a hint about what this is, not a claim this code verified. */}
      {lang !== null && (
        <span className="text-caption text-(--color-ink-muted)">{lang}</span>
      )}

      <pre className="overflow-x-auto rounded-control bg-(--color-surface-sunken) p-gutter">
        <code className="font-mono text-caption">
          {tokens.map((token, index) => (
            // The index is the position in a list derived from the text: two identical tokens are
            // genuinely two runs, and nothing in this list is ever reordered.
            <span key={index} className={cn(COLOURS[token.kind])}>
              {token.text}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}

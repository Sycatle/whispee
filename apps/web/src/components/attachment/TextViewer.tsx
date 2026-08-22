import { useEffect, useState } from "react";

import { type Kind, tokenize } from "@/lib/highlight";
import { type TextFile, MAX_TEXT_LINES, readText } from "@/lib/textfile";
import type { ViewerProps } from "@/lib/viewer";
import { cn } from "@/ui/cn";

/**
 * An attached file shown as text.
 *
 * # The safest of the viewers, and worth saying why
 *
 * `lib/preview.ts` sets the rule: received bytes go through a decoder that either produces a
 * neutral representation or rejects. An image comes back as pixels this code drew. Text comes
 * back as a `string`, and a string is never a document — nothing downstream interprets it. React
 * puts it in as text nodes, and `lib/highlight.ts` only labels substrings of it.
 *
 * So there is no equivalent here of "an SVG that turns out to run script". The refusal in
 * `lib/textfile.ts` is about honesty rather than safety: it declines to pretend a `.bin` is a
 * document.
 *
 * # The colours are a guess, and a harmless one
 *
 * The language is the sender's file extension. A lie costs a wrongly coloured file and nothing
 * else, because the tokeniser's own invariant is that its output reassembles into its input —
 * the characters on screen are the characters in the file whichever grammar was applied.
 */

/** What each kind is drawn with. The same table as `CodeBlock`, and the same reason it is here. */
const COLOURS: Record<Kind, string> = {
  comment: "text-(--color-syntax-comment) italic",
  string: "text-(--color-syntax-string)",
  keyword: "text-(--color-syntax-keyword)",
  number: "text-(--color-syntax-number)",
  punct: "text-(--color-syntax-punct)",
  plain: "",
};

export function TextViewer({ blob, name, mode, onRefused }: ViewerProps) {
  const [file, setFile] = useState<TextFile | null>(null);

  useEffect(() => {
    let live = true;

    void readText(blob, name).then((read) => {
      if (!live) return;

      if (read === null) {
        // One sentence for three causes — too large, not UTF-8, control characters — because the
        // reader has the same thing to do about each of them, and it is already on screen.
        onRefused("This file is not text this can show. It can still be downloaded.");
        return;
      }

      setFile(read);
    });

    return () => {
      live = false;
    };
    // `onRefused` is a callback prop rather than reactive state, so it is deliberately out: it is
    // recreated on every render of the parent and would re-read the file each time.
  }, [blob, name]);

  if (file === null) return null;

  return (
    <div
      className={cn(
        "w-full overflow-x-auto rounded-control bg-(--color-surface-sunken) p-gutter",
        // Inline it is a glance, full screen it is the file. Bounded either way: a thousand lines
        // in a thread would push the conversation off the screen, which is the same argument the
        // image thumbnail makes one file over.
        mode === "full" ? "max-h-full" : "max-h-[18rem]",
      )}
    >
      {/* `overflow-x-auto` above and `whitespace-pre` here: a line break inserted by the layout
          changes what code means, so lines run off the side rather than wrap. The column around
          this is `min-w-0`, which is what lets that overflow instead of stretching the thread. */}
      <pre className="whitespace-pre font-evidence text-caption">
        <code>
          {file.lines.map((line, index) => (
            // The index is the line number, and lines are never reordered.
            <span key={index} className="block">
              {tokenize(line, file.lang).map((token, at) => (
                <span key={at} className={cn(COLOURS[token.kind])}>
                  {token.text}
                </span>
              ))}
              {/* An empty line still needs a box to occupy, or a blank in the middle of a file
                  collapses and the lines below shift up by one. */}
              {line === "" && " "}
            </span>
          ))}
        </code>
      </pre>

      {(file.truncatedLines || file.truncatedColumns) && (
        <p className="mt-tight text-caption text-(--color-ink-muted)">
          {file.truncatedLines && `First ${MAX_TEXT_LINES} lines only. `}
          {file.truncatedColumns && "Long lines are cut. "}
          Download the file for the rest.
        </p>
      )}
    </div>
  );
}

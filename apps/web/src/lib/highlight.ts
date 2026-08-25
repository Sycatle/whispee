/**
 * Colouring a code block, in about as little code as the job admits.
 *
 * # It returns tokens, never markup
 *
 * `tokenize` hands back `{ kind, text }` pairs and the component turns them into elements. There
 * is no HTML string anywhere on this path, so there is nothing for a `dangerouslySetInnerHTML` to
 * be tempted by — which matters more here than in most places, because the input is a code sample
 * a peer wrote and the whole point of `lib/preview.ts` is that such input is never handed to the
 * browser as a document.
 *
 * The kinds are semantic and carry no CSS. The mapping from kind to class lives in the component,
 * the way `lib/emoji.ts` knows nothing about how `ui/Emoji.tsx` draws what it segments.
 *
 * # Why this is written here rather than installed
 *
 * Shiki and highlight.js are both better at this than the table below, and both arrive with their
 * own palette. This project's colours are OKLCH tokens with contrast argued in `index.css`, in
 * four blocks — light, dark, and the two explicit `[data-theme]` overrides. A theme that does not
 * know about any of that fails in the one direction nobody notices: text that is legible in the
 * light theme and grey-on-grey in the dark one, on a surface that shifts under it.
 *
 * The second reason is the one the emoji catalogue already argues: the build has to work offline,
 * and an application whose case is that you can check what you run should not ship a megabyte of
 * grammars to colour a chat message.
 *
 * What it costs: this is approximate. It does not know scope, it cannot tell a type from a
 * variable, and a language it has no grammar for gets no colour at all. For a code sample in a
 * conversation that is the right trade; for an editor it would not be.
 *
 * # Nothing is guessed
 *
 * A language with no grammar produces **one** `plain` token. No neutral fallback grammar, no
 * guessing that `//` opens a comment: applied to a language that does not work that way, a guess
 * greys out half a message. No colour is never wrong. A wrong colour is.
 *
 * # Three things stop this hanging the tab
 *
 * The input is hostile by default, so the loop is written for that. There is a ceiling on the
 * source and on the token count; every unterminated construct runs to the end and returns rather
 * than throwing; and the scanner asserts progress on every turn — if an index did not advance, a
 * character is consumed as `plain`. That last one is three lines and it is the only class of bug
 * here that costs somebody their tab.
 */

/** What a run of characters is, semantically. No colour, no class — see the module note. */
export type Kind = "comment" | "string" | "keyword" | "number" | "punct" | "plain";

export interface Token {
  readonly kind: Kind;
  readonly text: string;
}

/** Longest block that is coloured at all. Past it, the code is shown without highlighting. */
export const MAX_HIGHLIGHT = 20_000;
/** Most tokens a block may produce before it is given up on. */
export const MAX_TOKENS = 5_000;

interface StringRule {
  readonly open: string;
  readonly close: string;
  /** Character that neutralises the closer. Absent for languages with no escapes. */
  readonly escape?: string;
}

interface Grammar {
  readonly lineComment: readonly string[];
  readonly blockComment: readonly (readonly [string, string])[];
  readonly strings: readonly StringRule[];
  readonly keywords: ReadonlySet<string>;
}

function words(list: string): ReadonlySet<string> {
  return new Set(list.split(" "));
}

const QUOTES: readonly StringRule[] = [
  { open: '"', close: '"', escape: "\\" },
  { open: "'", close: "'", escape: "\\" },
];

const C_COMMENTS = { lineComment: ["//"], blockComment: [["/*", "*/"]] } as const;
const HASH_COMMENTS = { lineComment: ["#"], blockComment: [] } as const;

/**
 * The grammars, and the order they were chosen in.
 *
 * Rust and TypeScript first because they are what this repository is written in, so they are what
 * gets pasted into a conversation about it. The rest are the languages a snippet is next most
 * likely to be.
 */
const GRAMMARS: Record<string, Grammar> = {
  ts: {
    ...C_COMMENTS,
    strings: [...QUOTES, { open: "`", close: "`", escape: "\\" }],
    keywords: words(
      "abstract as async await break case catch class const continue declare default delete do else enum export extends false finally for from function get if implements import in instanceof interface is keyof let new null of private protected public readonly return satisfies set static super switch this throw true try type typeof undefined var void while yield",
    ),
  },
  rust: {
    ...C_COMMENTS,
    strings: [{ open: '"', close: '"', escape: "\\" }],
    keywords: words(
      "as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while",
    ),
  },
  python: {
    ...HASH_COMMENTS,
    strings: [
      { open: '"""', close: '"""' },
      { open: "'''", close: "'''" },
      ...QUOTES,
    ],
    keywords: words(
      "and as assert async await break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield",
    ),
  },
  go: {
    ...C_COMMENTS,
    strings: [...QUOTES, { open: "`", close: "`" }],
    keywords: words(
      "break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var nil true false",
    ),
  },
  json: {
    lineComment: [],
    blockComment: [],
    strings: [{ open: '"', close: '"', escape: "\\" }],
    keywords: words("true false null"),
  },
  sql: {
    lineComment: ["--"],
    blockComment: [["/*", "*/"]],
    strings: [{ open: "'", close: "'", escape: "\\" }],
    keywords: words(
      "add all alter and as asc between by case create delete desc distinct drop else end exists from full group having if in index inner insert into is join left limit not null on or order outer primary references right select set table then union unique update values where",
    ),
  },
  bash: {
    ...HASH_COMMENTS,
    strings: QUOTES,
    keywords: words(
      "case do done elif else esac export fi for function if in local return then until while echo cd set unset source",
    ),
  },
  css: {
    lineComment: [],
    blockComment: [["/*", "*/"]],
    strings: QUOTES,
    keywords: words("important media import supports keyframes from to and not only"),
  },
  yaml: {
    ...HASH_COMMENTS,
    strings: QUOTES,
    keywords: words("true false null yes no on off"),
  },
  html: {
    lineComment: [],
    blockComment: [["<!--", "-->"]],
    strings: QUOTES,
    keywords: words(""),
  },
};

/** Spellings that mean a grammar already in the table. */
const ALIASES: Record<string, string> = {
  typescript: "ts",
  tsx: "ts",
  js: "ts",
  javascript: "ts",
  jsx: "ts",
  mjs: "ts",
  cjs: "ts",
  rs: "rust",
  py: "python",
  golang: "go",
  sh: "bash",
  shell: "bash",
  zsh: "bash",
  yml: "yaml",
  scss: "css",
  xml: "html",
  svg: "html",
  jsonc: "json",
  postgres: "sql",
  psql: "sql",
};

/** The grammar for a language name, or `null` when there is none. See the note on guessing. */
export function grammarFor(lang: string | null): Grammar | null {
  if (lang === null) return null;
  const name = lang.toLowerCase();
  return GRAMMARS[ALIASES[name] ?? name] ?? null;
}

const IDENT_START = /[A-Za-z_$]/;
const IDENT = /[A-Za-z0-9_$]/;
const DIGIT = /[0-9]/;
const PUNCT = /[{}()[\];:,.<>+\-*/%=!&|^~?@#]/;

/**
 * Splits a block into runs.
 *
 * The invariant every test leans on: the concatenation of the tokens equals the input, exactly.
 * A scanner that loses or duplicates a character is a scanner that silently rewrites somebody's
 * code sample, and that is far worse than colouring it wrongly.
 */
export function tokenize(code: string, lang: string | null): Token[] {
  const grammar = grammarFor(lang);
  if (grammar === null || code.length > MAX_HIGHLIGHT) {
    return code === "" ? [] : [{ kind: "plain", text: code }];
  }

  const out: Token[] = [];
  let i = 0;
  let plain = "";

  const flush = () => {
    if (plain === "") return;
    out.push({ kind: "plain", text: plain });
    plain = "";
  };
  const push = (kind: Kind, text: string) => {
    flush();
    out.push({ kind, text });
  };

  while (i < code.length) {
    if (out.length > MAX_TOKENS) return [{ kind: "plain", text: code }];

    const before = i;

    // Block comments first: `/*` has to beat `/` as punctuation, and `<!--` has to beat `<`.
    const block = grammar.blockComment.find(([open]) => code.startsWith(open, i));
    if (block !== undefined) {
      const [open, close] = block;
      const end = code.indexOf(close, i + open.length);
      // Unterminated runs to the end. It renders; it does not throw.
      const stop = end === -1 ? code.length : end + close.length;
      push("comment", code.slice(i, stop));
      i = stop;
      continue;
    }

    const line = grammar.lineComment.find((open) => code.startsWith(open, i));
    if (line !== undefined) {
      const end = code.indexOf("\n", i);
      const stop = end === -1 ? code.length : end;
      push("comment", code.slice(i, stop));
      i = stop;
      continue;
    }

    // Longest opener first, so `"""` is not read as `"` followed by an empty string.
    const quote = [...grammar.strings]
      .sort((a, b) => b.open.length - a.open.length)
      .find((rule) => code.startsWith(rule.open, i));
    if (quote !== undefined) {
      let j = i + quote.open.length;
      while (j < code.length) {
        if (quote.escape !== undefined && code.startsWith(quote.escape, j)) {
          j += quote.escape.length + 1;
          continue;
        }
        if (code.startsWith(quote.close, j)) {
          j += quote.close.length;
          break;
        }
        j += 1;
      }
      push("string", code.slice(i, Math.min(j, code.length)));
      i = Math.min(j, code.length);
      continue;
    }

    const char = code[i] ?? "";

    if (DIGIT.test(char)) {
      let j = i;
      // One run of anything a number may contain. `1..2` ends up one token rather than three, and
      // that is a colour being slightly generous, not a character being lost.
      while (j < code.length && /[0-9A-Fa-fxXoObB._]/.test(code[j] ?? "")) j += 1;
      push("number", code.slice(i, j));
      i = j;
      continue;
    }

    if (IDENT_START.test(char)) {
      let j = i;
      while (j < code.length && IDENT.test(code[j] ?? "")) j += 1;
      const word = code.slice(i, j);
      // The whole identifier is looked up, never a prefix: `iffy` is not `if`, `forEach` is not
      // `for`, `return_value` is not `return`.
      if (grammar.keywords.has(word)) push("keyword", word);
      else plain += word;
      i = j;
      continue;
    }

    if (PUNCT.test(char)) {
      push("punct", char);
      i += 1;
      continue;
    }

    plain += char;
    i += 1;

    // The progress guard. Every branch above advances `i`, and this is what holds if one ever
    // stops doing so after an edit — a hung tab is the one failure here nobody can recover from.
    if (i <= before) {
      plain += code[before] ?? "";
      i = before + 1;
    }
  }

  flush();
  return out;
}

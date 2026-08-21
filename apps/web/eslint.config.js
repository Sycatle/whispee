import js from "@eslint/js";
import tseslint from "typescript-eslint";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";

/**
 * Lint configuration.
 *
 * # Why a linter at all, in a project that counts its dependencies
 *
 * The accessibility of this interface holds today by two means: the shape of the types, and
 * discipline. The first is solid — `label` is a required string on `Field` and `IconButton`, so
 * an unnamed icon button does not compile. The second is not: it is a convention written in
 * JSDoc, and a convention is only as durable as the attention of whoever writes the next
 * component. A regression already happened once and was caught by eye — `Messages.tsx` revealed
 * its per-message actions with `hidden`, and `display: none` takes an element out of the tab
 * order, so every message action was keyboard-unreachable while looking perfectly fine.
 *
 * These four packages are devDependencies. They are never bundled, they never run on the page
 * that holds the user's keys, and the supply-chain argument in `docs/THREAT-MODEL.md` — which is
 * about what ships to the browser — does not reach them.
 *
 * # What this linter does not catch, said plainly
 *
 * `jsx-a11y` reads JSX attributes, not component contracts. The `components` mapping below tells
 * it that `<IconButton>` is a button, but `IconButton`'s `label` prop is not `aria-label` and the
 * rule will not see it. So the linter covers native elements and hand-written `role=` attributes
 * — which is exactly the surface where this codebase's remaining defects were found — and covers
 * nothing of the house components, which the compiler already holds.
 */
export default tseslint.config(
  {
    ignores: [
      "dist/**",
      // Emitted by `wasm-pack` and patched by `scripts/patch-wasm-glue.mjs`. Linting generated
      // code reports on decisions nobody here makes.
      "src/lib/generated/**",
      "public/**",
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,
  jsxA11y.flatConfigs.recommended,

  {
    // Node scripts, not browser code: `process`, `console` and `URL` are ambient there. They are
    // also plain JavaScript, so the TypeScript escape hatch below does not reach them.
    files: ["scripts/**/*.mjs"],
    rules: { "no-undef": "off" },
  },

  {
    files: ["**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },

    settings: {
      // Without this the plugin sees `<IconButton>` as an unknown element and stays silent on it.
      // With it, the rules that apply to a button apply here too.
      "jsx-a11y": {
        components: {
          Button: "button",
          IconButton: "button",
          Input: "input",
          Textarea: "textarea",
        },
      },
    },

    rules: {
      // TypeScript resolves every identifier already, and it knows about the DOM lib while ESLint
      // does not. Leaving this on would mean reporting `window` and `document` as undefined, or
      // taking on a `globals` dependency to say what `tsconfig.json` says.
      "no-undef": "off",

      // Beyond the recommended set.
      "jsx-a11y/no-aria-hidden-on-focusable": "error",
      "jsx-a11y/anchor-ambiguous-text": "error",

      // **Two rules tried and rejected, so nobody adds them back hopefully.**
      //
      // `control-has-associated-label` reported 27 times, every one of them an `<IconButton
      // label="…">` — correct code. It is the `components` mapping above meeting its documented
      // limit: the plugin knows the element is a button and cannot see that `label` names it. A
      // rule whose every finding is false teaches the reader to skim past the linter, which
      // costs more than the rule was ever going to catch. What it would have enforced, the
      // required `label` prop already enforces at compile time.
      //
      // `prefer-tag-over-role` asked for an `<hr>` as a child of `<ol>` (invalid), an `<img>` in
      // place of an inline identicon SVG, and `<output>` — a form-result element — for a
      // portalled toast container. It is built for simple roles standing in for simple tags;
      // almost every `role=` here belongs to a composite pattern with no native equivalent.
      "jsx-a11y/control-has-associated-label": "off",
      "jsx-a11y/prefer-tag-over-role": "off",

      // Only `rules-of-hooks`, deliberately, rather than the plugin's recommended set. Version 7
      // ships the React Compiler rules (`set-state-in-effect`, `purity`, `refs`,
      // `static-components`), which describe a model this project has not adopted — they report
      // twelve times here, on code that works. Judging them is a piece of work of its own and
      // does not belong to an accessibility pass; enabling them now would mean twelve disable
      // directives written in a hurry.
      //
      // `exhaustive-deps` stays off for a different reason: several effects have incomplete
      // dependency arrays on purpose, each with a paragraph saying which re-run it avoids —
      // `Messages.tsx` on its scroll effect, `DetailPanel.tsx` on its Escape listener. The rule
      // would replace prose that explains with a directive that does not.
      "react-hooks/exhaustive-deps": "off",
      "react-hooks/rules-of-hooks": "error",

      // An unused argument that documents a signature is not a defect. An unused variable is.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
);

/**
 * These tests are the record of a dependency decision, not only a check on a three-line
 * function.
 *
 * They were written first, against `twMerge(clsx(...))`, to answer one question: does
 * `tailwind-merge` v3 understand the vocabulary this project actually writes — Tailwind v4
 * arbitrary-variable colours and semantic theme keys? The answer was no, and the head of `cn.ts`
 * carries the measurements. What is asserted below is therefore the contract that replaced it:
 * `cn` concatenates, the caller's `className` comes last, and same-property conflicts are not
 * resolved here.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { cn } from "./cn.ts";

// The witness. Under `tailwind-merge` this returned `"bg-(--color-danger)"` alone; it is the
// one family the library did handle. It is kept as a test anyway, because it pins the fact that
// the second class survives and comes last — which is the whole of the replacement contract.
test("cn keeps both token backgrounds, with the caller's last", () => {
  assert.equal(cn("bg-(--color-accent)", "bg-(--color-danger)"), "bg-(--color-accent) bg-(--color-danger)");
});

test("cn keeps both token text colours, with the caller's last", () => {
  assert.equal(cn("text-(--color-ink)", "text-(--color-danger)"), "text-(--color-ink) text-(--color-danger)");
});

test("cn keeps both token borders, with the caller's last", () => {
  assert.equal(
    cn("border-(--color-border-subtle)", "border-(--color-danger)"),
    "border-(--color-border-subtle) border-(--color-danger)",
  );
});

// The pairing that decided it. A merger classified these as one conflict group and dropped the
// size; concatenation keeps both, and they set different properties, so both apply.
test("cn does not let a token colour swallow a font size", () => {
  const result = cn("text-body", "text-(--color-danger)");
  assert.ok(result.includes("text-body"));
  assert.ok(result.includes("text-(--color-danger)"));
});

test("cn drops the falsy branches of a conditional", () => {
  const busy = false;
  const invalid = true;
  assert.equal(
    cn("rounded-control", busy && "opacity-50", invalid && "border-(--color-danger)"),
    "rounded-control border-(--color-danger)",
  );
});

test("cn accepts the object and array forms", () => {
  assert.equal(
    cn(["p-gutter", "gap-tight"], { "text-body": true, "text-caption": false }),
    "p-gutter gap-tight text-body",
  );
});

// A primitive calls `cn(variants(...), className)` on every render, and `className` is optional
// on all of them. A trailing space would end up in the DOM of every button in the application.
test("cn ignores an absent className rather than leaving a gap", () => {
  assert.equal(cn("p-pane", undefined), "p-pane");
  assert.equal(cn(undefined, null, false, ""), "");
});

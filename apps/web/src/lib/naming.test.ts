import assert from "node:assert/strict";
import { test } from "node:test";

import { compactNameOf, handleOf, nameMatches, nameOf, titleOf, type NameSources } from "./naming.ts";

/** Builds the two records `Session` holds, from a terser description. */
function sources(
  petnames: Record<string, string> = {},
  profiles: Record<string, string> = {},
): NameSources {
  const asserted: Record<string, { name: string }> = {};
  for (const [handle, name] of Object.entries(profiles)) asserted[handle] = { name };
  return { petnames, profiles: asserted };
}

test("somebody who has asserted nothing is shown by their handle alone", () => {
  const name = nameOf("charlie8295", sources());
  assert.deepEqual(name, { primary: "@charlie8295", secondary: null, isHandle: true });
});

test("the handle is still shown beside a display name", () => {
  const name = nameOf("charlie8295", sources({}, { charlie8295: "Charlie" }));
  assert.deepEqual(name, { primary: "Charlie", secondary: "@charlie8295", isHandle: false });
});

test("a local petname wins over a self-asserted display name", () => {
  const name = nameOf("charlie8295", sources({ charlie8295: "Charlie at work" }, { charlie8295: "Charlie" }));
  assert.equal(name.primary, "Charlie at work");
  assert.equal(name.secondary, "@charlie8295");
});

test("a display name that is only whitespace is ignored in favour of the handle", () => {
  const name = nameOf("charlie8295", sources({}, { charlie8295: "   " }));
  assert.equal(name.primary, "@charlie8295");
  assert.equal(name.isHandle, true);
});

test("two members claiming the same display name both fall back to their handle in compact mode", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { charlie8295: "Charlie", mallory1721: "charlie " });

  assert.equal(compactNameOf("charlie8295", claims, among), "@charlie8295");
  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a display name that is another member's handle is refused in compact mode", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { mallory1721: "charlie8295" });

  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a display name that is another member's handle with its sigil is refused too", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { mallory1721: "@charlie8295" });

  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a rival wearing the same name behind a sigil is caught too", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { charlie8295: "Charlie", mallory1721: "@charlie" });

  assert.equal(compactNameOf("charlie8295", claims, among), "@charlie8295");
  assert.equal(compactNameOf("mallory1721", claims, among), "@mallory1721");
});

test("a petname collision is the reader's own doing and is left alone", () => {
  const among = ["charlie8295", "mallory1721"];
  const chosen = sources({ charlie8295: "Charlie", mallory1721: "Charlie" });

  assert.equal(compactNameOf("charlie8295", chosen, among), "Charlie");
  assert.equal(compactNameOf("mallory1721", chosen, among), "Charlie");
});

test("an uncontested display name survives the compact form", () => {
  const among = ["charlie8295", "mallory1721"];
  const claims = sources({}, { charlie8295: "Charlie", mallory1721: "Mallory" });

  assert.equal(compactNameOf("charlie8295", claims, among), "Charlie");
});

test("a display name equal to one's own handle is kept as its owner wrote it", () => {
  const claims = sources({}, { charlie8295: "Charlie8295" });
  assert.equal(compactNameOf("charlie8295", claims, ["charlie8295"]), "Charlie8295");
});

test("a search term matches the handle, the display name and the petname alike", () => {
  const both = sources({ bob4410: "Bobby" }, { charlie8295: "Charlie" });

  assert.equal(nameMatches("charlie8295", both, "charlie"), true);
  assert.equal(nameMatches("charlie8295", both, "@charlie82"), true);
  assert.equal(nameMatches("bob4410", both, "bobby"), true);
  assert.equal(nameMatches("bob4410", both, "charlie"), false);
});

test("an empty search term matches everyone", () => {
  assert.equal(nameMatches("charlie8295", sources(), "  "), true);
});

test("a conversation is named after the accounts in it", () => {
  const claims = sources({}, { charlie8295: "Charlie", dana4417: "Dana" });
  const view = {
    accounts: [{ handle: "charlie8295" }, { handle: "dana4417" }],
    peers: [],
  };

  assert.equal(titleOf(view, claims, ["charlie8295", "dana4417"]), "Charlie, Dana");
});

test("a name that is ambiguous within the set falls back to the handle", () => {
  // The reason `among` is a parameter: the same two people are unambiguous in a conversation of
  // two and ambiguous in a rail that also lists another Charlie.
  const claims = sources({}, { charlie8295: "Charlie", charlie7712: "Charlie" });
  const view = { accounts: [{ handle: "charlie8295" }], peers: [] };

  assert.equal(titleOf(view, claims, ["charlie8295"]), "Charlie");
  assert.equal(titleOf(view, claims, ["charlie8295", "charlie7712"]), "@charlie8295");
});

test("with no accounts, a conversation is named after the handles its peers are known by", () => {
  // A device that has seen the traffic but not yet the profiles: the peers are all there is.
  const claims = sources();
  const view = { accounts: [], peers: [{ name: "dana4417" }, { name: "dana4417" }] };

  assert.equal(titleOf(view, claims, []), "@dana4417");
});

test("a conversation with nobody in it is still named", () => {
  // Never empty: an unnamed row cannot be described, and an empty announcement is silence where
  // a name was expected.
  assert.equal(titleOf({ accounts: [], peers: [] }, sources(), []), "empty conversation");
});

test("a group is named by everybody in it, ourselves last", () => {
  const claims = sources({}, { charlie8295: "Charlie", dana4417: "Dana", me1234: "Me" });
  const view = {
    accounts: [{ handle: "charlie8295" }, { handle: "dana4417" }],
    peers: [],
  };

  assert.equal(titleOf(view, claims, ["charlie8295", "dana4417"], "me1234"), "Charlie, Dana, Me");
});

test("a one-to-one is named after the other person alone", () => {
  // "Alice, you" would be two words to say what one says, and the reader knows they are there.
  //
  // The caller decides by omitting `self`, and that is deliberate: whether a conversation is a
  // group is a property of its MLS roster, not of how many people are currently in it. Deciding
  // it here, from the length of `accounts`, is what made a group of three renamed itself a
  // one-to-one the moment somebody was removed from it.
  const claims = sources({}, { charlie8295: "Charlie", me1234: "Me" });
  const view = { accounts: [{ handle: "charlie8295" }], peers: [] };

  assert.equal(titleOf(view, claims, ["charlie8295"]), "Charlie");
});

test("a group of two still names both, because a group is not a headcount", () => {
  // The regression this guards: removing the third member of a group of three leaves two, and
  // nothing about the conversation has changed except its size.
  const claims = sources({}, { charlie8295: "Charlie", me1234: "Me" });
  const view = { accounts: [{ handle: "charlie8295" }], peers: [] };

  assert.equal(titleOf(view, claims, ["charlie8295"], "me1234"), "Charlie, Me");
});

test("our own name is disambiguated against the group like everybody else's", () => {
  // Somebody else in the room asserting our display name means ours falls back to the handle too.
  const claims = sources({}, { charlie8295: "Sam", dana4417: "Dana", me1234: "Sam" });
  const view = { accounts: [{ handle: "charlie8295" }, { handle: "dana4417" }], peers: [] };

  assert.equal(
    titleOf(view, claims, ["charlie8295", "dana4417"], "me1234"),
    "@charlie8295, Dana, @me1234",
  );
});

// ---------------------------------------------------------------------------
// handleOf: an account is a key, and a handle is a claim about it
// ---------------------------------------------------------------------------

const ID = "d52c15beb77ff1bd33ba58ad12345678";

test("an account shows the handle it claims", () => {
  assert.equal(handleOf(ID, { petnames: {}, profiles: {}, handles: { [ID]: "bob5194" } }), "@bob5194");
});

test("an account nobody has heard from shows a short form of its id", () => {
  // Not a blank and not thirty-two hexadecimal characters in a line of prose. 64 bits, grouped in
  // fours, matching `attest::short_id` — legible, comparable at a glance, and honest about being
  // an identifier rather than a name.
  assert.equal(handleOf(ID, { petnames: {}, profiles: {} }), "d52c 15be b77f f1bd");
});

test("something that is not an id comes back with the sigil", () => {
  // The least surprising answer, and what every call site did before ids existed.
  assert.equal(handleOf("bob", { petnames: {}, profiles: {} }), "@bob");
});

test("a name is shown over a claimed handle, and the handle stays beside it", () => {
  const sources = { petnames: {}, profiles: { [ID]: { name: "Bob" } }, handles: { [ID]: "bob5194" } };
  assert.deepEqual(nameOf(ID, sources), {
    primary: "Bob",
    secondary: "@bob5194",
    isHandle: false,
  });
});

test("an unnamed account falls back to the short id rather than to its raw one", () => {
  const shown = nameOf(ID, { petnames: {}, profiles: {} });
  assert.equal(shown.primary, "d52c 15be b77f f1bd");
  assert.equal(shown.isHandle, true);
});

test("a display name that reads as another member's claimed handle loses", () => {
  // The impersonation `compactNameOf` has always caught, moved to where the anchor now lives:
  // since the credential stopped carrying the handle, what is on screen is what people claim.
  const other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const sources = {
    petnames: {},
    profiles: { [ID]: { name: "bob5194" } },
    handles: { [other]: "bob5194" },
  };
  assert.equal(compactNameOf(ID, sources, [ID, other]), "d52c 15be b77f f1bd");
});

test("a search term finds an account by the handle it claims", () => {
  assert.equal(
    nameMatches(ID, { petnames: {}, profiles: {}, handles: { [ID]: "bob5194" } }, "bob"),
    true,
  );
});

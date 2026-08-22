import assert from "node:assert/strict";
import { test } from "node:test";

import {
  archivesToVault,
  disclosesName,
  flagsOf,
  freshPreferences,
  isBlocked,
  isMuted,
  type ConversationFlags,
} from "./session-types.ts";

const NOW = 1_700_000_000_000;

test("a conversation that never had flags reads as having none, not as undefined", () => {
  // Every caller asks the same question — "what applies here" — and an answer that is sometimes
  // an object and sometimes nothing makes each of them remember the difference.
  assert.deepEqual(flagsOf(freshPreferences(), "aa"), {});
});

test("a mute lapses on its own, with nothing scheduled to end it", () => {
  // The stored value is the moment silence ends, not a boolean. That is the whole reason "mute
  // for an hour" needs no timer: the comparison happens where a notification would fire.
  const flags: ConversationFlags = { mutedUntil: NOW };

  assert.equal(isMuted(flags, NOW - 1), true);
  assert.equal(isMuted(flags, NOW), false, "a mute at its own deadline is still muting");
  assert.equal(isMuted(flags, NOW + 1), false);
});

test("no mute is not a mute", () => {
  assert.equal(isMuted({}, NOW), false);
});

test("naming a conversation in notifications has three states, not two", () => {
  // The middle one is the point. An absent flag follows the account, so turning the account-wide
  // setting on must not reveal the name of the thread somebody marked as the quiet one — and
  // turning it off must not leave a per-conversation `true` shouting.
  assert.equal(disclosesName({}, true), true);
  assert.equal(disclosesName({}, false), false);

  assert.equal(disclosesName({ discloseName: false }, true), false, "the override lost to the account");
  assert.equal(disclosesName({ discloseName: true }, false), true, "the override lost to the account");
});

test("only an explicit refusal keeps a conversation out of the vault", () => {
  // Absence is "never asked". Treating it as a refusal would cut backup off for every
  // conversation that predates the flag, silently and retroactively.
  assert.equal(archivesToVault({}), true);
  assert.equal(archivesToVault({ archiveToVault: true }), true);
  assert.equal(archivesToVault({ archiveToVault: false }), false);
});

test("blocking is a list of accounts, and an empty one blocks nobody", () => {
  const preferences = freshPreferences();
  assert.equal(isBlocked(preferences, "mallory"), false);

  preferences.blocked = ["mallory"];
  assert.equal(isBlocked(preferences, "mallory"), true);
  assert.equal(isBlocked(preferences, "alice"), false);
});

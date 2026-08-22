/**
 * The accounts this person has declined to read, and the way back.
 *
 * # Why a list exists at all, when the decision is made elsewhere
 *
 * Blocking happens on somebody's card, in front of the face it is about. Undoing it cannot only
 * happen there: a conversation that has gone quiet drops down the list, a group one has left is
 * gone entirely, and the card is reached *through* those. Without this screen, an account blocked
 * in a thread that later went silent is blocked with no way back — a state the interface can
 * produce and not undo, which is the one kind of state it must never produce.
 *
 * # Why the names are resolved here and not stored
 *
 * `blocked` holds account ids, because that is what the credential authenticates and what every
 * comparison in the protocol uses. A handle or a display name would have been kinder to read and
 * wrong to store: both are claims, both change, and a list keyed on a claim would let somebody
 * escape a block by renaming themselves.
 *
 * So the display resolves through `naming.ts` at render time, exactly as the thread does, and
 * falls back to the id in its grouped form when nothing is known — which is the honest answer for
 * an account whose profile was never seen, and it stays copy-pastable.
 *
 * # What this screen deliberately does not offer
 *
 * A way to block somebody from here. That would be a field to paste an account id into, and an
 * account id pasted from somewhere is not a person anybody recognises. Blocking belongs where the
 * person is.
 */
import { useId } from "react";

import type { ContactPolicy } from "@/lib/api";
import { compactNameOf, handleOf } from "@/lib/naming";
import { useNames } from "@/state/names";
import { useBump, useRevision, useSession } from "@/state/SessionProvider";
import { useReport } from "@/state/report";
import { Button } from "@/ui/Button";
import { Panel } from "@/ui/Panel";

/**
 * # This copy stops being true when calls land, and nothing here will notice
 *
 * It says blocking hides what someone says. Once audio calls exist that is incomplete, and the
 * incompleteness was decided on purpose: a blocked account's **voice** still reaches you in a
 * group call that somebody else placed. The guard is on who *placed* the call — an invitation
 * arrives unasked and interrupts — and never on who is in it, because filtering a voice out of a
 * conversation several people are holding breaks it for the person who did the filtering, while
 * costing the blocked person nothing.
 *
 * So this paragraph will need to become "hides what someone **writes**", plus a line saying the
 * voice still comes through in a call they did not place. Both halves: exact and incomplete is
 * worse than too broad, because somebody who blocks and then hears that voice concludes the whole
 * feature failed rather than that one channel is out of its reach.
 *
 * The note exists because the failure is silent — the same reason `content.ts` writes down that
 * byte 9 is reserved. There is a matching one at the track-attachment point in the calls work,
 * where the decision is made; this one is where the sentence lives, and whoever rewrites the
 * sentence has no reason to go and read a media layer.
 */
/**
 * Who may start a conversation with this account.
 *
 * # Why this sits above the block list and not in its own screen
 *
 * They are the two halves of one question, and the block list's own copy has always said so:
 * blocking hides what somebody says and lets it arrive, and this is the half that declines the
 * arrival. Separating them would leave each screen explaining the other.
 *
 * # Why the server holds this one
 *
 * Being added to a group is a row in a table the server maintains, so the server is the only party
 * that can decline to write it. That is not a convenience — it is what makes this the *only*
 * setting in this application whose truth is not local. `storage.ts` named it as the missing half
 * for as long as it was missing, and described it as enforced while nothing enforced it.
 *
 * # What "people you already share a group with" does not mean
 *
 * Verified. The server cannot see a verification — it is compared out of band, between two people,
 * and telling the server who has verified whom would hand it a finer map of who trusts whom than
 * it already has. So the middle option means what the server can actually check, and the copy says
 * that in those words rather than saying "known" and letting each reader supply their own meaning.
 */
function ContactPolicySetting() {
  const session = useSession();
  const report = useReport();
  const bump = useBump();
  useRevision();

  const current = session.contactPolicy;
  // Unique per mount, so two of these on one screen would not share a radio group or an id.
  const group = useId();

  const choose = (policy: ContactPolicy) => {
    session
      .setContactPolicy(policy)
      .then(() => {
        bump();
        report.done("Saved.");
      })
      .catch((failure: unknown) => {
        report.error(failure instanceof Error ? failure.message : String(failure));
      });
  };

  return (
    <Panel
      title="Who can start a conversation"
      description="This one is enforced by the server: it declines to add you, rather than delivering and hiding. It applies to new conversations only — the ones you are already in are untouched, and no setting could change that, since the membership that matters is inside the encryption."
    >
      <fieldset className="space-y-snug">
        <legend className="sr-only">Who can start a conversation with you</legend>
        {/*
          The hint is described-by and not part of the label, which is not a lint concession.
          A label wrapping both makes the accessible name the whole paragraph, so choosing between
          three options means hearing three explanations read out in full before the third can be
          compared with the first. The name is what distinguishes; the hint is what qualifies.
        */}
        {POLICIES.map((option) => (
          <div key={option.value} className="flex items-start gap-snug">
            <input
              id={`${group}-${option.value}`}
              aria-describedby={`${group}-${option.value}-hint`}
              type="radio"
              name={group}
              value={option.value}
              checked={current === option.value}
              onChange={() => choose(option.value)}
              className="mt-1 accent-(--color-accent)"
            />
            <span className="min-w-0">
              <label htmlFor={`${group}-${option.value}`} className="block text-body touch:min-h-11">
                {option.label}
              </label>
              <span
                id={`${group}-${option.value}-hint`}
                className="block text-caption text-(--color-ink-muted)"
              >
                {option.hint}
              </span>
            </span>
          </div>
        ))}
      </fieldset>
    </Panel>
  );
}

/**
 * The three, with the middle one spelled out rather than named.
 *
 * "Known" is a word every reader completes differently, and most complete it as "verified" — which
 * is precisely what the server cannot see. The label says the relation the server actually checks.
 */
const POLICIES: { value: ContactPolicy; label: string; hint: string }[] = [
  {
    value: "open",
    label: "Anyone",
    hint: "Anybody who knows your handle can open a conversation with you.",
  },
  {
    value: "known",
    label: "People you already share a group with",
    hint: "The server can check that you already meet somewhere. It cannot check that you have verified each other — that comparison happens between the two of you and never reaches it.",
  },
  {
    value: "closed",
    label: "Nobody new",
    hint: "Nobody can add you to a conversation you are not already in. Your existing conversations keep working.",
  },
];

export function BlockedAccounts() {
  const session = useSession();
  const names = useNames();
  const report = useReport();
  const bump = useBump();
  // The list moves when another of this account's devices decides something — the block travels
  // now — so this reads the revision rather than a snapshot taken on mount.
  useRevision();

  const blocked = [...session.blocked];

  const unblock = (account: string, shown: string) => {
    session
      .setBlocked(account, false)
      .then(() => {
        bump();
        report.done(`Unblocked. What ${shown} says will appear again.`);
      })
      .catch((failure: unknown) => {
        report.error(failure instanceof Error ? failure.message : String(failure));
      });
  };

  return (
    <>
      <ContactPolicySetting />

    <Panel
      title="Blocked"
      description="Blocking hides what someone says, on every device you are signed in on. It does not stop them sending: their messages are still delivered and stored, and they are never told."
    >
      {blocked.length === 0 ? (
        <p className="text-body text-(--color-ink-muted)">
          Nobody is blocked. You can block someone from their profile, in a conversation you share.
        </p>
      ) : (
        <ul className="space-y-snug">
          {blocked.map((account) => {
            // `among` is the rest of the list: two blocked accounts claiming one name must both
            // fall back to their handle here, for the reason `compactNameOf` gives — otherwise the
            // unblock button names one of two people and the reader cannot tell which.
            const shown = compactNameOf(account, names, blocked);

            return (
              <li key={account} className="flex items-center justify-between gap-snug">
                <span className="min-w-0">
                  <span className="block truncate text-body">{shown}</span>
                  {/* The handle under the name, always: this is a list of people one has decided
                      something about, and a name alone is a claim. */}
                  <span className="block truncate font-evidence text-caption text-(--color-ink-muted)">
                    {handleOf(account, names)}
                  </span>
                </span>
                <Button variant="secondary" size="sm" onClick={() => unblock(account, shown)}>
                  Unblock
                </Button>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
    </>
  );
}

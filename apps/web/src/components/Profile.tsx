/**
 * `#/settings/profile` — the name you show, and the handle you cannot change.
 *
 * # Why the handle sits here at all, disabled
 *
 * The obvious screen shows one editable field and nothing else. This one shows two things, and
 * the second is read-only, because "why can't I change my handle" is the question this feature
 * creates and the worst place to answer it is a support thread. The handle is the account: it is
 * the primary key on the server, the identity bytes inside the MLS credential, a leaf already
 * published in the transparency log, the subject of every attestation this device has signed, and
 * the prefix of every device id. Renaming it would not be a rename, it would be a new account.
 *
 * Saying that in one sentence under a disabled field costs three lines and removes a whole class
 * of misunderstanding about what the display name is.
 *
 * # What the display name is worth, said on the screen that sets it
 *
 * It travels inside MLS, so the server never sees it — that is the reason it exists in this form
 * rather than as a column. But it is **self-asserted**: the people who receive it learn that this
 * account claims that name, and nothing more. The hint says so. A screen that let somebody
 * believe their name was verified would be worse than one with no name at all.
 *
 * # What this does not solve
 *
 * The name reaches a conversation at its next epoch, not instantly, and only conversations that
 * exist. Somebody who has never spoken to you sees your handle, which is the correct thing for
 * them to see and also the only thing available. There is no directory of display names, and
 * building one would put a human name next to every account on the server.
 */
import { useState } from "react";

import { MAX_CODE_POINTS, sanitize, validate } from "@/lib/display-name";
import { formatHandle } from "@/lib/naming";
import { useReport } from "@/state/report";
import { useSession } from "@/state/SessionProvider";
import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { Panel } from "@/ui/Panel";
import { displayNameMessage } from "@/ui/displayNameMessage";

export function ProfileSettings() {
  const session = useSession();
  const report = useReport();

  const [draft, setDraft] = useState(session.displayName ?? "");
  const [busy, setBusy] = useState(false);

  // Validated on the cleaned value, not the raw one: refusing "Charlie " for a trailing space
  // nobody can see would be an error message about nothing. Empty is not an error here — it is
  // how somebody removes their name — so it is excluded before `validate` is consulted.
  const cleaned = sanitize(draft);
  const error = cleaned === "" ? null : validate(cleaned);
  const unchanged = cleaned === (session.displayName ?? "");

  async function save() {
    setBusy(true);
    try {
      await session.setDisplayName(draft);
      report.done(cleaned === "" ? "Display name removed." : `You now show as ${cleaned}.`);
    } catch (failure: unknown) {
      report.error(failure instanceof Error ? failure.message : "The display name could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-pane">
      <Panel
        title="Display name"
        description="Sent to the people you talk to inside the encrypted conversation, never to the server. It is what you say your name is — they see it next to your handle, which is what actually identifies you."
      >
        <form
          className="space-y-pane"
          onSubmit={(event) => {
            event.preventDefault();
            if (error === null && !unchanged) void save();
          }}
        >
          <Field
            label="Display name"
            hint="Leave it empty to go back to showing only your handle."
            error={displayNameMessage(error)}
          >
            {(control) => (
              <Input
                id={control.id}
                aria-describedby={control.describedBy}
                aria-invalid={control.invalid}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder="Charlie"
                autoComplete="nickname"
                // Twice the display cap, on purpose: the field must accept a paste that is too
                // long so the reader sees *why* it is refused. A `maxLength` that silently
                // swallowed the overflow would look like a broken keyboard.
                maxLength={MAX_CODE_POINTS * 2}
              />
            )}
          </Field>

          <Button type="submit" busy={busy} disabled={error !== null || unchanged}>
            Save
          </Button>
        </form>
      </Panel>

      <Panel
        title="Handle"
        description="Your handle cannot be changed. It is the account itself — the name your key is published under in the transparency log, the identity inside every encrypted group you belong to, and the prefix of each of your device identifiers. Changing it would not rename this account, it would create another one."
      >
        <Field label="Handle" hint="Share this to be reached. It is the same for everybody.">
          {(control) => (
            <Input
              id={control.id}
              aria-describedby={control.describedBy}
              value={formatHandle(session.handle)}
              readOnly
              disabled
            />
          )}
        </Field>
      </Panel>
    </div>
  );
}

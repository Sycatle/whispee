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
import {
  MAX_LENGTH as MAX_HANDLE_LENGTH,
  normalize as normalizeHandle,
  validate as validateHandle,
} from "@/lib/handle";

import { useReport } from "@/state/report";
import { useSession } from "@/state/SessionProvider";
import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { Panel } from "@/ui/Panel";
import { displayNameMessage } from "@/ui/displayNameMessage";
import { handleMessage } from "@/ui/handleMessage";

export function ProfileSettings() {
  const session = useSession();
  const [handleDraft, setHandleDraft] = useState(session.handle);
  const [renaming, setRenaming] = useState(false);

  // The field keeps what was typed and the canonical form is derived, as in the onboarding: a
  // field that silently drops the character just typed looks broken, and the person never learns
  // which characters the format takes.
  const wantedHandle = normalizeHandle(handleDraft);
  const handleProblem = handleDraft === "" ? null : validateHandle(wantedHandle);

  const rename = async () => {
    setRenaming(true);
    try {
      await session.renameHandle(wantedHandle);
      report.done(`You are now @${wantedHandle}.`);
    } catch (error) {
      // Shown rather than swallowed: the two refusals the server makes here — the name is taken,
      // or it was renamed too recently — are both things the reader can act on, and both are
      // sentences the route already wrote.
      report.error(error instanceof Error ? error.message : String(error));
      setHandleDraft(session.handle);
    } finally {
      setRenaming(false);
    }
  };
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
        description="How people reach you. It is unique, so no two accounts answer to the same one at the same time — but it is a name, not the account: what actually identifies you is your key, which is why this can move and your conversations do not notice."
      >
        <form
          className="space-y-pane"
          onSubmit={(event) => {
            event.preventDefault();
            if (handleProblem === null && wantedHandle !== session.handle) void rename();
          }}
        >
          <Field
            label="Handle"
            hint="Lowercase letters, digits and underscores, 3 to 32 characters."
            error={handleProblem === null ? undefined : handleMessage(handleProblem)}
          >
            {(control) => (
              <Input
                id={control.id}
                aria-describedby={control.describedBy}
                aria-invalid={control.invalid}
                value={handleDraft}
                onChange={(event) => setHandleDraft(event.target.value)}
                maxLength={MAX_HANDLE_LENGTH}
                autoComplete="username"
              />
            )}
          </Field>

          {/*
            Said before the button, not after the press.

            Two consequences the reader cannot guess and would not forgive discovering: the old
            name is gone for good — the server retires it so that no stale link to it can ever
            point at somebody else — and there is a day to wait before the next change. Both are
            arguments made in `migrations/0014_account_identity.sql`; this is where they reach the
            person they constrain.
          */}
          <p className="text-caption text-(--color-ink-muted)">
            Your current handle is retired when you change it: nobody, including you, can take it
            again. You can change it once a day.
          </p>

          <Button
            type="submit"
            busy={renaming}
            disabled={handleProblem !== null || wantedHandle === session.handle}
          >
            Change handle
          </Button>
        </form>
      </Panel>
    </div>
  );
}

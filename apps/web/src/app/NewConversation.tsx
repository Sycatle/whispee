import { type FormEvent, useState } from "react";

import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Input } from "@/ui/Input";
import { useDuo } from "@/lib/duo";
import { useOcclusion } from "@/lib/viewport";
import { useReport } from "@/state/report";
import { useBump, useSession } from "@/state/SessionProvider";
import { useNavigate } from "@/routes/Router";

/**
 * `#/new` — the form that used to sit permanently at the top of the rail.
 *
 * # Why it stopped living there
 *
 * It was the first thing in the list, above every conversation, on every screen, forever: a text
 * field and a full-width primary button occupying the top eighth of the rail to serve an action
 * taken a handful of times in the life of an account. At 288 pixels wide that is a conversation
 * and a half of vertical space spent on a control almost nobody is about to use. It is now the
 * `[+]` in the rail header, and this screen.
 *
 * # It is a screen and not a dialog
 *
 * It carries a text input, so on a phone it has to survive the software keyboard — which means
 * `useOcclusion()` and `safe-bottom`, the two things the rail never applied. A dialog would have
 * to solve the same problem inside a portal that does not inherit the shell's insets.
 */
export function NewConversation() {
  const session = useSession();
  const bump = useBump();
  const report = useReport();
  const navigate = useNavigate();
  const duo = useDuo();
  const occlusion = useOcclusion();
  const [peer, setPeer] = useState("");
  const [busy, setBusy] = useState(false);

  const start = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      // Several handles separated by commas open a group. Past one peer, the creator becomes
      // its first administrator.
      const handles = peer
        .split(",")
        .map((handle) => handle.trim().replace(/^@/, ""))
        .filter((handle) => handle.length > 0);

      const view = await session.startConversation(handles);
      setPeer("");
      bump();
      // Replaces rather than pushes: this screen has served its purpose and nobody wants the
      // back gesture out of a brand new conversation to land them back on the form that made it.
      navigate({ kind: "conversation", key: view.key }, { replace: true });
    } catch (e) {
      report.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="flex min-h-0 flex-1 flex-col bg-(--color-surface)">
      <header className="safe-top flex items-center gap-snug border-b border-(--color-border-subtle) px-pane py-snug">
        {/* Undoes a navigation, so it goes back rather than to a destination. See the rule in
            `routes/Router.tsx`: a chevron that navigated to `#/` would stack one entry per round
            trip and make leaving the application a dozen presses of the Android back button. */}
        {!duo && (
          <IconButton
            label="Back to conversations"
            icon={<Icon name="back" size={20} />}
            onClick={() => history.back()}
            className="-ml-tight"
          />
        )}
        <h1 className="text-body font-medium">Start a conversation</h1>
      </header>

      <form
        onSubmit={start}
        style={{ paddingBottom: occlusion || undefined }}
        className="safe-bottom min-h-0 flex-1 space-y-pane overflow-y-auto p-pane"
      >
        <Field
          label="Handles"
          hint="One handle, or several separated by commas to open a group. The creator of a group is its first administrator."
        >
          {(control) => (
            <Input
              id={control.id}
              describedBy={control.describedBy}
              invalid={control.invalid}
              value={peer}
              onChange={(e) => setPeer(e.target.value)}
              placeholder="bob, or bob, carol"
              autoComplete="off"
              required
              // `text-base` on purpose: below 16 pixels, iOS zooms into the field on focus and
              // does not zoom back out on blur.
              className="w-full text-base"
            />
          )}
        </Field>

        <Button type="submit" variant="primary" busy={busy}>
          Start a conversation
        </Button>
      </form>
    </section>
  );
}

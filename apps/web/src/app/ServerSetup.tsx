import { type FormEvent, useState } from "react";

import { Banner } from "../ui/Banner";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { Icon } from "../ui/Icon";
import { Input } from "../ui/Input";
import { chooseServer, reachable } from "../lib/server";

/**
 * The first screen a packaged application shows: which server is this?
 *
 * # Why the question is asked at all
 *
 * A messenger with one server is a product; a messenger with an address field is a protocol. This
 * project has been the second since it started — `deploy/` exists so that anybody can run the
 * delivery service — and the applications were the one place that did not know it. Every packaged
 * build carried `http://127.0.0.1:8787` compiled in, which is to say it could only reach a server
 * running on the same machine.
 *
 * # Why there is no way back to this screen
 *
 * Changing server means changing account. This device is attested by an account key the other
 * server has never heard of, and its conversations are MLS groups living in the first server's
 * tables. There is no migration that keeps anything, and a "switch server" button would therefore
 * be a button that silently discards an identity.
 *
 * So the address is shown in the settings, read-only, and the only exit is erasing the device —
 * which exists, and says what it costs. The alternative would be an affordance that looks
 * reversible and is not.
 *
 * # Why it checks before it stores
 *
 * The native side validates the *shape* of the address and would happily store a well-formed one
 * that answers nothing. A typo in a hostname then produces an application that starts, tries to
 * sign in, fails, and offers no way back to the field that was wrong. Reaching the server first
 * is what keeps the mistake on this screen, where it can still be corrected.
 */
export function ServerSetup({ onReady }: { onReady: (origin: string) => void }) {
  const [address, setAddress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;

    setBusy(true);
    setError(null);

    try {
      // The order matters: reach it, then keep it. Storing first would leave a broken address on
      // disk, and the next launch would skip this screen and fail somewhere with less context.
      //
      // The typed string is probed rather than the normalised one, because normalising is the
      // native side's job and asking it would mean storing. A trailing slash makes the probe URL
      // `…//v1/push/vapid`, which every server this could be resolves the same way.
      switch (await reachable(address.trim().replace(/\/+$/, ""))) {
        case "not-whispee":
          setError("Something answered, but it is not a Whispee server. Check the port.");
          return;
        case "unreachable":
          setError("Nothing answered at that address.");
          return;
      }

      onReady(await chooseServer(address));
    } catch (failure) {
      // The message comes from `apps/desktop/src/server.rs` and is written to be read here.
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="safe-top safe-bottom safe-sides mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-section p-pane">
      <div className="flex flex-col gap-snug">
        <span
          aria-hidden="true"
          className="flex size-10 items-center justify-center rounded-control bg-(--color-surface-sunken) text-(--color-ink-muted)"
        >
          <Icon name="devices" size={20} />
        </span>
        <h1 className="text-title font-medium text-(--color-ink)">Which server?</h1>
        <p className="text-body text-(--color-ink-muted)">
          Whispee has no central service. This application talks to the one you name — somebody
          else&rsquo;s, or your own. Your messages are encrypted before they reach it either way;
          what it does learn is in the threat model.
        </p>
      </div>

      {error !== null && <Banner tone="danger">{error}</Banner>}

      <form onSubmit={(event) => void submit(event)} className="flex flex-col gap-gutter">
        <Field
          label="Server address"
          hint="Over HTTPS. Plain http:// reaches only this machine, for development."
        >
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              describedBy={describedBy}
              invalid={invalid}
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              type="url"
              inputMode="url"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="https://whispee.example"
              // The same argument `components/Lock.tsx` makes on the same line: this screen exists
              // to receive one value and holds nothing else to read, so there is no content the
              // focus could be taken away from. It is rendered before the application, never
              // beside it.
              // eslint-disable-next-line jsx-a11y/no-autofocus
              autoFocus
            />
          )}
        </Field>

        <Button type="submit" variant="primary" busy={busy} disabled={address.trim() === ""}>
          Continue
        </Button>
      </form>

      <p className="text-caption text-(--color-ink-muted)">
        This is asked once. Changing it later means starting a new account, because this device is
        known to that server and to no other.
      </p>
    </main>
  );
}

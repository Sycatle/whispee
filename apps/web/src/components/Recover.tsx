import { useEffect, useState } from "react";
import { recoverWithPasskey, recoverWithPassword } from "@/lib/escrow";
import { MAX_LENGTH as MAX_HANDLE_LENGTH, normalize, validate } from "@/lib/handle";
import { passkeysAvailable } from "@/lib/passkey";
import { Session } from "@/lib/session";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { handleMessage } from "@/ui/handleMessage";

/**
 * Getting back in with a secret rather than with the twelve words.
 *
 * # Why this is a screen of its own and not a fourth branch of the form
 *
 * The other three modes on the first screen all end in claiming or resolving a handle, so they
 * share a form. This one does not: the passkey path asks for nothing at all — the platform lists
 * the passkeys it holds and the account arrives with the escrow — and the password path asks for
 * a handle for a reason no other path has, which is that the handle is the key derivation's
 * salt.
 *
 * # What the reader has to be told, and where
 *
 * Two things, and both belong on the screen rather than in a document nobody opens:
 *
 * * **The wait is not a bug.** The password path spends a second or more in Argon2id before it
 *   even speaks to the server, because the lookup value *is* the output of that derivation. A
 *   spinner with no sentence next to it reads as a hung page.
 * * **A refusal cannot say what went wrong.** The server answers the same 404 to a wrong
 *   password and to an account that never set one up — it holds a hash and compares it, so it
 *   genuinely cannot tell them apart. The copy has to be equally uninformative, or it claims
 *   knowledge nobody has.
 */
export function RecoverWithSecret({
  onReady,
  onCancel,
}: {
  onReady: (session: Session) => void;
  onCancel: () => void;
}) {
  const [handle, setHandle] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"password" | "passkey" | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [passkeys, setPasskeys] = useState(false);

  // Read once, on mount, rather than during render: `passkeysAvailable` touches `navigator`,
  // which does not exist during a server-side render and would make this component unusable in
  // one for a line that is only about what to draw.
  useEffect(() => {
    setPasskeys(passkeysAvailable());
  }, []);

  const canonical = normalize(handle);
  const handleProblem = handle === "" ? null : validate(canonical);

  const finish = async (
    attempt: () => Promise<
      | { ok: true; accountId: string; handle: string | null; seed: Uint8Array }
      | { ok: false; reason: "unknown" | "tampered" | "cancelled" | "throttled" }
    >,
    kind: "password" | "passkey",
  ) => {
    setBusy(kind);
    setProblem(null);
    try {
      const result = await attempt();

      if (!result.ok) {
        setProblem(
          result.reason === "unknown"
            ? // Deliberately covers both possibilities, because the answer did. Naming only one
              // — "wrong password" — would be a guess presented as a fact, and the other reading
              // ("no account has this") is the one that tells somebody to stop retrying.
              "Nothing opened with that. Either the secret is wrong, or this account never had recovery switched on."
            : result.reason === "cancelled"
              ? "No passkey was used. If this device holds none for Whispee, recover with your password or your twelve words instead."
              : result.reason === "throttled"
                ? "Too many attempts from here in the last minute. Wait, then try again."
                : "The server returned something that did not open. Nothing was changed; try again, and if it keeps happening use your twelve words.",
        );
        return;
      }

      if (result.handle === null) {
        // The account exists and its seed came back, but the directory holds no live handle for
        // it. Nothing downstream can run without one, and inventing one would claim a name.
        setProblem(
          "Your account came back, but the server lists no handle for it. Recover with your twelve words instead.",
        );
        return;
      }

      onReady(await Session.restoreFromEscrow(result.accountId, result.handle, result.seed));
    } catch (error) {
      setProblem(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="mx-auto flex min-h-dvh max-w-md flex-col justify-center gap-section p-pane">
      <div>
        <h1 className="text-title font-medium text-(--color-ink)">Recover with a secret</h1>
        <p className="mt-snug text-prose text-(--color-ink-muted)">
          For an account that set up a password or a passkey for this. If it did not, your twelve
          words are the way back.
        </p>
      </div>

      {passkeys && (
        <div className="flex flex-col gap-snug rounded-control border border-(--color-border-subtle) bg-(--color-surface-raised) p-pane">
          <p className="text-caption text-(--color-ink-muted)">
            Your passkey knows which account it belongs to, so there is nothing to type.
          </p>
          <Button
            variant="secondary"
            busy={busy === "passkey"}
            disabled={busy !== null}
            onClick={() => void finish(recoverWithPasskey, "passkey")}
            className="w-full"
          >
            Use a passkey
          </Button>
        </div>
      )}

      <form
        className="flex flex-col gap-pane"
        onSubmit={(event) => {
          event.preventDefault();
          void finish(() => recoverWithPassword(canonical, password), "password");
        }}
      >
        <Field
          label="Account handle"
          hint="Needed even though you are about to type a password: it is part of how the password is turned into a key, so it has to be exactly the handle the account had when recovery was set up."
          error={handleProblem === null ? undefined : handleMessage(handleProblem)}
        >
          {(control) => (
            <Input
              id={control.id}
              describedBy={control.describedBy}
              invalid={control.invalid}
              value={handle}
              onChange={(event) => setHandle(event.target.value)}
              placeholder="alice"
              maxLength={MAX_HANDLE_LENGTH}
              autoComplete="username"
            />
          )}
        </Field>

        <Field
          label="Recovery password"
          hint="Not the password that unlocks this app on a device you already had. This is the one set up for getting back in with nothing."
        >
          {(control) => (
            <Input
              id={control.id}
              describedBy={control.describedBy}
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
            />
          )}
        </Field>

        <Button
          type="submit"
          variant="primary"
          busy={busy === "password"}
          disabled={busy !== null || validate(canonical) !== null || password === ""}
          className="w-full"
        >
          Recover the account
        </Button>

        {/*
          Stated before the press, not after it starts. The derivation is deliberately expensive
          — that cost is the only thing standing between a stolen database and this account — and
          a wait nobody was warned about reads as a broken page on a phone.
        */}
        <p className="text-caption text-(--color-ink-muted)">
          This takes a second or two on a computer, longer on a phone, and the app will not
          respond while it runs. That is the point: the same work has to be redone on every single
          guess by anyone attacking your password.
        </p>
      </form>

      {problem !== null && <Banner tone="danger" title={problem} />}

      <p className="text-caption text-(--color-ink-muted)">
        You will get your account and your saved history back, but not your ongoing
        conversations: they live in encrypted groups this new device is not a member of, and only
        someone already in them can add it back.
      </p>

      <Button variant="quiet" onClick={onCancel} className="w-full">
        Back
      </Button>
    </main>
  );
}

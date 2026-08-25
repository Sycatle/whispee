import { useEffect, useState } from "react";

import type { RecoveryKind } from "@/lib/api";
import { ESCROW_POLICY, type Verdict, check } from "@/lib/password";
import { passkeysAvailable } from "@/lib/passkey";
import { loadCrypto } from "@/lib/wasm";
import { useReport } from "@/state/report";
import { useSession } from "@/state/SessionProvider";
import { Banner } from "@/ui/Banner";
import { Button } from "@/ui/Button";
import { Checkbox } from "@/ui/Checkbox";
import { Field } from "@/ui/Field";
import { Input } from "@/ui/Input";
import { Panel } from "@/ui/Panel";

/**
 * Recovery without the twelve words. **Off by default, and the default is the argument.**
 *
 * # What this screen is actually for
 *
 * Not to make a feature discoverable. To make a trade visible *before* it is taken, which is
 * the opposite job from `Vault.tsx` — there the trade is already made and the screen restates
 * it, here it has not been made and the screen has to be the thing that makes it refusable.
 *
 * The trade: until an account sets a password here, its root secret has never been on the
 * server in any form, and a stolen database yields nothing that leads to an account. Afterwards
 * the server holds that secret encrypted, and whoever takes the database can attack the password
 * offline — no rate limit, no clock, no need to touch anybody's hardware. Winning opens the
 * account and, because the vault's key comes from the same seed, every archived message with it.
 *
 * So the danger banner sits above the field rather than under it, stays on screen while the
 * factor is on, and the checkbox gates the button rather than being a switch that acts by itself
 * — the same distinction `Vault.tsx` and `Switch.tsx` already draw.
 *
 * # Why the passkey half carries no such banner
 *
 * Because it has no such cost. Its key is 32 uniform bytes from an authenticator, so there is
 * nothing to guess and the offline attack simply does not apply. It has a different cost, and
 * that one is stated where it belongs: the passkey can be lost, and it is bound to this origin.
 * Giving both halves the same red banner would be tidy and would teach the reader to skip it.
 *
 * # The generated passphrase, and why it is offered first
 *
 * A password strong enough to survive an offline attack is not something most people invent.
 * zxcvbn is here to say so, but a refusal with no way forward is a screen people fight rather
 * than read. Six words drawn from the recovery-phrase word list are 66 bits and take one press.
 *
 * It is **not** a recovery phrase, and it is drawn from the same word list, so the copy has to
 * keep them apart: twelve of those words are an account, six are a password that opens one.
 */
export function RecoverySettings() {
  const session = useSession();
  const report = useReport();

  const [factors, setFactors] = useState<RecoveryKind[] | null>(null);
  const [password, setPassword] = useState("");
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [understood, setUnderstood] = useState(false);
  const [running, setRunning] = useState<"password" | "passkey" | RecoveryKind | null>(null);
  const [passkeys, setPasskeys] = useState(false);

  useEffect(() => {
    setPasskeys(passkeysAvailable());
  }, []);

  const refresh = () => {
    session
      .listRecovery()
      .then((list) => {
        setFactors(list.map((factor) => factor.kind));
      })
      .catch((error: unknown) => {
        report.error(error instanceof Error ? error.message : String(error));
      });
  };

  // Fetched rather than read from the session: another device can add or remove a factor, and a
  // screen reporting a stale answer here reports that an account is recoverable when it is not.
  useEffect(refresh, [session]);

  /**
   * Judged as the user types, and the late verdict is dropped if the password has moved on.
   *
   * The dictionaries arrive through a dynamic import, so the first answer is a moment behind the
   * keystroke that asked for it. `Lock.tsx` solves the same race the same way, and for the same
   * reason: a verdict rendered against a password nobody is holding any more is worse than none.
   */
  useEffect(() => {
    if (password === "") {
      setVerdict(null);
      return;
    }

    let current = true;
    void check(password, [session.handle], ESCROW_POLICY).then((judged) => {
      if (current) setVerdict(judged);
    });
    return () => {
      current = false;
    };
  }, [password, session.handle]);

  const draw = async () => {
    const crypto = await loadCrypto();
    setPassword(crypto.generatePassphrase(6));
  };

  const setPasswordFactor = async () => {
    setRunning("password");
    try {
      await session.enablePasswordRecovery(password);
      setPassword("");
      setUnderstood(false);
      report.done("Recovery password set. Keep it somewhere you will still have it in a year.");
      refresh();
    } catch (error: unknown) {
      report.error(error instanceof Error ? error.message : String(error));
    } finally {
      setRunning(null);
    }
  };

  const setPasskeyFactor = async () => {
    setRunning("passkey");
    try {
      if (await session.enablePasskeyRecovery()) {
        report.done("Passkey recovery is on.");
        refresh();
      } else {
        report.error(
          "This device's passkeys cannot hold a key for Whispee. Use the password instead.",
        );
      }
    } catch (error: unknown) {
      report.error(error instanceof Error ? error.message : String(error));
    } finally {
      setRunning(null);
    }
  };

  const forget = async (kind: RecoveryKind) => {
    setRunning(kind);
    try {
      await session.forgetRecovery(kind);
      report.done(
        kind === "password"
          ? "The recovery password no longer opens this account."
          : "The passkey no longer opens this account.",
      );
      refresh();
    } catch (error: unknown) {
      report.error(error instanceof Error ? error.message : String(error));
    } finally {
      setRunning(null);
    }
  };

  const hasPassword = factors?.includes("password") === true;
  const hasPasskey = factors?.includes("passkey") === true;

  return (
    <div className="space-y-pane">
      <Panel
        title="Recovery password"
        description="A password that gets your account back when every device is gone — instead of typing the twelve words. It never reaches the server: what the server keeps is your account key, encrypted with it."
        actions={
          hasPassword ? (
            <Button
              onClick={() => void forget("password")}
              busy={running === "password" && factors !== null}
              disabled={running !== null}
            >
              Turn it off
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={() => void setPasswordFactor()}
              busy={running === "password"}
              disabled={running !== null || verdict?.ok !== true || !understood}
            >
              Set the password
            </Button>
          )
        }
      >
        <div className="space-y-pane">
          <Banner tone="danger" title="What this gives up, permanently">
            Right now your account key has <strong>never been on the server</strong>, in any
            form. Setting this password puts it there, encrypted with it. Anyone who ends up with
            a copy of that database — the person running it, a leak, an old backup — can then
            guess at your password for as long as they like, on their own machines, with nothing
            to stop them. Getting it right hands them your account and, because the same key
            opens your history backup, everything you have ever archived.
            <br />
            <br />
            That is why the bar below is higher than the one on your device lock, and why we
            offer to draw the password for you.
          </Banner>

          {hasPassword ? (
            <p className="text-caption text-(--color-ink-muted)">
              A recovery password is set. To change it, turn it off and set a new one — there is
              no way to check the old one from here, and a screen that pretended to would be
              guessing.
              <br />
              <br />
              Two things that quietly switch it off: renaming your handle, because the handle is
              part of how the password becomes a key; and rotating your account key, because what
              is stored is the old key. Both are reported here as the password simply being gone.
            </p>
          ) : (
            <>
              <Field
                label="Recovery password"
                hint="Sixteen characters at least, and it has to be one an attacker's word lists do not already contain. Length is what protects you — not capitals or punctuation."
                error={verdict !== null && !verdict.ok ? verdict.reason : undefined}
              >
                {(control) => (
                  <Input
                    id={control.id}
                    describedBy={control.describedBy}
                    invalid={verdict !== null && !verdict.ok}
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="new-password"
                  />
                )}
              </Field>

              <div className="flex flex-wrap items-center gap-snug">
                <Button variant="secondary" onClick={() => void draw()} disabled={running !== null}>
                  Draw one for me
                </Button>
                {verdict?.ok === true && (
                  <p className="text-caption text-(--color-ink-muted)">
                    {verdict.guessesLog10 === null
                      ? "The strength checker did not load, so only the length was checked."
                      : `About 10^${String(Math.round(verdict.guessesLog10))} guesses to find, by someone using published word lists.`}
                  </p>
                )}
              </div>

              <p className="text-caption text-(--color-ink-muted)">
                A drawn password is six words from the same list your recovery phrase uses.{" "}
                <strong>It is not a recovery phrase</strong>: twelve of those words are an
                account, six are a password that opens one. Write it down like anything else you
                cannot afford to lose.
              </p>

              <Checkbox
                label="I understand that my account key will be stored on the server, encrypted with this password, and that whoever obtains that copy can attack it offline."
                checked={understood}
                onChange={(event) => setUnderstood(event.target.checked)}
              />
            </>
          )}
        </div>
      </Panel>

      <Panel
        title="Passkey recovery"
        description="The same thing, with a key your device or password manager holds instead of one you remember. Nothing to type, and nothing to guess."
        actions={
          hasPasskey ? (
            <Button
              onClick={() => void forget("passkey")}
              busy={running === "passkey" && factors !== null}
              disabled={running !== null}
            >
              Turn it off
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={() => void setPasskeyFactor()}
              busy={running === "passkey"}
              disabled={running !== null || !passkeys}
            >
              Create a passkey
            </Button>
          )
        }
      >
        <div className="space-y-pane">
          {/*
            No danger banner here, and that is a decision rather than an omission. This factor's
            key comes from the authenticator at full strength, so the offline guessing that the
            password banner is about cannot happen. Repeating a red warning where it does not
            apply is how a reader learns to skip the one where it does.
          */}
          <p className="text-caption text-(--color-ink-muted)">
            Because the key is drawn by the authenticator rather than remembered by you, nobody
            can guess it — not even with a copy of the whole server. That is the one thing this
            has over the password.
          </p>

          <p className="text-caption text-(--color-ink-muted)">
            What it costs instead: the passkey is a thing you can lose. If your password manager
            or your phone syncs it, it survives losing this device; if it lives only in this
            device&apos;s hardware, it dies with it — and nothing here can tell which kind you
            are about to create, because the platform does not say. It is also tied to this
            site&apos;s address: a passkey made here will not open your account on a Whispee
            hosted somewhere else.
          </p>

          {!passkeys && (
            <Banner tone="warn" title="This browser cannot do it">
              It offers no passkey API. The recovery password above works everywhere.
            </Banner>
          )}
        </div>
      </Panel>

      {factors !== null && !hasPassword && !hasPasskey && (
        <p className="text-caption text-(--color-ink-muted)">
          Nothing is set up, which is the default and a perfectly good place to stay: your twelve
          words already recover this account, and they are the only version of this where the
          server has nothing to attack. These exist for people who will not keep a piece of paper
          for ten years — which is most people, and pretending otherwise is how accounts get lost.
        </p>
      )}
    </div>
  );
}

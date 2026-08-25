import { Banner } from "@/ui/Banner";
import { isTauri } from "@/lib/platform";

/**
 * The limit the user has to know in order to decide what to trust this tool with.
 *
 * # Where it went, and why it did not simply disappear
 *
 * It used to sit in the application header (`App.tsx:489-497`), which the three column shell no
 * longer has. It is not dropped: it is the one paragraph in the interface that says what the
 * whole product cannot do, and a redesign that quietly loses it would be a redesign that made
 * the tool look safer than it is.
 *
 * It now appears in exactly two places, both of them screens somebody reads rather than skims
 * past: the empty centre, which is the first thing seen on a cold start, and the top of the
 * settings screen, which is where someone goes when they are deciding how much to rely on this.
 *
 * # Two claims, and only one of them is about delivery
 *
 * The banner used to make both in one paragraph: that this code arrives from a server on every
 * load, and that the project is unaudited. They are unrelated, they have different remedies, and
 * merging them meant the desktop build — where the first is false — silently dropped the second
 * as well. Somebody who installed the signed binary was told nothing about the audit, which is
 * the half that still applies to them.
 *
 * So there are two banners now. [`DeliveryWarning`] is about the web target and answerable;
 * [`AuditWarning`] is about the project and is not.
 *
 * # Why it is silent under Tauri
 *
 * The argument is specifically about **delivery**: a web server hands over this code on every
 * single load, so it can hand over a different version tomorrow, to one person, and nothing in a
 * browser would show it. The desktop build is a signed binary that was downloaded once and
 * verified once; the same sentence there would be false. Showing a warning whose reasoning does
 * not apply is not extra caution, it is a claim the user cannot check — and it costs the
 * credibility of every other warning in the application.
 *
 * What this does not solve: the desktop build has its own supply chain, and "signed" only means
 * the key that signed it. That is a different argument and it belongs in `docs/THREAT-MODEL.md`,
 * not in a banner.
 */
export function WebClientWarning({ className }: { className?: string }) {
  return (
    <>
      <DeliveryWarning className={className} />
      <AuditWarning className={className} />
    </>
  );
}

/**
 * The delivery problem, and what can now be done about it.
 *
 * The sentence changed when the answer became true rather than because it read better. Every
 * release publishes a manifest of the bundle's hashes, attested by GitHub to the commit and the
 * workflow that produced it — so the claim "this is the published build" is checkable by somebody
 * other than the party making it. `scripts/verify-web.sh` does it by hand; the extension under
 * `extension/` does it continuously.
 *
 * **What did not change is that this banner stays.** The verdict cannot live in this page:
 * everything here is drawn by the server being checked, so a badge that went green on a
 * "verified" signal would be forged by exactly the server it was meant to catch. The check
 * belongs in the extension's own icon, and this paragraph can do no more than say so.
 */
function DeliveryWarning({ className }: { className?: string }) {
  if (isTauri()) return null;

  return (
    <Banner tone="warn" title="Web client" className={className}>
      The server delivers this code on every load, and could deliver a version that exfiltrates
      your keys. No browser API fixes that — but every release publishes the hashes of this
      bundle, so what you were served can be compared against what the source produced. The
      answer has to come from outside this page: see the repository&rsquo;s{" "}
      <code>extension/</code> and <code>scripts/verify-web.sh</code>.
    </Banner>
  );
}

/**
 * The audit, which no amount of build verification touches.
 *
 * Shown on **every** target, desktop included. A reproducible signed binary establishes that the
 * bytes match the source; it says nothing about whether the source is right, and this project's
 * README is explicit that no external review has happened or will. Hiding that from the people
 * who took the trouble to install the packaged build would be telling the least worried users the
 * least.
 */
function AuditWarning({ className }: { className?: string }) {
  return (
    <Banner tone="warn" title="Unaudited" className={className}>
      This is a learning project. Its cryptography has had no external review, and a protocol that
      is correct on paper fails in practice on details only an audit finds. For genuinely
      sensitive conversations, use Signal.
    </Banner>
  );
}

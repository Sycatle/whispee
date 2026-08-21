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
  if (isTauri()) return null;

  return (
    <Banner tone="warn" title="Web client" className={className}>
      The server delivers this code on every load, and could deliver a version that exfiltrates
      your keys. No browser API fixes that. This is a learning project, unaudited — for genuinely
      sensitive conversations, use Signal.
    </Banner>
  );
}

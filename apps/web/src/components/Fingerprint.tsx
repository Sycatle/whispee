/**
 * Renders a fingerprint for human comparison.
 *
 * Split into fixed-width blocks: comparing two continuous hex strings is notoriously
 * unreliable, and the attack is precisely to produce a key whose fingerprint *looks* like
 * the right one. We cannot make the comparison pleasant, but we can make it possible.
 */
export function Fingerprint({ value }: { value: string }) {
  return (
    /*
     * A grid, and not the inline flow this used to be.
     *
     * Inline blocks wrap wherever the line runs out, so the same fingerprint breaks in a
     * different place in a 320 px sheet and a 400 px detail panel — and the two screens being
     * compared are rarely the same width. Worse, `break-all` is on this element for a reason
     * (a hex run has no break opportunity of its own), and in inline flow it will happily cut a
     * block in half. A comparison done block by block against a display that splits blocks is
     * not a comparison; it is where a near-miss key gets waved through.
     *
     * Fixed tracks fix the reading order instead: every block occupies one cell, wrapping
     * happens between cells only, and the blocks line up in columns down the panel — which is
     * the axis the eye actually checks. `auto-fill` with a 5ch floor holds four hex characters
     * plus the 0.05em tracking from `.fingerprint`, so a track is never narrower than its
     * contents and `break-all` never has cause to fire.
     *
     * The family comes from `--font-evidence` by way of `.fingerprint` in `index.css`: one
     * decision, made once, for every screen that asks a human to read data rather than prose.
     *
     * What this does not solve: it does nothing about the comparison itself. Two fingerprints
     * agreeing here is only worth what the channel they were exchanged over is worth, and this
     * component cannot see that channel.
     */
    <output className="fingerprint grid grid-cols-[repeat(auto-fill,minmax(5ch,1fr))] gap-x-snug gap-y-tight text-body select-all break-all">
      {value.split(" ").map((block, index) => (
        <span key={`${block}-${index}`}>{block}</span>
      ))}
    </output>
  );
}

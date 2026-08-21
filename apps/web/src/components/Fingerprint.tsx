/**
 * Renders a fingerprint for human comparison.
 *
 * Split into fixed-width blocks: comparing two continuous hex strings is notoriously
 * unreliable, and the attack is precisely to produce a key whose fingerprint *looks* like
 * the right one. We cannot make the comparison pleasant, but we can make it possible.
 */
export function Fingerprint({ value }: { value: string }) {
  return (
    <output className="fingerprint block text-sm leading-relaxed break-all select-all">
      {value.split(" ").map((block, index) => (
        <span key={`${block}-${index}`} className="mr-2 inline-block">
          {block}
        </span>
      ))}
    </output>
  );
}

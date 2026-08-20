/**
 * Affichage d'une empreinte destinée à la comparaison humaine.
 *
 * Découpée en blocs et en chasse fixe : comparer deux chaînes hexadécimales continues est
 * notoirement peu fiable, et l'attaque consiste précisément à produire une clé dont
 * l'empreinte *ressemble* à la bonne. On ne peut pas rendre la comparaison agréable, mais
 * on peut la rendre possible.
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

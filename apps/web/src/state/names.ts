/**
 * The bridge between the two records `Session` holds and the pure rules in `lib/naming.ts`.
 *
 * It exists so that no component has to know that a name comes from two different places, and so
 * that reading a name subscribes to changes in it — `useSession()` does that, and going through
 * this hook means a component cannot accidentally read `session.profiles` off a prop instead.
 *
 * Deliberately not memoised. The object is two references and a fresh wrapper per render costs
 * nothing, whereas a `useMemo` here would need `useRevision()` in its dependencies to be correct
 * at all, and would be wrong the day somebody forgets — see the rules in `SessionProvider.tsx`.
 */
import type { NameSources } from "../lib/naming.ts";
import { useSession } from "./SessionProvider.tsx";

export function useNames(): NameSources {
  const session = useSession();
  return { petnames: session.petnames, profiles: session.profiles };
}

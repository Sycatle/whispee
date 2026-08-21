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

  // Our own name is folded into `profiles` rather than handled as a special case at each call
  // site. `profiles` holds what people assert about themselves, and that is precisely what a
  // display name is — ours is not a different kind of claim because we happen to be the one
  // making it, and treating it as one meant three copies of the same fallback rule in three
  // components.
  //
  // **Under the account id**, like every other entry. It used to be the handle, which was the
  // same string; since the rekey it is not, and the mismatch was invisible in most places and
  // wrong in one that matters — a message mentioning *us* looked up our id, found nothing, and
  // drew a thirty-two character identifier where our own name belongs.
  //
  // The `at` is zero and never compared: nothing arrives over the wire for our own account, since
  // `absorbProfile` is only reached by a message from a peer.
  const profiles =
    session.displayName === undefined
      ? session.profiles
      : { ...session.profiles, [session.accountId]: { name: session.displayName, at: 0 } };

  // Our own handle, for the same reason. `session.handles` is what *peers* have claimed, and we
  // never receive our own claim — so without this line we are the one account in every room that
  // renders as an id.
  const handles = { ...session.handles, [session.accountId]: session.handle };

  return { petnames: session.petnames, profiles, handles };
}

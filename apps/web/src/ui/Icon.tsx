import {
  Bell,
  ChevronDown,
  ChevronLeft,
  Copy,
  Info,
  Lock,
  MonitorSmartphone,
  Paperclip,
  Plus,
  QrCode,
  Search,
  SendHorizontal,
  Settings,
  SmilePlus,
  SunMoon,
  Trash2,
  TriangleAlert,
  UserRound,
  Vault,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

/**
 * The icon inventory. Twenty, named by role, and closed.
 *
 * # Named imports only, never `import * as icons`
 *
 * A star import defeats tree-shaking: the bundler cannot prove which of the fifteen hundred
 * modules in `lucide-react` are unreachable, so it keeps them. Twenty named imports are a few
 * kilobytes; the star import is the whole set. This is not a style preference, it is the
 * difference between the budget the plan allowed for icons and roughly three hundred times it.
 *
 * # Every icon in the application goes through this file
 *
 * One place to see the whole inventory, so growth is a decision someone makes rather than a
 * thing that happens. The size of the bundle is bounded by construction rather than by anyone's
 * discipline. And the names are *roles* — `send`, `revoke`, `backup` — not Lucide's names, so
 * replacing Lucide, or hand-drawing one glyph, touches this file and no call site.
 *
 * # What this does not cover
 *
 * The emoji people send. They are content, not chrome: the sender and the receiver have to see
 * the same thing, and a line-art icon would say something else entirely.
 *
 * They used to be Unicode, drawn by whatever font the platform had — which meant three different
 * pictures on three platforms, and tofu on a Linux build with no emoji font installed. They are
 * now Twemoji artwork, shipped in the sprite sheets under `public/emoji` and drawn by
 * `ui/Emoji.tsx`. The conclusion is unchanged and the reason is stronger: content is not an entry
 * in this table.
 *
 * `emoji` below is the exception that proves it. It is the *button* that opens the picker, which
 * is an interface control like any other.
 */
export type IconName =
  | "add"
  | "alert"
  | "attach"
  | "backup"
  | "back"
  | "close"
  | "collapse"
  | "copy"
  | "devices"
  | "emoji"
  | "info"
  | "lock"
  | "notifications"
  | "pair"
  | "profile"
  | "revoke"
  | "search"
  | "send"
  | "settings"
  | "theme";

const ICONS: Record<IconName, LucideIcon> = {
  /** Start a conversation, add a member. */
  add: Plus,
  /** Anything the user must not scroll past. */
  alert: TriangleAlert,
  /** The composer's paperclip, which was a literal emoji. */
  attach: Paperclip,
  /** The vault. Lucide's `Vault` is a strongbox, which is what the vault screen describes. */
  backup: Vault,
  /** Leaves a pane on the way back. Distinct from `collapse`, which opens something in place. */
  back: ChevronLeft,
  /** Dismiss a dialog, a sheet, a banner. */
  close: X,
  /** The disclosure chevron on the rail's sections. */
  collapse: ChevronDown,
  /** Copy a fingerprint or a pairing code — the one gesture the evidence screens all need. */
  copy: Copy,
  /** The device list: this account's, and a peer's. */
  devices: MonitorSmartphone,
  /**
   * Opens the emoji picker, from the composer and from the reaction bar.
   *
   * Chrome, not content — which is the distinction the note at the top of this file draws, and
   * the reason it survives the emoji becoming artwork of their own. What a person *says* is a
   * Twemoji SVG on every platform (`ui/Emoji.tsx`); the button that opens the drawer of them is
   * an interface control and belongs to the same line-art set as everything else here.
   */
  emoji: SmilePlus,
  /** Opens the detail panel, where verification actually happens. */
  info: Info,
  /** The local lock. A padlock, and no attempt to distinguish locked from unlocked by shape. */
  lock: Lock,
  notifications: Bell,
  /** Pairing, which is a QR code in practice. */
  pair: QrCode,
  /** Your own account: the name you show and the handle you cannot change. */
  profile: UserRound,
  /** Revoke a device, delete a vault entry. Destructive, and drawn as such. */
  revoke: Trash2,
  search: Search,
  send: SendHorizontal,
  settings: Settings,
  /** One glyph for the theme control, whose three states are named in words beside it. */
  theme: SunMoon,
};

export function Icon({
  name,
  size = 16,
  label,
  className,
}: {
  name: IconName;
  /** Pixels. The default matches the 14 px body text these sit beside. */
  size?: number;
  /**
   * Set only when the icon is the *sole* content of a control — a bare icon button. Anywhere a
   * visible label sits next to it, leave this out: the icon is then decorative and announcing it
   * would read the same thing twice.
   */
  label?: string;
  className?: string;
}) {
  const Glyph = ICONS[name];
  return (
    <Glyph
      size={size}
      // Lucide sizes its stroke for 24 px. Left alone, a glyph drawn at 16 px comes out heavier
      // than the text beside it, which is the usual reason icon sets look bolted on.
      strokeWidth={1.75}
      aria-hidden={label === undefined ? true : undefined}
      role={label === undefined ? undefined : "img"}
      aria-label={label}
      focusable="false"
      className={className}
    />
  );
}

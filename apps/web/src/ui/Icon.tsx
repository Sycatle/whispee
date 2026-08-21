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
  SunMoon,
  Trash2,
  TriangleAlert,
  Vault,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

/**
 * The icon inventory. Eighteen, named by role, and closed.
 *
 * # Named imports only, never `import * as icons`
 *
 * A star import defeats tree-shaking: the bundler cannot prove which of the fifteen hundred
 * modules in `lucide-react` are unreachable, so it keeps them. Eighteen named imports are a few
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
 * The five reaction emoji stay Unicode. They are content, not chrome: they must look like what
 * the recipient sees, and redrawing them in a line-art set would make the sender and the
 * receiver disagree about what was sent.
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
  | "info"
  | "lock"
  | "notifications"
  | "pair"
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
  /** Opens the detail panel, where verification actually happens. */
  info: Info,
  /** The local lock. A padlock, and no attempt to distinguish locked from unlocked by shape. */
  lock: Lock,
  notifications: Bell,
  /** Pairing, which is a QR code in practice. */
  pair: QrCode,
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

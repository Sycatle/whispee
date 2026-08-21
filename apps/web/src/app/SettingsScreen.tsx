import { DeviceSettings } from "@/components/Devices";
import { LockSettings } from "@/components/Lock";
import { NoticeSettings } from "@/components/Notices";
import { PairDevice } from "@/components/Pairing";
import { ProfileSettings } from "@/components/Profile";
import { SignalSettings } from "@/components/Signals";
import { VaultSettings } from "@/components/Vault";
import { useDuo } from "@/lib/duo";
import { useTheme } from "@/lib/theme";
import { useOcclusion } from "@/lib/viewport";
import { Icon } from "@/ui/Icon";
import { IconButton } from "@/ui/IconButton";
import { Panel } from "@/ui/Panel";
import { cn } from "@/ui/cn";
import type { SettingsSection } from "@/routes/route";
import { useNavigate } from "@/routes/Router";
import { WebClientWarning } from "./WebClientWarning";

/**
 * `#/settings/<section>` — the panels that used to swap themselves into the rail, plus a profile.
 *
 * # The bug this fixes for free, which is not a cosmetic one
 *
 * `Pairing` and `Lock` both contain text inputs, and both were rendered *inside the rail*. The
 * rail applies neither `useOcclusion()` nor `safe-bottom`. On a phone that means the software
 * keyboard slides over the field you are typing in: **people were entering their lock password
 * behind the keyboard**, unable to see a character of it, on the one screen where a typo cannot
 * be recovered from. Routing these to a full-screen view that applies both is what makes the
 * field visible. It is worth saying plainly because a redesign is easy to file as decoration.
 *
 * # A navigation list, not tabs
 *
 * Eight destinations in three groups, each with its own heading. Tabs would have to fit eight
 * labels on one line at 480 pixels — the narrowest the desktop window goes — and would lose the
 * grouping, which is the part that tells somebody where to look for a setting they have not seen
 * before.
 *
 * # Why it takes the detail column too
 *
 * Settings are not a property of a conversation, so leaving the right hand column showing one
 * would be a third of the window contradicting the other two. The rail stays: it is where you
 * came from and where you are going back to.
 */

interface Entry {
  section: SettingsSection;
  label: string;
  icon: React.ReactNode;
}

const GROUPS: { heading: string; entries: Entry[] }[] = [
  {
    heading: "Your account",
    entries: [
      { section: "profile", label: "Name and handle", icon: <Icon name="profile" /> },
      { section: "devices", label: "Your devices", icon: <Icon name="devices" /> },
      { section: "pairing", label: "Add a device", icon: <Icon name="pair" /> },
      { section: "backup", label: "History backup", icon: <Icon name="backup" /> },
    ],
  },
  {
    heading: "Privacy",
    entries: [
      { section: "lock", label: "Lock", icon: <Icon name="lock" /> },
      { section: "receipts", label: "Receipts and indicators", icon: <Icon name="settings" /> },
      { section: "notifications", label: "Notifications", icon: <Icon name="notifications" /> },
    ],
  },
  {
    heading: "System",
    entries: [{ section: "appearance", label: "Appearance", icon: <Icon name="theme" /> }],
  },
];

const TITLES: Record<SettingsSection, string> = {
  profile: "Name and handle",
  devices: "Your devices",
  pairing: "Add a device",
  lock: "Lock",
  backup: "History backup",
  receipts: "Receipts and indicators",
  notifications: "Notifications",
  appearance: "Appearance",
};

const THEMES = [
  { value: "system", label: "Match the system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
] as const;

/**
 * The only genuinely new settings screen in this batch, and it is three radio buttons.
 *
 * Native radios rather than a segmented control: arrow-key navigation, the group semantics and
 * the announced position in the set all come with the element, and every hand-rolled segmented
 * control in the wild reimplements two of the three and forgets the last.
 */
function Appearance() {
  const { theme, setTheme } = useTheme();

  return (
    <Panel
      title="Theme"
      description="Matching the system is the default, and the only setting with no flash: an override contrary to the operating system paints one frame in the wrong palette before the script that reads your choice has run. The content security policy forbids the inline script that would prevent it."
    >
      <fieldset className="space-y-snug">
        <legend className="sr-only">Theme</legend>
        {THEMES.map((option) => (
          <label key={option.value} className="flex items-center gap-snug text-body touch:min-h-11">
            <input
              type="radio"
              name="theme"
              value={option.value}
              checked={theme === option.value}
              onChange={() => setTheme(option.value)}
              className="accent-(--color-accent)"
            />
            {option.label}
          </label>
        ))}
      </fieldset>
    </Panel>
  );
}

/**
 * The panels, now reached by URL.
 *
 * Three of them still take a callback, and it is not an oversight on either side: `onClose` and
 * `onDone` mean "this flow has finished", which is a different statement from "the panel is
 * gone". They used to collapse an inline panel; here they hand the reader back to the list of
 * settings, which is the closest thing to what they meant. Navigating rather than going back:
 * the flow completing is not the reader undoing anything, and `history.back()` from a pairing
 * they just finished would land them wherever they came from instead of where the result is.
 */
function Section({ section }: { section: SettingsSection }) {
  const navigate = useNavigate();
  const done = () => navigate({ kind: "settings", section: null });

  switch (section) {
    case "profile":
      return <ProfileSettings />;
    case "devices":
      return <DeviceSettings onClose={done} />;
    case "pairing":
      return <PairDevice onDone={done} />;
    case "lock":
      return <LockSettings onDone={done} />;
    case "backup":
      return <VaultSettings />;
    case "receipts":
      return <SignalSettings />;
    case "notifications":
      return <NoticeSettings />;
    case "appearance":
      return <Appearance />;
  }
}

function Navigation({ section }: { section: SettingsSection | null }) {
  const navigate = useNavigate();

  return (
    <nav aria-label="Settings" className="space-y-pane p-snug">
      {GROUPS.map((group) => (
        <div key={group.heading}>
          <h3 className="px-snug py-tight text-caption font-medium tracking-wide text-(--color-ink-muted) uppercase">
            {group.heading}
          </h3>
          <ul>
            {group.entries.map((entry) => (
              <li key={entry.section}>
                <button
                  type="button"
                  onClick={() => navigate({ kind: "settings", section: entry.section })}
                  aria-current={section === entry.section ? "page" : undefined}
                  className={cn(
                    "flex w-full items-center gap-snug rounded-control px-snug py-snug text-left text-body touch:min-h-11",
                    "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-(--color-accent)",
                    section === entry.section
                      ? "bg-(--color-surface-raised) font-medium"
                      : "hover:bg-(--color-surface-sunken)",
                  )}
                >
                  <span className="shrink-0 text-(--color-ink-muted)">{entry.icon}</span>
                  <span className="min-w-0 flex-1 truncate">{entry.label}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function SettingsScreen({ section }: { section: SettingsSection | null }) {
  const duo = useDuo();
  const occlusion = useOcclusion();

  // On one panel the list and the section are two screens, so that the back gesture steps from a
  // setting to the list before leaving settings altogether.
  const showNavigation = duo || section === null;

  return (
    <section className="flex min-h-0 flex-1 bg-(--color-surface)">
      {showNavigation && (
        // No `border-r`. The shell no longer divides anything with a hairline — panes are
        // separated by the gutter of ground between them — and a rule drawn here would be the
        // only vertical line left in the window, which would read as an accident rather than as
        // a system.
        //
        // What that does not solve: this is a split *inside* one pane, so there is no gutter to
        // do the separating either. The list and the section it opens now touch, and what tells
        // them apart is the section's own header and the selected row's `surface-raised`. If
        // that turns out to be too little, the answer is to give the list a background of its
        // own — not to bring the hairline back.
        <div
          className={cn(
            "safe-top min-h-0 overflow-y-auto",
            duo ? "w-64 shrink-0 bg-(--color-surface)" : "safe-sides w-full",
          )}
        >
          <header className="flex items-center gap-snug px-pane py-snug">
            <h1 className="flex-1 text-title font-medium">Settings</h1>
            {!duo && (
              <IconButton
                label="Back to conversations"
                icon={<Icon name="close" />}
                onClick={() => history.back()}
              />
            )}
          </header>
          <div className="px-pane">
            <WebClientWarning />
          </div>
          <Navigation section={section} />
        </div>
      )}

      {section !== null && (
        <div
          // The two things the rail never applied, and the reason the lock password is now
          // visible while it is being typed on a phone.
          style={{ paddingBottom: occlusion || undefined }}
          className="safe-top safe-bottom safe-sides min-h-0 min-w-0 flex-1 overflow-y-auto"
        >
          <header className="sticky top-0 z-(--z-index-sticky) flex items-center gap-snug border-b border-(--color-border-subtle) bg-(--color-surface) px-pane py-snug">
            {/* Undoes the navigation that got here rather than naming a destination — see the
                rule in `routes/Router.tsx`. */}
            <IconButton
              label={duo ? "Close settings" : "Back to settings"}
              icon={<Icon name={duo ? "close" : "back"} size={20} />}
              onClick={() => history.back()}
              className="-ml-tight"
            />
            <h1 className="min-w-0 flex-1 truncate text-body font-medium">{TITLES[section]}</h1>
          </header>

          <div className="space-y-pane p-pane">
            <Section section={section} />
          </div>
        </div>
      )}

      {duo && section === null && (
        <div className="flex min-h-0 flex-1 items-center justify-center p-pane text-center text-body text-(--color-ink-muted)">
          Pick a setting on the left.
        </div>
      )}
    </section>
  );
}

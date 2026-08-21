/**
 * The names of the shortcuts, apart from their definitions.
 *
 * A separate file for one union, so that `ui/Menu.tsx` can type its `shortcut` prop without
 * importing the keymap — the menu draws a chord, it has no business holding the list of them.
 */
export type BindingId = "rail.filter" | "detail.toggle" | "settings.open" | "help.shortcuts";

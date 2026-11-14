#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  class EdCommands;

  /** Each command's keys as registered: what Settings › Keys resets to, and what keys.ini leaves out. */
  using EdKeyDefaults = std::map<std::string, std::string, std::less<>>;

  /** Two keys per command in Settings › Keys; the registry takes any number, the page shows these two. */
  constexpr int kKeySlots = 2;

  /** The keys of every command now, by id: taken right after the commands are registered, before keys.ini is read. */
  [[nodiscard]] EdKeyDefaults KeyDefaults(const EdCommands& commands);

  /**
   * keys.ini: one line per command whose keys differ from its default, `<id>=<keys>` (`file.save=Ctrl+S, F2`), an
   * empty value for a command whose keys were taken away. Lines starting `;` or `#` and a `[Keys]` header are
   * skipped. Applies each line; what it can't use (no such command, a chord it can't read) is returned, one text per
   * problem, and the rest still applies.
   */
  std::vector<std::string> ReadKeymap(EdCommands& commands, std::string_view text);
  /** keys.ini's text for the commands' keys now: only those that differ from `defaults`, in the registry's order. */
  [[nodiscard]] std::string WriteKeymap(const EdCommands& commands, const EdKeyDefaults& defaults);

  /** Slot `slot` (0 or 1) of a command's keys: its first or second chord, or empty. */
  [[nodiscard]] std::string KeySlot(std::string_view keys, int slot);
  /**
   * The keys with slot `slot` set to `chord` (empty: cleared; the chord after it moves up). A chord already in the
   * other slot isn't doubled: it moves here. Chords past the two slots are kept after them.
   */
  [[nodiscard]] std::string WithKeySlot(std::string_view keys, int slot, std::string_view chord);

  /** A chord from a key name (as CanonicalChord reads one) and the modifiers held; empty when the key has no name. */
  [[nodiscard]] std::string ChordOf(std::string_view key, bool ctrl, bool shift, bool alt);
  /** A Windows virtual-key code's name as the editor writes keys ('A' gives "A", VK_F5 "F5", VK_OEM_PLUS "="); empty
   * for the modifiers themselves and for keys the editor doesn't bind (the numeric keypad, media keys, ","). */
  [[nodiscard]] std::string VirtualKeyName(unsigned virtualKey);

  /**
   * Chords a text field or the panels' keyboard navigation use themselves, so a command bound to one doesn't run
   * from there: while `typing`, every chord without Ctrl or Alt except F1-F24 and Escape, and Ctrl+A/C/V/X/Z/Y,
   * Ctrl+Shift+Z, Ctrl with Left/Right/Home/End/Backspace/Delete; at any time the arrows, Space, Enter, Tab and
   * Escape alone (ImGui's keyboard navigation).
   */
  [[nodiscard]] bool PanelsKeepChord(std::string_view chord, bool typing);

  /**
   * Commands that also run while a play has the game's keys (the view then belongs to the game): F5's Play/Stop and
   * F6's view switch. Everything else bound there stays the game's.
   */
  [[nodiscard]] bool RunsOverGame(std::string_view commandId);
} // namespace faf::editor

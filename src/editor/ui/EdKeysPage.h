#pragma once

#include <string>

#include "editor/ui/EdKeymap.h"

namespace faf::editor
{
  class EdCommands;

  /** The chord pressed in the panels this frame (a key with its modifiers), or empty: none, or only a modifier. */
  [[nodiscard]] std::string PanelChordPressed();

  /**
   * True while Settings › Keys waits for a key, and on the frame a key ended the wait: no command runs from the
   * keyboard then (the key that set a binding doesn't also run it).
   */
  [[nodiscard]] bool KeysPageCapturing();

  /**
   * Settings › Keys, drawn into the current window: a filter, then every command by category with its two keys. A
   * key's button waits for the next key (Escape stops waiting, Backspace takes the key away); a key another command
   * has is said on both rows, with a button that takes it from the other. Each row resets to its default, and Reset
   * all does every row. True when keys changed this frame (the caller writes keys.ini).
   */
  bool DrawKeysPage(EdCommands& commands, const EdKeyDefaults& defaults);
} // namespace faf::editor

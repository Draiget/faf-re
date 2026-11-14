#pragma once

namespace faf::editor
{
  class EdCommands;

  /** Opens the command palette (Ctrl+K, Ctrl+Shift+P, or the title row's search box) at the next frame, with `query`
   * typed (test runs: `/palette <text>`). */
  void OpenCommandPalette(const char* query = "");
  [[nodiscard]] bool CommandPaletteOpen();

  /**
   * The command palette (design §3): every command of the registry found by typing a few of its letters (FuzzyScore),
   * the ones run last first when nothing is typed; each row says its keys, and one that can't run now says why and
   * stays unrun. Up and Down pick, Enter runs, Escape closes.
   */
  void DrawCommandPalette(EdCommands& commands);
} // namespace faf::editor

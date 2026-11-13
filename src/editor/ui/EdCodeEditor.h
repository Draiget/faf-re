#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * A Lua code input (the Script Editor; user ask 2026-11-11: a separate window with Lua highlighting): ImGui's
   * multiline text input does the editing (keys, selection, clipboard, undo) with its own text drawn transparent, and
   * the same text is drawn over it coloured by EdLuaSyntax (keywords, strings, comments, numbers, calls, the game's
   * globals), with line numbers beside it and `errorLine` (1-based; 0 for none) marked. The monospace font when there
   * is one. True when the text changed.
   */
  /** The debugger's marks in the gutter: breakpoints (red dots), the line paused at, and a click on a line's number. */
  struct EdCodeMarks
  {
    std::vector<int> breakpoints; // 1-based lines
    int pausedLine = 0;
    int clickedLine = 0; // out: the line whose number was clicked this frame (0: none)
  };

  bool LuaCodeInput(const char* id, std::string& text, int errorLine, float height, EdCodeMarks* marks = nullptr);

  /** Scrolls the code input to a line at its next draw (a Check's error line). */
  void LuaCodeScrollTo(int line);
} // namespace faf::editor

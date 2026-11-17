#pragma once

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  /**
   * Engine addition (UI scaling and DPI, issues #455 and #409): the scale of the display the game's
   * main window is on, as the system's own UI uses it (Windows' "Scale" setting: 1.5 at 150 %, 2.0
   * on a Retina display). 1.0 before the window exists. Lua reads it as `GetDisplayScale()`.
   */
  [[nodiscard]] float UI_GetDisplayScale();

  /**
   * Engine addition: called once per UI frame. When the display scale differs from the one Lua was
   * last given (the window went to a display with another scale, the player changed the system's
   * scale, or Lua asked before the main window existed and got the primary display's), calls
   * `/lua/ui/uimain.lua:OnDisplayScaleChanged(scale)` if that module has the function; FAF's Lua
   * without it is left alone. Until Lua has asked, it only records the scale.
   */
  void UI_NoteDisplayScale(LuaPlus::LuaState* state);
} // namespace moho

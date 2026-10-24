#pragma once

// FAF FA-Binary-Patches (section/DrawFunc.cpp, hooks/HDraw.cpp, hooks/GetFPS.cpp):
// the UI Lua functions UI_DrawRect, UI_DrawCircle and UI_DrawLine, which draw
// world-space shapes from a world view's `OnRenderWorld(self, delta)` script
// callback (FAF's lua/ui/controls/components/WorldViewShapeComponent.lua and
// the shapes/painting code on top of it). The callback runs at the end of
// `CUIWorldView::Render` (`CUIWorldView::RenderWorldShapes`) for a view whose
// custom rendering is on (`CMauiControl::SetCustomRender`).
//
// Not in the shipped binary: these exist only in FAF's patched executable.

struct lua_State;

namespace moho
{
  class CScrLuaInitForm;

  /**
   * FAF FA-Binary-Patches (hooks/GetFPS.cpp, StoreFPS): keeps this frame's
   * time, which the patch stores where `CScApp::Main` pushes it into its
   * frame-rate window (0x008D1A85), for the `delta` argument of
   * `OnRenderWorld`.
   */
  void UI_SetRenderWorldFrameSeconds(float frameSeconds) noexcept;

  /**
   * FAF FA-Binary-Patches (section/DrawFunc.cpp, LuaDrawRect):
   * `UI_DrawRect(pos:vector, size:float, color:string, thickness?=0.15:float)`.
   *
   * What it does:
   * Draws the outline of the `size` x `size` square whose corner is `pos`,
   * extending along +X and +Z, at least two LOD units thick.
   */
  int cfunc_UI_DrawRect(lua_State* luaContext);
  CScrLuaInitForm* func_UI_DrawRect_LuaFuncDef();

  /**
   * FAF FA-Binary-Patches (section/DrawFunc.cpp, LuaDrawCircle):
   * `UI_DrawCircle(pos:vector, radius:float, color:string, thickness?=0.15:float)`.
   *
   * What it does:
   * Draws a horizontal ring of `radius` around `pos` (48 segments).
   */
  int cfunc_UI_DrawCircle(lua_State* luaContext);
  CScrLuaInitForm* func_UI_DrawCircle_LuaFuncDef();

  /**
   * FAF FA-Binary-Patches (section/DrawFunc.cpp, LuaDrawLine):
   * `UI_DrawLine(pos1:vector, pos2:vector, color:string, thickness?=0.15:float)`.
   *
   * What it does:
   * Draws a band from `pos1` to `pos2`, widened horizontally.
   */
  int cfunc_UI_DrawLine(lua_State* luaContext);
  CScrLuaInitForm* func_UI_DrawLine_LuaFuncDef();
} // namespace moho

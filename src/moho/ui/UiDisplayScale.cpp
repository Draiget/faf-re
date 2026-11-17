#include "moho/ui/UiDisplayScale.h"

#include <cmath>
#include <exception>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/app/AppRuntimeTypes.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "platform/Window.h"
#include "platform/shell/window.h"

namespace
{
  /// The scale the UI's Lua was last given (GetDisplayScale or OnDisplayScaleChanged); 0 before.
  float sReportedScale = 0.0f;

  /// The scale of the display the main window is on; before that window exists (the menus' Lua
  /// starts early), the primary display's.
  [[nodiscard]] float CurrentDisplayScale()
  {
    platform::window::Handle window = nullptr;
    if (moho::sMainWindow != nullptr) {
      window = platform::window::FromNativeHandle(reinterpret_cast<void*>(moho::sMainWindow->GetHandle()));
    }
    return platform::window::DisplayScale(window);
  }
} // namespace

float moho::UI_GetDisplayScale()
{
  sReportedScale = CurrentDisplayScale();
  return sReportedScale;
}

void moho::UI_NoteDisplayScale(
  LuaPlus::LuaState* const state
)
{
  const float scale = CurrentDisplayScale();
  if (sReportedScale == 0.0f) {
    // Lua never asked (FAF's Lua without faf-re's hooks): nothing to tell it.
    sReportedScale = scale;
    return;
  }
  if (std::fabs(scale - sReportedScale) < 0.001f) {
    return;
  }
  gpg::Logf(
    "UI: the display scale is now %.2f (was %.2f)", static_cast<double>(scale), static_cast<double>(sReportedScale)
  );
  sReportedScale = scale;
  if (state == nullptr) {
    return;
  }
  try {
    const LuaPlus::LuaObject uiMain = SCR_Import(state, "/lua/ui/uimain.lua");
    const LuaPlus::LuaObject callback = uiMain["OnDisplayScaleChanged"];
    if (!callback.IsFunction()) {
      return;
    }
    LuaPlus::LuaFunction<void> function(callback);
    function(static_cast<double>(scale));
  } catch (const std::exception& exception) {
    gpg::Warnf(
      "Error running '/lua/ui/uimain.lua:OnDisplayScaleChanged': %s",
      exception.what() != nullptr ? exception.what() : ""
    );
  }
}

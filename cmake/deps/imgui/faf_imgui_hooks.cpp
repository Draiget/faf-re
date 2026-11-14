// Dear ImGui's test-engine hooks for faf_imgui_core (built with IMGUI_ENABLE_TEST_ENGINE): they forward to what a program
// set with faf::imgui_hooks::SetItemHooks, and do nothing otherwise. See faf_imgui_hooks.h.

#include "faf_imgui_hooks.h"

#include "imgui_internal.h"

namespace
{
  faf::imgui_hooks::ItemAddFn gAdd = nullptr;
  faf::imgui_hooks::ItemInfoFn gInfo = nullptr;
} // namespace

namespace faf::imgui_hooks
{
  void SetItemHooks(
    const ItemAddFn add,
    const ItemInfoFn info
  )
  {
    gAdd = add;
    gInfo = info;
  }
} // namespace faf::imgui_hooks

void ImGuiTestEngineHook_ItemAdd(
  ImGuiContext* ctx,
  ImGuiID id,
  const ImRect& bb,
  const ImGuiLastItemData* /*item_data*/
)
{
  if (gAdd != nullptr) {
    gAdd(ctx, id, bb);
  }
}

void ImGuiTestEngineHook_ItemInfo(
  ImGuiContext* ctx,
  ImGuiID id,
  const char* label,
  ImGuiItemStatusFlags flags
)
{
  if (gInfo != nullptr) {
    gInfo(ctx, id, label, flags);
  }
}

void ImGuiTestEngineHook_Log(
  ImGuiContext* /*ctx*/,
  const char* /*fmt*/,
  ...
)
{
}

const char* ImGuiTestEngine_FindItemDebugLabel(
  ImGuiContext* /*ctx*/,
  ImGuiID /*id*/
)
{
  return nullptr;
}

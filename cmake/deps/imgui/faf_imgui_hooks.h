#pragma once

// Dear ImGui's test-engine item hooks (IMGUI_ENABLE_TEST_ENGINE, imgui_internal.h), forwarded to functions a program
// sets: every item's box as ImGui adds it, and a widget's label and status. The map editor's QA tools use them (the
// click sweep and the layout check, src/editor/ui/EdUiQa.cpp); unset, the hooks do nothing, and ImGui only calls them
// while the context's TestEngineHookItems is set.

#include "imgui.h"

struct ImRect;
typedef int ImGuiItemStatusFlags;

namespace faf::imgui_hooks
{
  using ItemAddFn = void (*)(ImGuiContext* ctx, ImGuiID id, const ImRect& bb);
  using ItemInfoFn = void (*)(ImGuiContext* ctx, ImGuiID id, const char* label, ImGuiItemStatusFlags flags);
  void SetItemHooks(ItemAddFn add, ItemInfoFn info);
} // namespace faf::imgui_hooks

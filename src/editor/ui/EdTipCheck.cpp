#include "editor/ui/EdTipCheck.h"

#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cstring>

namespace faf::editor
{
  void EdTipCheck::Start(
    const int framesToWait
  )
  {
    mState = State::Waiting;
    mWait = framesToWait;
    mPoints.clear();
    mNext = 0;
    mTally = TipTally();
    gpg::Logf("editor: tipcheck: starts in %d frames", framesToWait);
  }

  void EdTipCheck::BeforeNewFrame()
  {
    mFed = false;
    if (mState == State::Waiting) {
      if (--mWait > 0) {
        return;
      }
      // The panels shown now (not the dock space's host, the title row or the view's overlays).
      const ImGuiContext& g = *GImGui;
      const ImGuiViewport* const main = ImGui::GetMainViewport();
      std::vector<TipRect> rects;
      for (const ImGuiWindow* const window : g.Windows) {
        if (
          // (a docked panel is flagged as a child window of its dock's host: it counts)
          !window->WasActive || window->Hidden ||
          ((window->Flags & ImGuiWindowFlags_ChildWindow) != 0 && !window->DockIsActive) ||
          (window->Flags & (ImGuiWindowFlags_Tooltip | ImGuiWindowFlags_Popup)) != 0 || window->Viewport != main ||
          (window->Flags & ImGuiWindowFlags_NoBringToFrontOnFocus) != 0 || std::strncmp(window->Name, "##", 2) == 0
        ) {
          continue;
        }
        rects.push_back(TipRect{window->Name, window->Pos.x, window->Pos.y, window->Size.x, window->Size.y});
      }
      mPoints = TipCheckPoints(rects, 24.0f);
      ImGuiStyle& style = ImGui::GetStyle();
      mSavedDelays[0] = style.HoverDelayShort;
      mSavedDelays[1] = style.HoverDelayNormal;
      mSavedDelays[2] = style.HoverStationaryDelay;
      style.HoverDelayShort = 0.0f;
      style.HoverDelayNormal = 0.0f;
      style.HoverStationaryDelay = 0.0f;
      mState = State::Walking;
      gpg::Logf("editor: tipcheck: %zu points over %zu panels", mPoints.size(), rects.size());
    }
    if (mState != State::Walking || mNext >= mPoints.size()) {
      return;
    }
    ImGui::GetIO().AddMousePosEvent(mPoints[mNext].x, mPoints[mNext].y);
    mFed = true;
  }

  void EdTipCheck::AfterRender()
  {
    if (mState != State::Walking) {
      return;
    }
    if (mFed && mNext < mPoints.size()) {
      const ImGuiContext& g = *GImGui;
      bool tooltip = false;
      for (const ImGuiWindow* const window : g.Windows) {
        if ((window->Flags & ImGuiWindowFlags_Tooltip) != 0 && window->Active) {
          tooltip = true;
          break;
        }
      }
      const ImGuiID hovered = g.HoveredId != 0 ? g.HoveredId : g.HoveredIdPreviousFrame;
      const TipPoint& point = mPoints[mNext];
      mTally.Record(hovered, point.window, point.x, point.y, tooltip);
      ++mNext;
    }
    if (mNext < mPoints.size()) {
      return;
    }
    ImGuiStyle& style = ImGui::GetStyle();
    style.HoverDelayShort = mSavedDelays[0];
    style.HoverDelayNormal = mSavedDelays[1];
    style.HoverStationaryDelay = mSavedDelays[2];
    const std::vector<TipTally::Control> missing = mTally.Missing();
    gpg::Logf(
      "editor: tipcheck: %zu controls hovered, %d with a tooltip, %zu without",
      mTally.Controls().size(),
      mTally.WithTooltip(),
      missing.size()
    );
    for (const TipTally::Control& control : missing) {
      gpg::Logf(
        "editor: tipcheck: no tooltip: %s at %.0f, %.0f (id %08X)",
        control.window.c_str(),
        static_cast<double>(control.x),
        static_cast<double>(control.y),
        control.id
      );
    }
    mState = State::Done;
  }
} // namespace faf::editor

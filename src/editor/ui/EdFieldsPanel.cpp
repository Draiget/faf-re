#include "editor/ui/EdFieldsPanel.h"

#include "editor/ui/EdControls.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] bool Contains(
      const std::string& text,
      const char* const filter
    )
    {
      if (filter == nullptr || filter[0] == '\0') {
        return true;
      }
      std::string a = text;
      std::string b = filter;
      for (char& c : a) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      for (char& c : b) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return a.find(b) != std::string::npos;
    }

    /** The grid as grey cells (its lowest black, its highest white), filling `size` x `size` pixels. */
    void DrawGrid(
      const field::Grid& grid,
      const float size
    )
    {
      constexpr int kCells = 96;
      std::vector<float> cells;
      field::Downsample(grid, kCells, kCells, cells);
      float low = cells.empty() ? 0.0f : cells.front();
      float high = low;
      for (const float value : cells) {
        low = std::min(low, value);
        high = std::max(high, value);
      }
      const float range = high > low ? high - low : 1.0f;
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const float cell = size / static_cast<float>(kCells);
      for (int z = 0; z < kCells; ++z) {
        for (int x = 0; x < kCells; ++x) {
          const float value = (cells[static_cast<std::size_t>(z) * kCells + static_cast<std::size_t>(x)] - low) / range;
          const auto grey = static_cast<int>(std::clamp(value, 0.0f, 1.0f) * 255.0f);
          draw->AddRectFilled(
            ImVec2(at.x + static_cast<float>(x) * cell, at.y + static_cast<float>(z) * cell),
            ImVec2(at.x + static_cast<float>(x + 1) * cell + 0.5f, at.y + static_cast<float>(z + 1) * cell + 0.5f),
            IM_COL32(grey, grey, grey, 255)
          );
        }
      }
      ImGui::Dummy(ImVec2(size, size));
      ImGui::TextDisabled(
        "%d x %d samples, %.2f to %.2f", grid.w, grid.h, static_cast<double>(low), static_cast<double>(high)
      );
    }
  } // namespace

  void EdFieldsPanel::Draw(
    bool& open,
    const bool mapOpen
  )
  {
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(460.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Fields###Fields"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map: the ops run on its heights.");
      ImGui::End();
      return;
    }
    if (ImGui::Button(mStack.Empty() ? "Start from the map's heights" : "Start again from the map")) {
      field::Grid ground;
      if (mGround && mGround(ground)) {
        mStack.Start(std::move(ground));
        mStatus = "The map's heights are the stack's base.";
      } else {
        mStatus = "The map's heights aren't ready yet.";
      }
    }
    EdSetItemTooltip("The ops work on a copy: the map changes only with Put on the map");
    const std::vector<std::string>& names = field::OpNames();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##fieldsfilter", "Find an op (blur, terrace, warp...)", mFilter, sizeof(mFilter));
    mOp = std::clamp(mOp, 0, std::max(0, static_cast<int>(names.size()) - 1));
    ImGui::SetNextItemWidth(-1.0f);
    if (EdBeginCombo("##fieldsop", names.empty() ? "(no ops)" : names[static_cast<std::size_t>(mOp)].c_str())) {
      for (int i = 0; i < static_cast<int>(names.size()); ++i) {
        if (
          Contains(names[static_cast<std::size_t>(i)], mFilter) &&
          ImGui::Selectable(names[static_cast<std::size_t>(i)].c_str(), i == mOp)
        ) {
          mOp = i;
        }
      }
      ImGui::EndCombo();
    }
    ImGui::TextDisabled("Parameters, one a line (key = value):");
    ImGui::InputTextMultiline("##fieldsparams", mParams, sizeof(mParams), ImVec2(-1.0f, Em(70.0f)));
    ImGui::BeginDisabled(mStack.Empty() || names.empty());
    if (ImGui::Button("Apply")) {
      std::string error;
      const std::string& op = names[static_cast<std::size_t>(mOp)];
      if (mStack.Apply(op, ParseOpParams(mParams), error)) {
        mStatus = op + " applied (" + std::to_string(mStack.Steps().size()) + " steps).";
        gpg::Logf("editor: fields: %s", mStack.Steps().back().c_str());
      } else {
        mStatus = op + ": " + error;
        gpg::Warnf("editor: fields: %s: %s", op.c_str(), error.c_str());
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Back")) {
      mStatus = mStack.Back() ? "The last op taken off." : "Only the map's heights are left.";
    }
    ImGui::SameLine();
    if (ImGui::Button("Put on the map")) {
      mCommitAsked = true;
    }
    EdSetItemTooltip("The top of the stack becomes the map's heights, as one undo step");
    ImGui::EndDisabled();
    if (!mStatus.empty()) {
      ImGui::TextWrapped("%s", mStatus.c_str());
    }
    if (const field::Grid* const top = mStack.Top(); top != nullptr) {
      ImGui::Separator();
      const float size = std::min(ImGui::GetContentRegionAvail().x, Em(260.0f));
      DrawGrid(*top, size);
      for (std::size_t i = 0; i < mStack.Steps().size(); ++i) {
        ImGui::Text("%zu. %s", i + 1, mStack.Steps()[i].c_str());
      }
    }
    ImGui::End();
  }

  bool EdFieldsPanel::TakeCommit(
    field::Grid& out
  )
  {
    if (!mCommitAsked) {
      return false;
    }
    mCommitAsked = false;
    if (mStack.Top() == nullptr) {
      return false;
    }
    out = *mStack.Top();
    mStatus = "Put on the map (one undo step).";
    return true;
  }

  bool EdFieldsPanel::RunForTest(
    const std::string& op,
    const std::string& params,
    std::string& status
  )
  {
    field::Grid ground;
    if (!mGround || !mGround(ground)) {
      status = "no heights yet";
      return false;
    }
    mStack.Start(std::move(ground));
    std::string error;
    if (!mStack.Apply(op, ParseOpParams(params), error)) {
      status = op + ": " + error;
      return false;
    }
    mCommitAsked = true;
    status = mStack.Steps().back();
    return true;
  }
} // namespace faf::editor

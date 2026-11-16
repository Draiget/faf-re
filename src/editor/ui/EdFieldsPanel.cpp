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
      return a.contains(b);
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
    DrawQuickGen();
    ImGui::SeparatorText("Ops on a copy of the heights");
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
      const std::string& op = names[static_cast<std::size_t>(mOp)];
      if (const auto applied = mStack.Apply(op, ParseOpParams(mParams))) {
        mStatus = op + " applied (" + std::to_string(mStack.Steps().size()) + " steps).";
        gpg::Logf("editor: fields: %s", mStack.Steps().back().c_str());
      } else {
        mStatus = op + ": " + applied.error();
        gpg::Warnf("editor: fields: %s: %s", op.c_str(), applied.error().c_str());
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
    ImGui::SetNextItemWidth(Em(70.0f));
    FillSliderInt("##commitlayer", &mCommitLayer, 1, 8, "layer %d");
    ImGui::SameLine();
    if (ImGui::Button("Commit to layer")) {
      mLayerCommitAsked = true;
    }
    EdSetItemTooltip("The top of the stack (0..1) as that layer's paint, as one undo step");
    ImGui::Checkbox("Live preview", &mLive);
    EdSetItemTooltip("The last op is applied again half a second after its parameters change");
    ImGui::EndDisabled();
    // Live: the parameters changed and the wait passed: the last op off and on again with them.
    if (mLive && !mStack.Empty() && !mStack.Steps().empty() && !names.empty()) {
      const double now = ImGui::GetTime();
      if (mLiveParams != mParams) {
        mLiveParams = mParams;
        mLiveDue = now + 0.5;
      } else if (mLiveDue > 0.0 && now >= mLiveDue) {
        mLiveDue = -1.0;
        const std::string& op = names[static_cast<std::size_t>(mOp)];
        const auto applied = mStack.Back() ? mStack.Apply(op, ParseOpParams(mParams)) : std::unexpected(std::string());
        if (applied) {
          mStatus = op + " again with the new values (live).";
        } else if (!applied.error().empty()) {
          mStatus = op + ": " + applied.error();
        }
      }
    } else {
      mLiveParams = mParams;
    }
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

  const std::vector<EdFieldsPanel::QuickGenPreset>& EdFieldsPanel::QuickGenPresets()
  {
    // FAF Studio's fieldgen.lua presets: feature size, the relief's size, gullies, warp, detail (their op chains are
    // in EdApp's RunQuickGen).
    static const std::vector<QuickGenPreset> presets = {
      {"Hills",
       "Rolling hills: rounded hills and broad swells with a little warp; fine detail damped on the steep ground.",
       140.0f,
       18.0f,
       0.0f,
       0.5f,
       0.5f},
      {"Mountains",
       "Mountain ranges: ridged crests over a broad massif, finer detail on the steep ground, weathered by gullies.",
       240.0f,
       60.0f,
       0.5f,
       0.4f,
       0.6f},
      {"Badlands", "Flat topped mesas with steep stepped sides and rough cliffs.", 200.0f, 35.0f, 0.3f, 0.4f, 0.5f},
      {"Dunes",
       "Sand dunes: long crests with a gentle windward and a steep lee side, some stretches flat.",
       120.0f,
       10.0f,
       0.0f,
       0.5f,
       0.4f},
      {"Plains",
       "Small, soft relief for flat ground: gentle swells and a little roughness.",
       90.0f,
       4.0f,
       0.0f,
       0.3f,
       0.8f},
      {"Rocks", "Fields of boulders: rounded cells roughened by fractal noise.", 45.0f, 10.0f, 0.0f, 0.3f, 0.6f},
    };
    return presets;
  }

  void EdFieldsPanel::DrawQuickGen()
  {
    if (!ImGui::CollapsingHeader("Generate into the map", ImGuiTreeNodeFlags_DefaultOpen)) {
      return;
    }
    QuickGenSettings& q = mQuick;
    std::vector<const char*> names;
    for (const QuickGenPreset& p : QuickGenPresets()) {
      names.push_back(p.label);
    }
    ImGui::SetNextItemWidth(Em(140.0f));
    if (EdCombo("##qgpreset", &q.preset, names.data(), static_cast<int>(names.size()))) {
      const QuickGenPreset& p = QuickGenPresets()[static_cast<std::size_t>(q.preset)];
      q.scale = p.scale;
      q.amplitude = p.amplitude;
      q.warp = p.warp;
      q.detail = p.detail;
      q.gullies = p.gullies;
    }
    EdSetItemTooltip("%s", QuickGenPresets()[static_cast<std::size_t>(std::clamp(q.preset, 0, 5))].tip);
    ImGui::SameLine();
    static constexpr const char* kBlends[] = {"Add", "Multiply", "Raise only", "Lower only", "Replace"};
    ImGui::SetNextItemWidth(Em(120.0f));
    (void)EdCombo("##qgblend", &q.blend, kBlends, 5);
    EdSetItemTooltip(
      "Add: on top of the ground. Multiply: more on higher ground. Raise only / Lower only. Replace: in "
      "place of the ground (the mean height stays)"
    );
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qgamp", &q.amplitude, 0.5f, 150.0f, "Relief %.1f units");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qgstrength", &q.strength, 0.0f, 1.0f, "Strength %.2f");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qgscale", &q.scale, 10.0f, 800.0f, "Feature size %.0f units");
    ImGui::SetNextItemWidth(Em(100.0f));
    ImGui::InputInt("Seed##qg", &q.seed);
    ImGui::SameLine();
    if (ImGui::SmallButton("Random##qg")) {
      q.seed = static_cast<int>(ImGui::GetFrameCount() * 2654435761u % 9999u) + 1;
    }
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qgdetail", &q.detail, 0.0f, 1.0f, "Detail %.2f");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qgwarp", &q.warp, 0.0f, 1.0f, "Warp %.2f");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qggullies", &q.gullies, 0.0f, 1.0f, q.gullies > 0.001f ? "Gullies %.2f" : "Gullies: off");
    EdSetItemTooltip("A brief droplet erosion of the relief: gullies and drainage, more droplets the higher");
    static constexpr const char* kMasks[] = {"Whole map", "Playable area", "An area"};
    ImGui::SetNextItemWidth(Em(140.0f));
    (void)EdCombo("##qgmask", &q.mask, kMasks, 3);
    if (q.mask == 2) {
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(120.0f));
      if (EdBeginCombo("##qgarea", q.area.empty() ? "(choose)" : q.area.c_str())) {
        for (const std::string& a : mAreas) {
          if (ImGui::Selectable(a.c_str(), a == q.area)) {
            q.area = a;
          }
        }
        ImGui::EndCombo();
      }
    }
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##qgfeather", &q.feather, 0.0f, 120.0f, "Soft border %.0f units");
    ImGui::Checkbox("Keep start and resource spots flat", &q.keepFlat);
    if (q.keepFlat) {
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(90.0f));
      FillSliderFloat("##qgflat", &q.flatRadius, 4.0f, 80.0f, "%.0f units");
    }
    ImGui::Checkbox("Keep the water level", &q.keepWater);
    EdSetItemTooltip("Dry ground stays above the water and the sea floor below it");
    if (ImGui::Button("Preview##qg")) {
      mQuickAsk = 1;
    }
    ImGui::SameLine();
    if (PrimaryButton("Apply to terrain##qg")) {
      mQuickAsk = 2;
    }
    EdSetItemTooltip("Mixed into the map's heights, one undo step");
    if (!mQuickText.empty()) {
      ImGui::TextWrapped("%s", mQuickText.c_str());
    }
    if (mQuickChange.w > 1) {
      DrawGrid(mQuickChange, std::min(ImGui::GetContentRegionAvail().x, Em(200.0f)));
    }
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

  bool EdFieldsPanel::TakeLayerCommit(
    field::Grid& out,
    int& layer
  )
  {
    if (!mLayerCommitAsked) {
      return false;
    }
    mLayerCommitAsked = false;
    if (mStack.Top() == nullptr) {
      return false;
    }
    out = *mStack.Top();
    for (float& v : out.v) {
      v = std::clamp(v, 0.0f, 1.0f);
    }
    layer = mCommitLayer;
    mStatus = "Put into layer " + std::to_string(layer) + " (one undo step).";
    return true;
  }

  std::expected<std::string, std::string> EdFieldsPanel::RunForTest(
    const std::string& op,
    const std::string& params
  )
  {
    field::Grid ground;
    if (!mGround || !mGround(ground)) {
      return std::unexpected("no heights yet");
    }
    mStack.Start(std::move(ground));
    if (const auto applied = mStack.Apply(op, ParseOpParams(params)); !applied) {
      return std::unexpected(op + ": " + applied.error());
    }
    mCommitAsked = true;
    return mStack.Steps().back();
  }
} // namespace faf::editor

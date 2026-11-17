#include "editor/ui/EdPathsPanel.h"
#include "gpg/core/utils/Logging.h"

#include "editor/ui/EdControls.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <ranges>
#include <functional>

namespace faf::editor
{
  EdPathsPanel::EdPathsPanel(
    EdDocument& document
  )
    : mDocument(document)
  {}

  float EdPathsPanel::Ground(
    const float x,
    const float z
  ) const
  {
    return ground ? ground(x, z) : 0.0f;
  }

  void EdPathsPanel::Track(
    const bool changed
  )
  {
    if (ImGui::IsItemActivated()) {
      mDragBefore = std::make_unique<EdDocument::PathsState>(mFrameStart);
    }
    if (changed && !ImGui::IsItemActive()) {
      mDocument.PathsEdited(mDragBefore != nullptr ? std::move(*mDragBefore) : mFrameStart);
      mDragBefore.reset();
      mFrameStart = mDocument.PathsNow();
    } else if (ImGui::IsItemDeactivatedAfterEdit() && mDragBefore != nullptr) {
      mDocument.PathsEdited(std::move(*mDragBefore));
      mDragBefore.reset();
      mFrameStart = mDocument.PathsNow();
    } else if (ImGui::IsItemDeactivated()) {
      mDragBefore.reset();
    }
    if (changed) {
      mDocument.PathsTouched();
    }
  }

  void EdPathsPanel::Draw(
    bool& open,
    const bool mapOpen
  )
  {
    ImGui::SetNextWindowSize(ImVec2(Em(360.0f), Em(620.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Paths###Paths"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to lay paths on it.");
      ImGui::End();
      return;
    }
    mFrameStart = mDocument.PathsNow();
    HelpNote(
      "Paths are kept with the map: a curve through points that shapes the ground along it (carve a valley, raise a "
      "ridge, lay a road or a ramp, cut a river), with texture, props and decals along it. Apply replaces the path's "
      "earlier result; Bake keeps the ground as it is."
    );
    DrawList();
    KeptPath* const path = mDocument.EditPaths().set.Find(mState.current);
    if (path != nullptr) {
      ImGui::PushID(path->id.c_str());
      DrawPath(*path);
      // DrawPath may have replaced the list (a delete): look the path up again.
      if (KeptPath* const again = mDocument.EditPaths().set.Find(mState.current); again != nullptr) {
        DrawPoints(*again);
        DrawProfile(*again);
        DrawAlong(*again);
        DrawActions(*again);
      }
      ImGui::PopID();
    }
    DrawSkeleton();
    if (!mState.status.empty()) {
      ImGui::Separator();
      ImGui::TextWrapped("%s", mState.status.c_str());
    }
    ImGui::End();
  }

  void EdPathsPanel::DrawList()
  {
    if (!Section("Paths")) {
      return;
    }
    ImGui::Checkbox("Edit on the map", &mState.editing);
    EdSetItemTooltip(
      "A click adds a point to the current path (a new path when none is chosen), a drag moves points, "
      "Ctrl+click picks more, Shift+click on the curve inserts one, Del deletes, Esc lets go."
    );
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(110.0f));
    FillDragFloat("##snap", &mState.snap, 0.25f, 0.0f, 64.0f, mState.snap > 0.0f ? "Snap %.1f" : "Snap off");
    // A new path's mode and curve.
    {
      static const char* const kModes[kKeptPathModeCount] = {"Carve", "Raise", "Level", "Ramp", "Road", "River"};
      ImGui::SetNextItemWidth(Em(110.0f));
      (void)EdCombo("##newmode", &mState.newMode, kModes, kKeptPathModeCount);
      ImGui::SameLine();
      ImGui::Checkbox("Bezier", &mState.newBezier);
      ImGui::SameLine();
      if (ImGui::Button("New path")) {
        // The next click on the map starts it.
        mState.current.clear();
        mState.selected.clear();
        mState.editing = true;
        mState.status = "Click the map to place the new path's first point.";
      }
    }
    const EdDocument::PathsState& state = mDocument.PathsNow();
    if (state.set.paths.empty()) {
      ImGui::TextDisabled("No paths yet: turn on Edit on the map and click.");
      return;
    }
    if (
      ImGui::BeginListBox(
        "##paths", ImVec2(-1.0f, Em(22.0f) * std::min<float>(6.0f, static_cast<float>(state.set.paths.size()) + 0.5f))
      )
    ) {
      for (const KeptPath& p : state.set.paths) {
        char label[200];
        (void)std::snprintf(
          label,
          sizeof(label),
          "%s%s  (%s, %zu points)%s###%s",
          state.results.contains(p.id) ? "\xE2\x97\x8F " : "",
          p.name.c_str(),
          KeptPathModeName(p.mode),
          p.points.size(),
          p.skeleton ? " skeleton" : "",
          p.id.c_str()
        );
        if (ImGui::Selectable(label, p.id == mState.current)) {
          mState.current = p.id;
          mState.selected.clear();
          mDocument.PathsTouched();
        }
      }
      ImGui::EndListBox();
    }
    ImGui::TextDisabled("\xE2\x97\x8F applied (its result is on the map)");
  }

  void EdPathsPanel::DrawPath(
    KeptPath& path
  )
  {
    if (!Section("Path")) {
      return;
    }
    char name[128];
    (void)std::snprintf(name, sizeof(name), "%s", path.name.c_str());
    ImGui::SetNextItemWidth(-1.0f);
    const bool renamed = ImGui::InputText("##name", name, sizeof(name));
    if (renamed) {
      path.name = name;
    }
    Track(renamed);
    // Mode: switching resets the heights as Studio does.
    {
      int mode = static_cast<int>(path.mode);
      static const char* const kModes[kKeptPathModeCount] = {"Carve", "Raise", "Level", "Ramp", "Road", "River"};
      RowLabel("Mode");
      ImGui::SetNextItemWidth(-1.0f);
      const bool changed = EdCombo("##mode", &mode, kModes, kKeptPathModeCount);
      if (changed) {
        SetKeptPathMode(path, static_cast<KeptPathMode>(mode), [this](const float x, const float z) {
          return Ground(x, z);
        });
      }
      Track(changed);
    }
    {
      int kind = path.bezier ? 1 : 0;
      static const char* const kKinds[2] = {"Catmull-Rom", "Bezier"};
      RowLabel("Curve");
      ImGui::SetNextItemWidth(-1.0f);
      const bool changed = EdCombo("##kind", &kind, kKinds, 2);
      if (changed) {
        path.bezier = kind == 1;
        if (!path.bezier) {
          for (KeptPathPoint& p : path.points) {
            p.hasHo = p.hasHi = false;
          }
        }
      }
      Track(changed);
    }
    Track(ImGui::Checkbox("Closed loop", &path.closed));
    ImGui::SameLine();
    Track(ImGui::Checkbox("Copy by the symmetry", &path.sym));
    EdSetItemTooltip("The path is laid in every symmetric part too (the Tools panel's symmetry)");
    ImGui::SetNextItemWidth(-1.0f);
    Track(FillSliderFloat("##strength", &path.strength, 0.0f, 1.0f, "Strength %.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    Track(FillSliderInt("##erosion", &path.erosion, 0, 80, "Bank erosion %d passes"));
    EdSetItemTooltip("Thermal passes over the path's reach: cut walls slump to a natural talus (0 = off)");
    ImGui::SetNextItemWidth(-1.0f);
    Track(FillSliderFloat("##blend", &path.blend, 0.0f, 60.0f, "Blend into the ground %.1f"));
    EdSetItemTooltip("The change spreads into the ground around by a blur this wide (units, 0 = off)");
    ImGui::SetNextItemWidth(-1.0f);
    Track(FillSliderFloat("##tension", &path.tension, 0.2f, 2.0f, "Curve tension %.2f"));
    if (!KeptPathOffsetMode(path.mode) && path.mode != KeptPathMode::River) {
      Track(ImGui::Checkbox("Limit the grade", &path.limitGrade));
      ImGui::SameLine();
      Track(ImGui::Checkbox("Points between pins follow them", &path.interp));
      ImGui::SetNextItemWidth(-1.0f);
      Track(FillSliderFloat("##grade", &path.grade, 0.05f, 1.5f, "Maximum grade %.2f"));
      EdSetItemTooltip("Rise per run; 0.75 is what land units climb");
    }
    // The planned grade along the path, worked out again when the paths change.
    if (mReportRevision != mDocument.PathsRevision() || mReportFor != path.id) {
      mReportRevision = mDocument.PathsRevision();
      mReportFor = path.id;
      mReport = ReportKeptPath(path, [this](const float x, const float z) {
        return Ground(x, z);
      }, mDocument.WaterNow().elevation);
    }
    char report[200];
    (void)std::snprintf(
      report,
      sizeof(report),
      "Length %.0f; steepest grade %.2f; %.0f%% over %.2f in %zu stretch%s",
      static_cast<double>(KeptPathLength(path)),
      static_cast<double>(mReport.max),
      static_cast<double>(mReport.over * 100.0f),
      static_cast<double>(path.grade),
      mReport.flagged.size(),
      mReport.flagged.size() == 1 ? "" : "es"
    );
    ImGui::TextDisabled("%s", report);
  }

  void EdPathsPanel::DrawPoints(
    KeptPath& path
  )
  {
    if (!Section("Points")) {
      return;
    }
    std::vector<int>& sel = mState.selected;
    sel.erase(
      std::remove_if(
        sel.begin(),
        sel.end(),
        [&path](const int i) {
      return i < 0 || static_cast<std::size_t>(i) >= path.points.size();
    }
      ),
      sel.end()
    );
    if (ImGui::SmallButton("All")) {
      sel.clear();
      for (std::size_t i = 0; i < path.points.size(); ++i) {
        sel.push_back(static_cast<int>(i));
      }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("None")) {
      sel.clear();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%zu of %zu points chosen", sel.size(), path.points.size());
    if (sel.empty()) {
      ImGui::TextDisabled("Click a point on the map (Edit on the map) or choose All.");
      return;
    }
    // The first chosen point's values; a change goes to every chosen point.
    KeptPathPoint& first = path.points[static_cast<std::size_t>(sel.front())];
    const auto field =
      [&](const char* id, float KeptPathPoint::* member, const float lo, const float hi, const char* format) {
      float v = first.*member;
      ImGui::SetNextItemWidth(-1.0f);
      const bool changed = FillSliderFloat(id, &v, lo, hi, format);
      if (changed) {
        for (const int i : sel) {
          path.points[static_cast<std::size_t>(i)].*member = v;
        }
      }
      Track(changed);
    };
    field("##w", &KeptPathPoint::w, 0.5f, 80.0f, "Half width %.1f");
    field("##f", &KeptPathPoint::f, 0.0f, 80.0f, "Falloff width %.1f");
    char hLabel[96];
    (void)std::snprintf(
      hLabel, sizeof(hLabel), "%s %%.2f", first.abs ? "Height (pinned)" : KeptPathHeightLabel(path.mode)
    );
    field("##h", &KeptPathPoint::h, -100.0f, 300.0f, hLabel);
    field("##bank", &KeptPathPoint::bank, -45.0f, 45.0f, "Bank angle %.1f deg");
    if (!KeptPathOffsetMode(path.mode)) {
      bool pinned = first.abs;
      const bool changed = ImGui::Checkbox("Pinned to its own height", &pinned);
      if (changed) {
        for (const int i : sel) {
          PinKeptPathPoint(path.points[static_cast<std::size_t>(i)], pinned, [this](const float x, const float z) {
            return Ground(x, z);
          });
        }
      }
      Track(changed);
      EdSetItemTooltip(
        "A pinned point aims at the height above; unpinned points between two pins lie on the line between them"
      );
    }
    if (path.bezier) {
      bool own = first.hasHo;
      const bool changed = ImGui::Checkbox("Own handles", &own);
      if (changed) {
        std::vector<std::array<float, 2>> out;
        std::vector<std::array<float, 2>> in;
        KeptPathHandles(path, out, in);
        for (const int i : sel) {
          KeptPathPoint& p = path.points[static_cast<std::size_t>(i)];
          p.hasHo = p.hasHi = own;
          p.ho[0] = out[static_cast<std::size_t>(i)][0];
          p.ho[1] = out[static_cast<std::size_t>(i)][1];
          p.hi[0] = in[static_cast<std::size_t>(i)][0];
          p.hi[1] = in[static_cast<std::size_t>(i)][1];
        }
      }
      Track(changed);
      if (first.hasHo) {
        ImGui::SetNextItemWidth(-1.0f);
        Track(ImGui::DragFloat2("Out handle", first.ho, 0.1f));
        ImGui::SetNextItemWidth(-1.0f);
        Track(ImGui::DragFloat2("In handle", first.hi, 0.1f));
      }
    }
    if (ImGui::Button("Delete the chosen points")) {
      EdDocument::PathsState before = mDocument.PathsNow();
      std::vector<int> order = sel;
      std::ranges::sort(order, std::ranges::greater{});
      for (const int i : order) {
        path.points.erase(path.points.begin() + i);
      }
      sel.clear();
      mDocument.PathsEdited(std::move(before));
      mFrameStart = mDocument.PathsNow();
    }
  }

  void EdPathsPanel::DrawProfile(
    KeptPath& path
  )
  {
    if (!Section("Cross-section profile", false)) {
      return;
    }
    {
      const auto& presets = KeptPathProfilePresets();
      int current = 0;
      for (std::size_t i = 0; i < presets.size(); ++i) {
        if (path.profile.preset == presets[i].id) {
          current = static_cast<int>(i);
        }
      }
      auto labels = presets | std::views::transform([&](const auto& p) {
        return p.label;
      }) |
        std::ranges::to<std::vector<const char*>>();
      RowLabel("Preset");
      ImGui::SetNextItemWidth(-1.0f);
      const bool changed = EdCombo("##preset", &current, labels.data(), static_cast<int>(labels.size()));
      if (changed) {
        UseKeptPathPreset(path, presets[static_cast<std::size_t>(current)].id);
      }
      Track(changed);
    }
    Track(ImGui::Checkbox("Smooth curve", &path.profile.smooth));
    ImGui::SameLine();
    Track(ImGui::Checkbox("Same on both sides", &path.profile.symmetric));
    // The curve: the middle line on the left, the edge of the half width on the right.
    float values[64];
    for (int i = 0; i < 64; ++i) {
      values[i] = EvalKeptPathProfile(path.profile, static_cast<float>(i) / 63.0f);
    }
    ImGui::PlotLines(
      "##curve", values, 64, 0, "effect across the path (middle to edge)", 0.0f, 1.05f, ImVec2(-1.0f, Em(70.0f))
    );
    int remove = -1;
    for (std::size_t i = 0; i < path.profile.points.size(); ++i) {
      ImGui::PushID(static_cast<int>(i));
      auto& q = path.profile.points[i];
      ImGui::SetNextItemWidth(Em(120.0f));
      bool changed = FillSliderFloat("##x", &q[0], 0.0f, 1.0f, "Across %.2f");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(120.0f));
      changed |= FillSliderFloat("##v", &q[1], 0.0f, 1.0f, "Effect %.2f");
      if (changed) {
        path.profile.preset = "custom";
        std::stable_sort(path.profile.points.begin(), path.profile.points.end(), [](const auto& a, const auto& b) {
          return a[0] < b[0];
        });
      }
      Track(changed);
      ImGui::SameLine();
      if (path.profile.points.size() > 2 && ImGui::SmallButton("x")) {
        remove = static_cast<int>(i);
      }
      ImGui::PopID();
    }
    if (remove >= 0) {
      EdDocument::PathsState before = mDocument.PathsNow();
      path.profile.points.erase(path.profile.points.begin() + remove);
      path.profile.preset = "custom";
      mDocument.PathsEdited(std::move(before));
      mFrameStart = mDocument.PathsNow();
    }
    if (ImGui::SmallButton("Add a point")) {
      EdDocument::PathsState before = mDocument.PathsNow();
      // In the widest gap.
      auto& pts = path.profile.points;
      std::size_t at = 0;
      float gap = -1.0f;
      for (std::size_t i = 0; i + 1 < pts.size(); ++i) {
        if (pts[i + 1][0] - pts[i][0] > gap) {
          gap = pts[i + 1][0] - pts[i][0];
          at = i;
        }
      }
      const float x = pts.size() >= 2 ? (pts[at][0] + pts[at + 1][0]) * 0.5f : 0.5f;
      pts.insert(
        pts.begin() + static_cast<std::ptrdiff_t>(std::min(at + 1, pts.size())),
        {x, EvalKeptPathProfile(path.profile, x)}
      );
      path.profile.preset = "custom";
      mDocument.PathsEdited(std::move(before));
      mFrameStart = mDocument.PathsNow();
    }
  }

  void EdPathsPanel::DrawAlong(
    KeptPath& path
  )
  {
    if (Section("Texture along the path", false)) {
      static const char* const kKinds[3] = {
        "Core (inside the half width)", "Bank (the falloff band)", "Reach (all of it)"
      };
      for (std::size_t e = 0; e < path.strata.size(); ++e) {
        ImGui::PushID(static_cast<int>(e));
        KeptPathStrata& s = path.strata[e];
        ImGui::SetNextItemWidth(Em(110.0f));
        Track(FillSliderInt("##layer", &s.layer, 0, 8, s.layer == 0 ? "Layer off" : "Layer %d"));
        ImGui::SameLine();
        int kind = static_cast<int>(s.kind);
        ImGui::SetNextItemWidth(-1.0f);
        const bool changed = EdCombo("##kind", &kind, kKinds, 3);
        if (changed) {
          s.kind = static_cast<KeptStrataKind>(kind);
        }
        Track(changed);
        ImGui::SetNextItemWidth(-1.0f);
        Track(FillSliderFloat("##str", &s.strength, 0.0f, 1.0f, "Texture strength %.2f"));
        ImGui::PopID();
      }
    }
    const auto scatter = [this](KeptPathScatter& s, const bool decals) {
      static const char* const kSides[4] = {"Both sides", "Left", "Right", "On the line"};
      Track(ImGui::Checkbox(decals ? "Lay decals" : "Lay props", &s.on));
      char what[256];
      (void)std::snprintf(what, sizeof(what), "%s", s.what.c_str());
      ImGui::SetNextItemWidth(-1.0f);
      const bool typed = ImGui::InputTextWithHint(
        "##what",
        decals ? "decal texture (/env/.../decals/x.dds)" : "prop blueprint (/env/.../props/x_prop.bp)",
        what,
        sizeof(what)
      );
      if (typed) {
        s.what = what;
      }
      Track(typed);
      int side = static_cast<int>(s.side);
      RowLabel("Where");
      ImGui::SetNextItemWidth(-1.0f);
      const bool sideChanged = EdCombo("##side", &side, kSides, 4);
      if (sideChanged) {
        s.side = static_cast<KeptScatterSide>(side);
      }
      Track(sideChanged);
      ImGui::SetNextItemWidth(-1.0f);
      Track(FillSliderFloat("##spacing", &s.spacing, 1.0f, 80.0f, "Spacing %.1f"));
      ImGui::SetNextItemWidth(-1.0f);
      Track(FillSliderFloat("##lateral", &s.lateral, -20.0f, 40.0f, "Beyond the edge %.1f"));
      ImGui::SetNextItemWidth(-1.0f);
      Track(FillSliderFloat("##jitter", &s.jitter, 0.0f, 10.0f, "Jitter %.1f"));
      if (decals) {
        ImGui::SetNextItemWidth(-1.0f);
        Track(FillSliderFloat("##size", &s.size, 1.0f, 60.0f, "Size %.1f"));
      }
      ImGui::SetNextItemWidth(Em(140.0f));
      Track(FillSliderFloat("##smin", &s.scaleMin, 0.1f, 3.0f, "Scale %.2f"));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(-1.0f);
      Track(FillSliderFloat("##smax", &s.scaleMax, 0.1f, 3.0f, "to %.2f"));
      ImGui::SetNextItemWidth(-1.0f);
      Track(FillSliderInt("##seed", &s.seed, 1, 9999, "Seed %d"));
    };
    if (Section("Props along the path", false)) {
      ImGui::PushID("props");
      scatter(path.props, false);
      ImGui::PopID();
    }
    if (Section("Decals along the path", false)) {
      ImGui::PushID("decals");
      scatter(path.decals, true);
      ImGui::PopID();
    }
  }

  void EdPathsPanel::DrawActions(
    const KeptPath& path
  )
  {
    if (!Section("Apply")) {
      return;
    }
    const bool applied = mDocument.PathsNow().results.contains(path.id);
    const std::string id = path.id;
    if (ImGui::Button("Preview")) {
      mState.ask = PathEditState::Ask::Preview;
      mState.askIds = {id};
    }
    EdSetItemTooltip("The heights on the map without an undo step of their own; the next path action takes them off");
    ImGui::SameLine();
    ImGui::BeginDisabled(!mState.previewShown);
    if (ImGui::Button("Take the preview off")) {
      mState.ask = PathEditState::Ask::RevertPreview;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::Checkbox("Live", &mState.livePreview);
    EdSetItemTooltip("Preview again after every change of the path");
    if (PrimaryButton(applied ? "Apply again" : "Apply")) {
      mState.ask = PathEditState::Ask::Apply;
      mState.askIds = {id};
    }
    EdSetItemTooltip("Heights, texture, props and decals as one undo step; replaces this path's earlier result");
    ImGui::SameLine();
    ImGui::BeginDisabled(!applied);
    if (ImGui::Button("Unapply")) {
      mState.ask = PathEditState::Ask::Unapply;
      mState.askIds = {id};
    }
    ImGui::SameLine();
    if (ImGui::Button("Bake")) {
      mState.ask = PathEditState::Ask::Bake;
      mState.askIds = {id};
    }
    EdSetItemTooltip("The ground keeps this result; the next Apply adds to it instead of replacing it");
    ImGui::EndDisabled();
    if (ImGui::Button("Apply every path")) {
      mState.ask = PathEditState::Ask::ApplyMany;
      mState.askIds.clear();
      for (const KeptPath& p : mDocument.PathsNow().set.paths) {
        mState.askIds.push_back(p.id);
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Duplicate")) {
      EdDocument::PathsState before = mDocument.PathsNow();
      KeptPath copy = path;
      copy.id = mDocument.EditPaths().set.TakeId();
      copy.name = path.name + " copy";
      copy.skeleton = false;
      for (KeptPathPoint& p : copy.points) {
        p.x += 8.0f;
        p.z += 8.0f;
      }
      mState.current = copy.id;
      mDocument.EditPaths().set.paths.push_back(std::move(copy));
      mDocument.PathsEdited(std::move(before));
      mFrameStart = mDocument.PathsNow();
      return;
    }
    // Copy / Paste (FAF Studio's paths): the path as the paths file's text on the clipboard, pasted as a new path
    // (into this map or another one).
    ImGui::SameLine();
    if (ImGui::Button("Copy")) {
      KeptPathSet one;
      one.paths.push_back(path);
      ImGui::SetClipboardText(KeptPathsText(one).c_str());
      gpg::Logf("editor: paths: %s copied", path.name.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Paste")) {
      std::string error;
      const char* const text = ImGui::GetClipboardText();
      auto pasted = text != nullptr ? ReadKeptPaths(text) : std::expected<KeptPathSet, std::string>(std::unexpect);
      if (!pasted) {
        error = pasted.error();
      }
      if (pasted && !pasted->paths.empty()) {
        EdDocument::PathsState before = mDocument.PathsNow();
        for (KeptPath& p : pasted->paths) {
          p.id = mDocument.EditPaths().set.TakeId();
          p.name += " (pasted)";
          p.skeleton = false;
          mState.current = p.id;
          mDocument.EditPaths().set.paths.push_back(std::move(p));
        }
        mDocument.PathsEdited(std::move(before));
        mFrameStart = mDocument.PathsNow();
        gpg::Logf("editor: paths: %zu pasted", pasted->paths.size());
        return;
      }
      gpg::Warnf("editor: paths: the clipboard holds no path%s%s", error.empty() ? "" : ": ", error.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Select all points")) {
      mState.selected.clear();
      for (int i = 0; i < static_cast<int>(path.points.size()); ++i) {
        mState.selected.push_back(i);
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete path")) {
      EdDocument::PathsState before = mDocument.PathsNow();
      auto& list = mDocument.EditPaths().set.paths;
      list.erase(
        std::remove_if(
          list.begin(),
          list.end(),
          [&id](const KeptPath& p) {
        return p.id == id;
      }
        ),
        list.end()
      );
      mState.current.clear();
      mState.selected.clear();
      mDocument.PathsEdited(std::move(before));
      mFrameStart = mDocument.PathsNow();
      mState.status =
        applied ? "The path is gone; its result stays on the ground (Undo brings the path back)." : "The path is gone.";
    }
  }

  void EdPathsPanel::DrawSkeleton()
  {
    if (!Section("Map skeleton", false)) {
      return;
    }
    HelpNote(
      "Lanes between the start positions as paths, with base pads: open lanes, lanes with ridges, plateaus with ramps "
      "and chokes, or islands with moats and causeways; joined in a ring, to a plaza in the middle, or both. Generate "
      "lays the paths (edit them as any path), Apply all puts pads, paths and lane smoothing down as one undo step."
    );
    SkeletonSettings& s = mState.skeleton;
    {
      static const char* const kStyles[4] = {"Open lanes", "Ridge lanes", "Ramps and chokes", "Islands"};
      int style = static_cast<int>(s.style);
      RowLabel("Style");
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##style", &style, kStyles, 4)) {
        s.style = static_cast<SkeletonStyle>(style);
      }
      static const char* const kTopo[3] = {"Ring", "Hub", "Ring and hub"};
      int topo = static_cast<int>(s.topology);
      RowLabel("Lanes join");
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##topology", &topo, kTopo, 3)) {
        s.topology = static_cast<SkeletonTopology>(topo);
      }
    }
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderInt("##lanes", &s.lanes, 1, 4, "Parallel lanes %d");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##lw", &s.laneWidth, 2.0f, 40.0f, "Lane half width %.1f");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##lf", &s.laneFalloff, 0.0f, 30.0f, "Lane falloff %.1f");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##lg", &s.laneGrade, 0.1f, 1.0f, "Lane grade %.2f");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##bend", &s.bend, 0.0f, 60.0f, "Bend %.1f");
    switch (s.style) {
    case SkeletonStyle::Ridge:
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##rh", &s.ridgeHeight, 1.0f, 40.0f, "Ridge height %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##rw", &s.ridgeWidth, 1.0f, 20.0f, "Ridge width %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##rg", &s.ridgeGap, 0.0f, 20.0f, "Gap to the lane %.1f");
      break;
    case SkeletonStyle::Ramps:
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##pl", &s.plateau, 1.0f, 40.0f, "Plateau height %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##ph", &s.plateauHalf, 4.0f, 60.0f, "Plateau half size %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##rpw", &s.rampWidth, 2.0f, 20.0f, "Ramp half width %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##cw", &s.chokeWidth, 1.0f, 20.0f, "Choke half width %.1f");
      break;
    case SkeletonStyle::Islands:
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##ir", &s.islandRadius, 8.0f, 120.0f, "Island radius %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##mw", &s.moatWidth, 4.0f, 60.0f, "Moat width %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##md", &s.moatDepth, 1.0f, 40.0f, "Moat depth below the water %.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##bw", &s.bridgeWidth, 1.0f, 20.0f, "Causeway half width %.1f");
      break;
    case SkeletonStyle::Open:
      break;
    }
    if (s.topology != SkeletonTopology::Ring) {
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##hub", &s.hubHalf, 2.0f, 60.0f, "Plaza half size %.1f");
    }
    ImGui::Checkbox("Base pads", &s.pads);
    ImGui::SameLine();
    ImGui::Checkbox("Smooth the lanes", &s.smooth);
    EdSetItemTooltip("Apply all ends with the pathable slope limit over the lanes (the SC tools' limit and margin)");
    if (ImGui::Button("Generate")) {
      mState.ask = PathEditState::Ask::SkeletonGenerate;
    }
    ImGui::SameLine();
    if (PrimaryButton("Apply all")) {
      mState.ask = PathEditState::Ask::SkeletonApply;
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
      mState.ask = PathEditState::Ask::SkeletonClear;
    }
  }
} // namespace faf::editor

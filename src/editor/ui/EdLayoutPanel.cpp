#include "editor/ui/EdLayoutPanel.h"

#include "editor/doc/EdDocument.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace faf::editor
{
  namespace
  {
    ImU32 Colour(
      const std::array<std::uint8_t, 3>& c,
      const int alpha = 255
    )
    {
      return IM_COL32(c[0], c[1], c[2], alpha);
    }
  } // namespace

  EdLayoutPanel::EdLayoutPanel(
    EdDocument& document
  )
    : mDocument(document)
  {}

  EdLayoutPanel::~EdLayoutPanel()
  {
    if (mImage != 0) {
      mRetired.push_back(mImage);
    }
    for (const std::uint64_t image : mRetired) {
      EdImGuiRenderer::DestroyImage(image);
    }
  }

  void EdLayoutPanel::Changed(
    MapLayout before
  )
  {
    mDocument.Layout().Touch();
    mDocument.LayoutReplaced(std::move(before));
  }

  void EdLayoutPanel::BeginChange()
  {
    if (ImGui::IsItemActivated()) {
      mEditBefore = mDocument.Layout();
    }
  }

  void EdLayoutPanel::EndChange(
    const bool edited
  )
  {
    if (edited) {
      mDocument.Layout().Touch();
    }
    if (ImGui::IsItemDeactivated() && mEditBefore.has_value()) {
      if (ImGui::IsItemDeactivatedAfterEdit()) {
        mDocument.LayoutReplaced(std::move(*mEditBefore));
      }
      mEditBefore.reset();
    }
  }

  bool EdLayoutPanel::ApplyTemplate(
    const std::string& id
  )
  {
    MapLayout& layout = mDocument.Layout();
    const MapLayout::TemplateInfo* info = nullptr;
    for (const MapLayout::TemplateInfo& t : MapLayout::Templates()) {
      if (id == t.id) {
        info = &t;
      }
    }
    if (info == nullptr) {
      return false;
    }
    MapLayout before = layout;
    // The master part is drawn under the template's own symmetry; the editor's is set to it after.
    if (mImagesFor) {
      layout.SetImages(mImagesFor(info->symmetry));
    }
    std::string symmetry;
    if (!layout.ApplyTemplate(id, symmetry)) {
      return false;
    }
    Changed(std::move(before));
    mSymmetryAsk = symmetry;
    mStatus = std::string("Template ") + info->label + ": the editor's symmetry is now the template's.";
    return true;
  }

  void EdLayoutPanel::DrawLayersPanel(
    bool& open,
    const bool mapOpen
  )
  {
    if (!ImGui::Begin(Panel("Layout layers###LayoutLayers"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to draw its layout.");
      ImGui::End();
      return;
    }
    MapLayout& layout = mDocument.Layout();
    const float s = Em(1.0f);
    if (Section("Templates")) {
      const float w = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) / 2.0f;
      int n = 0;
      for (const MapLayout::TemplateInfo& t : MapLayout::Templates()) {
        if (n++ % 2 != 0) {
          ImGui::SameLine();
        }
        if (ImGui::Button(t.label, ImVec2(w, 0.0f))) {
          (void)ApplyTemplate(t.id);
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s\nReplaces the drawing (one undo step).", t.tip);
        }
      }
    }
    if (Section("Layers")) {
      int remove = -1;
      int move = 0;
      int moveIndex = -1;
      for (int i = static_cast<int>(layout.Layers().size()) - 1; i >= 0; --i) {
        LayoutLayer& layer = layout.Layers()[static_cast<std::size_t>(i)];
        ImGui::PushID(layer.id);
        bool visible = layer.visible;
        if (ImGui::Checkbox("##visible", &visible)) {
          MapLayout before = layout;
          layout.Layers()[static_cast<std::size_t>(i)].visible = visible;
          Changed(std::move(before));
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("Shown on the canvas and built (hidden layers are left out)");
        }
        ImGui::SameLine();
        const ImVec2 p = ImGui::GetCursorScreenPos();
        const float sw = ImGui::GetFrameHeight() * 0.6f;
        ImGui::GetWindowDrawList()->AddRectFilled(
          ImVec2(p.x, p.y + sw * 0.35f), ImVec2(p.x + sw, p.y + sw * 1.35f), Colour(layer.color), 2.0f * s
        );
        ImGui::Dummy(ImVec2(sw, sw));
        ImGui::SameLine();
        const float nameWidth = std::max(
          Em(40.0f),
          ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("^v" ICON_TRASH).x -
            ImGui::GetStyle().FramePadding.x * 6.0f - ImGui::GetStyle().ItemSpacing.x * 3.0f
        );
        if (ImGui::Selectable(layer.name.c_str(), layout.selected == i, 0, ImVec2(nameWidth, 0.0f))) {
          layout.selected = i;
          layout.Touch();
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s", LayoutKindOf(layer.kind).tip);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("^")) {
          move = 1;
          moveIndex = i;
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("v")) {
          move = -1;
          moveIndex = i;
        }
        ImGui::SameLine();
        if (ImGui::SmallButton(ICON_TRASH)) {
          remove = i;
        }
        ImGui::PopID();
      }
      if (moveIndex >= 0) {
        MapLayout before = layout;
        if (layout.MoveLayer(moveIndex, move)) {
          Changed(std::move(before));
        }
      }
      if (remove >= 0) {
        MapLayout before = layout;
        if (layout.RemoveLayer(remove)) {
          Changed(std::move(before));
        }
      }
      ImGui::TextDisabled("Applied from the bottom up.");
      if (EdBeginCombo("##addlayer", ICON_PLUS " Add a layer")) {
        for (const LayoutKindInfo& info : LayoutKinds()) {
          if (ImGui::Selectable(info.label)) {
            MapLayout before = layout;
            if (layout.AddLayer(info.kind) >= 0) {
              Changed(std::move(before));
            }
          }
          if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("%s", info.tip);
          }
        }
        ImGui::EndCombo();
      }
    }
    if (LayoutLayer* layer = layout.Layer(layout.selected); layer != nullptr && Section("Selected layer")) {
      const LayoutKindInfo& info = LayoutKindOf(layer->kind);
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s: %s", info.label, info.tip);
      ImGui::PopTextWrapPos();
      for (const LayoutParamDef& def : info.params) {
        float value = layer->P(def.key);
        char format[96];
        (void)std::snprintf(format, sizeof(format), "%s %s", def.label, def.format);
        ImGui::SetNextItemWidth(-1.0f);
        const bool edited = FillSliderFloat((std::string("##") + def.key).c_str(), &value, def.min, def.max, format);
        BeginChange();
        if (edited) {
          layer->p[def.key] = value;
        }
        EndChange(edited);
      }
      float rgb[3] = {layer->color[0] / 255.0f, layer->color[1] / 255.0f, layer->color[2] / 255.0f};
      RowLabel("Colour on the canvas");
      if (ColourField("##layercolour", rgb)) {
        MapLayout before = layout;
        for (int c = 0; c < 3; ++c) {
          layout.Layer(layout.selected)->color[static_cast<std::size_t>(c)] =
            static_cast<std::uint8_t>(std::clamp(std::lround(rgb[c] * 255.0f), 0L, 255L));
        }
        Changed(std::move(before));
      }
    }
    if (Section("Generate")) {
      float x0 = 0.0f, z0 = 0.0f, x1 = 0.0f, z1 = 0.0f;
      mDocument.LayoutArea(x0, z0, x1, z1);
      ImGui::TextDisabled(
        "%d x %d cells of %.1f units over the playable area",
        layout.Frame().rw,
        layout.Frame().rh,
        static_cast<double>(layout.Frame().cell)
      );
      int res = layout.Res();
      ImGui::SetNextItemWidth(-1.0f);
      if (
        FillSliderInt("##layoutres", &res, MapLayout::kMinRes, MapLayout::kMaxRes, "Resolution %d") &&
        !ImGui::IsMouseDown(ImGuiMouseButton_Left)
      ) {
        MapLayout before = layout;
        if (layout.Refit(res, x0, z0, x1, z1)) {
          Changed(std::move(before));
        }
      }
      if (ImGui::IsItemDeactivatedAfterEdit() && res != layout.Res()) {
        MapLayout before = layout;
        if (layout.Refit(res, x0, z0, x1, z1)) {
          Changed(std::move(before));
        }
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Cells on the long side; what is drawn stays where it is on the map");
      }
      if (layout.Stale(x0, z0, x1, z1)) {
        ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.3f, 1.0f), "The playable area changed.");
        ImGui::SameLine();
        if (ImGui::SmallButton("Fit to the area")) {
          MapLayout before = layout;
          if (layout.Refit(layout.Res(), x0, z0, x1, z1)) {
            Changed(std::move(before));
          }
        }
      }
      ImGui::SetNextItemWidth(-1.0f);
      bool edited = FillSliderFloat("##layoutbase", &layout.base, 0.0f, 200.0f, "Ground height %.0f");
      BeginChange();
      EndChange(edited);
      ImGui::SetNextItemWidth(-1.0f);
      edited = FillSliderFloat("##layoutwater", &layout.water, 0.0f, 200.0f, "Water level %.0f");
      BeginChange();
      EndChange(edited);
      ImGui::SetNextItemWidth(-1.0f);
      edited = FillDragInt("##layoutseed", &layout.seed, 0.2f, 1, 99999, "Seed %d");
      BeginChange();
      EndChange(edited);
      if (PrimaryButton(ICON_TERRAIN " Generate terrain", ImVec2(-1.0f, 0.0f))) {
        mGenerateAsked = true;
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(
          "Writes the heights the layers make (and the water level, when a Water layer has paint) as one undo step"
        );
      }
      const std::vector<LayoutBase> bases = layout.BaseCentres();
      ImGui::TextDisabled("%zu bases drawn (start positions).", bases.size());
    }
    if (!mStatus.empty()) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextUnformatted(mStatus.c_str());
      ImGui::PopTextWrapPos();
    }
    ImGui::End();
  }

  void EdLayoutPanel::UpdateImage()
  {
    const MapLayout& layout = mDocument.Layout();
    if (mImage != 0 && mImageRevision == layout.revision && mImageSelected == layout.selected) {
      return;
    }
    std::vector<std::uint8_t> rgba;
    layout.Pixels(rgba);
    std::vector<std::uint32_t> bgra(rgba.size() / 4);
    for (std::size_t k = 0; k < bgra.size(); ++k) {
      bgra[k] = 0xFF000000u | (static_cast<std::uint32_t>(rgba[k * 4]) << 16) |
        (static_cast<std::uint32_t>(rgba[k * 4 + 1]) << 8) | rgba[k * 4 + 2];
    }
    if (mImage != 0) {
      mRetired.push_back(mImage);
    }
    mImage = EdImGuiRenderer::CreateImage(layout.Frame().rw, layout.Frame().rh, bgra.data());
    mImageRevision = layout.revision;
    mImageSelected = layout.selected;
  }

  void EdLayoutPanel::PaintAt(
    const float cx,
    const float cz,
    const bool erase
  )
  {
    MapLayout& layout = mDocument.Layout();
    layout.Line(layout.selected, mLastX, mLastZ, cx, cz, mSize, mHardness, mStrength, erase);
    mLastX = cx;
    mLastZ = cz;
    layout.Touch();
  }

  void EdLayoutPanel::DrawCanvasPanel(
    bool& open,
    const bool mapOpen
  )
  {
    // Pictures replaced before the last frame was drawn are done with now.
    for (const std::uint64_t image : mRetired) {
      EdImGuiRenderer::DestroyImage(image);
    }
    mRetired.clear();
    if (!ImGui::Begin(Panel("Layout canvas###LayoutCanvas"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to draw its layout.");
      ImGui::End();
      return;
    }
    MapLayout& layout = mDocument.Layout();
    const float s = Em(1.0f);
    struct ToolInfo
    {
      Tool tool;
      const char* icon;
      const char* name;
      const char* tip;
    };
    static const ToolInfo kTools[] = {
      {Tool::Brush, ICON_BRUSH, "Brush", "Paints the selected layer (right button erases)"},
      {Tool::Eraser, ICON_ERASER, "Eraser", "Takes paint away"},
      {Tool::Line, ICON_PATH, "Line", "A line of the brush's width (rivers, ridges)"},
      {Tool::Rect, ICON_FRAME, "Rect", "A filled rectangle"},
      {Tool::Ellipse, ICON_AREA, "Ellipse", "A filled ellipse"},
      {Tool::Lasso, ICON_WAND, "Lasso", "Draw an outline: the inside is filled"},
    };
    const float tileW =
      std::max(40.0f * s, (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * 5.0f) / 6.0f);
    for (const ToolInfo& t : kTools) {
      if (&t != &kTools[0]) {
        ImGui::SameLine();
      }
      if (ModeTile(t.icon, t.name, mTool == t.tool, ImVec2(tileW, 0.0f))) {
        mTool = t.tool;
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", t.tip);
      }
    }
    const float third = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * 2.0f) / 3.0f;
    ImGui::SetNextItemWidth(third);
    (void)FillSliderFloat("##lsize", &mSize, 0.5f, 64.0f, "Size %.1f");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(third);
    (void)FillSliderFloat("##lhard", &mHardness, 0.0f, 1.0f, "Hardness %.2f");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(third);
    (void)FillSliderFloat("##lstrength", &mStrength, 0.05f, 1.0f, "Strength %.2f");
    const auto layerOp = [&](const char* label, const char* tip, auto op) {
      if (ImGui::Button(label)) {
        if (layout.BeginStroke(layout.selected)) {
          op();
          LayoutStroke stroke;
          if (layout.EndStroke(stroke)) {
            mDocument.LayoutStroked(std::move(stroke));
          }
        }
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", tip);
      }
    };
    layerOp("Clear", "Empties the selected layer", [&] {
      layout.Fill(layout.selected, 0.0f);
    });
    ImGui::SameLine();
    layerOp("Fill", "Fills the selected layer", [&] {
      layout.Fill(layout.selected, 1.0f);
    });
    ImGui::SameLine();
    layerOp("Smooth", "Softens what is drawn on the selected layer", [&] {
      layout.Smooth(layout.selected);
    });
    ImGui::SameLine();
    layerOp("Invert", "Turns the selected layer into its opposite", [&] {
      layout.Invert(layout.selected);
    });
    DrawCanvas();
    ImGui::End();
  }

  void EdLayoutPanel::DrawCanvas()
  {
    MapLayout& layout = mDocument.Layout();
    const LayoutFrame& f = layout.Frame();
    UpdateImage();
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    if (avail.x < 16.0f || avail.y < 16.0f || f.rw < 1 || f.rh < 1) {
      return;
    }
    const float scale = std::min(avail.x / static_cast<float>(f.rw), avail.y / static_cast<float>(f.rh));
    const ImVec2 size(static_cast<float>(f.rw) * scale, static_cast<float>(f.rh) * scale);
    const ImVec2 cursor = ImGui::GetCursorScreenPos();
    const ImVec2 p0(cursor.x + (avail.x - size.x) / 2.0f, cursor.y);
    ImGui::SetCursorScreenPos(p0);
    ImGui::InvisibleButton(
      "##layoutcanvas", size, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight
    );
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImVec2 p1(p0.x + size.x, p0.y + size.y);
    if (mImage != 0) {
      draw->AddImage(static_cast<ImTextureID>(mImage), p0, p1);
    }
    draw->AddRect(p0, p1, IM_COL32(255, 255, 255, 60));
    const ImVec2 mouse = ImGui::GetIO().MousePos;
    const float cx = (mouse.x - p0.x) / scale;
    const float cz = (mouse.y - p0.y) / scale;
    const auto toScreen = [&](const float x, const float z) {
      return ImVec2(p0.x + x * scale, p0.y + z * scale);
    };
    const bool brushLike = mTool == Tool::Brush || mTool == Tool::Eraser || mTool == Tool::Line;
    // Starting a stroke or a shape.
    if (
      !mStroking && hovered &&
      (ImGui::IsMouseClicked(ImGuiMouseButton_Left) || ImGui::IsMouseClicked(ImGuiMouseButton_Right)) &&
      layout.BeginStroke(layout.selected)
    ) {
      mStroking = true;
      mErasing = mTool == Tool::Eraser || ImGui::IsMouseClicked(ImGuiMouseButton_Right);
      mStartX = mLastX = cx;
      mStartZ = mLastZ = cz;
      mLasso.assign(1, {cx, cz});
      if (mTool == Tool::Brush || mTool == Tool::Eraser) {
        PaintAt(cx, cz, mErasing);
      }
    }
    if (mStroking) {
      const bool down = ImGui::IsMouseDown(ImGuiMouseButton_Left) || ImGui::IsMouseDown(ImGuiMouseButton_Right);
      if (mTool == Tool::Brush || mTool == Tool::Eraser) {
        if (std::hypot(cx - mLastX, cz - mLastZ) > 0.25f) {
          PaintAt(cx, cz, mErasing);
        }
      } else if (mTool == Tool::Lasso) {
        if (std::hypot(cx - mLasso.back().first, cz - mLasso.back().second) > 0.5f) {
          mLasso.emplace_back(cx, cz);
        }
      }
      if (!down) {
        // The shape is made on release.
        if (mTool == Tool::Line) {
          layout.Line(layout.selected, mStartX, mStartZ, cx, cz, mSize, mHardness, mStrength, mErasing);
        } else if (mTool == Tool::Rect) {
          (void)layout.FillRect(layout.selected, mStartX, mStartZ, cx, cz, mStrength, mErasing);
        } else if (mTool == Tool::Ellipse) {
          (void)layout.FillEllipse(layout.selected, mStartX, mStartZ, cx, cz, mStrength, mErasing);
        } else if (mTool == Tool::Lasso) {
          (void)layout.FillPolygon(layout.selected, mLasso, mStrength, mErasing);
        }
        mStroking = false;
        mLasso.clear();
        LayoutStroke stroke;
        if (layout.EndStroke(stroke)) {
          mDocument.LayoutStroked(std::move(stroke));
        }
      } else {
        // The shape's outline while it is drawn.
        const ImU32 outline = IM_COL32(255, 255, 255, 200);
        if (mTool == Tool::Line) {
          draw->AddLine(toScreen(mStartX, mStartZ), toScreen(cx, cz), outline, std::max(1.0f, mSize * 2.0f * scale));
        } else if (mTool == Tool::Rect) {
          draw->AddRect(toScreen(mStartX, mStartZ), toScreen(cx, cz), outline);
        } else if (mTool == Tool::Ellipse) {
          const ImVec2 a = toScreen((mStartX + cx) / 2.0f, (mStartZ + cz) / 2.0f);
          draw->AddEllipse(
            a, ImVec2(std::fabs(cx - mStartX) * scale / 2.0f, std::fabs(cz - mStartZ) * scale / 2.0f), outline
          );
        } else if (mTool == Tool::Lasso) {
          for (std::size_t k = 1; k < mLasso.size(); ++k) {
            draw->AddLine(
              toScreen(mLasso[k - 1].first, mLasso[k - 1].second), toScreen(mLasso[k].first, mLasso[k].second), outline
            );
          }
        }
      }
    }
    // The brush on the canvas and its copies under the symmetry.
    if (hovered && brushLike) {
      for (const auto& [ix, iz] : layout.BrushImages(cx, cz)) {
        draw->AddCircle(toScreen(ix, iz), mSize * scale, IM_COL32(255, 255, 255, 170), 0, 1.5f);
      }
    }
    // The start positions the bases give.
    for (const LayoutBase& base : layout.BaseCentres()) {
      float bx = 0.0f, bz = 0.0f;
      layout.ToCell(base.x, base.z, bx, bz);
      const ImVec2 c = toScreen(bx, bz);
      draw->AddCircleFilled(c, Em(4.0f), IM_COL32(255, 255, 255, 230));
      draw->AddCircle(c, Em(4.0f), IM_COL32(0, 0, 0, 200));
    }
    if (hovered) {
      float wx = 0.0f, wz = 0.0f;
      layout.ToWorld(cx, cz, wx, wz);
      ImGui::SetTooltip("%.0f, %.0f", static_cast<double>(wx), static_cast<double>(wz));
    }
  }
} // namespace faf::editor

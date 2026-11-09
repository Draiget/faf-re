#include "editor/EdTools.h"

#include <cmath>
#include <string>
#include <cctype>
#include <algorithm>
#include <cstdio>

#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    const ImU32 kAccent = IM_COL32(227, 148, 67, 255);
    const ImU32 kAccentSoft = IM_COL32(227, 148, 67, 40);
    const ImU32 kIconIdle = IM_COL32(139, 147, 157, 255);
    const ImU32 kIconHot = IM_COL32(216, 220, 225, 255);
    const ImU32 kCellBack = IM_COL32(21, 24, 29, 255);
    const ImU32 kCellLine = IM_COL32(58, 65, 75, 255);

    struct ToolInfo
    {
      const char* name;
      const char* key;
    };
    constexpr ToolInfo kTools[] = {
      {"Select", "S"}, {"Terrain", "T"}, {"Texture", "P"}, {"Water", "W"}, {"Props", "O"}, {"Decals", "D"}, {"Markers", "M"},
      {"Units", "U"},
    };

    /** Draws tool `index`'s icon in the square at `p`, `s` wide. */
    void DrawToolIcon(ImDrawList* const draw, const int index, const ImVec2 p, const float s, const ImU32 color)
    {
      const auto at = [&](const float x, const float y) { return ImVec2(p.x + x * s, p.y + y * s); };
      switch (index) {
      case 0: // arrow
        draw->AddTriangleFilled(at(0.25f, 0.1f), at(0.25f, 0.8f), at(0.78f, 0.58f), color);
        draw->AddQuadFilled(at(0.47f, 0.55f), at(0.58f, 0.5f), at(0.76f, 0.88f), at(0.65f, 0.93f), color);
        break;
      case 1: // mountain
        draw->AddTriangleFilled(at(0.1f, 0.85f), at(0.4f, 0.4f), at(0.62f, 0.85f), color);
        draw->AddTriangleFilled(at(0.45f, 0.85f), at(0.7f, 0.5f), at(0.92f, 0.85f), color);
        break;
      case 2: // brush
        draw->AddQuadFilled(at(0.62f, 0.12f), at(0.88f, 0.38f), at(0.52f, 0.72f), at(0.28f, 0.48f), color);
        draw->AddTriangleFilled(at(0.26f, 0.55f), at(0.45f, 0.74f), at(0.12f, 0.9f), color);
        break;
      case 3: // waves
        for (int row = 0; row < 2; ++row) {
          const float y = 0.42f + 0.24f * static_cast<float>(row);
          ImVec2 points[13];
          for (int i = 0; i < 13; ++i) {
            const float t = static_cast<float>(i) / 12.0f;
            points[i] = at(0.1f + 0.8f * t, y + 0.07f * std::sin(t * 6.2831853f * 2.0f));
          }
          draw->AddPolyline(points, 13, color, ImDrawFlags_None, s * 0.08f);
        }
        break;
      case 4: // tree
        draw->AddTriangleFilled(at(0.5f, 0.08f), at(0.78f, 0.5f), at(0.22f, 0.5f), color);
        draw->AddTriangleFilled(at(0.5f, 0.3f), at(0.86f, 0.78f), at(0.14f, 0.78f), color);
        draw->AddRectFilled(at(0.45f, 0.78f), at(0.55f, 0.94f), color);
        break;
      case 5: // decal
        draw->AddRect(at(0.15f, 0.15f), at(0.85f, 0.85f), color, s * 0.08f, ImDrawFlags_None, s * 0.08f);
        draw->AddCircleFilled(at(0.5f, 0.5f), s * 0.17f, color);
        break;
      case 6: // marker pin
        draw->AddCircleFilled(at(0.5f, 0.38f), s * 0.28f, color);
        draw->AddTriangleFilled(at(0.25f, 0.5f), at(0.75f, 0.5f), at(0.5f, 0.94f), color);
        draw->AddCircleFilled(at(0.5f, 0.38f), s * 0.11f, kCellBack);
        break;
      default: // a tank: hull, turret, barrel
        draw->AddRectFilled(at(0.1f, 0.55f), at(0.9f, 0.85f), color, s * 0.06f);
        draw->AddCircleFilled(at(0.45f, 0.48f), s * 0.16f, color);
        draw->AddLine(at(0.5f, 0.45f), at(0.92f, 0.3f), color, s * 0.08f);
        break;
      }
    }

    struct SymmetryMode
    {
      const char* name;
      int copies;
      bool square;
    };
    constexpr SymmetryMode kSymmetry[] = {
      {"None", 1, false},           {"Left-right", 2, false},   {"Top-bottom", 2, false},     {"Diagonal \\", 2, true},
      {"Diagonal /", 2, true},      {"Half turn", 2, false},    {"Both axes", 4, false},      {"Both diagonals", 4, true},
      {"Quarter turns", 4, true},   {"N-way turn", 0, true},
    };

    /** The symmetry mode's copies of the point (u, v) in [0, 1]; `n` for the N-way turn. */
    int SymmetryCopies(const int mode, const float u, const float v, const int n, ImVec2* const out)
    {
      const ImVec2 id(u, v), mx(1.0f - u, v), mz(u, 1.0f - v), d1(v, u), d2(1.0f - v, 1.0f - u), pt(1.0f - u, 1.0f - v);
      switch (mode) {
      case 0: out[0] = id; return 1;
      case 1: out[0] = id; out[1] = mx; return 2;
      case 2: out[0] = id; out[1] = mz; return 2;
      case 3: out[0] = id; out[1] = d1; return 2;
      case 4: out[0] = id; out[1] = d2; return 2;
      case 5: out[0] = id; out[1] = pt; return 2;
      case 6: out[0] = id; out[1] = mx; out[2] = mz; out[3] = pt; return 4;
      case 7: out[0] = id; out[1] = d1; out[2] = d2; out[3] = pt; return 4;
      case 8: out[0] = id; out[1] = ImVec2(1.0f - v, u); out[2] = pt; out[3] = ImVec2(v, 1.0f - u); return 4;
      default:
        for (int k = 0; k < n; ++k) {
          const float a = 6.2831853f * static_cast<float>(k) / static_cast<float>(n);
          const float du = u - 0.5f;
          const float dv = v - 0.5f;
          out[k] = ImVec2(0.5f + du * std::cos(a) - dv * std::sin(a), 0.5f + du * std::sin(a) + dv * std::cos(a));
        }
        return n;
      }
    }

    /** The mode's diagram: the map square, its mirror lines or turn centre, and one sample point's copies. */
    void DrawSymmetryIcon(ImDrawList* const draw, const int mode, const int n, const ImVec2 p, const float s)
    {
      const float pad = s * 0.08f;
      const ImVec2 a(p.x + pad, p.y + pad);
      const float w = s - 2.0f * pad;
      const auto at = [&](const float u, const float v) { return ImVec2(a.x + u * w, a.y + v * w); };
      draw->AddRectFilled(a, ImVec2(a.x + w, a.y + w), kCellBack, 2.0f);
      draw->AddRect(a, ImVec2(a.x + w, a.y + w), kCellLine, 2.0f);
      const auto line = [&](const ImVec2 from, const ImVec2 to) {
        // dashed
        for (int i = 0; i < 8; i += 2) {
          const float t0 = static_cast<float>(i) / 8.0f;
          const float t1 = static_cast<float>(i + 1) / 8.0f;
          draw->AddLine(ImVec2(from.x + (to.x - from.x) * t0, from.y + (to.y - from.y) * t0),
                        ImVec2(from.x + (to.x - from.x) * t1, from.y + (to.y - from.y) * t1), kAccent, 1.2f);
        }
      };
      if (mode == 1 || mode == 6) line(at(0.5f, 0.0f), at(0.5f, 1.0f));
      if (mode == 2 || mode == 6) line(at(0.0f, 0.5f), at(1.0f, 0.5f));
      if (mode == 3 || mode == 7) line(at(0.0f, 0.0f), at(1.0f, 1.0f));
      if (mode == 4 || mode == 7) line(at(1.0f, 0.0f), at(0.0f, 1.0f));
      if (mode == 5 || mode == 8 || mode == 9) draw->AddCircleFilled(at(0.5f, 0.5f), s * 0.05f, kAccent);
      ImVec2 copies[8];
      const int count = SymmetryCopies(mode, 0.27f, 0.22f, n, copies);
      for (int i = 0; i < count; ++i) {
        draw->AddCircleFilled(at(copies[i].x, copies[i].y), s * 0.075f, i == 0 ? IM_COL32(255, 255, 255, 255) : kAccent);
      }
    }

    void Note(const char* const text)
    {
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::TextWrapped("%s", text);
      ImGui::PopStyleColor();
    }

    void SectionHeader(const char* const text)
    {
      ImGui::Spacing();
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::TextUnformatted(text);
      ImGui::PopStyleColor();
    }

    /** A row of buttons, the chosen one marked, like the mockup's segmented buttons. */
    void Segmented(const char* const* labels, const int count, int& chosen)
    {
      const float width = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * static_cast<float>(count - 1)) /
                          static_cast<float>(count);
      for (int i = 0; i < count; ++i) {
        if (i > 0) {
          ImGui::SameLine();
        }
        const bool on = i == chosen;
        if (on) {
          ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.89f, 0.58f, 0.26f, 0.30f));
          ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.83f, 0.65f, 1.0f));
        }
        if (ImGui::Button(labels[i], ImVec2(width, 0.0f))) {
          chosen = i;
        }
        if (on) {
          ImGui::PopStyleColor(2);
        }
      }
    }
  } // namespace

  void EdTools::Draw()
  {
    DrawStrip();
    ImGui::SameLine();
    if (ImGui::BeginChild("##toolsettings", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None)) {
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.67f, 0.70f, 0.74f, 1.0f));
      ImGui::TextUnformatted(kTools[mTool].name);
      ImGui::PopStyleColor();
      ImGui::Separator();
      switch (mTool) {
      case 0: DrawSelect(); break;
      case 1: DrawTerrain(); break;
      case 2: DrawTexture(); break;
      case 3: DrawWater(); break;
      case 4: DrawProps(); break;
      case 5: DrawDecals(); break;
      case 6: DrawMarkers(); break;
      default: DrawUnits(); break;
      }
    }
    ImGui::EndChild();
  }

  void EdTools::DrawStrip()
  {
    const float cell = ImGui::GetFrameHeight() * 1.55f;
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 3.0f));
    if (ImGui::BeginChild("##toolstrip", ImVec2(cell + 4.0f, 0.0f), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar)) {
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      for (int i = 0; i < static_cast<int>(IM_ARRAYSIZE(kTools)); ++i) {
        ImGui::PushID(i);
        const ImVec2 p = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton("##tool", ImVec2(cell, cell))) {
          mTool = i;
        }
        const bool hovered = ImGui::IsItemHovered();
        if (hovered) {
          ImGui::SetTooltip("%s (%s)", kTools[i].name, kTools[i].key);
        }
        const ImVec2 q(p.x + cell, p.y + cell);
        if (i == mTool) {
          draw->AddRectFilled(p, q, kAccentSoft, 4.0f);
          draw->AddRectFilled(p, ImVec2(p.x + 2.0f, q.y), kAccent);
        } else if (hovered) {
          draw->AddRectFilled(p, q, IM_COL32(42, 47, 55, 255), 4.0f);
        }
        const float icon = cell * 0.56f;
        DrawToolIcon(draw, i, ImVec2(p.x + (cell - icon) * 0.5f, p.y + (cell - icon) * 0.5f), icon,
                     i == mTool ? kAccent : (hovered ? kIconHot : kIconIdle));
        draw->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 0.62f, ImVec2(q.x - ImGui::GetFontSize() * 0.45f, q.y - ImGui::GetFontSize() * 0.7f),
                      IM_COL32(93, 100, 109, 255), kTools[i].key);
        ImGui::PopID();
      }
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
  }

  void EdTools::DrawBrush(const bool withModes)
  {
    SectionHeader("BRUSH");
    if (withModes) {
      // Three rows of three; each entry is its HeightBrushMode.
      static const char* const kRows[3][3] = {{"Raise", "Lower", "Smooth"}, {"Flatten", "Set height", "Noise"}, {"Terrace", "Plane", "Stamp"}};
      static constexpr int kModeOf[3][3] = {{0, 1, 2}, {3, 5, 4}, {6, 7, 8}};
      for (int row = 0; row < 3; ++row) {
        int chosen = -1;
        for (int i = 0; i < 3; ++i) {
          chosen = kModeOf[row][i] == mBrushMode ? i : chosen;
        }
        const int before = chosen;
        Segmented(kRows[row], 3, chosen);
        if (chosen != before && chosen >= 0) {
          mBrushMode = kModeOf[row][chosen];
        }
      }
      switch (static_cast<HeightBrushMode>(mBrushMode)) {
      case HeightBrushMode::Flatten:
        Note("Flattens to the height under the stroke's first point.");
        break;
      case HeightBrushMode::SetHeight:
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::DragFloat("##setheight", &mSetHeight, 0.25f, 0.0f, 500.0f, "Height %.1f");
        break;
      case HeightBrushMode::Terrace:
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::DragFloat("##terrace", &mTerraceStep, 0.1f, 0.5f, 100.0f, "Step %.1f");
        break;
      case HeightBrushMode::Plane: {
        char text[120];
        (void)std::snprintf(text, sizeof(text), "Ctrl+click three points on the terrain; the brush moves the ground towards their plane (%d of 3%s).",
                            mPlanePoints, mPlanePoints == 3 && !mPlaneSet ? ", on one line" : "");
        Note(text);
        if (ImGui::Button("Clear points")) {
          ClearPlanePoints();
        }
        break;
      }
      case HeightBrushMode::Stamp:
        if (ImGui::Button("Stamp image...")) {
          mStampRequested = true;
        }
        ImGui::SameLine();
        ImGui::TextDisabled("%s", mStamp != nullptr ? mStampName.c_str() : "none");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::DragFloat("##stampheight", &mStampHeight, 0.25f, -200.0f, 200.0f, "Stamp height %.1f");
        Note("Each click adds the image over the brush's square: white adds the stamp height times strength.");
        break;
      default:
        break;
      }
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::SliderFloat("##radius", &mRadius, 3.0f, 40.0f, "Radius %.0f");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::SliderFloat("##strength", &mStrength, 0.05f, 1.0f, "Strength %.2f");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::SliderFloat("##falloff", &mFalloff, 0.0f, 1.0f, "Falloff %.2f");
  }

  void EdTools::DrawSymmetry(const bool withCheck)
  {
    SectionHeader("SYMMETRY");
    const float available = ImGui::GetContentRegionAvail().x;
    const int columns = 5;
    const float spacing = ImGui::GetStyle().ItemSpacing.x * 0.6f;
    const float cell = (available - spacing * static_cast<float>(columns - 1)) / static_cast<float>(columns);
    const float labelHeight = ImGui::GetFontSize() * 1.6f;
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    for (int i = 0; i < static_cast<int>(IM_ARRAYSIZE(kSymmetry)); ++i) {
      if (i % columns != 0) {
        ImGui::SameLine(0.0f, spacing);
      }
      ImGui::PushID(i);
      const ImVec2 p = ImGui::GetCursorScreenPos();
      if (ImGui::InvisibleButton("##sym", ImVec2(cell, cell + labelHeight))) {
        mSymmetry = i;
      }
      const bool on = i == mSymmetry;
      const bool hovered = ImGui::IsItemHovered();
      if (hovered) {
        ImGui::SetTooltip("%s%s", kSymmetry[i].name, kSymmetry[i].square ? " (square maps)" : "");
      }
      draw->AddRectFilled(p, ImVec2(p.x + cell, p.y + cell + labelHeight), on ? kAccentSoft : IM_COL32(34, 38, 45, 255), 4.0f);
      draw->AddRect(p, ImVec2(p.x + cell, p.y + cell + labelHeight), on ? kAccent : (hovered ? IM_COL32(74, 83, 95, 255) : kCellLine), 4.0f);
      DrawSymmetryIcon(draw, i, mNWay, ImVec2(p.x + cell * 0.12f, p.y + cell * 0.06f), cell * 0.76f);
      const float labelSize = ImGui::GetFontSize() * 0.66f;
      const ImVec2 textSize = ImGui::GetFont()->CalcTextSizeA(labelSize, cell, cell, kSymmetry[i].name);
      draw->AddText(ImGui::GetFont(), labelSize, ImVec2(p.x + (cell - textSize.x) * 0.5f, p.y + cell * 0.86f),
                    on ? IM_COL32(255, 211, 166, 255) : kIconIdle, kSymmetry[i].name, nullptr, cell);
      ImGui::PopID();
    }
    if (mSymmetry == 9) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::SliderInt("##nway", &mNWay, 3, 8, "Copies %d");
    }
    if (mDetectedSymmetry >= 0) {
      char found[120];
      if (mDetectedSymmetry == 9) {
        (void)std::snprintf(found, sizeof(found), "The map's heights: %d-way turn (%.1f%% of points match).", mNWay,
                            static_cast<double>(mDetectedMatch) * 100.0);
      } else {
        (void)std::snprintf(found, sizeof(found), "The map's heights: %s (%.1f%% of points match).", kSymmetry[mDetectedSymmetry].name,
                            static_cast<double>(mDetectedMatch) * 100.0);
      }
      ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "%s", found);
    } else if (mDetectedSymmetry == -1) {
      ImGui::TextDisabled("The map's heights fit no symmetry.");
    }
    const int copies = mSymmetry == 9 ? mNWay : kSymmetry[mSymmetry].copies;
    char note[300];
    if (mSymmetry == 9) {
      (void)std::snprintf(note, sizeof(note),
                          "Every edit is written to all %d copies: the first sector (from the centre towards the right, turning down) "
                          "is painted, the others copy it. Turns other than 4 fall between vertices, so their copies are "
                          "close, not identical; the check shows by how much.",
                          copies);
    } else {
      (void)std::snprintf(note, sizeof(note),
                          "Every edit is written to all %d copies. Where copies overlap, each vertex takes the strongest copy, "
                          "so the halves stay identical.",
                          copies);
    }
    Note(note);
    if (!withCheck) {
      return;
    }

    SectionHeader("SYMMETRY CHECK");
    if (mSymmetry == 0) {
      Note("Pick a symmetry to check the map against it.");
      return;
    }
    if (ImGui::Button("Check")) {
      mCheckRequested = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Show differences", &mShowDifferences);
    if (!CheckIsCurrent()) {
      Note("Compares every vertex with its copies; differing ones are marked red on the terrain.");
      return;
    }
    // Heights in game units; mask weights as a share of full.
    const float largest = mCheckedMasks ? static_cast<float>(mLargest) / 2.55f : static_cast<float>(mLargest) / 128.0f;
    const char* const unit = mCheckedMasks ? "mask texels" : "vertices";
    const char* const format = mCheckedMasks ? "%.0f%%" : "%.2f";
    char amount[32];
    (void)std::snprintf(amount, sizeof(amount), format, static_cast<double>(largest));
    char result[200];
    if (mDiffering == 0) {
      (void)std::snprintf(result, sizeof(result), "All %d %s match their copies (largest difference %s).", mChecked, unit, amount);
    } else {
      (void)std::snprintf(result, sizeof(result), "%d of %d %s differ from a copy, by up to %s.", mDiffering, mChecked, unit, amount);
    }
    ImGui::TextWrapped("%s", result);
    if (mDiffering > 0) {
      if (ImGui::Button("Copy the source part to the other copies")) {
        mRepairRequested = true;
      }
      Note(mSymmetry == 9 ? "The source part is the first sector. One undo step."
                          : "The source part is the top or left one (the copy nearest the map's top-left corner). One undo step.");
    }
  }

  void EdTools::DrawSelect()
  {
    Note("Click a prop to select it (Ctrl adds), drag to move the selection over the ground, Q and E turn it by 15 degrees, "
         "Delete removes it. Each is one undo step.");
    char count[64];
    (void)std::snprintf(count, sizeof(count), "%d selected", mSelectionCount);
    ImGui::TextUnformatted(count);
  }

  void EdTools::DrawTerrain()
  {
    DrawBrush(true);
    DrawSymmetry();
    DrawLimits();
    SectionHeader("HEIGHT FIELD");
    if (ImGui::Button("Import...")) {
      mImportRequested = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Export...")) {
      mExportRequested = true;
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::DragFloat("##heightscale", &mHeightScale, 0.01f, 0.01f, 16.0f, "Height scale %.2f");
    static constexpr const char* kSizes[] = {"Export at the map's size", "Export 257 wide", "Export 513 wide", "Export 1025 wide",
                                             "Export 2049 wide", "Export 4097 wide"};
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::Combo("##exportsize", &mExportSize, kSizes, IM_ARRAYSIZE(kSizes));
    Note("Import reads .png, .raw, .r16 (World Machine), .bmp or .tif, resampled to the map's size; export writes .png (16-bit grey), "
         ".raw or .r16. Heights are times the scale both ways. An import is one undo step.");
  }

  void EdTools::AddPlanePoint(const float x, const float height, const float z) noexcept
  {
    if (mPlanePoints == 3) {
      // The oldest goes.
      for (int i = 0; i < 2; ++i) {
        mPlanePointX[i] = mPlanePointX[i + 1];
        mPlanePointH[i] = mPlanePointH[i + 1];
        mPlanePointZ[i] = mPlanePointZ[i + 1];
      }
      mPlanePoints = 2;
    }
    mPlanePointX[mPlanePoints] = x;
    mPlanePointH[mPlanePoints] = height;
    mPlanePointZ[mPlanePoints] = z;
    ++mPlanePoints;
    mPlaneSet = false;
    if (mPlanePoints == 3) {
      // In samples and height words, as the brush reads it.
      const double px[3] = {mPlanePointX[0], mPlanePointX[1], mPlanePointX[2]};
      const double ph[3] = {mPlanePointH[0] * 128.0, mPlanePointH[1] * 128.0, mPlanePointH[2] * 128.0};
      const double pz[3] = {mPlanePointZ[0], mPlanePointZ[1], mPlanePointZ[2]};
      mPlaneSet = PlaneThrough(px, ph, pz, mPlaneX, mPlaneZ, mPlaneC);
    }
  }

  int EdTools::PlanePoints(float (&x)[3], float (&height)[3], float (&z)[3]) const noexcept
  {
    for (int i = 0; i < mPlanePoints; ++i) {
      x[i] = mPlanePointX[i];
      height[i] = mPlanePointH[i];
      z[i] = mPlanePointZ[i];
    }
    return mPlanePoints;
  }

  namespace
  {
    /** "grass001" from "/env/evergreen/layers/grass001_albedo.dds"; "(empty)" for none. */
    std::string LayerLabel(const std::string& path)
    {
      if (path.empty()) {
        return "(empty)";
      }
      std::string name = path.substr(path.find_last_of('/') + 1);
      for (const char* const suffix : {"_albedo.dds", ".dds"}) {
        const std::string tail = suffix;
        if (name.size() > tail.size()) {
          std::string lower = name.substr(name.size() - tail.size());
          for (char& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          if (lower == tail) {
            name.resize(name.size() - tail.size());
            break;
          }
        }
      }
      return name;
    }
  } // namespace

  void EdTools::DrawLimits()
  {
    SectionHeader("LIMIT");
    ImGui::Checkbox("Only between heights", &mLimitHeight);
    if (mLimitHeight) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::DragFloatRange2("##limitheights", &mLimitLow, &mLimitHigh, 0.25f, 0.0f, 512.0f, "From %.1f", "to %.1f");
    }
    ImGui::Checkbox("Only below slope", &mLimitSlope);
    if (mLimitSlope) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::SliderFloat("##limitslope", &mLimitSlopeDegrees, 1.0f, 85.0f, "%.0f degrees");
    }
  }

  void EdTools::DrawLayerSlots()
  {
    SectionHeader("LAYERS");
    if (mSlots.size() != 10) {
      Note("Open a map to see its layers.");
      return;
    }
    mLibrary.Pump(3);
    static const char* const kSlotNames[10] = {"Lower", "1", "2", "3", "4", "5", "6", "7", "8", "Upper"};
    const float thumb = ImGui::GetFrameHeight() * 1.6f;
    for (int slot = 0; slot < 10; ++slot) {
      LayerSlot& layer = mSlots[static_cast<std::size_t>(slot)];
      ImGui::PushID(slot);
      const std::uint64_t image = mLibrary.Thumbnail(layer.albedo);
      const ImVec2 at = ImGui::GetCursorScreenPos();
      if (image != 0U) {
        ImGui::Image(static_cast<ImTextureID>(image), ImVec2(thumb, thumb));
      } else {
        ImGui::Dummy(ImVec2(thumb, thumb));
        ImGui::GetWindowDrawList()->AddRect(at, ImVec2(at.x + thumb, at.y + thumb), IM_COL32(58, 65, 75, 255));
      }
      if (ImGui::IsItemClicked()) {
        mBrowseSlot = slot;
        mBrowseOpen = true;
      }
      ImGui::SameLine();
      ImGui::BeginGroup();
      ImGui::Text("%s  %s", kSlotNames[slot], LayerTextureName(layer.albedo).c_str());
      if (ImGui::IsItemHovered() && !layer.albedo.empty()) {
        ImGui::SetTooltip("%s\n%s", layer.albedo.c_str(), layer.normals.empty() ? "(no normal map)" : layer.normals.c_str());
      }
      ImGui::SetNextItemWidth(-1.0f);
      float size = layer.albedoSize;
      if (ImGui::DragFloat("##size", &size, 0.05f, 0.1f, 1024.0f, "Size %.2f") && size > 0.0f) {
        // Albedo and normal map keep their ratio (most maps have them equal).
        const float ratio = layer.albedoSize > 0.0f ? layer.normalsSize / layer.albedoSize : 1.0f;
        mChangedSlot = slot;
        mChangedValue = layer;
        mChangedValue.albedoSize = size;
        mChangedValue.normalsSize = size * ratio;
      }
      ImGui::EndGroup();
      ImGui::PopID();
    }
    Note("Click a thumbnail to choose its texture.");
    if (!mShaders.empty()) {
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::BeginCombo("##shader", ("Shader " + mShader).c_str())) {
        for (const std::string& shader : mShaders) {
          if (ImGui::Selectable(shader.c_str(), shader == mShader) && shader != mShader) {
            mShaderChange = shader;
          }
        }
        ImGui::EndCombo();
      }
    }
    DrawTextureBrowser();
  }

  void EdTools::DrawTextureBrowser()
  {
    constexpr const char* kTitle = "Layer textures";
    if (mBrowseOpen) {
      mBrowseOpen = false;
      ImGui::OpenPopup(kTitle);
    }
    ImGui::SetNextWindowSize(ImVec2(760.0f, 560.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal(kTitle, nullptr)) {
      return;
    }
    ImGui::Text("Layer %s", mBrowseSlot == 0 ? "Lower" : (mBrowseSlot == 9 ? "Upper" : std::to_string(mBrowseSlot).c_str()));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260.0f);
    ImGui::InputTextWithHint("##filter", "search name or biome", mBrowseFilter, sizeof(mBrowseFilter));
    ImGui::SameLine();
    if (mBrowseSlot >= 1 && mBrowseSlot <= 8 && ImGui::Button("Empty")) {
      mChangedSlot = mBrowseSlot;
      mChangedValue = mSlots[static_cast<std::size_t>(mBrowseSlot)];
      mChangedValue.albedo.clear();
      mChangedValue.normals.clear();
      ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    std::string filter = mBrowseFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (ImGui::BeginChild("##grid", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
      const float cell = 96.0f;
      const int columns = std::max(1, static_cast<int>(ImGui::GetContentRegionAvail().x / (cell + 8.0f)));
      int shown = 0;
      std::string biome;
      for (const LayerTexture& texture : mLibrary.Textures()) {
        std::string key = texture.biome + "/" + texture.name;
        for (char& c : key) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (!filter.empty() && key.find(filter) == std::string::npos) {
          continue;
        }
        if (texture.biome != biome) {
          biome = texture.biome;
          shown = 0;
          ImGui::SeparatorText(biome.c_str());
        }
        if (shown % columns != 0) {
          ImGui::SameLine();
        }
        ++shown;
        ImGui::PushID(texture.path.c_str());
        ImGui::BeginGroup();
        const std::uint64_t image = mLibrary.Thumbnail(texture.path);
        bool picked = false;
        if (image != 0U) {
          picked = ImGui::ImageButton("##pick", static_cast<ImTextureID>(image), ImVec2(cell, cell));
        } else {
          picked = ImGui::Button("...", ImVec2(cell + 6.0f, cell + 6.0f));
        }
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + cell);
        ImGui::TextUnformatted(texture.name.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndGroup();
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s\n%s", texture.path.c_str(), texture.normals.empty() ? "(no normal map beside it)" : texture.normals.c_str());
        }
        if (picked && mBrowseSlot >= 0 && mBrowseSlot < static_cast<int>(mSlots.size())) {
          mChangedSlot = mBrowseSlot;
          mChangedValue = mSlots[static_cast<std::size_t>(mBrowseSlot)];
          mChangedValue.albedo = texture.path;
          if (!texture.normals.empty()) {
            mChangedValue.normals = texture.normals;
          }
          ImGui::CloseCurrentPopup();
        }
        ImGui::PopID();
      }
    }
    ImGui::EndChild();
    mLibrary.Pump(6);
    ImGui::EndPopup();
  }

  void EdTools::DrawTexture()
  {
    DrawLayerSlots();
    SectionHeader("PAINT LAYER");
    // Strata 1-8 have masks; the lower layer is under everything and the upper one is blended by its alpha.
    for (int layer = 0; layer < 8; ++layer) {
      // The slots as the terrain has them now (a swapped texture shows at once), else the names read at open.
      const std::string path = mSlots.size() == 10 ? mSlots[static_cast<std::size_t>(layer + 1)].albedo
                               : static_cast<std::size_t>(layer + 1) < mLayerNames.size() ? mLayerNames[static_cast<std::size_t>(layer + 1)] : "";
      char label[160];
      if (mHasCoverage) {
        (void)std::snprintf(label, sizeof(label), "%d  %s  %.0f%%##layer%d", layer + 1, LayerLabel(path).c_str(),
                            static_cast<double>(mCoverage[layer] * 100.0f), layer);
      } else {
        (void)std::snprintf(label, sizeof(label), "%d  %s##layer%d", layer + 1, LayerLabel(path).c_str(), layer);
      }
      if (ImGui::Selectable(label, mMaskLayer == layer)) {
        mMaskLayer = layer;
      }
      if (!path.empty() && ImGui::IsItemHovered()) {
        ImGui::SetTooltip("%s", path.c_str());
      }
    }
    if (mSlots.size() == 10) {
      ImGui::TextDisabled("Under all: %s", LayerLabel(mSlots.front().albedo).c_str());
    } else if (!mLayerNames.empty()) {
      ImGui::TextDisabled("Under all: %s", LayerLabel(mLayerNames.front()).c_str());
    }
    if (ImGui::SmallButton("Clear")) {
      mMaskOp = MaskOp::Clear;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Import...")) {
      mMaskOp = MaskOp::Import;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Export...")) {
      mMaskOp = MaskOp::Export;
    }
    SectionHeader("BRUSH");
    static const char* const kMaskModes[] = {"Paint", "Erase", "Smooth"};
    Segmented(kMaskModes, 3, mMaskMode);
    ImGui::Checkbox("Lower the layers above", &mLowerAbove);
    ImGui::Checkbox("Show the layer's weight", &mShowWeight);
    DrawBrush(false);
    DrawSymmetry(true);
    DrawLimits();

    SectionHeader("RULES");
    Note("Each rule sets its layer to full where the ground is in its height and slope range; they run in order over the whole map.");
    int remove = -1;
    for (std::size_t i = 0; i < mRules.size(); ++i) {
      MaskRule& rule = mRules[i];
      ImGui::PushID(static_cast<int>(i));
      ImGui::SetNextItemWidth(70.0f);
      int layer = rule.layer + 1;
      if (ImGui::InputInt("##layer", &layer)) {
        rule.layer = std::clamp(layer - 1, 0, 7);
      }
      ImGui::SameLine();
      ImGui::TextUnformatted("layer");
      ImGui::SameLine();
      if (ImGui::SmallButton("Remove")) {
        remove = static_cast<int>(i);
      }
      ImGui::Checkbox("Height", &rule.useHeight);
      if (rule.useHeight) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::DragFloatRange2("##heights", &rule.low, &rule.high, 0.25f, 0.0f, 512.0f, "%.1f", "%.1f");
      }
      ImGui::Checkbox("Slope", &rule.useSlope);
      if (rule.useSlope) {
        float lowDegrees = std::atan(rule.minSlope) * 57.29578f;
        float highDegrees = std::atan(std::min(rule.maxSlope, 1000.0f)) * 57.29578f;
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::DragFloatRange2("##slopes", &lowDegrees, &highDegrees, 0.5f, 0.0f, 90.0f, "%.0f deg", "%.0f deg")) {
          rule.minSlope = std::tan(lowDegrees * 0.0174532925f);
          rule.maxSlope = highDegrees >= 89.9f ? 1000.0f : std::tan(highDegrees * 0.0174532925f);
        }
      }
      ImGui::Separator();
      ImGui::PopID();
    }
    if (remove >= 0) {
      mRules.erase(mRules.begin() + remove);
    }
    if (ImGui::Button("Add rule")) {
      MaskRule rule;
      rule.layer = mMaskLayer;
      rule.useSlope = true;
      rule.minSlope = std::tan(30.0f * 0.0174532925f);
      rule.maxSlope = 1000.0f;
      mRules.push_back(rule);
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(mRules.empty());
    if (ImGui::Button("Apply rules to whole map")) {
      mRulesRequested = true;
    }
    ImGui::EndDisabled();
  }

  void EdTools::DrawWater()
  {
    // Each control edits the panel's copy; the app puts it on the map at once and records one undo step when the
    // drag (or the click) ends.
    bool active = false;
    const auto changed = [&](const bool edited) {
      active = active || ImGui::IsItemActive();
      if (edited) {
        mWaterChanged = true;
      }
      if (ImGui::IsItemDeactivatedAfterEdit()) {
        mWaterChanged = true;
        mWaterFinal = true;
      }
    };
    SectionHeader("SEA");
    if (ImGui::Checkbox("The map has a sea", &mWater.enabled)) {
      mWaterChanged = true;
      mWaterFinal = true;
    }
    ImGui::BeginDisabled(!mWater.enabled);
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##level", &mWater.elevation, 0.1f, 0.0f, 512.0f, "Level %.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##deep", &mWater.deep, 0.1f, 0.0f, 512.0f, "Deep %.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##abyss", &mWater.abyss, 0.1f, 0.0f, 512.0f, "Abyss %.2f"));
    if (mWater.enabled && (mWater.deep >= mWater.elevation || mWater.abyss >= mWater.deep)) {
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
      ImGui::TextWrapped("Deep should be below the level and abyss below deep: the water's colour runs from the level down to them.");
      ImGui::PopStyleColor();
    }
    Note("The level is where the sea's surface is; deep and abyss are the heights the water's colour darkens towards. "
         "Units, the shore and the minimap all follow the level.");

    SectionHeader("LOOK");
    moho::WaterShaderNumericState& s = mWater.shader;
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::ColorEdit3("##watercolor", s.mWaterColor, ImGuiColorEditFlags_Float));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat2("##waterlerp", s.mWaterLerp, 0.005f, 0.0f, 1.0f, "Lerp %.3f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##refraction", &s.mRefractionScale, 0.005f, 0.0f, 2.0f, "Refraction %.3f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##fresnelbias", &s.mFresnelBias, 0.005f, 0.0f, 1.0f, "Fresnel bias %.3f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##fresnelpower", &s.mFresnelPower, 0.01f, 0.0f, 10.0f, "Fresnel power %.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##unitreflection", &s.mUnitReflectionAmount, 0.005f, 0.0f, 1.0f, "Unit reflection %.3f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##skyreflection", &s.mSkyReflectionAmount, 0.005f, 0.0f, 3.0f, "Sky reflection %.3f"));

    SectionHeader("SUN ON THE WATER");
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::ColorEdit3("##suncolor", s.mSunColor, ImGuiColorEditFlags_Float));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat3("##sundirection", s.mSunDirection, 0.01f, -1.0f, 1.0f, "%.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##sunshininess", &s.mSunShininess, 0.5f, 0.0f, 500.0f, "Shininess %.1f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##sunreflection", &s.mSunReflectionAmount, 0.01f, 0.0f, 10.0f, "Reflection %.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat("##sunglow", &s.mSunGlow, 0.01f, 0.0f, 10.0f, "Glow %.2f"));

    SectionHeader("WAVES");
    ImGui::SetNextItemWidth(-1.0f);
    changed(ImGui::DragFloat4("##repeat", s.mNormalRepeatRate, 0.0005f, 0.0f, 1.0f, "%.4f"));
    float* const movements[4] = {s.mNormal1Movement, s.mNormal2Movement, s.mNormal3Movement, s.mNormal4Movement};
    for (int i = 0; i < 4; ++i) {
      ImGui::PushID(i);
      ImGui::SetNextItemWidth(-1.0f);
      changed(ImGui::DragFloat2("##movement", movements[i], 0.0005f, -1.0f, 1.0f, "%.4f"));
      ImGui::PopID();
    }
    Note("The four normal maps' repeat, then each one's movement (x, z per second).");
    ImGui::EndDisabled();

    SectionHeader("TEXTURES");
    static const char* const kTextureNames[6] = {"Cubemap", "Ramp", "Normals 1", "Normals 2", "Normals 3", "Normals 4"};
    for (int i = 0; i < 6; ++i) {
      ImGui::TextDisabled("%s", kTextureNames[i]);
      ImGui::SameLine(90.0f);
      ImGui::TextUnformatted(mWater.textures[i].empty() ? "(none)" : mWater.textures[i].c_str());
    }
    mWaterEditing = active;
    Note("Water bodies at their own levels come with the water-levels work (docs/WATER_BODIES.md on feat/water-levels).");
  }

  void EdTools::DrawProps()
  {
    SectionHeader("PROP");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##propfilter", "search", mPropFilter, sizeof(mPropFilter));
    std::string filter = mPropFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (mPropBlueprints.empty()) {
      Note("The prop list comes once the game's rules are built after startup.");
    } else if (ImGui::BeginChild("##props", ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing() * 12.0f), ImGuiChildFlags_Borders)) {
      for (const std::string& blueprint : mPropBlueprints) {
        if (!filter.empty() && blueprint.find(filter) == std::string::npos) {
          continue;
        }
        // "/env/evergreen/props/trees/pine06_s1_prop.bp" shows as "trees/pine06_s1".
        std::string label = blueprint;
        if (const std::size_t props = label.find("/props/"); props != std::string::npos) {
          label = label.substr(props + 7);
        }
        if (label.size() > 8 && label.compare(label.size() - 8, 8, "_prop.bp") == 0) {
          label.resize(label.size() - 8);
        }
        if (ImGui::Selectable(label.c_str(), blueprint == mPropBlueprint)) {
          mPropBlueprint = blueprint;
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s", blueprint.c_str());
        }
      }
    }
    if (!mPropBlueprints.empty()) {
      ImGui::EndChild();
    }
    if (!mPropDetails.empty()) {
      Note(mPropDetails.c_str());
    }
    SectionHeader("PLACE");
    static const char* const kModes[] = {"Single", "Scatter", "Erase"};
    Segmented(kModes, 3, mPropMode);
    if (mPropMode == 1) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::SliderFloat("##density", &mPropDensity, 0.5f, 60.0f, "%.1f props a second");
    }
    ImGui::Checkbox("Random turn", &mPropRandomTurn);
    DrawBrush(false);
    DrawSymmetry(false);
    Note("Single shows the prop under the cursor and places it at a click, Scatter while the button is held, inside the brush; Erase removes those inside it. "
         "Shift+click erases in any mode. Symmetric copies are placed and removed with them.");
  }

  void EdTools::DrawDecals()
  {
    SectionHeader("MODE");
    static const char* const kModes[] = {"Place", "Select", "Path"};
    mDecalMode = std::clamp(mDecalMode, 0, 2);
    Segmented(kModes, 3, mDecalMode);
    if (mDecalMode == 2) {
      char text[96];
      (void)std::snprintf(text, sizeof(text), "%d points, %d decals", mDecalPathPoints, mDecalPathDecals);
      ImGui::TextUnformatted(text);
      ImGui::BeginDisabled(mDecalPathPoints < 2);
      if (ImGui::Button("Place")) {
        mDecalPathAction = DecalPathAction::Place;
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(mDecalPathPoints == 0);
      if (ImGui::Button("Last point")) {
        mDecalPathAction = DecalPathAction::RemoveLast;
      }
      ImGui::SameLine();
      if (ImGui::Button("Clear")) {
        mDecalPathAction = DecalPathAction::Clear;
      }
      ImGui::EndDisabled();
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::SliderFloat("##decaloverlap", &mDecalOverlap, 0.0f, 0.9f, "Overlap %.2f");
      Note("Click the ground to lay the curve's points; the decals follow it end to end, each its length along the curve "
           "and its width across, turned with it. Enter or Place lays them (one undo step), Backspace drops the last point, "
           "Escape clears. Symmetric copies follow.");
    }
    if (mDecalMode == 1) {
      char count[64];
      (void)std::snprintf(count, sizeof(count), "%d decal%s selected", mDecalSelectionCount, mDecalSelectionCount == 1 ? "" : "s");
      ImGui::TextUnformatted(count);
      Note("Click a decal to select it (Ctrl adds), drag to move, Shift+click or Delete removes. Each edit is one undo step.");
    }

    // The textures: each as itself on a checkerboard, filtered by name and type.
    SectionHeader("TEXTURE");
    if (!mDecalTexturesListed) {
      mDecalTexturesListed = true;
      mDecalTextures = ListDecalTextures();
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##decalfilter", "search", mDecalFilter, sizeof(mDecalFilter));
    static const char* const kTypes[] = {"All", "Albedo", "Normals", "Glow"};
    Segmented(kTypes, 4, mDecalTypeFilter);
    std::string filter = mDecalFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    mLibrary.Pump(4);
    const float cell = ImGui::GetFrameHeight() * 2.6f;
    if (ImGui::BeginChild("##decaltextures", ImVec2(0.0f, cell * 4.6f), ImGuiChildFlags_Borders)) {
      const int columns = std::max(1, static_cast<int>(ImGui::GetContentRegionAvail().x / (cell + 4.0f)));
      int column = 0;
      static constexpr int kTypeOf[] = {0, 1, 2, 6};
      for (const DecalTexture& texture : mDecalTextures) {
        if (mDecalTypeFilter != 0 && texture.type != kTypeOf[mDecalTypeFilter]) {
          continue;
        }
        std::string lowerPath = texture.path;
        for (char& c : lowerPath) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (!filter.empty() && lowerPath.find(filter) == std::string::npos) {
          continue;
        }
        if (column > 0) {
          ImGui::SameLine(0.0f, 4.0f);
        }
        column = (column + 1) % columns;
        ImGui::PushID(texture.path.c_str());
        const ImVec2 p = ImGui::GetCursorScreenPos();
        ImDrawList* const draw = ImGui::GetWindowDrawList();
        // A checkerboard under it, so transparent parts show as such.
        const float square = cell / 4.0f;
        for (int y = 0; y < 4; ++y) {
          for (int x = 0; x < 4; ++x) {
            draw->AddRectFilled(ImVec2(p.x + x * square, p.y + y * square), ImVec2(p.x + (x + 1) * square, p.y + (y + 1) * square),
                                (x + y) % 2 == 0 ? IM_COL32(70, 74, 80, 255) : IM_COL32(52, 55, 60, 255));
          }
        }
        if (ImGui::InvisibleButton("##decal", ImVec2(cell, cell))) {
          mDecalTexture = texture.path;
          mDecalMode = 0;
        }
        if (const std::uint64_t image = mLibrary.Thumbnail(texture.path, true); image != 0U) {
          draw->AddImage(static_cast<ImTextureID>(image), p, ImVec2(p.x + cell, p.y + cell));
        }
        if (texture.path == mDecalTexture) {
          draw->AddRect(p, ImVec2(p.x + cell, p.y + cell), kAccent, 3.0f, 0, 2.0f);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
          ImGui::SetTooltip("%s\n%s, placed as %s%s", texture.name.c_str(), texture.biome.c_str(), DecalTypeName(texture.type),
                            texture.pair.empty() ? "" : "\nwith a spec map");
        }
        ImGui::PopID();
      }
      if (mDecalTextures.empty()) {
        Note("No decal textures found under /env/*/decals/.");
      }
    }
    ImGui::EndChild();
    if (!mDecalTexture.empty()) {
      const std::size_t slash = mDecalTexture.find_last_of('/');
      ImGui::TextWrapped("%s (%s)", mDecalTexture.substr(slash + 1).c_str(), DecalTypeName(DecalTypeForTexture(mDecalTexture)));
      bool hasPair = false;
      for (const DecalTexture& texture : mDecalTextures) {
        hasPair = hasPair || (texture.path == mDecalTexture && !texture.pair.empty());
      }
      ImGui::BeginDisabled(!hasPair);
      ImGui::Checkbox("With its spec map", &mDecalWithPair);
      ImGui::EndDisabled();
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip(hasPair ? "The decal's second texture is its _spec map, as the game's maps keep albedo decals"
                                  : "Only an _albedo texture with a _spec next to it has one");
      }
    } else {
      Note("Pick a texture to place.");
    }

    SectionHeader("SIZE AND TURN");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::DragFloat2("##decalsize", mDecalSize, 0.25f, 0.5f, 1024.0f, "%.1f");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::SliderFloat("##decalturn", &mDecalTurn, -180.0f, 180.0f, "Turn %.0f deg");
    ImGui::Checkbox("Random turn", &mDecalRandomTurn);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::DragFloat("##decalcutoff", &mDecalCutoff, 5.0f, 0.0f, 5000.0f, mDecalCutoff <= 0.0f ? "Fade distance: from its size" : "Fade at %.0f");
    DrawSymmetry(false);
    Note("Place: a click puts the texture there, centred, with its symmetric copies (turned with the symmetry). "
         "Size is along and across its heading, in game units.");
  }

  void EdTools::DrawUnits()
  {
    SectionHeader("MODE");
    static const char* const kModes[] = {"Place", "Select"};
    mUnitMode = std::clamp(mUnitMode, 0, 1);
    Segmented(kModes, 2, mUnitMode);
    if (mUnitMode == 1) {
      char count[64];
      (void)std::snprintf(count, sizeof(count), "%d unit%s selected", mUnitSelectionCount, mUnitSelectionCount == 1 ? "" : "s");
      ImGui::TextUnformatted(count);
      Note("Click a unit to select it (Ctrl adds), drag it or its arrows to move, Shift+click or Delete removes. Each edit is one undo step.");
    }

    // The army new units join: the players' and the extra armies.
    SectionHeader("ARMY");
    std::vector<std::string> armies = mArmies;
    armies.insert(armies.end(), mExtraArmies.begin(), mExtraArmies.end());
    if (!armies.empty() && std::find(armies.begin(), armies.end(), mUnitArmy) == armies.end()) {
      mUnitArmy = armies.back();
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##unitarmy", mUnitArmy.empty() ? "(none)" : mUnitArmy.c_str())) {
      for (const std::string& army : armies) {
        if (ImGui::Selectable(army.c_str(), army == mUnitArmy)) {
          mUnitArmy = army;
        }
      }
      ImGui::EndCombo();
    }

    SectionHeader("UNIT");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##unitfilter", "search id or name", mUnitFilter, sizeof(mUnitFilter));
    std::string filter = mUnitFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (mUnitTypes.empty()) {
      Note("The unit list comes once the game's rules are built after startup.");
    } else if (ImGui::BeginChild("##unittypes", ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing() * 12.0f), ImGuiChildFlags_Borders)) {
      for (const auto& [id, name] : mUnitTypes) {
        std::string lower = id + " " + name;
        for (char& c : lower) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (!filter.empty() && lower.find(filter) == std::string::npos) {
          continue;
        }
        if (ImGui::Selectable(id.c_str(), id == mUnitType)) {
          mUnitType = id;
          mUnitMode = 0;
        }
        ImGui::SameLine(ImGui::GetFontSize() * 5.5f);
        ImGui::TextDisabled("%s", name.c_str());
      }
    }
    if (!mUnitTypes.empty()) {
      ImGui::EndChild();
    }
    ImGui::Checkbox("Random turn", &mUnitRandomTurn);
    DrawSymmetry(false);
    Note("Place: a click puts the unit there with its symmetric copies, in the army above, in its INITIAL group (the units the "
         "army starts with); names are UNIT_n, as the game's saves name them.");
  }

  void EdTools::DrawPlayableArea()
  {
    SectionHeader("PLAYABLE AREA");
    bool on = mArea.has_value();
    if (ImGui::Checkbox("The map has a playable area", &on)) {
      mAreaChanged = true;
      if (on) {
        // A border a tenth of the map in from each side, on the game's 4-unit grid.
        const int marginX = (mMapWidth / 10) / 4 * 4;
        const int marginZ = (mMapHeight / 10) / 4 * 4;
        mAreaChange = std::array<int, 4>{marginX, marginZ, (mMapWidth - marginX) / 4 * 4, (mMapHeight - marginZ) / 4 * 4};
      } else {
        mAreaChange.reset();
      }
    }
    if (mArea) {
      std::array<int, 4> area = *mArea;
      static const char* const kEdges[4] = {"##x0", "##z0", "##x1", "##z1"};
      static const char* const kFormats[4] = {"Left %d", "Top %d", "Right %d", "Bottom %d"};
      for (int i = 0; i < 4; ++i) {
        ImGui::SetNextItemWidth(-1.0f);
        const int limit = i % 2 == 0 ? mMapWidth : mMapHeight;
        if (ImGui::DragInt(kEdges[i], &area[static_cast<std::size_t>(i)], 1.0f, 0, limit, kFormats[i])) {
          area[static_cast<std::size_t>(i)] = std::clamp(area[static_cast<std::size_t>(i)] / 4 * 4, 0, limit);
          if (area[0] < area[2] && area[1] < area[3]) {
            mAreaChanged = true;
            mAreaChange = area;
          }
        }
      }
      char size[64];
      (void)std::snprintf(size, sizeof(size), "%d x %d of %d x %d", area[2] - area[0], area[3] - area[1], mMapWidth, mMapHeight);
      ImGui::TextDisabled("%s", size);
    }
    Note("The game rounds each edge down to a multiple of 4. The ground outside is darkened as in the game; with the Markers tool, "
         "drag the border's edges in the view. Saved as an area of _save.lua that _script.lua's OnPopulate makes the playable area.");
  }

  void EdTools::DrawMarkers()
  {
    SectionHeader("PLACE");
    const std::vector<MarkerType>& types = MarkerTypes();
    mMarkerType = std::clamp(mMarkerType, 0, static_cast<int>(types.size()) - 1);
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::BeginCombo("##markertype", types[static_cast<std::size_t>(mMarkerType)].type)) {
      std::string group;
      for (std::size_t i = 0; i < types.size(); ++i) {
        if (group != types[i].group) {
          group = types[i].group;
          ImGui::SeparatorText(group.c_str());
        }
        if (ImGui::Selectable(types[i].type, static_cast<int>(i) == mMarkerType)) {
          mMarkerType = static_cast<int>(i);
        }
      }
      ImGui::EndCombo();
    }
    Note("Click the ground to place one (with its symmetric copies), click a marker to select it (Ctrl adds), drag to move, "
         "Shift+click or Delete removes. Start positions are named ARMY_1, ARMY_2... (the scenario's army list is edited with the armies).");
    ImGui::Checkbox("Connect path nodes", &mConnectNodes);
    Note("Clicking a path node links it to the selected nodes of its graph, or unlinks them; Ctrl+Shift+click does the same "
         "without the mode. Placing a path node links it to the selected one, so clicks lay a path. Symmetric copies follow.");
    DrawSymmetry(false);

    SectionHeader("SELECTED");
    if (mMarkerSelection.empty()) {
      Note("No marker selected.");
    } else if (mMarkerSelection.size() > 1) {
      char count[48];
      (void)std::snprintf(count, sizeof(count), "%zu markers selected", mMarkerSelection.size());
      ImGui::TextUnformatted(count);
    } else {
      const SaveEntry& marker = mMarkerSelection.front();
      // The name, then each property's value as the save writes it; Enter applies a change.
      const auto field = [&](const std::string& key, const std::string& value) {
        ImGui::PushID(key.c_str());
        ImGui::TextDisabled("%s", key.c_str());
        ImGui::SameLine(90.0f);
        const std::string id = marker.name + "/" + key;
        if (mMarkerEditing != id) {
          (void)std::snprintf(mMarkerEditBuffer, sizeof(mMarkerEditBuffer), "%s", value.c_str());
        }
        ImGui::SetNextItemWidth(-1.0f);
        char buffer[256];
        (void)std::snprintf(buffer, sizeof(buffer), "%s", mMarkerEditing == id ? mMarkerEditBuffer : value.c_str());
        if (ImGui::InputText("##value", buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
          mMarkerEditName = marker.name;
          mMarkerEditKey = key;
          mMarkerEditValue = buffer;
          mMarkerEditing.clear();
        } else if (ImGui::IsItemActive()) {
          mMarkerEditing = id;
          (void)std::snprintf(mMarkerEditBuffer, sizeof(mMarkerEditBuffer), "%s", buffer);
        } else if (mMarkerEditing == id) {
          mMarkerEditing.clear();
        }
        ImGui::PopID();
      };
      field("name", marker.name);
      for (const auto& [key, value] : marker.properties) {
        field(key, value);
      }
    }

    SectionHeader("ARMIES");
    {
      // The game reads the first team, which must be named FFA (SinglePlayerLaunch.lua, VerifyScenarioConfiguration);
      // its order is the lobby's slot order. Teams themselves are set in the lobby.
      const bool oneFfa = mTeams.size() == 1 && mTeams.front().name == "FFA";
      if (!oneFfa && !mTeams.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
        ImGui::TextWrapped("The scenario has %zu team%s%s. The game needs one team named FFA with every player army: the lobby "
                           "takes its slots from the first team only.",
                           mTeams.size(), mTeams.size() == 1 ? "" : "s", mTeams.front().name == "FFA" ? "" : ", the first not named FFA");
        ImGui::PopStyleColor();
        if (ImGui::Button("Make one FFA team")) {
          ScenarioTeam all{"FFA", {}};
          for (const ScenarioTeam& team : mTeams) {
            all.armies.insert(all.armies.end(), team.armies.begin(), team.armies.end());
          }
          mTeamsChange = {all};
          mTeamsChanged = true;
        }
      }
      if (!mTeams.empty()) {
        const std::vector<std::string>& slots = mTeams.front().armies;
        ImGui::TextDisabled("Lobby slots, in order (%zu)", slots.size());
        for (std::size_t i = 0; i < slots.size(); ++i) {
          ImGui::PushID(static_cast<int>(i));
          ImGui::Text("%zu", i + 1);
          ImGui::SameLine(28.0f);
          ImGui::TextUnformatted(slots[i].c_str());
          const float buttons = ImGui::GetFrameHeight() * 2.0f + ImGui::GetStyle().ItemSpacing.x;
          ImGui::SameLine(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - buttons);
          ImGui::BeginDisabled(i == 0);
          if (ImGui::ArrowButton("##up", ImGuiDir_Up)) {
            mTeamsChange = mTeams;
            std::swap(mTeamsChange.front().armies[i], mTeamsChange.front().armies[i - 1]);
            mTeamsChanged = true;
          }
          ImGui::EndDisabled();
          ImGui::SameLine();
          ImGui::BeginDisabled(i + 1 == slots.size());
          if (ImGui::ArrowButton("##down", ImGuiDir_Down)) {
            mTeamsChange = mTeams;
            std::swap(mTeamsChange.front().armies[i], mTeamsChange.front().armies[i + 1]);
            mTeamsChanged = true;
          }
          ImGui::EndDisabled();
          ImGui::PopID();
        }
      }
      if (!mExtraEditing) {
        std::string extra;
        for (const std::string& army : mExtraArmies) {
          extra += (extra.empty() ? "" : " ") + army;
        }
        (void)std::snprintf(mExtraBuffer, sizeof(mExtraBuffer), "%s", extra.c_str());
      }
      ImGui::TextDisabled("Extra armies");
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::InputText("##extra", mExtraBuffer, sizeof(mExtraBuffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
        mExtraChanged = true;
        mExtraEditing = false;
      } else {
        mExtraEditing = ImGui::IsItemActive();
      }
      Note("Placing a start position adds its army (ARMY_n) to the scenario's team list and to _save.lua's armies; deleting or "
           "renaming it follows. The order is the lobby's slot order; teams are chosen in the lobby. Extra armies (ARMY_17, "
           "NEUTRAL_CIVILIAN...) hold the map's neutral and civilian units.");
    }
    DrawPlayableArea();
  }
} // namespace faf::editor

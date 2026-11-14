#include "editor/EdTools.h"
#include "editor/doc/EdLighting.h"
#include "editor/doc/EdWaterPreset.h"
#include "moho/misc/StartupHelpers.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdFonts.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/tools/EdShaderSlots.h"
#include "editor/ui/EdHelp.h"
#include "gpg/core/utils/Logging.h"

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

    struct ToolInfo
    {
      const char* name;
    };
    constexpr ToolInfo kTools[] = {
      {"Select"},
      {"Terrain"},
      {"Texture"},
      {"Water"},
      {"Props"},
      {"Decals"},
      {"Markers"},
      {"Units"},
    };

    struct SymmetryMode
    {
      const char* name;
      int copies;
      bool square;
    };
    constexpr SymmetryMode kSymmetry[] = {
      {"None", 1, false},
      {"Left-right", 2, false},
      {"Top-bottom", 2, false},
      {"Diagonal \\", 2, true},
      {"Diagonal /", 2, true},
      {"Half turn", 2, false},
      {"Both axes", 4, false},
      {"Both diagonals", 4, true},
      {"Quarter turns", 4, true},
      {"N-way turn", 0, true},
    };

    /** The symmetry mode's copies of the point (u, v) in [0, 1]; `n` for the N-way turn. */
    int SymmetryCopies(
      const int mode,
      const float u,
      const float v,
      const int n,
      ImVec2* const out
    )
    {
      const ImVec2 id(u, v), mx(1.0f - u, v), mz(u, 1.0f - v), d1(v, u), d2(1.0f - v, 1.0f - u), pt(1.0f - u, 1.0f - v);
      switch (mode) {
      case 0:
        out[0] = id;
        return 1;
      case 1:
        out[0] = id;
        out[1] = mx;
        return 2;
      case 2:
        out[0] = id;
        out[1] = mz;
        return 2;
      case 3:
        out[0] = id;
        out[1] = d1;
        return 2;
      case 4:
        out[0] = id;
        out[1] = d2;
        return 2;
      case 5:
        out[0] = id;
        out[1] = pt;
        return 2;
      case 6:
        out[0] = id;
        out[1] = mx;
        out[2] = mz;
        out[3] = pt;
        return 4;
      case 7:
        out[0] = id;
        out[1] = d1;
        out[2] = d2;
        out[3] = pt;
        return 4;
      case 8:
        out[0] = id;
        out[1] = ImVec2(1.0f - v, u);
        out[2] = pt;
        out[3] = ImVec2(v, 1.0f - u);
        return 4;
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
    void DrawSymmetryIcon(
      ImDrawList* const draw,
      const int mode,
      const int n,
      const ImVec2 p,
      const float s
    )
    {
      const float pad = s * 0.08f;
      const ImVec2 a(p.x + pad, p.y + pad);
      const float w = s - 2.0f * pad;
      const auto at = [&](const float u, const float v) {
        return ImVec2(a.x + u * w, a.y + v * w);
      };
      draw->AddRectFilled(a, ImVec2(a.x + w, a.y + w), SurfaceU32(), 2.0f);
      draw->AddRect(a, ImVec2(a.x + w, a.y + w), LineU32(), 2.0f);
      const auto line = [&](const ImVec2 from, const ImVec2 to) {
        // dashed
        for (int i = 0; i < 8; i += 2) {
          const float t0 = static_cast<float>(i) / 8.0f;
          const float t1 = static_cast<float>(i + 1) / 8.0f;
          draw->AddLine(
            ImVec2(from.x + (to.x - from.x) * t0, from.y + (to.y - from.y) * t0),
            ImVec2(from.x + (to.x - from.x) * t1, from.y + (to.y - from.y) * t1),
            AccentU32(),
            1.2f
          );
        }
      };
      if (mode == 1 || mode == 6)
        line(at(0.5f, 0.0f), at(0.5f, 1.0f));
      if (mode == 2 || mode == 6)
        line(at(0.0f, 0.5f), at(1.0f, 0.5f));
      if (mode == 3 || mode == 7)
        line(at(0.0f, 0.0f), at(1.0f, 1.0f));
      if (mode == 4 || mode == 7)
        line(at(1.0f, 0.0f), at(0.0f, 1.0f));
      if (mode == 5 || mode == 8 || mode == 9)
        draw->AddCircleFilled(at(0.5f, 0.5f), s * 0.05f, AccentU32());
      ImVec2 copies[kMaxSymmetryCopies];
      const int count = SymmetryCopies(mode, 0.27f, 0.22f, std::clamp(n, 2, kMaxSymmetryCopies), copies);
      for (int i = 0; i < count; ++i) {
        draw->AddCircleFilled(at(copies[i].x, copies[i].y), s * 0.075f, i == 0 ? InkU32() : AccentU32());
      }
    }

    /** The panel's help: one line with the rest on hover (ui/EdHelp.cpp). */
    void Note(
      const char* const text
    )
    {
      HelpNote(text);
    }

    /** A title inside a section (the folding ones are Section, ui/EdControls): small dimmed capitals. */
    void SectionHeader(
      const char* const text
    )
    {
      ImGui::Spacing();
      std::string caps = text;
      for (char& ch : caps) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
      }
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::PushFont(nullptr, std::round(ImGui::GetFontSize() * 0.85f));
      ImGui::TextUnformatted(caps.c_str());
      ImGui::PopFont();
      ImGui::PopStyleColor();
    }

    /** A row of buttons, the chosen one marked, like the mockup's segmented buttons. */
    void Segmented(
      const char* const* labels,
      const int count,
      int& chosen
    )
    {
      // The mockup's segmented control: a bordered track, the buttons flat on it, the chosen one filled with the
      // accent.
      const float inset = 2.0f;
      const ImVec2 start = ImGui::GetCursorScreenPos();
      const float total = ImGui::GetContentRegionAvail().x;
      const float height = ImGui::GetFrameHeight() + inset * 2.0f;
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      const float rounding = ImGui::GetStyle().FrameRounding + 1.0f;
      draw->AddRectFilled(
        start, ImVec2(start.x + total, start.y + height), ImGui::GetColorU32(ImGuiCol_FrameBg), rounding
      );
      draw->AddRect(start, ImVec2(start.x + total, start.y + height), ImGui::GetColorU32(ImGuiCol_Border), rounding);
      const float gap = 2.0f;
      const float width = (total - inset * 2.0f - gap * static_cast<float>(count - 1)) / static_cast<float>(count);
      ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
      ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(gap, 0.0f));
      ImGui::SetCursorScreenPos(ImVec2(start.x + inset, start.y + inset));
      for (int i = 0; i < count; ++i) {
        if (i > 0) {
          ImGui::SameLine();
        }
        const bool on = i == chosen;
        ImGui::PushStyleColor(ImGuiCol_Button, on ? AccentColor(1.0f) : ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
        ImGui::PushStyleColor(
          ImGuiCol_ButtonHovered, on ? AccentColor(0.9f) : ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered)
        );
        ImGui::PushStyleColor(ImGuiCol_Text, on ? AccentText() : ImGui::GetStyleColorVec4(ImGuiCol_Text));
        if (ImGui::Button(labels[i], ImVec2(width, 0.0f))) {
          chosen = i;
        }
        ImGui::PopStyleColor(3);
      }
      ImGui::PopStyleVar(2);
      ImGui::SetCursorScreenPos(ImVec2(start.x, start.y + height + ImGui::GetStyle().ItemSpacing.y));
      ImGui::Dummy(ImVec2(0.0f, 0.0f));
    }
  } // namespace

  void EdTools::Draw()
  {
    // The tool strip is the shell's, at the window's left edge (EdShell::DrawToolStrip); the panel is the tool's
    // settings, its tab named after the tool.
    // The scrollbar always has its room: the symmetry tiles take their height from the width, so a scrollbar that
    // came and went with the content's height flipped every frame (narrower, shorter, no scrollbar; wider, taller,
    // a scrollbar again; user report).
    if (
      ImGui::BeginChild(
        "##toolsettings", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar
      )
    ) {
      switch (mTool) {
      case 0:
        DrawSelect();
        break;
      case 1:
        DrawTerrain();
        break;
      case 2:
        DrawTexture();
        break;
      case 3:
        DrawWater();
        break;
      case 4:
        DrawProps();
        break;
      case 5:
        DrawDecals();
        break;
      case 6:
        DrawMarkers();
        break;
      default:
        DrawUnits();
        break;
      }
    }
    ImGui::EndChild();
  }

  int EdTools::ToolCount() noexcept
  {
    return static_cast<int>(IM_ARRAYSIZE(kTools));
  }

  const char* EdTools::ToolName(
    const int tool
  ) noexcept
  {
    return tool >= 0 && tool < ToolCount() ? kTools[tool].name : "";
  }

  const char* EdTools::ToolIcon(
    const int tool
  ) noexcept
  {
    // The mockup's tool icons (data_shell.ts TOOLS).
    static constexpr const char* kIcons[] = {
      ICON_SELECT,
      ICON_RAISE,
      ICON_BRUSH,
      ICON_WATER,
      ICON_TREE,
      ICON_DECAL,
      ICON_MARKER,
      ICON_UNIT,
    };
    static_assert(std::size(kIcons) == std::size(kTools));
    return tool >= 0 && tool < ToolCount() ? kIcons[tool] : ICON_DOTS;
  }

  bool EdTools::DrawStrip(
    const float width
  )
  {
    // The mockup's tool strip: square buttons down the window's edge, the chosen one filled with the accent, each
    // with its key in the corner, rules between the families (select | terrain, texture, water | objects).
    const float cell = std::round(Em(28.0f));
    const float x = std::round(ImGui::GetCursorScreenPos().x + (width - cell) * 0.5f);
    const float iconSize = std::round(ImGui::GetFontSize() * 1.2f);
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    ImFont* const font = ImGui::GetFont();
    const auto rule = [&] {
      const float y = std::round(ImGui::GetCursorScreenPos().y + Em(4.0f));
      draw->AddLine(
        ImVec2(x + Em(3.0f), y + 0.5f), ImVec2(x + cell - Em(3.0f), y + 0.5f), ImGui::GetColorU32(ImGuiCol_Border)
      );
      ImGui::Dummy(ImVec2(cell, Em(8.0f)));
    };
    // One square: its icon, the key in the corner; the fill says chosen (accent), on (the accent's soft fill), hovered.
    const auto square = [&](
                          const char* const id,
                          const char* const icon,
                          const char* const key,
                          const bool chosen,
                          const bool on,
                          const bool enabled
                        ) {
      ImGui::SetCursorScreenPos(ImVec2(x, ImGui::GetCursorScreenPos().y));
      const ImVec2 p = ImGui::GetCursorScreenPos();
      const bool clicked = ImGui::InvisibleButton(id, ImVec2(cell, cell)) && enabled;
      const bool hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled);
      const ImVec2 q(p.x + cell, p.y + cell);
      if (chosen) {
        draw->AddRectFilled(p, q, AccentU32(), Em(5.0f));
      } else if (on) {
        draw->AddRectFilled(p, q, AccentU32(0.16f), Em(5.0f));
      } else if (hovered && enabled) {
        draw->AddRectFilled(p, q, ImGui::GetColorU32(ImGuiCol_Button), Em(5.0f));
      }
      ImU32 ink = chosen ? ImGui::GetColorU32(AccentText())
        : on             ? AccentU32()
        : hovered        ? ImGui::GetColorU32(ImGuiCol_Text)
                         : ImGui::GetColorU32(ImGuiCol_TextDisabled);
      if (!enabled) {
        ink = (ink & ~IM_COL32_A_MASK) | (static_cast<ImU32>(255 * 0.35f) << IM_COL32_A_SHIFT);
      }
      const ImVec2 size = font->CalcTextSizeA(iconSize, FLT_MAX, 0.0f, icon);
      draw->AddText(font, iconSize, ImVec2(p.x + (cell - size.x) * 0.5f, p.y + (cell - size.y) * 0.5f), ink, icon);
      if (key != nullptr && key[0] != 0) {
        const float keySize = std::round(ImGui::GetFontSize() * 0.6f);
        const ImVec2 keyText = font->CalcTextSizeA(keySize, FLT_MAX, 0.0f, key);
        const ImU32 keyInk = (ink & ~IM_COL32_A_MASK) |
          (static_cast<ImU32>(((ink >> IM_COL32_A_SHIFT) & 0xFF) * 0.7f) << IM_COL32_A_SHIFT);
        draw->AddText(font, keySize, ImVec2(q.x - keyText.x - Em(2.0f), q.y - keyText.y + Em(1.0f)), keyInk, key);
      }
      return std::pair<bool, bool>(clicked, hovered);
    };

    bool picked = false;
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, Em(2.0f)));
    for (int i = 0; i < static_cast<int>(IM_ARRAYSIZE(kTools)); ++i) {
      if (i == 1 || i == 4) {
        rule();
      }
      ImGui::PushID(i);
      // Its key from the command registry (tool.N, Settings > Keys): the first, or none.
      std::string key = static_cast<std::size_t>(i) < mToolKeys.size() ? mToolKeys[static_cast<std::size_t>(i)] : "";
      if (const std::size_t comma = key.find(','); comma != std::string::npos) {
        key.resize(comma);
      }
      const bool enabled = !mReadOnly || i == 0;
      const auto [clicked, hovered] =
        square("##tool", ToolIcon(i), key.size() == 1 ? key.c_str() : nullptr, i == mTool, false, enabled);
      if (clicked) {
        mTool = i;
        picked = true;
      }
      if (hovered && !enabled) {
        EdSetTooltip("%s: not in Review, which only looks (Alt+1 to edit)", kTools[i].name);
      } else if (hovered) {
        if (key.empty()) {
          EdSetTooltip("%s", kTools[i].name);
        } else {
          EdSetTooltip("%s (%s)", kTools[i].name, key.c_str());
        }
      }
      ImGui::PopID();
    }
    // Measuring: the kilometre lines on or off; Alt+drag measures with any tool.
    rule();
    {
      const auto [clicked, hovered] = square("##measure", ICON_RULER, nullptr, false, mShowKmGrid, true);
      if (clicked) {
        mShowKmGrid = !mShowKmGrid;
      }
      if (hovered) {
        EdSetTooltip(
          "Measure: lines every kilometre (51.2 units, the game's scale) and the map's centre lines %s. Alt+drag in "
          "the view measures a distance.",
          mShowKmGrid ? "shown" : "hidden"
        );
      }
    }
    ImGui::PopStyleVar();
    return picked;
  }

  void EdTools::DrawSymmetryPicture(
    ImDrawList* const draw,
    const int mode,
    const ImVec2 p,
    const float s
  ) const
  {
    DrawSymmetryIcon(draw, mode, mNWay, p, s);
  }

  void EdTools::DrawSymmetryTooltip(
    const int mode,
    const bool fromToolbar
  ) const
  {
    if (mode < 0 || mode >= static_cast<int>(IM_ARRAYSIZE(kSymmetry))) {
      return;
    }
    const int turns = std::clamp(mNWay, 2, kMaxSymmetryCopies);
    char nway[160];
    std::snprintf(
      nway,
      sizeof(nway),
      "Turned round the middle %d times (set in the Terrain tool): %d copies, each turned 1/%d further.",
      turns,
      turns,
      turns
    );
    static constexpr const char* kAbout[] = {
      "Each edit stays where you make it; nothing is copied.",
      "Mirrored across the vertical middle line: the right half copies the left, facing the other way.",
      "Mirrored across the horizontal middle line: the bottom half copies the top, facing the other way.",
      "Mirrored across the diagonal from the top-left corner to the bottom-right.",
      "Mirrored across the diagonal from the top-right corner to the bottom-left.",
      "Turned half way round the middle: the copy sits opposite and faces the other way, as on most 1v1 maps.",
      "Mirrored across both middle lines: four copies, one in each quarter.",
      "Mirrored across both diagonals: four copies.",
      "Turned a quarter at a time round the middle: four copies, each facing a quarter turn on.",
      nullptr,
    };
    if (gBoldFont != nullptr) {
      ImGui::PushFont(gBoldFont, 0.0f);
    }
    ImGui::Text("Symmetry: %s", kSymmetry[mode].name);
    if (gBoldFont != nullptr) {
      ImGui::PopFont();
    }
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + Em(250.0f));
    ImGui::TextDisabled(
      "%s%s", kAbout[mode] != nullptr ? kAbout[mode] : nway, kSymmetry[mode].square ? " Square maps only." : ""
    );
    ImGui::PopTextWrapPos();

    // The map in motion.
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const float side = Em(150.0f);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(side, side));
    const ImVec2 q(p.x + side, p.y + side);
    draw->AddRectFilledMultiColor(
      p,
      q,
      IM_COL32(0x3C, 0x55, 0x38, 0xFF),
      IM_COL32(0x4A, 0x5E, 0x3A, 0xFF),
      IM_COL32(0x2E, 0x4E, 0x5E, 0xFF),
      IM_COL32(0x38, 0x4C, 0x40, 0xFF)
    );
    for (int k = 1; k < 4; ++k) {
      const float f = side * static_cast<float>(k) / 4.0f;
      draw->AddLine(ImVec2(p.x + f, p.y), ImVec2(p.x + f, q.y), IM_COL32(0xFF, 0xFF, 0xFF, 0x14));
      draw->AddLine(ImVec2(p.x, p.y + f), ImVec2(q.x, p.y + f), IM_COL32(0xFF, 0xFF, 0xFF, 0x14));
    }
    draw->AddRect(p, q, LineU32());
    const auto at = [&](const float u, const float v) {
      return ImVec2(p.x + u * side, p.y + v * side);
    };
    // The mirror lines, or the turn centre.
    const ImU32 axis = AccentU32();
    if (mode == 1 || mode == 6)
      draw->AddLine(at(0.5f, 0.0f), at(0.5f, 1.0f), axis, 1.6f);
    if (mode == 2 || mode == 6)
      draw->AddLine(at(0.0f, 0.5f), at(1.0f, 0.5f), axis, 1.6f);
    if (mode == 3 || mode == 7)
      draw->AddLine(at(0.0f, 0.0f), at(1.0f, 1.0f), axis, 1.6f);
    if (mode == 4 || mode == 7)
      draw->AddLine(at(1.0f, 0.0f), at(0.0f, 1.0f), axis, 1.6f);
    if (mode == 9) {
      for (int k = 0; k < turns; ++k) {
        const float a = 6.2831853f * static_cast<float>(k) / static_cast<float>(turns) - 1.5707963f;
        draw->AddLine(at(0.5f, 0.5f), at(0.5f + 0.7f * std::cos(a), 0.5f + 0.7f * std::sin(a)), AccentU32(0.35f), 1.0f);
      }
    }
    if (mode == 5 || mode == 8 || mode == 9) {
      draw->AddCircleFilled(at(0.5f, 0.5f), Em(3.0f), axis);
    }
    draw->PushClipRect(p, q, true);
    // A dab painting a loop in the first sector; the stroke it leaves fades behind it, at every copy.
    const float time = static_cast<float>(ImGui::GetTime());
    const auto path = [](const float t, float& u, float& v) {
      u = 0.30f + 0.11f * std::cos(t * 1.6f);
      v = 0.22f + 0.08f * std::sin(t * 3.2f);
    };
    ImVec2 copies[kMaxSymmetryCopies];
    constexpr int kTrail = 22;
    for (int k = kTrail; k >= 1; --k) {
      float u = 0.0f;
      float v = 0.0f;
      path(time - static_cast<float>(k) * 0.05f, u, v);
      const int count = SymmetryCopies(mode, u, v, turns, copies);
      const float fade = 1.0f - static_cast<float>(k) / static_cast<float>(kTrail + 1);
      for (int c = 0; c < count; ++c) {
        draw->AddCircleFilled(
          at(copies[c].x, copies[c].y),
          side * 0.028f,
          c == 0 ? IM_COL32(0xFF, 0xFF, 0xFF, static_cast<int>(110.0f * fade))
                 : (AccentU32() & 0x00FFFFFFu) | (static_cast<ImU32>(130.0f * fade) << 24)
        );
      }
    }
    float u = 0.0f;
    float v = 0.0f;
    float u2 = 0.0f;
    float v2 = 0.0f;
    path(time, u, v);
    path(time + 0.12f, u2, v2);
    ImVec2 ahead[kMaxSymmetryCopies];
    const int count = SymmetryCopies(mode, u, v, turns, copies);
    (void)SymmetryCopies(mode, u2, v2, turns, ahead);
    for (int c = 0; c < count; ++c) {
      const ImU32 colour = c == 0 ? IM_COL32(0xFF, 0xFF, 0xFF, 0xFF) : AccentU32();
      const ImVec2 centre = at(copies[c].x, copies[c].y);
      const ImVec2 next = at(ahead[c].x, ahead[c].y);
      const float r = side * 0.06f;
      draw->AddCircle(centre, r, colour, 0, 1.6f);
      // Its heading: a mirror turns the copies' way round, a turn keeps it.
      const float dx = next.x - centre.x;
      const float dy = next.y - centre.y;
      const float length = std::max(0.001f, std::hypot(dx, dy));
      draw->AddLine(centre, ImVec2(centre.x + dx / length * r * 1.5f, centre.y + dy / length * r * 1.5f), colour, 2.0f);
    }
    draw->PopClipRect();
    ImGui::TextDisabled("White: where you edit. Blue: its copies.");
    if (fromToolbar) {
      ImGui::TextDisabled("All ten modes: the arrow beside these pictures.");
    }
  }

  const char* EdTools::HudMode() const noexcept
  {
    if (!mHudOverride.empty()) {
      return mHudOverride.c_str();
    }
    // By HeightBrushMode, as the panel's tiles name them.
    static constexpr const char* kModes[] = {
      "Raise",
      "Lower",
      "Smooth",
      "Flatten",
      "Noise",
      "Set height",
      "Terrace",
      "Plane",
      "Stamp",
      "Erode",
      "Water erode",
      "Rain",
      "Deposit",
      "Plateau",
      "Sharpen",
      "Ramp",
      "Path",
    };
    if (mTool != 1 || mBrushMode < 0 || mBrushMode >= static_cast<int>(std::size(kModes))) {
      return nullptr;
    }
    return kModes[mBrushMode];
  }

  int EdTools::HudCopies() const noexcept
  {
    // The brushes mirror (terrain heights, texture paint).
    if (mTool != 1 && mTool != 2) {
      return 1;
    }
    if (mSymmetry < 0 || mSymmetry >= static_cast<int>(IM_ARRAYSIZE(kSymmetry))) {
      return 1;
    }
    return kSymmetry[mSymmetry].copies > 0 ? kSymmetry[mSymmetry].copies : mNWay;
  }

  const char* EdTools::SymmetryName(
    const int mode
  ) noexcept
  {
    return mode >= 0 && mode < static_cast<int>(IM_ARRAYSIZE(kSymmetry)) ? kSymmetry[mode].name : "";
  }

  void EdTools::SetBrushFolder(
    std::filesystem::path folder
  )
  {
    mBrushFolder = std::move(folder);
    RescanBrushes();
  }

  void EdTools::RescanBrushes()
  {
    mBrushImages = ListBrushImages(mBrushFolder);
  }

  bool EdTools::ChooseStampSource(
    const int index
  )
  {
    if (index >= 1 && index < kBrushShapeCount) {
      const auto shape = static_cast<BrushShape>(index);
      SetStamp(StampFromGrid(RasterizeShape(shape)), BrushShapeName(shape));
      return true;
    }
    const int image = index - kBrushShapeCount;
    if (image < 0 || image >= static_cast<int>(mBrushImages.size())) {
      return false;
    }
    ShapeGrid grid;
    std::string error;
    if (!LoadBrushImage(mBrushImages[static_cast<std::size_t>(image)].path, kShapeGridSize, grid, error)) {
      gpg::Warnf(
        "editor: brush image %s: %s", mBrushImages[static_cast<std::size_t>(image)].name.c_str(), error.c_str()
      );
      return false;
    }
    SetStamp(StampFromGrid(grid), mBrushImages[static_cast<std::size_t>(image)].name);
    return true;
  }

  bool EdTools::ChooseShapeImage(
    const int index
  )
  {
    if (index < 0 || index >= static_cast<int>(mBrushImages.size())) {
      return false;
    }
    auto grid = std::make_shared<ShapeGrid>();
    std::string error;
    if (!LoadBrushImage(mBrushImages[static_cast<std::size_t>(index)].path, kShapeGridSize, *grid, error)) {
      gpg::Warnf(
        "editor: brush image %s: %s", mBrushImages[static_cast<std::size_t>(index)].name.c_str(), error.c_str()
      );
      return false;
    }
    mShapeImage = std::move(grid);
    mShapeImageName = mBrushImages[static_cast<std::size_t>(index)].name;
    mBrushShape = static_cast<int>(BrushShape::Image);
    return true;
  }

  void EdTools::DrawShaderBrowser()
  {
    if (!mShaderBrowserOpen) {
      return;
    }
    ImGui::SetNextWindowSize(ImVec2(Em(980.0f), Em(640.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Terrain shaders###ShaderBrowser", &mShaderBrowserOpen)) {
      ImGui::End();
      return;
    }
    if (mBrowsedShader.empty()) {
      mBrowsedShader = mShader;
    }
    // The shaders the game data has, by family.
    ImGui::BeginChild("##families", ImVec2(Em(260.0f), 0.0f), ImGuiChildFlags_Borders);
    for (const ShaderFamily family : {
           ShaderFamily::Original, ShaderFamily::Extended, ShaderFamily::Pbr, ShaderFamily::Splat, ShaderFamily::Older
         }) {
      bool header = false;
      for (const std::string& shader : mShaders) {
        if (ShaderProfileOf(shader).family != family) {
          continue;
        }
        if (!header) {
          SectionHeader(ShaderFamilyName(family));
          header = true;
        }
        const std::string label = shader + (shader == mShader ? "  (the map's)" : "");
        if (ImGui::Selectable(label.c_str(), shader == mBrowsedShader)) {
          mBrowsedShader = shader;
        }
      }
    }
    ImGui::EndChild();
    ImGui::SameLine();

    // The chosen shader's profile.
    const ShaderProfile profile = ShaderProfileOf(mBrowsedShader);
    ImGui::BeginChild("##profile", ImVec2(0.0f, 0.0f));
    ImGui::TextUnformatted(profile.name.c_str());
    ImGui::TextWrapped("%s", profile.summary.c_str());
    ImGui::TextDisabled(
      "%s. Masks: %s. Paints %d layers.",
      ShaderFamilyName(profile.family),
      MaskRangeText(profile.remapped).c_str(),
      profile.painted
    );
    if (profile.remapped != RemappedStrata(mShader) && profile.name != mShader) {
      ImGui::TextColored(
        ImVec4(0.95f, 0.75f, 0.35f, 1.0f),
        "It reads the masks differently from %s: the paint so far would look different until the layers are converted.",
        mShader.c_str()
      );
    }
    ImGui::Separator();
    ImGui::TextWrapped("%s", profile.instructions.c_str());
    if (!profile.layout.empty()) {
      ImGui::Spacing();
      ImGui::TextWrapped("%s", profile.layout.c_str());
    }
    if (
      !profile.rows.empty() &&
      ImGui::BeginTable(
        "##layers", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp
      )
    ) {
      ImGui::TableSetupColumn("Layer", ImGuiTableColumnFlags_WidthFixed, Em(90.0f));
      ImGui::TableSetupColumn("Albedo (colour)");
      ImGui::TableSetupColumn("Normal map");
      ImGui::TableHeadersRow();
      for (const ShaderLayerRow& row : profile.rows) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(row.layer.c_str());
        ImGui::TableNextColumn();
        ImGui::TextWrapped("%s", row.albedo.c_str());
        ImGui::TableNextColumn();
        ImGui::TextWrapped("%s", row.normal.c_str());
      }
      ImGui::EndTable();
    }
    for (const std::string& note : profile.notes) {
      ImGui::Bullet();
      ImGui::TextWrapped("%s", note.c_str());
    }
    ImGui::Spacing();
    ImGui::BeginDisabled(profile.name == mShader || profile.name.empty());
    if (PrimaryButton("Use this shader")) {
      mShaderChange = profile.name;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("One undo step. The paint keeps its bytes.");

    // Convert the paint to the chosen shader (FAF Studio's Convert layers, the masks part).
    if (profile.name != mShader && mConvertPlan.to == profile.name) {
      SectionHeader("CONVERT THE PAINT TO THIS SHADER");
      if (!mConvertPlan.refused.empty()) {
        ImGui::TextWrapped("%s", mConvertPlan.refused.c_str());
      } else {
        for (const std::string& line : mConvertPlan.lines) {
          ImGui::Bullet();
          ImGui::TextWrapped("%s", line.c_str());
        }
        for (const std::string& warning : mConvertPlan.warnings) {
          ImGui::Bullet();
          ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.35f, 1.0f), "%s", warning.c_str());
        }
        if (!mConvertPlan.lost.empty()) {
          static const char* const kLost[] = {"Move to a free layer", "Merge into a layer", "Drop"};
          int lost = static_cast<int>(mConvertOptions.lost);
          ImGui::SetNextItemWidth(Em(240.0f));
          if (EdCombo("Paint it can't draw", &lost, kLost, 3)) {
            mConvertOptions.lost = static_cast<LostLayers>(lost);
          }
          if (mConvertOptions.lost == LostLayers::Merge) {
            int into = mConvertOptions.mergeInto + 1;
            ImGui::SetNextItemWidth(Em(240.0f));
            if (FillSliderInt("Into layer", &into, 1, std::max(1, mConvertPlan.toPainted))) {
              mConvertOptions.mergeInto = into - 1;
            }
          }
        }
        if (mConvertPlan.toBiplanar) {
          ImGui::Checkbox("Move the cliff layers to layers 3 and 4", &mConvertOptions.arrange);
        }
        if (PrimaryButton("Convert and switch")) {
          mConvertRequested = true;
        }
        ImGui::SameLine();
        ImGui::TextDisabled("Masks and layers only; the textures stay. One undo step.");
      }
    }
    if (!mConvertReport.empty()) {
      SectionHeader("LAST CONVERSION");
      for (const std::string& line : mConvertReport) {
        ImGui::Bullet();
        ImGui::TextWrapped("%s", line.c_str());
      }
    }
    ImGui::EndChild();
    ImGui::End();
  }

  void EdTools::DrawShapePicker()
  {
    const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
    ImGui::SetNextItemWidth(half);
    const bool image = mBrushShape == static_cast<int>(BrushShape::Image);
    if (
      EdBeginCombo(
        "##brushshape", image ? mShapeImageName.c_str() : BrushShapeName(static_cast<BrushShape>(mBrushShape))
      )
    ) {
      for (int k = 0; k < kBrushShapeCount; ++k) {
        if (ImGui::Selectable(BrushShapeName(static_cast<BrushShape>(k)), k == mBrushShape)) {
          mBrushShape = k;
        }
      }
      if (!mBrushImages.empty()) {
        ImGui::Separator();
      }
      for (std::size_t i = 0; i < mBrushImages.size(); ++i) {
        if (ImGui::Selectable(mBrushImages[i].name.c_str(), image && mShapeImageName == mBrushImages[i].name)) {
          (void)ChooseShapeImage(static_cast<int>(i));
        }
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::BeginDisabled(mBrushShape == 0);
    FillSliderFloat("##shapeangle", &mShapeAngle, -180.0f, 180.0f, "Turn %.0f deg");
    ImGui::EndDisabled();
  }

  void EdTools::DrawBrush(
    const bool withModes
  )
  {
    if (Section("Brush")) {
      if (withModes) {
        // Rows of up to three; each entry is its HeightBrushMode.
        static const char* const kRows[6][3] = {
          {"Raise", "Lower", "Smooth"},
          {"Flatten", "Set height", "Noise"},
          {"Terrace", "Plane", "Stamp"},
          {"Erode", "Water erode", "Rain"},
          {"Deposit", "Plateau", "Sharpen"},
          {"Ramp", "Path", ""}
        };
        static constexpr int kModeOf[6][3] = {{0, 1, 2}, {3, 5, 4}, {6, 7, 8}, {9, 10, 11}, {12, 13, 14}, {15, 16, -1}};
        static constexpr int kRowSize[6] = {3, 3, 3, 3, 3, 2};
        // The mockup's mode grid: bordered tiles, three a row, each its icon above its name, the picked one in the
        // accent's soft fill.
        static const char* const kIcons[6][3] = {
          {ICON_RAISE, ICON_LOWER, ICON_SMOOTH},
          {ICON_FLATTEN, ICON_HEIGHTS, ICON_NOISE},
          {ICON_TERRACE, ICON_RAMP, ICON_STAMP},
          {ICON_ERODE, ICON_WATER, ICON_RAIN},
          {ICON_LAYERS, ICON_PLATEAU, ICON_SLOPE},
          {ICON_RAMP, ICON_PATH, ""}
        };
        const float gap = ImGui::GetStyle().ItemSpacing.x;
        const float tileWidth = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
        for (int row = 0; row < 6; ++row) {
          for (int i = 0; i < kRowSize[row]; ++i) {
            if (i > 0) {
              ImGui::SameLine();
            }
            const int mode = kModeOf[row][i];
            if (ModeTile(kIcons[row][i], kRows[row][i], mode == mBrushMode, ImVec2(tileWidth, 0.0f))) {
              mBrushMode = mode;
            }
          }
        }
        switch (static_cast<HeightBrushMode>(mBrushMode)) {
        case HeightBrushMode::Raise:
        case HeightBrushMode::Lower:
          Note("Left-drag raises or lowers as chosen; right-drag does the opposite.");
          break;
        case HeightBrushMode::Flatten:
          Note("Flattens to the height under the stroke's first point.");
          break;
        case HeightBrushMode::SetHeight:
          ImGui::SetNextItemWidth(-1.0f);
          FillDragFloat("##setheight", &mSetHeight, 0.25f, 0.0f, 500.0f, "Height %.1f");
          break;
        case HeightBrushMode::Terrace:
          ImGui::SetNextItemWidth(-1.0f);
          FillDragFloat("##terrace", &mTerraceStep, 0.1f, 0.5f, 100.0f, "Step %.1f");
          break;
        case HeightBrushMode::Plane: {
          char text[120];
          (void)std::snprintf(
            text,
            sizeof(text),
            "Ctrl+click three points on the terrain; the brush moves the ground towards their plane (%d of 3%s).",
            mPlanePoints,
            mPlanePoints == 3 && !mPlaneSet ? ", on one line" : ""
          );
          Note(text);
          if (ImGui::Button("Clear points")) {
            ClearPlanePoints();
          }
          break;
        }
        case HeightBrushMode::Stamp: {
          // The source: a picture from a file, one of the procedural shapes, or an image of the brush library.
          ImGui::SetNextItemWidth(-1.0f);
          if (EdBeginCombo("##stampsource", mStamp != nullptr ? mStampName.c_str() : "Choose a stamp")) {
            for (int k = 1; k < kBrushShapeCount; ++k) {
              if (
                ImGui::Selectable(
                  BrushShapeName(static_cast<BrushShape>(k)), mStampName == BrushShapeName(static_cast<BrushShape>(k))
                )
              ) {
                (void)ChooseStampSource(k);
              }
            }
            if (!mBrushImages.empty()) {
              ImGui::Separator();
            }
            for (std::size_t i = 0; i < mBrushImages.size(); ++i) {
              if (ImGui::Selectable(mBrushImages[i].name.c_str(), mStampName == mBrushImages[i].name)) {
                (void)ChooseStampSource(kBrushShapeCount + static_cast<int>(i));
              }
            }
            ImGui::EndCombo();
          }
          if (ImGui::Button("Image file...")) {
            mStampRequested = true;
          }
          ImGui::SameLine();
          if (ImGui::Button("Import to library...")) {
            mBrushImportRequested = true;
          }
          static const char* const kStampModes[] = {"Add", "Subtract", "Max", "Min", "Replace"};
          Segmented(kStampModes, 5, mStampMode);
          ImGui::SetNextItemWidth(-1.0f);
          FillDragFloat("##stampheight", &mStampHeight, 0.25f, -200.0f, 200.0f, "Stamp height %.1f");
          const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
          ImGui::SetNextItemWidth(half);
          FillSliderFloat("##stampturn", &mStampTurn, -180.0f, 180.0f, "Turn %.0f deg");
          ImGui::SameLine();
          ImGui::Checkbox("Random turn", &mStampRandomTurn);
          float sizeJitter = mStampSizeJitter * 100.0f;
          float placeJitter = mStampPlaceJitter * 100.0f;
          float spacing = mStampSpacing * 100.0f;
          ImGui::SetNextItemWidth(half);
          if (FillSliderFloat("##stampsize", &sizeJitter, 0.0f, 90.0f, "Size +-%.0f%%")) {
            mStampSizeJitter = sizeJitter / 100.0f;
          }
          ImGui::SameLine();
          ImGui::SetNextItemWidth(-1.0f);
          if (FillSliderFloat("##stampplace", &placeJitter, 0.0f, 100.0f, "Place +-%.0f%%")) {
            mStampPlaceJitter = placeJitter / 100.0f;
          }
          ImGui::SetNextItemWidth(-1.0f);
          if (
            FillSliderFloat(
              "##stampspacing", &spacing, 0.0f, 300.0f, spacing <= 0.0f ? "One per click" : "Spacing %.0f%%"
            )
          ) {
            mStampSpacing = spacing / 100.0f;
          }
          if (mStampMode >= 2) {
            ImGui::Checkbox("Measure from the stroke's first dab", &mStampBaseFromStroke);
          }
          Note(
            "Add and Subtract press the picture into the ground; Max raises the ground to it, Min lowers it to it "
            "upside "
            "down, Replace sets the ground inside its circle to it, all from the ground under the dab (or the stroke's "
            "first). White is the stamp height times strength. With a spacing, a drag stamps along its path."
          );
          break;
        }
        case HeightBrushMode::Erode:
          ImGui::SetNextItemWidth(-1.0f);
          FillSliderFloat("##talus", &mErodeTalus, 0.05f, 2.0f, "Talus slope %.2f");
          Note(
            "Slopes steeper than the talus slope slump towards it; gentler ground stays. Ground moves downhill, none "
            "is "
            "made."
          );
          break;
        case HeightBrushMode::WaterErode:
          Note(
            "Droplets released over the brush run downhill, carry ground away where they speed up and leave it where "
            "they slow, carving gullies and fans, on harder and softer patches of ground. What runs out of the brush "
            "is "
            "mostly put back low inside it. Strength sets how much water. Right-drag deposits."
          );
          break;
        case HeightBrushMode::Rain:
          Note(
            "Like Water erode, but the water runs on past the brush and keeps digging downhill, up to 0.8 of the "
            "radius "
            "beyond it: valleys that lead away from where you paint."
          );
          break;
        case HeightBrushMode::Deposit:
          Note(
            "Lays sediment under the brush as an even heap; the water carries a little of it downhill, so it settles "
            "like washed-in ground. Ground is made."
          );
          break;
        case HeightBrushMode::Smooth:
          Note("Evens the ground out; a stronger brush blurs wider. Right-drag sharpens.");
          break;
        case HeightBrushMode::Sharpen:
          Note("Pushes the ground away from its blurred self: edges, ridges and gullies stand out.");
          break;
        case HeightBrushMode::Ramp:
          Note(
            "Drag from the start to the end: a straight slope as wide as the brush between the ground's heights "
            "there, its edges softened by the falloff. One undo step."
          );
          break;
        case HeightBrushMode::Path: {
          ImGui::SetNextItemWidth(-1.0f);
          if (EdBeginCombo("##pathmode", PathModeName(static_cast<PathMode>(mPathMode)))) {
            for (int m = 0; m < kPathModeCount; ++m) {
              if (ImGui::Selectable(PathModeName(static_cast<PathMode>(m)), m == mPathMode)) {
                mPathMode = m;
              }
            }
            ImGui::EndCombo();
          }
          const auto mode = static_cast<PathMode>(mPathMode);
          if (mode == PathMode::Carve || mode == PathMode::Raise || mode == PathMode::River) {
            ImGui::SetNextItemWidth(-1.0f);
            FillDragFloat("##pathdepth", &mPathDepth, 0.1f, 0.5f, 100.0f, "Depth %.1f");
          }
          ImGui::Checkbox("Loop (back to the first point)", &mPathClosed);
          char text[200];
          (void)std::snprintf(
            text,
            sizeof(text),
            "Click points on the terrain (%zu so far); the curve through them shapes the ground as wide as the brush. "
            "Carve and River dig, Raise builds up, Level flattens to the first point, Ramp climbs from point to point.",
            mPathPoints.size()
          );
          Note(text);
          ImGui::BeginDisabled(mPathPoints.size() < 2);
          if (ImGui::Button("Apply")) {
            RequestPathApply();
          }
          ImGui::EndDisabled();
          ImGui::SameLine();
          ImGui::BeginDisabled(mPathPoints.empty());
          if (ImGui::Button("Remove last")) {
            RemoveLastPathPoint();
          }
          ImGui::SameLine();
          if (ImGui::Button("Clear")) {
            ClearPathPoints();
          }
          ImGui::EndDisabled();
          break;
        }
        case HeightBrushMode::Plateau:
          Note(
            "Brings the ground to the height under the stroke's first point in one go where the brush is full; the "
            "falloff shapes the shoulder. Builds flat tops with soft edges."
          );
          break;
        case HeightBrushMode::Noise:
          ImGui::SetNextItemWidth(-1.0f);
          FillSliderFloat("##noisescale", &mNoiseScale, 1.0f, 64.0f, "Bump size %.0f");
          ImGui::SetNextItemWidth(-1.0f);
          FillSliderInt("##noiseoctaves", &mNoiseOctaves, 1, 4, "Detail layers %d");
          ImGui::SetNextItemWidth(-1.0f);
          FillSliderFloat("##noiserough", &mNoiseRoughness, 0.0f, 1.0f, "Roughness %.2f");
          Note(
            "Smooth bumps, a new pattern each stroke; detail layers add smaller bumps, roughness how strong they are."
          );
          break;
        default:
          break;
        }
        // The brush's shape: every mode that paints sample by sample (the droplet brushes keep a round brush).
        const auto mode = static_cast<HeightBrushMode>(mBrushMode);
        if (
          mode != HeightBrushMode::WaterErode && !IsErosionMode(mode) && mode != HeightBrushMode::Ramp &&
          mode != HeightBrushMode::Path
        ) {
          DrawShapePicker();
        }
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##radius", &mRadius, 1.0f, 128.0f, "Radius %.0f");
      if (ImGui::IsItemHovered()) {
        EdSetTooltip("1 to 128 game units; Ctrl+click to type a size");
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##strength", &mStrength, -1.0f, 1.0f, "Strength %.2f");
      if (ImGui::IsItemHovered()) {
        EdSetTooltip("Below zero the mode does its opposite: raise lowers, smooth sharpens, water erode deposits");
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##falloff", &mFalloff, 0.0f, 1.0f, "Falloff %.2f");
      DrawFalloffCurve();
      ImGui::Checkbox("Airbrush", &mAirbrush);
      if (ImGui::IsItemHovered()) {
        EdSetTooltip(
          "On: the brush keeps working where the cursor is, also held still. Off: it lays dabs a third of its radius "
          "apart along the stroke, none while held still (FAF Studio's way)"
        );
      }
      if (!mStrokeStats.empty()) {
        Note(mStrokeStats.c_str());
      }
    }
  }

  void EdTools::DrawErosionWindow()
  {
    if (!mErosionOpen) {
      return;
    }
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(560.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Erosion###ErosionWindow", &mErosionOpen)) {
      ImGui::End();
      return;
    }
    // Presets: a solver and the settings that give its look.
    ImGui::TextDisabled("Presets");
    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const float width = (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f;
    int column = 0;
    for (const ErosionPreset& preset : ErosionPresets()) {
      if (column++ % 3 != 0) {
        ImGui::SameLine(0.0f, gap);
      }
      if (ModeTile(preset.label, mErosionPreset == preset.id, ImVec2(width, 0.0f))) {
        mErosionPreset = preset.id;
        mErosionSolver = preset.solver;
        mErosionValues[preset.solver] = ErosionPresetValues(preset);
      }
    }
    // The solver and its settings.
    const ErosionSolver* solver = FindErosionSolver(mErosionSolver);
    if (solver == nullptr) {
      solver = &ErosionSolvers().front();
      mErosionSolver = solver->id;
    }
    ImGui::Spacing();
    ImGui::SetNextItemWidth(-1.0f);
    if (EdBeginCombo("##erosionsolver", solver->label)) {
      for (const ErosionSolver& s : ErosionSolvers()) {
        if (ImGui::Selectable(s.label, &s == solver)) {
          mErosionSolver = s.id;
          mErosionPreset.clear();
        }
      }
      ImGui::EndCombo();
    }
    solver = FindErosionSolver(mErosionSolver);
    ErosionValues& values = mErosionValues[mErosionSolver];
    if (values.empty()) {
      values = ErosionDefaults(*solver);
    }
    if (
      ImGui::BeginChild(
        "##erosionsettings", ImVec2(0.0f, -ImGui::GetFrameHeightWithSpacing() * 8.4f), ImGuiChildFlags_Borders
      )
    ) {
      for (const ErosionParam& param : solver->params) {
        float value = static_cast<float>(values[param.key]);
        char format[96];
        (void)std::snprintf(format, sizeof(format), "%s %s", param.label, param.format);
        ImGui::SetNextItemWidth(-1.0f);
        if (FillSliderFloat(param.key, &value, static_cast<float>(param.min), static_cast<float>(param.max), format)) {
          values[param.key] = param.step >= 1.0 ? std::round(value) : value;
          mErosionPreset.clear();
        }
        if (param.tip != nullptr) {
          EdSetItemTooltip("%s\n%s", param.label, param.tip);
        }
      }
    }
    ImGui::EndChild();
    // What Apply also paints: each mask a full run leaves, into a texture layer, in the same undo step.
    static constexpr const char* kMaskNames[4] = {"Wear", "Deposit", "Flow", "Rivers"};
    static constexpr const char* kMaskTips[4] = {
      "Where ground was worn away: steep flanks and gullies (rock, scree).",
      "Where sediment settled: valley floors and fans (sand, soil).",
      "Where the water ran (wet ground, river beds).",
      "Where rivers gather (the drainage): the bigger the catchment, the stronger.",
    };
    static constexpr const char* kLayers[] = {
      "Layer 1", "Layer 2", "Layer 3", "Layer 4", "Layer 5", "Layer 6", "Layer 7", "Layer 8"
    };
    ImGui::TextDisabled("Masks to layers (Apply)");
    for (int m = 0; m < 4; ++m) {
      ImGui::PushID(m);
      ImGui::Checkbox(kMaskNames[m], &mErosionMasks.on[m]);
      EdSetItemTooltip("%s", kMaskTips[m]);
      ImGui::SameLine(Em(110.0f));
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::BeginDisabled(!mErosionMasks.on[m]);
      int index = mErosionMasks.layer[m] - 1;
      if (EdCombo("##masklayer", &index, kLayers, IM_ARRAYSIZE(kLayers))) {
        mErosionMasks.layer[m] = index + 1;
      }
      ImGui::EndDisabled();
      ImGui::PopID();
    }
    // Preview (a coarse run on the map, as an undo step), Revert, Apply (the full run).
    if (PrimaryButton("Apply")) {
      mErosionAsk = ErosionAsk::Apply;
    }
    EdSetItemTooltip("The full run on the whole map, as one undo step (a preview shown is taken off first).");
    ImGui::SameLine();
    if (ImGui::Button("Preview")) {
      mErosionAsk = ErosionAsk::Preview;
    }
    EdSetItemTooltip("A quick run on every few samples, its change put on the map (the fine detail stays).");
    ImGui::SameLine();
    ImGui::BeginDisabled(!mErosionPreviewShown);
    if (ImGui::Button("Revert")) {
      mErosionAsk = ErosionAsk::Revert;
    }
    ImGui::EndDisabled();
    if (!mErosionStatus.empty()) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", mErosionStatus.c_str());
      ImGui::PopTextWrapPos();
    }
    ImGui::End();
  }

  void EdTools::DrawScToolsWindow()
  {
    if (!mScToolsOpen) {
      return;
    }
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(620.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("SC tools###ScToolsWindow", &mScToolsOpen)) {
      ImGui::End();
      return;
    }
    PadSettings& p = mPadSettings;
    if (Section("Base pads and resource rings")) {
      ImGui::Checkbox("Start positions", &p.startPads);
      ImGui::BeginDisabled(!p.startPads);
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##starthalf", &p.startHalf, 2.0f, 40.0f, "Flat half-width %.0f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##startskirt", &p.startSkirt, 0.0f, 40.0f, "Skirt %.0f");
      ImGui::EndDisabled();
      ImGui::Checkbox("Mass points", &p.massPads);
      ImGui::BeginDisabled(!p.massPads);
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##masshalf", &p.massHalf, 1.0f, 10.0f, "Flat half-width %.0f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##massskirt", &p.massSkirt, 0.0f, 20.0f, "Skirt %.0f");
      ImGui::EndDisabled();
      ImGui::Checkbox("Hydrocarbons", &p.hydroPads);
      ImGui::BeginDisabled(!p.hydroPads);
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##hydrohalf", &p.hydroHalf, 1.0f, 12.0f, "Flat half-width %.0f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##hydroskirt", &p.hydroSkirt, 0.0f, 20.0f, "Skirt %.0f");
      ImGui::EndDisabled();
      ImGui::Checkbox("Resource rings", &p.ring);
      EdSetItemTooltip("Mass and hydrocarbons within this distance of a start share its pad's height.");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::BeginDisabled(!p.ring);
      FillSliderFloat("##ringradius", &p.ringRadius, 5.0f, 80.0f, "Within %.0f");
      ImGui::EndDisabled();
      ImGui::Checkbox("Clusters", &p.cluster);
      EdSetItemTooltip("Other resources of a kind closer than this share one height.");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::BeginDisabled(!p.cluster);
      FillSliderFloat("##clusterdist", &p.clusterDist, 2.0f, 60.0f, "Within %.0f");
      ImGui::EndDisabled();
      static constexpr const char* kLevels[] = {
        "Pad height: the mean", "Pad height: the lowest", "Pad height: the highest"
      };
      ImGui::SetNextItemWidth(-1.0f);
      (void)EdCombo("##padlevel", &p.level, kLevels, IM_ARRAYSIZE(kLevels));
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##padstrength", &p.strength, 0.0f, 1.0f, "Strength %.2f");
      if (PrimaryButton("Apply pads")) {
        mScAsk = ScAsk::PadsApply;
      }
      ImGui::SameLine();
      ImGui::BeginDisabled(!mPadsApplied);
      if (ImGui::Button("Remove")) {
        mScAsk = ScAsk::PadsRemove;
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::Checkbox("Auto", &p.autoApply);
      EdSetItemTooltip("Re-apply by itself half a second after a marker stopped moving.");
      if (mPadsStale) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
        ImGui::TextWrapped("The markers or settings changed since the pads were applied.");
        ImGui::PopStyleColor();
      }
      Note(
        "Each pad is flat under its marker and blends into the ground over its skirt; applying again replaces the last "
        "pads (they come off first), one undo step each time."
      );
    }
    if (Section("Slope limit")) {
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##slopelimit", &mSlope.limit, 0.2f, 1.5f, "Limit (rating) %.2f");
      EdSetItemTooltip("The slope rating land units can't cross over: 0.75 is the game's.");
      static constexpr const char* kModes[] = {"Lower the high side", "Raise the low side", "Both"};
      int mode = mSlope.mode == "lower" ? 0 : mSlope.mode == "raise" ? 1 : 2;
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##slopemode", &mode, kModes, IM_ARRAYSIZE(kModes))) {
        mSlope.mode = mode == 0 ? "lower" : mode == 1 ? "raise" : "both";
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##slopebalance", &mSlope.balance, 0.0f, 1.0f, "Balance %.2f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##slopemargin", &mSlope.margin, 0.0f, 0.2f, "Margin %.2f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##slopestrength", &mSlope.strength, 0.0f, 1.0f, "Strength %.2f");
      if (PrimaryButton("Limit slopes")) {
        mScAsk = ScAsk::SlopeApply;
      }
      ImGui::SameLine();
      if (ImGui::Button("Report")) {
        mScAsk = ScAsk::SlopeReport;
      }
      if (!mSlopeReport.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(mSlopeReport.c_str());
        ImGui::PopTextWrapPos();
      }
    }
    if (Section("Ramp check")) {
      if (ImGui::Button("Check the ruler's route", ImVec2(-1.0f, 0.0f))) {
        mScAsk = ScAsk::Ramp;
      }
      Note("Alt+drag lays the ruler; this measures the grade along it (rise over 3 units) against the slope limit.");
      if (!mRampReport.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(mRampReport.c_str());
        ImGui::PopTextWrapPos();
      }
    }
    if (!mScStatus.empty()) {
      ImGui::Separator();
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", mScStatus.c_str());
      ImGui::PopTextWrapPos();
    }
    ImGui::End();
  }

  void EdTools::SetInteropFile(
    const bool exportFile,
    const std::string& file
  )
  {
    char* const path = exportFile ? mInteropExportPath : mInteropImportPath;
    const std::size_t size = exportFile ? sizeof(mInteropExportPath) : sizeof(mInteropImportPath);
    (void)std::snprintf(path, size, "%s", file.c_str());
  }

  void EdTools::DrawInteropWindow()
  {
    if (!mInteropOpen) {
      return;
    }
    ImGui::SetNextWindowSize(ImVec2(Em(400.0f), Em(640.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Import / Export###InteropWindow", &mInteropOpen)) {
      ImGui::End();
      return;
    }
    ImportSettings& s = mImport;
    const float browseWidth = ImGui::CalcTextSize("Browse...").x + ImGui::GetStyle().FramePadding.x * 2.0f;
    if (Section("Import a heightmap")) {
      ImGui::SetNextItemWidth(-browseWidth - ImGui::GetStyle().ItemSpacing.x);
      ImGui::InputTextWithHint(
        "##interopin", "PNG, TIFF or raw 16-bit file", mInteropImportPath, sizeof(mInteropImportPath)
      );
      ImGui::SameLine();
      if (ImGui::Button("Browse...##in")) {
        mInteropBrowse = 1;
      }
      static constexpr const char* kMappings[] = {
        "Values: stretched over a height range", "Values: heights (1/128 unit a step)"
      };
      int mapping = static_cast<int>(s.mapping);
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##interopmapping", &mapping, kMappings, IM_ARRAYSIZE(kMappings))) {
        s.mapping = static_cast<ImportSettings::Mapping>(mapping);
      }
      if (s.mapping == ImportSettings::Mapping::Normalised) {
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##interoplow", &s.low, 0.0f, 256.0f, "Darkest at %.1f");
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##interophigh", &s.high, 0.0f, 512.0f, "Brightest at %.1f");
      } else {
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##interopscale", &s.scale, 0.05f, 4.0f, "Heights times %.2f");
      }
      ImGui::Checkbox("Flip left-right", &s.flipX);
      ImGui::SameLine();
      ImGui::Checkbox("Flip top-bottom", &s.flipZ);
      static constexpr const char* kTurns[] = {
        "Not turned", "Turned 90 clockwise", "Turned 180", "Turned 90 anticlockwise"
      };
      ImGui::SetNextItemWidth(-1.0f);
      (void)EdCombo("##interopturns", &s.turns, kTurns, IM_ARRAYSIZE(kTurns));
      static constexpr const char* kBlends[] = {
        "Replace the heights", "Add to the heights", "Keep the higher", "Keep the lower"
      };
      int blend = static_cast<int>(s.blend);
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##interopblend", &blend, kBlends, IM_ARRAYSIZE(kBlends))) {
        s.blend = static_cast<ImportSettings::Blend>(blend);
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##interopstrength", &s.strength, 0.0f, 1.0f, "Strength %.2f");
      ImGui::Checkbox("Only a region", &s.region);
      EdSetItemTooltip("The image fitted onto a rectangle of the map (in samples, one a game unit); the rest stays.");
      if (s.region) {
        int from[2] = {s.regionX0, s.regionZ0};
        int to[2] = {s.regionX1, s.regionZ1};
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::DragInt2("##regionfrom", from, 1.0f, 0, 4096, "From %d")) {
          s.regionX0 = from[0];
          s.regionZ0 = from[1];
        }
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::DragInt2("##regionto", to, 1.0f, 0, 4096, "To %d")) {
          s.regionX1 = to[0];
          s.regionZ1 = to[1];
        }
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##interopfeather", &s.feather, 0.0f, 256.0f, "Feather %.0f");
      EdSetItemTooltip("Samples in from the edge over which the import fades in, so it meets the map without a step.");
      const bool haveFile = mInteropImportPath[0] != '\0';
      ImGui::BeginDisabled(!haveFile);
      if (PrimaryButton("Import")) {
        mInteropAsk = InteropAsk::Import;
      }
      ImGui::SameLine();
      if (ImGui::Button("Probe")) {
        mInteropAsk = InteropAsk::Probe;
      }
      EdSetItemTooltip("Read the file and say its size and what its values become.");
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(!mInteropCanRevert);
      if (ImGui::Button("Revert")) {
        mInteropAsk = InteropAsk::Revert;
      }
      EdSetItemTooltip("Undo the last import (while nothing was edited after it).");
      ImGui::EndDisabled();
      ImGui::BeginDisabled(!haveFile);
      ImGui::Checkbox("Live link", &mInteropLive);
      ImGui::EndDisabled();
      EdSetItemTooltip(
        "Import again, with these settings, a second after another tool saved the file. While the last link import is "
        "the newest step it is replaced, so the history keeps one step."
      );
      if (mInteropLive && !mInteropLinkNote.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", mInteropLinkNote.c_str());
      }
      if (!mInteropProbe.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(mInteropProbe.c_str());
        ImGui::PopTextWrapPos();
      }
    }
    if (Section("Export the heights")) {
      ImGui::SetNextItemWidth(-browseWidth - ImGui::GetStyle().ItemSpacing.x);
      ImGui::InputTextWithHint(
        "##interopout", "16-bit PNG or .raw / .r16 file", mInteropExportPath, sizeof(mInteropExportPath)
      );
      ImGui::SameLine();
      if (ImGui::Button("Browse...##out")) {
        mInteropBrowse = 2;
      }
      static constexpr const char* kSizes[] = {"The map's size", "257", "513", "1025", "2049", "4097"};
      ImGui::SetNextItemWidth(-1.0f);
      (void)EdCombo("##interopsize", &mInteropExportSize, kSizes, IM_ARRAYSIZE(kSizes));
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##interopexportscale", &mInteropExportScale, 0.05f, 4.0f, "Heights times %.2f");
      ImGui::Checkbox("Write a sidecar (.json)", &mInteropSidecar);
      EdSetItemTooltip(
        "The map, the image's size, the sea level and how a value becomes a height, for the other tool."
      );
      const bool haveFile = mInteropExportPath[0] != '\0';
      ImGui::BeginDisabled(!haveFile);
      if (PrimaryButton("Export")) {
        mInteropAsk = InteropAsk::Export;
      }
      ImGui::SameLine();
      if (ImGui::Button("Send and watch")) {
        mInteropAsk = InteropAsk::SendAndWatch;
      }
      EdSetItemTooltip(
        "Export, then link the same file back in as heights: edit it in another tool, save, and the map follows."
      );
      ImGui::EndDisabled();
    }
    if (!mInteropStatus.empty()) {
      ImGui::Separator();
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", mInteropStatus.c_str());
      ImGui::PopTextWrapPos();
    }
    ImGui::End();
  }

  void EdTools::DrawFalloffCurve()
  {
    // The mockup's curve under the sliders: the brush's weight across its middle (BrushWeightAt, so its shape and
    // angle too), on a frame with quarter lines, the area under it in the accent's soft fill.
    const float width = ImGui::GetContentRegionAvail().x;
    const float height = std::round(ImGui::GetFrameHeight() * 2.6f);
    const ImVec2 at = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(width, height));
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImVec2 end(at.x + width, at.y + height);
    const float rounding = ImGui::GetStyle().FrameRounding;
    draw->AddRectFilled(at, end, ImGui::GetColorU32(ImGuiCol_FrameBg), rounding);
    const ImU32 grid = ImGui::GetColorU32(ImGuiCol_Border, 0.6f);
    for (int q = 1; q < 4; ++q) {
      const float x = at.x + width * static_cast<float>(q) / 4.0f;
      draw->AddLine(ImVec2(x, at.y + 1.0f), ImVec2(x, end.y - 1.0f), grid);
    }
    const HeightBrush brush = CurrentHeightBrush();
    constexpr int kSamples = 64;
    const float pad = 4.0f;
    ImVec2 points[kSamples + 1];
    for (int i = 0; i <= kSamples; ++i) {
      const float t = static_cast<float>(i) / kSamples;
      const float weight = std::clamp(BrushWeightAt(brush, (t * 2.0f - 1.0f) * brush.radius, 0.0f), 0.0f, 1.0f);
      points[i] = ImVec2(at.x + width * t, end.y - pad - (height - pad * 2.0f) * weight);
    }
    const ImU32 line = ImGui::ColorConvertFloat4ToU32(AccentColor(1.0f));
    const ImU32 fill = ImGui::ColorConvertFloat4ToU32(AccentColor(0.18f));
    for (int i = 0; i < kSamples; ++i) {
      draw->AddQuadFilled(
        ImVec2(points[i].x, end.y - 1.0f), points[i], points[i + 1], ImVec2(points[i + 1].x, end.y - 1.0f), fill
      );
    }
    draw->AddPolyline(points, kSamples + 1, line, ImDrawFlags_None, 2.0f);
    draw->AddRect(at, end, ImGui::GetColorU32(ImGuiCol_Border), rounding);
    if (ImGui::IsItemHovered()) {
      EdSetTooltip("The brush's strength across its middle: full in the middle, fading by the falloff to its edge.");
    }
  }

  void EdTools::DrawSymmetryMenu()
  {
    // The toolbar's symmetry menu: all ten modes, what the map's heights fit, what an edit writes.
    {
      const int columns = 5;
      const float spacing = ImGui::GetStyle().ItemSpacing.x * 0.6f;
      const float cell = Em(68.0f);
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
          EdBeginTooltip();
          DrawSymmetryTooltip(i, false);
          ImGui::EndTooltip();
        }
        draw->AddRectFilled(
          p, ImVec2(p.x + cell, p.y + cell + labelHeight), on ? AccentU32(0.16f) : SurfaceU32(), 4.0f
        );
        draw->AddRect(
          p, ImVec2(p.x + cell, p.y + cell + labelHeight), on ? AccentU32() : (hovered ? InkDimU32() : LineU32()), 4.0f
        );
        DrawSymmetryIcon(draw, i, mNWay, ImVec2(p.x + cell * 0.12f, p.y + cell * 0.06f), cell * 0.76f);
        const float labelSize = ImGui::GetFontSize() * 0.66f;
        const ImVec2 textSize = ImGui::GetFont()->CalcTextSizeA(labelSize, cell, cell, kSymmetry[i].name);
        draw->AddText(
          ImGui::GetFont(),
          labelSize,
          ImVec2(p.x + (cell - textSize.x) * 0.5f, p.y + cell * 0.86f),
          on ? AccentU32() : InkDimU32(),
          kSymmetry[i].name,
          nullptr,
          cell
        );
        ImGui::PopID();
      }
      if (mSymmetry == 9) {
        ImGui::SetNextItemWidth(cell * columns + spacing * (columns - 1));
        FillSliderInt("##nway", &mNWay, 3, 8, "Copies %d");
      }
      if (mDetectedSymmetry >= 0) {
        char found[120];
        if (mDetectedSymmetry == 9) {
          (void)std::snprintf(
            found,
            sizeof(found),
            "The map's heights: %d-way turn (%.1f%% of points match).",
            mNWay,
            static_cast<double>(mDetectedMatch) * 100.0
          );
        } else {
          (void)std::snprintf(
            found,
            sizeof(found),
            "The map's heights: %s (%.1f%% of points match).",
            kSymmetry[mDetectedSymmetry].name,
            static_cast<double>(mDetectedMatch) * 100.0
          );
        }
        ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "%s", found);
        if (mDetectedStarts + mDetectedResources > 0) {
          ImGui::TextDisabled(
            "Markers that fit it: %d start position%s, %d resource marker%s.",
            mDetectedStarts,
            mDetectedStarts == 1 ? "" : "s",
            mDetectedResources,
            mDetectedResources == 1 ? "" : "s"
          );
        }
        if (mDetectedOffsetX != 0.0f || mDetectedOffsetZ != 0.0f) {
          Note(
            "Its centre is off the map's middle (by the markers' partners): Make symmetric uses that centre; the "
            "brushes "
            "still mirror about the middle."
          );
        }
      } else if (mDetectedSymmetry == -1) {
        ImGui::TextDisabled("The map's heights and markers fit no symmetry.");
      }
      const int copies = mSymmetry == 9 ? mNWay : kSymmetry[mSymmetry].copies;
      char note[300];
      if (mSymmetry == 9) {
        (void)std::snprintf(
          note,
          sizeof(note),
          "Every edit is written to all %d copies: the first sector (from the centre towards the right, turning down) "
          "is painted, the others copy it. Turns other than 4 fall between vertices, so their copies are "
          "close, not identical; the check shows by how much.",
          copies
        );
      } else {
        (void)std::snprintf(
          note,
          sizeof(note),
          "Every edit is written to all %d copies. Where copies overlap, each vertex takes the strongest copy, "
          "so the halves stay identical.",
          copies
        );
      }
      ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + cell * columns + spacing * (columns - 1));
      ImGui::TextDisabled("%s", note);
      ImGui::PopTextWrapPos();
    }
  }

  void EdTools::DrawSymmetry(
    const bool withCheck
  )
  {
    // The mode is picked in the toolbar (its pictures and its menu); a tool panel keeps the check.
    if (!withCheck) {
      return;
    }
    if (Section("Symmetry check")) {
      ImGui::TextDisabled("Symmetry: %s (set in the toolbar)", kSymmetry[mSymmetry].name);
      if (mDetectedSymmetry >= 0) {
        ImGui::TextColored(
          ImVec4(0.55f, 0.80f, 0.55f, 1.0f),
          "The map's heights: %s (%.1f%% of points match).",
          mDetectedSymmetry == 9 ? "N-way turn" : kSymmetry[mDetectedSymmetry].name,
          static_cast<double>(mDetectedMatch) * 100.0
        );
      }
      if (mSymmetry == 0) {
        Note("Pick a symmetry in the toolbar to check the map against it.");
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
      const float largest =
        mCheckedMasks ? static_cast<float>(mLargest) / 2.55f : static_cast<float>(mLargest) / 128.0f;
      const char* const unit = mCheckedMasks ? "mask texels" : "vertices";
      const char* const format = mCheckedMasks ? "%.0f%%" : "%.2f";
      char amount[32];
      (void)std::snprintf(amount, sizeof(amount), format, static_cast<double>(largest));
      char result[200];
      if (mDiffering == 0) {
        (void)std::snprintf(
          result, sizeof(result), "All %d %s match their copies (largest difference %s).", mChecked, unit, amount
        );
      } else {
        (void)std::snprintf(
          result, sizeof(result), "%d of %d %s differ from a copy, by up to %s.", mDiffering, mChecked, unit, amount
        );
      }
      ImGui::TextWrapped("%s", result);
      if (mDiffering > 0) {
        SectionHeader("MAKE SYMMETRIC");
        const int parts = SymmetryParts(static_cast<Symmetry>(mSymmetry), mNWay);
        mSymPart = std::clamp(mSymPart, 0, parts - 1);
        const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
        int part = mSymPart + 1;
        ImGui::SetNextItemWidth(half);
        if (FillSliderInt("##sympart", &part, 1, parts, "Source part %d")) {
          mSymPart = part - 1;
        }
        ImGui::SameLine();
        static const char* const kCombine[] = {"Copy it", "Average", "Highest", "Lowest"};
        ImGui::SetNextItemWidth(-1.0f);
        (void)EdCombo("##symcombine", &mSymCombine, kCombine, 4);
        ImGui::BeginDisabled(mSymCombine != 0);
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##symseam", &mSymSeam, 0.0f, 32.0f, mSymSeam <= 0.0f ? "Hard seam" : "Seam %.0f");
        ImGui::EndDisabled();
        if (mTool == 1) {
          ImGui::Checkbox("Texture masks too", &mSymMasks);
          ImGui::SameLine();
          ImGui::Checkbox("Terrain types too", &mSymTypes);
        }
        if (PrimaryButton("Make symmetric")) {
          mRepairRequested = true;
        }
        Note(
          "Part 1 is the left or top one, the others follow round the centre. Copy it takes the source part; Average, "
          "Highest and Lowest combine every copy instead. A seam cross-fades the part's borders into the copies next "
          "to "
          "them. Heights, masks and terrain types are each one undo step."
        );
      }
    }
  }

  void EdTools::DrawSelect()
  {
    ImGui::Checkbox("Follow symmetry", &mFollowSymmetry);
    EdSetItemTooltip(
      "Follow symmetry\nMoving, turning or deleting an object does the same to its mirrored copies: the objects of its "
      "kind "
      "at the images of its place under the map's symmetry (the toolbar's)."
    );
    // What a click, the hover and a box may pick is in the view, under the camera row (EdShell::DrawViewOverlays).
    if (!mPickable.All()) {
      Note("Some kinds aren't picked (the Pick pills in the view): they stay drawn but can't be grabbed or moved.");
    }
    // What is selected, and what a click would pick (the white ring in the view).
    ImGui::TextUnformatted(mSelectSelected.empty() ? "Nothing selected" : mSelectSelected.c_str());
    ImGui::TextDisabled("Under the cursor: %s", mSelectHover.empty() ? "-" : mSelectHover.c_str());
    Note(
      "Click a marker, unit, prop or decal to select it; the white ring shows what a click picks. Ctrl adds or takes "
      "one out, "
      "a drag or the arrows move the selection, Delete removes it, Q and E turn props by 15 degrees. Each is one undo "
      "step."
    );
    DrawArrange();
  }

  void EdTools::DrawArrange()
  {
    if (!Section("Arrange")) {
      return;
    }
    // Rows of equal buttons; each one undo step on the selection of whichever kind is selected.
    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const bool none = !mSelectAny;
    if (none) {
      Note("Select two or more markers, units, props or decals to line them up.");
    }
    ImGui::BeginDisabled(none);
    const auto row = [&](const char* label, std::initializer_list<std::pair<const char*, ArrangeOp>> buttons) {
      if (label[0] != '\0') {
        ImGui::TextDisabled("%s", label);
      }
      const float width = (ImGui::GetContentRegionAvail().x - gap * static_cast<float>(buttons.size() - 1)) /
        static_cast<float>(buttons.size());
      bool first = true;
      for (const auto& [text, op] : buttons) {
        if (!first) {
          ImGui::SameLine(0.0f, gap);
        }
        first = false;
        if (ImGui::Button(text, ImVec2(width, 0.0f))) {
          mArrangeRequest = op;
        }
        EdSetItemTooltip("%s", ArrangeTitle(op));
      }
    };
    row(
      "Align", {{"Left", ArrangeOp::AlignLeft}, {"Centre X", ArrangeOp::AlignCentreX}, {"Right", ArrangeOp::AlignRight}}
    );
    row("", {{"Top", ArrangeOp::AlignTop}, {"Centre Z", ArrangeOp::AlignCentreZ}, {"Bottom", ArrangeOp::AlignBottom}});
    row(
      "Spread",
      {{"Distribute X", ArrangeOp::DistributeX},
       {"Distribute Z", ArrangeOp::DistributeZ},
       {"Circle", ArrangeOp::Circle}}
    );
    row("Mirror", {{"Left-right", ArrangeOp::MirrorX}, {"Top-bottom", ArrangeOp::MirrorZ}});
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Snap to grid");
    static constexpr const char* kSteps[] = {"Every 1", "Every 2", "Every 4", "Every 8"};
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.5f);
    ImGui::Combo("##arrangesnap", &mArrangeSnap, kSteps, IM_ARRAYSIZE(kSteps));
    ImGui::SameLine(0.0f, gap);
    if (ImGui::Button("Snap", ImVec2(-1.0f, 0.0f))) {
      mArrangeRequest = ArrangeOp::Snap;
    }
    EdSetItemTooltip("Snap to grid\nEvery selected one to the nearest point of the grid, in map units.");
    ImGui::EndDisabled();
    if (!none && !mArrangeMessage.empty()) {
      Note(mArrangeMessage.c_str());
    }
  }

  void EdTools::DrawTerrain()
  {
    DrawBrush(true);
    const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
    if (ImGui::Button("Erosion...", ImVec2(half, 0.0f))) {
      mErosionOpen = true;
    }
    EdSetItemTooltip("The Erosion window: a solver run over the whole map, with presets, a preview and Apply.");
    ImGui::SameLine();
    if (ImGui::Button("SC tools...", ImVec2(-1.0f, 0.0f))) {
      mScToolsOpen = true;
    }
    EdSetItemTooltip("Base pads under the markers, the pathable slope limit, the grade along a route.");
    DrawSymmetry();
    DrawLimits();
    if (Section("Height field")) {
      if (ImGui::Button("Import...")) {
        mImportRequested = true;
      }
      ImGui::SameLine();
      if (ImGui::Button("Export...")) {
        mExportRequested = true;
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillDragFloat("##heightscale", &mHeightScale, 0.01f, 0.01f, 16.0f, "Height scale %.2f");
      static constexpr const char* kSizes[] = {
        "Export at the map's size",
        "Export 257 wide",
        "Export 513 wide",
        "Export 1025 wide",
        "Export 2049 wide",
        "Export 4097 wide"
      };
      ImGui::SetNextItemWidth(-1.0f);
      EdCombo("##exportsize", &mExportSize, kSizes, IM_ARRAYSIZE(kSizes));
      Note(
        "Import reads .png, .raw, .r16 (World Machine), .bmp or .tif, resampled to the map's size; export writes .png "
        "(16-bit grey), "
        ".raw or .r16. Heights are times the scale both ways. An import is one undo step."
      );
    }
  }

  void EdTools::AddPlanePoint(
    const float x,
    const float height,
    const float z
  ) noexcept
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

  int EdTools::PlanePoints(
    float (&x)[3],
    float (&height)[3],
    float (&z)[3]
  ) const noexcept
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
    std::string LayerLabel(
      const std::string& path
    )
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
    if (Section("Limit")) {
      ImGui::Checkbox("Only between heights", &mLimitHeight);
      if (mLimitHeight) {
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::DragFloatRange2("##limitheights", &mLimitLow, &mLimitHigh, 0.25f, 0.0f, 512.0f, "From %.1f", "to %.1f");
      }
      ImGui::Checkbox("Only below slope", &mLimitSlope);
      if (mLimitSlope) {
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##limitslope", &mLimitSlopeDegrees, 1.0f, 85.0f, "%.0f degrees");
      }
    }
  }

  void EdTools::DrawLayersPanel()
  {
    // The mockup's Layers panel (the right dock): the shader, the ten layers top to bottom as the terrain stacks them,
    // the paint layer picked here, a layer dragged to another place with its mask.
    if (mSlots.size() != 10) {
      Note("Open a map to see its layers.");
      return;
    }
    mLibrary.Pump(3);
    if (Section("Shader")) {
      RowLabel("Terrain shader");
      if (EdBeginCombo("##layersshader", mShader.c_str())) {
        for (const std::string& shader : mShaders) {
          if (ImGui::Selectable(shader.c_str(), shader == mShader) && shader != mShader) {
            mShaderChange = shader;
          }
        }
        ImGui::EndCombo();
      }
      if (ImGui::Button("Browse...")) {
        mShaderBrowserOpen = true;
        mBrowsedShader = mShader;
      }
      EdSetItemTooltip("Every terrain shader: what each draws, how it reads the masks, which layers it uses");
      ImGui::SameLine();
      if (ImGui::Button("Convert...")) {
        mShaderBrowserOpen = true;
        mBrowsedShader = mShader;
      }
      EdSetItemTooltip("Change the shader and carry the paint over (in the shader browser)");
      DrawShaderBrowser();
    }

    if (Section("Layers")) {
      static const char* const kSlotNames[10] = {"Lower", "1", "2", "3", "4", "5", "6", "7", "8", "Upper"};
      // The biome from the texture's folder: "/env/evergreen2/layers/..." is Evergreen2.
      const auto biomeOf = [](const std::string& path) {
        std::string lower = path;
        for (char& c : lower) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        const std::size_t env = lower.find("/env/");
        if (env == std::string::npos) {
          return std::string();
        }
        const std::size_t end = path.find('/', env + 5);
        std::string biome = path.substr(env + 5, end == std::string::npos ? std::string::npos : end - env - 5);
        if (!biome.empty()) {
          biome[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(biome[0])));
        }
        return biome;
      };
      const float rowHeight = std::round(Em(42.0f));
      const float thumb = std::round(Em(28.0f));
      const float width = ImGui::GetContentRegionAvail().x;
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 listAt = ImGui::GetCursorScreenPos();
      const ImVec4 bright = ImGui::GetStyleColorVec4(ImGuiCol_Text);
      const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
      const ImU32 soft = ImGui::GetColorU32(ImVec4(
        (bright.x * 2.0f + dim.x) / 3.0f, (bright.y * 2.0f + dim.y) / 3.0f, (bright.z * 2.0f + dim.z) / 3.0f, 1.0f
      ));
      const float small = std::round(ImGui::GetFontSize() * 0.84f);
      ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
      for (int slot = 9; slot >= 0; --slot) {
        const LayerSlot& layer = mSlots[static_cast<std::size_t>(slot)];
        const bool stratum = slot >= 1 && slot <= 8;
        const bool painting = stratum && mMaskLayer == slot - 1;
        ImGui::PushID(slot);
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const ImVec2 to(at.x + width, at.y + rowHeight);
        const bool clicked = ImGui::InvisibleButton("##row", ImVec2(width, rowHeight));
        const bool hovered = ImGui::IsItemHovered();
        // Drag a stratum onto another place: it moves there with its mask.
        if (stratum) {
          if (ImGui::BeginDragDropSource()) {
            const int from = slot - 1;
            ImGui::SetDragDropPayload("EDITOR_LAYER", &from, sizeof(from));
            ImGui::Text("Layer %s  %s", kSlotNames[slot], LayerTextureName(layer.albedo).c_str());
            ImGui::EndDragDropSource();
          }
          if (ImGui::BeginDragDropTarget()) {
            if (const ImGuiPayload* const payload = ImGui::AcceptDragDropPayload("EDITOR_LAYER"); payload != nullptr) {
              AskLayerMove(*static_cast<const int*>(payload->Data), slot - 1);
            }
            ImGui::EndDragDropTarget();
          }
        }
        // Its menu: the texture, moving it, its paint.
        if (ImGui::BeginPopupContextItem("##layermenu")) {
          if (ImGui::MenuItem("Choose a texture...")) {
            mBrowseSlot = slot;
            mBrowseOpen = true;
          }
          if (stratum) {
            ImGui::Separator();
            if (ImGui::MenuItem("Move up", nullptr, false, slot < 8)) {
              AskLayerMove(slot - 1, slot);
            }
            if (ImGui::MenuItem("Move down", nullptr, false, slot > 1)) {
              AskLayerMove(slot - 1, slot - 2);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Clear its paint")) {
              mMaskLayer = slot - 1;
              mMaskOp = MaskOp::Clear;
            }
            if (ImGui::MenuItem("Fill its paint (the whole map)")) {
              mMaskLayer = slot - 1;
              mMaskOp = MaskOp::Fill;
            }
            if (ImGui::MenuItem("Import its mask...")) {
              mMaskLayer = slot - 1;
              mMaskOp = MaskOp::Import;
            }
            if (ImGui::MenuItem("Export its mask...")) {
              mMaskLayer = slot - 1;
              mMaskOp = MaskOp::Export;
            }
          }
          if (
            slot >= 1 && !layer.albedo.empty() &&
            ImGui::MenuItem(stratum ? "Remove its texture and paint" : "Remove its texture")
          ) {
            mChangedSlot = slot;
            mChangedValue = layer;
            mChangedValue.albedo.clear();
            mChangedValue.normals.clear();
            mChangedValue.albedoSize = 4.0f;
            mChangedValue.normalsSize = 4.0f;
            if (stratum) {
              mMaskLayer = slot - 1;
              mMaskOp = MaskOp::Clear;
            }
          }
          ImGui::Separator();
          ImGui::SetNextItemWidth(Em(180.0f));
          float size = layer.albedoSize;
          if (FillDragFloat("##size", &size, 0.05f, 0.1f, 1024.0f, "Size %.2f") && size > 0.0f) {
            // Albedo and normal map keep their ratio (most maps have them equal).
            const float ratio = layer.albedoSize > 0.0f ? layer.normalsSize / layer.albedoSize : 1.0f;
            mChangedSlot = slot;
            mChangedValue = layer;
            mChangedValue.albedoSize = size;
            mChangedValue.normalsSize = size * ratio;
          }
          ImGui::SetItemTooltip("The tile: world units one repeat of the texture covers (its normal map follows)");
          if (!layer.normals.empty()) {
            ImGui::SetNextItemWidth(Em(180.0f));
            float normals = layer.normalsSize;
            if (FillDragFloat("##nsize", &normals, 0.05f, 0.1f, 1024.0f, "Normal map %.2f") && normals > 0.0f) {
              mChangedSlot = slot;
              mChangedValue = layer;
              mChangedValue.normalsSize = normals;
            }
            ImGui::SetItemTooltip(
              "The normal map's own tile (usually the texture's: the bumps then sit on their colours)"
            );
          }
          if (const float optimal = mOptimalTiles[static_cast<std::size_t>(slot)]; optimal > 0.0f && slot < 9) {
            char label[64];
            std::snprintf(label, sizeof(label), "Optimal tile size (%.1f)", static_cast<double>(optimal));
            if (
              ImGui::MenuItem(
                label,
                nullptr,
                false,
                std::fabs(layer.albedoSize - optimal) > 0.01f || std::fabs(layer.normalsSize - optimal) > 0.01f
              )
            ) {
              mChangedSlot = slot;
              mChangedValue = layer;
              mChangedValue.albedoSize = optimal;
              mChangedValue.normalsSize = optimal;
            }
            ImGui::SetItemTooltip(
              "The largest tile that stays sharp at the closest zoom, from the texture's width; the normal map too"
            );
          }
          ImGui::EndPopup();
        }
        if (painting) {
          dl->AddRectFilled(at, to, AccentU32(0.16f));
          dl->AddRectFilled(at, ImVec2(at.x + Em(2.0f), to.y), AccentU32());
        } else if (hovered) {
          dl->AddRectFilled(at, to, ImGui::GetColorU32(ImGuiCol_Button));
        }
        if (slot > 0) {
          dl->AddLine(
            ImVec2(at.x, to.y - 0.5f), ImVec2(to.x, to.y - 0.5f), ImGui::GetColorU32(ImGuiCol_TableBorderLight)
          );
        }
        // The grip (strata move), the thumbnail (a click chooses its texture), the words, its share of the map.
        const float midY = at.y + rowHeight * 0.5f;
        if (stratum) {
          dl->AddText(
            ImVec2(at.x + Em(8.0f), std::round(midY - ImGui::GetFontSize() * 0.55f)),
            ImGui::GetColorU32(ImGuiCol_TextDisabled),
            ICON_GRIP
          );
        }
        const ImVec2 t0(at.x + Em(28.0f), std::round(midY - thumb * 0.5f));
        const ImVec2 t1(t0.x + thumb, t0.y + thumb);
        const std::uint64_t image = mLibrary.Thumbnail(layer.albedo);
        if (image != 0U) {
          dl->AddImageRounded(
            static_cast<ImTextureID>(image), t0, t1, ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, Em(5.0f)
          );
        } else {
          // Empty: the mockup's hatched square.
          dl->AddRectFilled(t0, t1, ImGui::GetColorU32(ImGuiCol_FrameBg), Em(5.0f));
          dl->PushClipRect(t0, t1, true);
          for (float k = -thumb; k < thumb; k += Em(6.0f)) {
            dl->AddLine(
              ImVec2(t0.x + k, t1.y), ImVec2(t0.x + k + thumb, t0.y), ImGui::GetColorU32(ImGuiCol_Button), 1.0f
            );
          }
          dl->PopClipRect();
          dl->AddRect(t0, t1, ImGui::GetColorU32(ImGuiCol_Border), Em(5.0f));
        }
        const bool onThumb = ImGui::IsMouseHoveringRect(t0, t1);
        if (clicked && onThumb) {
          mBrowseSlot = slot;
          mBrowseOpen = true;
        } else if (clicked && stratum) {
          mMaskLayer = slot - 1;
          gpg::Logf("editor: Layers: painting layer %d", slot);
        }
        const float tx = t1.x + Em(10.0f);
        const std::string name = layer.albedo.empty() ? std::string("(empty)") : LayerTextureName(layer.albedo);
        const float titleY = midY - Em(17.0f);
        dl->AddText(
          gBoldFont != nullptr ? gBoldFont : ImGui::GetFont(),
          ImGui::GetFontSize(),
          ImVec2(tx, titleY),
          InkU32(),
          kSlotNames[slot]
        );
        const float nameX = tx +
          (gBoldFont != nullptr ? gBoldFont : ImGui::GetFont())
            ->CalcTextSizeA(ImGui::GetFontSize(), FLT_MAX, 0.0f, kSlotNames[slot])
            .x +
          Em(6.0f);
        const float right = to.x - Em(56.0f);
        dl->PushClipRect(ImVec2(tx, at.y), ImVec2(right, to.y), true);
        dl->AddText(ImVec2(nameX, titleY), InkU32(), name.c_str());
        std::string about;
        if (slot == 0) {
          about = "under every layer";
        } else if (slot == 9) {
          about = "over every layer, by its alpha";
        } else if (layer.albedo.empty()) {
          about = "choose a texture to paint this layer";
        } else {
          const std::string biome = biomeOf(layer.albedo);
          about = (biome.empty() ? std::string() : biome + " \xC2\xB7 ") + mShader;
        }
        if (const ShaderSlotUse use = ShaderSlotUseOf(mShader, slot); use.mapWide) {
          about = "map-wide: " + use.text;
        }
        dl->AddText(
          ImGui::GetFont(),
          small,
          ImVec2(tx, titleY + Em(19.0f)),
          ImGui::GetColorU32(ImGuiCol_TextDisabled),
          about.c_str()
        );
        dl->PopClipRect();
        // A map-wide slot holds data, not paint: no share of the map.
        if (stratum && mHasCoverage && !layer.albedo.empty() && !ShaderSlotUseOf(mShader, slot).mapWide) {
          char share[16];
          (void)std::snprintf(share, sizeof(share), "%.0f %%", static_cast<double>(mCoverage[slot - 1] * 100.0f));
          const ImVec2 size = ImGui::GetFont()->CalcTextSizeA(small, FLT_MAX, 0.0f, share);
          dl->AddText(
            ImGui::GetFont(), small, ImVec2(to.x - size.x - Em(12.0f), std::round(midY - size.y * 0.5f)), soft, share
          );
        }
        if (hovered && !layer.albedo.empty()) {
          EdSetTooltip(
            "%s\n%s\nClick: paint this layer. Thumbnail: choose its texture. Drag: move it. Right-click: more.",
            layer.albedo.c_str(),
            layer.normals.empty() ? "(no normal map)" : layer.normals.c_str()
          );
        }
        ImGui::PopID();
      }
      ImGui::PopStyleVar();
      const ImVec2 listEnd(listAt.x + width, ImGui::GetCursorScreenPos().y);
      dl->AddRect(listAt, listEnd, ImGui::GetColorU32(ImGuiCol_Border), Em(6.0f));
      ImGui::Dummy(ImVec2(0.0f, Em(6.0f)));
      if (ImGui::Button(ICON_MATERIAL "  Material editor...")) {
        mMaterialAsk = std::clamp(mMaskLayer + 1, 1, 8);
      }
      EdSetItemTooltip("A texture for the paint layer, built from nodes, shown on the map as you edit");
      ImGui::SameLine();
      if (ImGui::Button(".scmst  " ICON_CHEVRON)) {
        ImGui::OpenPopup("##layersets");
      }
      EdSetItemTooltip(
        "FAForeverMapEditor's layer files: the shader and all ten layers (.scmst), or one layer (.scmsl)"
      );
      if (ImGui::BeginPopup("##layersets")) {
        if (ImGui::MenuItem("Import a layer set (.scmst)...")) {
          mLayerFileAsk = LayerFileAsk::ImportSet;
        }
        if (ImGui::MenuItem("Export the layer set (.scmst)...")) {
          mLayerFileAsk = LayerFileAsk::ExportSet;
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Import the paint layer (.scmsl)...")) {
          mLayerFileSlot = std::clamp(mMaskLayer + 1, 1, 8);
          mLayerFileAsk = LayerFileAsk::ImportLayer;
        }
        if (ImGui::MenuItem("Export the paint layer (.scmsl)...")) {
          mLayerFileSlot = std::clamp(mMaskLayer + 1, 1, 8);
          mLayerFileAsk = LayerFileAsk::ExportLayer;
        }
        ImGui::EndPopup();
      }
      DrawTextureBrowser();
    }

    DrawThemes();

    if (Section("Map-wide textures")) {
      const MapTextureRow& normals = mMapTextureRows[0];
      const MapTextureRow& lighting = mMapTextureRows[1];
      const MapTextureRow& specular = mMapTextureRows[2];
      const MapTextureRow& macro = mMapTextureRows[3];
      if (!normals.available && !lighting.available && !specular.available && !macro.available) {
        Note(
          "This shader draws no map-wide textures. The numbered shaders (Terrain250...), TerrainPBR and Terrain301 "
          "read "
          "normals and lighting; Terrain001 and 051 a specular; TTerrain(XP), TTerrainXPExt, Terrain000 and 050 a "
          "macrotexture."
        );
      }
      // A row: its state's sign, its name and state, Make (or Remake) and Clear.
      const auto row = [this](const int kind, const char* const name, const MapTextureRow& state) {
        const bool fromPaint = kind >= 2;
        ImGui::PushID(kind);
        const char* const sign = state.stale ? ICON_WARN : state.present ? ICON_OK : ICON_MINUS;
        ImGui::PushStyleColor(
          ImGuiCol_Text,
          state.stale ? ImVec4(0xF0 / 255.0f, 0xB0 / 255.0f, 0x4A / 255.0f, 1.0f)
                      : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled)
        );
        ImGui::TextUnformatted(sign);
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::TextUnformatted(name);
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextDisabled("%s", state.state.c_str());
        ImGui::PopTextWrapPos();
        if (ImGui::Button(state.made || state.present ? "Remake" : "Make")) {
          AskMapTexture(kind, MapTextureOp::Make);
        }
        EdSetItemTooltip(
          "%s",
          fromPaint ? "Draw it from the paint (each layer's colour and kind of ground) and the heights, into the map's "
                      "folder"
                    : "Draw it from the map's heights, its sun and its sea, into the map's folder"
        );
        ImGui::SameLine();
        ImGui::BeginDisabled(!state.present);
        if (ImGui::Button("Clear")) {
          AskMapTexture(kind, MapTextureOp::Clear);
        }
        EdSetItemTooltip("Take it out of the slot (the shader then reads none)");
        ImGui::SameLine();
        if (ImGui::Button("Export...")) {
          AskMapTexture(kind, MapTextureOp::Export);
        }
        EdSetItemTooltip("Save the slot's texture as a .dds file");
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Import...")) {
          AskMapTexture(kind, MapTextureOp::Import);
        }
        EdSetItemTooltip("A .dds made elsewhere (packed as this shader reads it), copied into the map's folder");
        ImGui::EndGroup();
        ImGui::Spacing();
        ImGui::PopID();
      };
      if (normals.available && normals.shared) {
        row(0, "Normals and lighting (shadow, water depth)", normals);
      } else {
        if (normals.available) {
          row(0, "Normal map", normals);
        }
        if (lighting.available) {
          row(1, "Lighting (shadow, occlusion, water depth)", lighting);
        }
      }
      if (specular.available) {
        row(2, "Specular (shine colour, sharpness)", specular);
      }
      if (macro.available) {
        row(3, "Macrotexture (colour laid over the ground)", macro);
      }
    }
  }

  void EdTools::DrawLayerSlots()
  {
    if (Section("Layers")) {
      if (mSlots.size() != 10) {
        Note("Open a map to see its layers.");
        return;
      }
      if (ImGui::Button("Make a texture with nodes...", ImVec2(-1.0f, 0.0f))) {
        mMaterialAsk = std::clamp(mMaskLayer + 1, 1, 8);
      }
      EdSetItemTooltip(
        "The Material Editor (View > Material Editor), on the paint layer: textures built from nodes as in UE4, "
        "shown on the map as you edit"
      );
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
          ImGui::GetWindowDrawList()->AddRect(at, ImVec2(at.x + thumb, at.y + thumb), LineU32());
        }
        if (ImGui::IsItemClicked()) {
          mBrowseSlot = slot;
          mBrowseOpen = true;
        }
        // Strata 1 to 8 move: dragged onto another (their masks go with them), or from the right-click menu.
        if (slot >= 1 && slot <= 8) {
          if (ImGui::BeginDragDropSource()) {
            const int stratum = slot - 1;
            ImGui::SetDragDropPayload("EDITOR_LAYER", &stratum, sizeof(stratum));
            ImGui::Text("Layer %s  %s", kSlotNames[slot], LayerTextureName(layer.albedo).c_str());
            ImGui::EndDragDropSource();
          }
          if (ImGui::BeginDragDropTarget()) {
            if (const ImGuiPayload* const payload = ImGui::AcceptDragDropPayload("EDITOR_LAYER"); payload != nullptr) {
              AskLayerMove(*static_cast<const int*>(payload->Data), slot - 1);
            }
            ImGui::EndDragDropTarget();
          }
          if (ImGui::BeginPopupContextItem("##layermove")) {
            if (ImGui::MenuItem("Move up", nullptr, false, slot < 8)) {
              AskLayerMove(slot - 1, slot);
            }
            if (ImGui::MenuItem("Move down", nullptr, false, slot > 1)) {
              AskLayerMove(slot - 1, slot - 2);
            }
            ImGui::EndPopup();
          }
        }
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::Text("%s  %s", kSlotNames[slot], LayerTextureName(layer.albedo).c_str());
        if (ImGui::IsItemHovered() && !layer.albedo.empty()) {
          EdSetTooltip(
            "%s\n%s", layer.albedo.c_str(), layer.normals.empty() ? "(no normal map)" : layer.normals.c_str()
          );
        }
        // What the shader makes of this slot (FAF's newer shaders keep some for map-wide data), and whether it does
        // now.
        if (const ShaderSlotUse use = ShaderSlotUseOf(mShader, slot); !use.text.empty()) {
          ImGui::PushTextWrapPos(0.0f);
          ImGui::TextColored(
            use.mapWide ? ImVec4(0.95f, 0.75f, 0.30f, 1.0f) : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled),
            "%s",
            use.text.c_str()
          );
          ImGui::PopTextWrapPos();
          if (use.mapWide && mMapSizeUnits > 0.0f) {
            const bool on = MapWideOn(layer.albedoSize, mMapSizeUnits);
            ImGui::TextDisabled(
              on ? "On: its size is above the map's (%.0f)."
                 : "Off, read as an ordinary layer: its size isn't above the map's (%.0f).",
              mMapSizeUnits
            );
            EdSetItemTooltip(
              "terrain.fx reads the slot as map-wide data only when its size is above the map's, so the tile value is "
              "under 1; FAF's map tools bake the texture."
            );
          }
        }
        ImGui::SetNextItemWidth(-1.0f);
        float size = layer.albedoSize;
        if (FillDragFloat("##size", &size, 0.05f, 0.1f, 1024.0f, "Size %.2f") && size > 0.0f) {
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
        ImGui::SetNextItemWidth(-Em(80.0f));
        if (EdBeginCombo("##shader", ("Shader " + mShader).c_str())) {
          for (const std::string& shader : mShaders) {
            if (ImGui::Selectable(shader.c_str(), shader == mShader) && shader != mShader) {
              mShaderChange = shader;
            }
          }
          ImGui::EndCombo();
        }
        ImGui::SameLine();
        if (ImGui::Button("Browse...", ImVec2(-1.0f, 0.0f))) {
          mShaderBrowserOpen = true;
          mBrowsedShader = mShader;
        }
        DrawShaderBrowser();
      }
    }
    if (Section("Layer files")) {
      {
        static const char* const kFileSlots[10] = {"Lower", "1", "2", "3", "4", "5", "6", "7", "8", "Upper"};
        mLayerFileSlot = std::clamp(mLayerFileSlot, 0, 9);
        ImGui::SetNextItemWidth(-1.0f);
        if (EdBeginCombo("##layerfileslot", (std::string("Layer ") + kFileSlots[mLayerFileSlot]).c_str())) {
          for (int slot = 0; slot < 10; ++slot) {
            if (ImGui::Selectable(kFileSlots[slot], slot == mLayerFileSlot)) {
              mLayerFileSlot = slot;
            }
          }
          ImGui::EndCombo();
        }
        if (ImGui::Button("Import layer...")) {
          mLayerFileAsk = LayerFileAsk::ImportLayer;
        }
        ImGui::SameLine();
        if (ImGui::Button("Export layer...")) {
          mLayerFileAsk = LayerFileAsk::ExportLayer;
        }
        if (ImGui::Button("Import set...")) {
          mLayerFileAsk = LayerFileAsk::ImportSet;
        }
        ImGui::SameLine();
        if (ImGui::Button("Export set...")) {
          mLayerFileAsk = LayerFileAsk::ExportSet;
        }
        Note(
          "FAForeverMapEditor's layer files: one layer's textures and sizes (.scmsl), or the shader and all ten layers "
          "(.scmst). An import is one undo step; the masks stay as they are."
        );
      }
      DrawTextureBrowser();
    }
  }

  void EdTools::DrawTerrainTypes()
  {
    if (Section("Terrain type")) {
      const auto describe = [this](const int code) -> std::string {
        for (const TerrainTypeInfo& type : mTerrainTypes) {
          if (type.code == code) {
            return type.description.empty() ? type.name : type.description + " (" + type.name + ")";
          }
        }
        return "type " + std::to_string(code);
      };
      if (mTerrainTypes.empty()) {
        Note("The types come from the game's /lua/TerrainTypes.lua once it is read.");
      } else {
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint(
          "##typefilter", "search type or style", mTerrainTypeFilter, sizeof(mTerrainTypeFilter)
        );
        std::string filter = mTerrainTypeFilter;
        for (char& c : filter) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (
          ImGui::BeginChild(
            "##terraintypes",
            ImVec2(
              0.0f, FillHeight(ImGui::GetFrameHeightWithSpacing() * 4.0f, ImGui::GetTextLineHeightWithSpacing() * 8.0f)
            ),
            ImGuiChildFlags_Borders
          )
        ) {
          for (const TerrainTypeInfo& type : mTerrainTypes) {
            std::string key = type.name + " " + type.description + " " + type.style;
            for (char& c : key) {
              c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (!filter.empty() && key.find(filter) == std::string::npos) {
              continue;
            }
            ImGui::PushID(type.code);
            // The type's colour (its file's ARGB) as a swatch, then its code, description and style.
            const ImVec4 swatch(
              static_cast<float>((type.color >> 16) & 0xFF) / 255.0f,
              static_cast<float>((type.color >> 8) & 0xFF) / 255.0f,
              static_cast<float>(type.color & 0xFF) / 255.0f,
              1.0f
            );
            ImGui::ColorButton(
              "##swatch",
              swatch,
              ImGuiColorEditFlags_NoTooltip,
              ImVec2(ImGui::GetFrameHeight(), ImGui::GetFrameHeight() * 0.8f)
            );
            ImGui::SameLine();
            char label[200];
            (void)std::snprintf(
              label,
              sizeof(label),
              "%3d  %s%s",
              type.code,
              type.description.empty() ? type.name.c_str() : type.description.c_str(),
              type.blocking ? "  (blocking)" : ""
            );
            if (ImGui::Selectable(label, type.code == mTerrainTypeCode)) {
              mTerrainTypeCode = type.code;
            }
            if (ImGui::IsItemHovered()) {
              EdSetTooltip("%s, %s", type.name.c_str(), type.style.empty() ? "no style" : type.style.c_str());
            }
            ImGui::PopID();
          }
        }
        ImGui::EndChild();
        ImGui::Text("Painting: %s", describe(mTerrainTypeCode).c_str());
        ImGui::TextDisabled("Under the cursor: %s", mTypeUnderCursor < 0 ? "-" : describe(mTypeUnderCursor).c_str());
      }
      ImGui::Checkbox("Show the types on the ground", &mShowTerrainTypes);
      DrawBrush(false);
      DrawSymmetry(false);
      Note(
        "Each cell has a type: its effects (dust, wakes), and for some (lava) whether units can go there. A stroke "
        "paints the "
        "type in the brush, with its symmetric copies, as one undo step; the Default type (1) isn't drawn."
      );
    }
  }

  void EdTools::DrawTextureBrowser()
  {
    constexpr const char* kTitle = "Layer textures";
    if (mBrowseOpen) {
      mBrowseOpen = false;
      ImGui::OpenPopup(kTitle);
    }
    // Most of the editor's window each time it opens, centred: the textures large enough to tell apart (user report: it
    // was small).
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.72f, viewport->WorkSize.y * 0.78f), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(
      ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
      ImGuiCond_Appearing,
      ImVec2(0.5f, 0.5f)
    );
    if (!ImGui::BeginPopupModal(kTitle, nullptr)) {
      return;
    }
    ImGui::Text(
      "Layer %s", mBrowseSlot == 0 ? "Lower" : (mBrowseSlot == 9 ? "Upper" : std::to_string(mBrowseSlot).c_str())
    );
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(260.0f));
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
    {
      static const char* const kPick[] = {"Texture", "Normal map only"};
      int pick = mBrowseNormals ? 1 : 0;
      ImGui::SetNextItemWidth(Em(170.0f));
      if (EdCombo("##browsepick", &pick, kPick, 2)) {
        mBrowseNormals = pick == 1;
      }
      EdSetItemTooltip(
        "Texture: the albedo with the normal map beside it. Normal map only: the layer keeps its albedo and takes "
        "this normal map"
      );
    }
    if (mBrowseNormals) {
      ImGui::SameLine();
      ImGui::Checkbox("Relief", &mBrowseRelief);
      EdSetItemTooltip("Normal maps shown as lit relief (bumps as bumps), else as their raw colours");
      if (mBrowseSlot >= 0 && mBrowseSlot < static_cast<int>(mSlots.size())) {
        ImGui::SameLine();
        if (ImGui::Button("No normal map")) {
          mChangedSlot = mBrowseSlot;
          mChangedValue = mSlots[static_cast<std::size_t>(mBrowseSlot)];
          mChangedValue.normals.clear();
          ImGui::CloseCurrentPopup();
        }
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Make one with nodes...")) {
      mMaterialAsk = mBrowseSlot;
      ImGui::CloseCurrentPopup();
    }
    EdSetItemTooltip(
      "Opens the Material Editor on this layer: build its texture from nodes (noise, textures, blends) and see it on "
      "the map "
      "as you go; Apply writes it into the map"
    );
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    std::string filter = mBrowseFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (ImGui::BeginChild("##grid", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
      const float cell = 128.0f;
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
        if (mBrowseNormals && texture.normals.empty()) {
          continue; // (normal maps only)
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
        const std::uint64_t image = !mBrowseNormals ? mLibrary.Thumbnail(texture.path)
          : mBrowseRelief                           ? mLibrary.Relief(texture.normals)
                                                    : mLibrary.Thumbnail(texture.normals);
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
          EdSetTooltip(
            "%s\n%s",
            texture.path.c_str(),
            texture.normals.empty() ? "(no normal map beside it)" : texture.normals.c_str()
          );
        }
        if (picked && mBrowseSlot >= 0 && mBrowseSlot < static_cast<int>(mSlots.size())) {
          mChangedSlot = mBrowseSlot;
          mChangedValue = mSlots[static_cast<std::size_t>(mBrowseSlot)];
          if (mBrowseNormals) {
            mChangedValue.normals = texture.normals;
          } else {
            mChangedValue.albedo = texture.path;
            if (!texture.normals.empty()) {
              mChangedValue.normals = texture.normals;
            }
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
    if (Section("Paint")) {
      static const char* const kTargets[] = {"Layer masks", "Terrain types"};
      mTexturePaint = std::clamp(mTexturePaint, 0, 1);
      Segmented(kTargets, 2, mTexturePaint);
      if (mTexturePaint == 1) {
        DrawTerrainTypes();
        DrawTypesFromLayers();
        return;
      }
      if (!mPaintNote.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.3f, 1.0f));
        ImGui::TextWrapped("%s", mPaintNote.c_str());
        ImGui::PopStyleColor();
      }
    }
    {
      // The paint layer is picked in the Layers panel (the right dock), where the layers are.
      const std::string path =
        mSlots.size() == 10 ? mSlots[static_cast<std::size_t>(mMaskLayer + 1)].albedo : std::string();
      ImGui::TextDisabled("Painting layer %d  %s", mMaskLayer + 1, LayerLabel(path).c_str());
      EdSetItemTooltip("Pick the layer to paint, its texture and its order in the Layers panel");
    }
    if (Section("Brush")) {
      static const char* const kMaskModes[] = {"Paint", "Erase", "Smooth"};
      Segmented(kMaskModes, 3, mMaskMode);
      ImGui::Checkbox("Lower the layers above", &mLowerAbove);
      ImGui::Checkbox("Show the layer's weight", &mShowWeight);
      {
        const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
        float target = mMaskTarget * 100.0f;
        ImGui::SetNextItemWidth(half);
        if (FillSliderFloat("##masktarget", &target, 5.0f, 100.0f, "Up to %.0f%%")) {
          mMaskTarget = target / 100.0f;
        }
        ImGui::SameLine();
        float scatter = mMaskScatter * 100.0f;
        ImGui::SetNextItemWidth(-1.0f);
        if (
          FillSliderFloat("##maskscatter", &scatter, 0.0f, 100.0f, scatter <= 0.0f ? "No scatter" : "Scatter %.0f%%")
        ) {
          mMaskScatter = scatter / 100.0f;
        }
        ImGui::SetNextItemWidth(half);
        FillSliderFloat(
          "##maskminslope",
          &mMaskMinSlopeDegrees,
          0.0f,
          60.0f,
          mMaskMinSlopeDegrees <= 0.0f ? "Any slope" : "Steeper than %.0f deg"
        );
        ImGui::SameLine();
        ImGui::Checkbox("Build up", &mMaskBuildUp);
        Note(
          "Paint stops at its Up to share. Without Build up, a stroke gives each texel the strongest weight any of its "
          "dabs gave it, so going over a spot again doesn't add more. Scatter speckles the edge, the same at every "
          "copy."
        );
      }
      DrawShapePicker();
      DrawBrush(false);
      DrawSymmetry(true);
      DrawLimits();
    }
    if (Section("Rules")) {
      Note(
        "Each rule sets its layer to full where the ground is in its height and slope range; they run in order over "
        "the "
        "whole map."
      );
      int remove = -1;
      for (std::size_t i = 0; i < mRules.size(); ++i) {
        MaskRule& rule = mRules[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::SetNextItemWidth(Em(70.0f));
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
          if (
            ImGui::DragFloatRange2("##slopes", &lowDegrees, &highDegrees, 0.5f, 0.0f, 90.0f, "%.0f deg", "%.0f deg")
          ) {
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
    DrawMaskGenerator();
    DrawRecipes();
  }

  bool EdTools::RunLayerMenuItem(
    const int slot,
    const std::string& item
  )
  {
    if (slot < 0 || slot >= static_cast<int>(mSlots.size())) {
      return false;
    }
    const LayerSlot& layer = mSlots[static_cast<std::size_t>(slot)];
    const bool stratum = slot >= 1 && slot <= 8;
    if (item == "fill" && stratum) {
      mMaskLayer = slot - 1;
      mMaskOp = MaskOp::Fill;
      return true;
    }
    if (item == "remove" && slot >= 1 && !layer.albedo.empty()) {
      mChangedSlot = slot;
      mChangedValue = layer;
      mChangedValue.albedo.clear();
      mChangedValue.normals.clear();
      mChangedValue.albedoSize = 4.0f;
      mChangedValue.normalsSize = 4.0f;
      if (stratum) {
        mMaskLayer = slot - 1;
        mMaskOp = MaskOp::Clear;
      }
      return true;
    }
    if (item == "optimal" && slot < 9 && mOptimalTiles[static_cast<std::size_t>(slot)] > 0.0f) {
      mChangedSlot = slot;
      mChangedValue = layer;
      mChangedValue.albedoSize = mOptimalTiles[static_cast<std::size_t>(slot)];
      mChangedValue.normalsSize = mOptimalTiles[static_cast<std::size_t>(slot)];
      return true;
    }
    return false;
  }

  void EdTools::DrawTypesFromLayers()
  {
    if (!Section("From the textures")) {
      return;
    }
    Note(
      "Each layer has a terrain type: by default the one its texture's name suggests (sand, rock, snow, lava ...). "
      "Generate "
      "gives every cell the type of the layer seen most there. One undo step."
    );
    const auto nameOf = [this](const int code) -> std::string {
      for (const TerrainTypeInfo& type : mTerrainTypes) {
        if (type.code == code) {
          return type.name.empty() ? "type " + std::to_string(code) : type.name;
        }
      }
      return "type " + std::to_string(code);
    };
    static const char* const kSlotNames[] = {"Base", "1", "2", "3", "4", "5", "6", "7", "8"};
    for (int layer = 0; layer <= 8 && layer < static_cast<int>(mSlots.size()); ++layer) {
      const LayerSlot& slot = mSlots[static_cast<std::size_t>(layer)];
      if (slot.albedo.empty()) {
        continue;
      }
      ImGui::PushID(layer);
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(kSlotNames[layer]);
      ImGui::SameLine(Em(40.0f));
      ImGui::TextUnformatted(LayerTextureName(slot.albedo).c_str());
      ImGui::SameLine(std::max(Em(150.0f), ImGui::GetContentRegionAvail().x * 0.5f));
      int& chosen = mLayerTypeOverride[static_cast<std::size_t>(layer)];
      const std::string automatic = "Auto: " + nameOf(DefaultTerrainTypeFor(slot.albedo, mTerrainTypes));
      ImGui::SetNextItemWidth(-1.0f);
      if (EdBeginCombo("##type", chosen < 0 ? automatic.c_str() : nameOf(chosen).c_str())) {
        if (ImGui::Selectable(automatic.c_str(), chosen < 0)) {
          chosen = -1;
        }
        for (const TerrainTypeInfo& type : mTerrainTypes) {
          if (ImGui::Selectable(nameOf(type.code).c_str(), chosen == type.code)) {
            chosen = type.code;
          }
        }
        ImGui::EndCombo();
      }
      ImGui::PopID();
    }
    ImGui::Checkbox("Only cells with the Default type", &mTypesOnlyDefault);
    ImGui::SetItemTooltip("Keep the types already painted; only cells still Default take their layer's type");
    if (ImGui::Button("Generate from the textures")) {
      mTypesFromLayersAsk = true;
    }
  }

  void EdTools::DrawThemes()
  {
    mLayersShown = true;
    if (!Section("Texture sets")) {
      return;
    }
    Note(
      "A set of textures for every kind of ground: the base layer, each kind's layer for this shader and the Upper "
      "layer, at their optimal tile sizes. The paint stays. Try it, then keep it or go back; Apply keeps it at once."
    );
    std::vector<const char*> names;
    for (const TextureTheme& theme : TextureThemes()) {
      names.push_back(theme.label);
    }
    ImGui::BeginDisabled(mThemeTrying);
    ImGui::SetNextItemWidth(-1.0f);
    (void)EdCombo("##theme", &mThemeIndex, names.data(), static_cast<int>(names.size()));
    ImGui::EndDisabled();
    // What it would give each layer, in columns: the layer, its kind, the texture, its tile.
    for (const std::string& line : mThemePreview) {
      static const float kColumns[] = {0.0f, 44.0f, 124.0f, 290.0f};
      const float left = ImGui::GetCursorPosX();
      std::size_t at = 0;
      for (int column = 0; column < 4 && at <= line.size(); ++column) {
        const std::size_t tab = std::min(line.find('\t', at), line.size());
        if (column > 0) {
          ImGui::SameLine(left + Em(kColumns[column]));
        }
        ImGui::TextDisabled("%s", line.substr(at, tab - at).c_str());
        at = tab + 1;
      }
    }
    if (mThemeTrying) {
      if (PrimaryButton("Keep it")) {
        mThemeOp = ThemeOp::Keep;
      }
      ImGui::SameLine();
      if (ImGui::Button("Back to before")) {
        mThemeOp = ThemeOp::Back;
      }
    } else {
      if (ImGui::Button("Try")) {
        mThemeOp = ThemeOp::Try;
      }
      EdSetItemTooltip("Put the set on the layers to look at it\nKeep it or go back to the textures before.");
      ImGui::SameLine();
      if (ImGui::Button("Apply")) {
        mThemeOp = ThemeOp::Apply;
      }
      EdSetItemTooltip("Put the set on the layers\nOne undo step.");
    }
  }

  void EdTools::DrawRecipes()
  {
    mRecipesOpen = Section("Stratum recipes");
    if (!mRecipesOpen) {
      return;
    }
    Note(
      "Paints the layers with the kinds of ground a landscape is made of (grass, dirt, wet ground, sand, rock, dark "
      "rock, "
      "high rock, snow), from the map's own heights, slopes and water. Each layer's kind comes from its texture; "
      "correct "
      "it below. One undo step."
    );
    // The style.
    std::vector<const char*> styles;
    for (const faf::editor::RecipeStyle& style : RecipeStyles()) {
      styles.push_back(style.name);
    }
    int style = mRecipeStyle;
    ImGui::SetNextItemWidth(-1.0f);
    if (EdCombo("##recipestyle", &style, styles.data(), static_cast<int>(styles.size()))) {
      SetRecipeStyle(style);
    }
    // The layers and their kinds.
    ImGui::TextDisabled("Kind of ground of each layer");
    static const char* const kKinds[] = {
      "Not used", "Grass", "Rock", "Sand", "Dirt", "Wet ground", "High rock", "Dark rock", "Snow"
    };
    for (int layer = 0; layer <= mRecipeCap && layer < 9; ++layer) {
      const std::string& name = mRecipeNames[static_cast<std::size_t>(layer)];
      if (name.empty()) {
        continue;
      }
      ImGui::PushID(layer);
      ImGui::AlignTextToFramePadding();
      if (layer == 0) {
        ImGui::TextUnformatted("Base");
      } else {
        ImGui::Text("%d", layer);
      }
      ImGui::SameLine(Em(40.0f));
      ImGui::TextUnformatted(name.c_str());
      ImGui::SameLine(std::max(Em(150.0f), ImGui::GetContentRegionAvail().x * 0.5f));
      int& chosen = mRecipeOverride[static_cast<std::size_t>(layer)];
      const GroundKind detected = mRecipeDetected[static_cast<std::size_t>(layer)];
      char automatic[48];
      std::snprintf(automatic, sizeof(automatic), "Auto: %s", kKinds[static_cast<int>(detected)]);
      ImGui::SetNextItemWidth(-1.0f);
      if (EdBeginCombo("##kind", chosen < 0 ? automatic : kKinds[chosen])) {
        if (ImGui::Selectable(automatic, chosen < 0)) {
          chosen = -1;
        }
        for (int k = 1; k <= 8; ++k) {
          if (ImGui::Selectable(kKinds[k], chosen == k)) {
            chosen = k;
          }
        }
        if (ImGui::Selectable("Not used (leave this layer alone)", chosen == 0)) {
          chosen = 0;
        }
        ImGui::EndCombo();
      }
      ImGui::PopID();
    }
    // The settings.
    if (ImGui::TreeNode("Settings")) {
      for (const RecipeKnobInfo& knob : RecipeKnobList()) {
        ImGui::SetNextItemWidth(Em(120.0f));
        ImGui::SliderFloat(knob.label, &(mRecipeKnobs.*knob.member), knob.min, knob.max, knob.format);
      }
      if (ImGui::Button("Back to the style's values")) {
        mRecipeKnobs = RecipeKnobsOf(mRecipeStyle);
      }
      ImGui::TreePop();
    }
    if (ImGui::Button("Paint the map")) {
      mRecipeApply = true;
    }
    EdSetItemTooltip(
      "Paint every layer of a known kind over the whole map\nOne undo step; the brush's symmetry applies."
    );
    if (!mRecipeResult.empty()) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", mRecipeResult.c_str());
      ImGui::PopTextWrapPos();
    }
    // `/panelbottom` (test runs): the panel kept scrolled to its end, so this section shows in a capture.
    static const bool toBottom = moho::CFG_GetArgOption("/panelbottom", 0, nullptr);
    if (toBottom) {
      ImGui::SetScrollHereY(1.0f);
    }
  }

  void EdTools::DrawMaskGenerator()
  {
    mGenOpen = Section("Mask generator");
    if (!mGenOpen) {
      return;
    }
    Note(
      "Rules make a mask over the whole map from the ground: each source rule combines with what the rules above made, "
      "each modifier changes it. The preview shows it; Write puts it into a layer as one undo step."
    );
    // Starting points.
    ImGui::SetNextItemWidth(-1.0f);
    if (EdBeginCombo("##genpreset", "Start from...")) {
      for (const MaskPreset& preset : MaskPresets()) {
        if (ImGui::Selectable(preset.name)) {
          AskGenPreset(preset.id);
        }
      }
      ImGui::EndCombo();
    }
    // The rules.
    bool changed = false;
    int remove = -1;
    int moveUp = -1;
    for (std::size_t i = 0; i < mGenRules.size(); ++i) {
      MaskGenRule& rule = mGenRules[i];
      const MaskRuleSpec* const spec = MaskRuleSpecOf(rule.type);
      if (spec == nullptr) {
        continue;
      }
      ImGui::PushID(static_cast<int>(i));
      const float rightEdge = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
      // A modifier works on the rules above it: indented under them.
      const float indent = spec->modifier ? Em(16.0f) : 0.0f;
      if (indent > 0.0f) {
        ImGui::Indent(indent);
      }
      changed |= ImGui::Checkbox("##on", &rule.enabled);
      EdSetItemTooltip("Use this rule");
      ImGui::SameLine();
      const bool open =
        ImGui::TreeNodeEx("##rule", ImGuiTreeNodeFlags_AllowOverlap, "%s", DescribeMaskRule(rule).c_str());
      const ImGuiStyle& style = ImGui::GetStyle();
      const float buttons = ImGui::CalcTextSize("Up").x + ImGui::CalcTextSize("Remove").x +
        style.FramePadding.x * 4.0f + style.ItemSpacing.x;
      ImGui::SameLine(rightEdge - buttons);
      ImGui::BeginDisabled(i == 0);
      if (ImGui::SmallButton("Up")) {
        moveUp = static_cast<int>(i);
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      if (ImGui::SmallButton("Remove")) {
        remove = static_cast<int>(i);
      }
      if (open) {
        if (!spec->modifier) {
          if (i > 0) {
            static const char* const kOps[] = {
              "AND (the smaller)", "OR (the larger)", "Multiply", "Difference (minus)", "Add"
            };
            int op = static_cast<int>(rule.op);
            ImGui::SetNextItemWidth(Em(150.0f));
            if (EdCombo("With the rules above", &op, kOps, 5)) {
              rule.op = static_cast<MaskCombine>(op);
              changed = true;
            }
          }
          changed |= ImGui::Checkbox("Invert (not)", &rule.invert);
        }
        for (const MaskParamSpec& param : spec->params) {
          float value = rule.Value(param.key);
          ImGui::SetNextItemWidth(Em(120.0f));
          if (ImGui::SliderFloat(param.label, &value, param.min, param.max, param.format)) {
            if (param.step >= 1.0f) {
              value = std::round(value / param.step) * param.step;
            }
            rule.v[param.key] = value;
            changed = true;
          }
        }
        ImGui::TreePop();
      }
      if (indent > 0.0f) {
        ImGui::Unindent(indent);
      }
      ImGui::PopID();
    }
    if (remove >= 0) {
      mGenRules.erase(mGenRules.begin() + remove);
      changed = true;
    } else if (moveUp > 0) {
      std::swap(mGenRules[static_cast<std::size_t>(moveUp)], mGenRules[static_cast<std::size_t>(moveUp - 1)]);
      changed = true;
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (EdBeginCombo("##genadd", "Add a rule...")) {
      bool modifiers = false;
      for (const MaskRuleSpec& spec : MaskRuleCatalogue()) {
        if (spec.modifier && !modifiers) {
          ImGui::SeparatorText("Change the result");
          modifiers = true;
        }
        if (ImGui::Selectable(spec.label)) {
          mGenRules.push_back(NewMaskRule(spec.id));
          changed = true;
        }
      }
      ImGui::EndCombo();
    }
    if (changed) {
      ++mGenRevision;
    }
    // The preview.
    if (mGenPreviewImage != 0) {
      const float side = std::min(ImGui::GetContentRegionAvail().x, Em(180.0f));
      ImGui::Image(static_cast<ImTextureID>(mGenPreviewImage), ImVec2(side, side));
    }
    if (!mGenNote.empty()) {
      ImGui::TextDisabled("%s", mGenNote.c_str());
    } else if (!mGenRules.empty()) {
      ImGui::TextDisabled("The mask covers %.1f %% of the map", static_cast<double>(mGenCoverage * 100.0f));
    }
    // Where it goes.
    ImGui::SetNextItemWidth(Em(120.0f));
    if (ImGui::InputInt("Layer", &mGenTarget.layer)) {
      mGenTarget.layer = std::clamp(mGenTarget.layer, 1, 8);
    }
    static const char* const kModes[] = {"Replace", "Add to", "Subtract from"};
    int mode = static_cast<int>(mGenTarget.mode);
    ImGui::SetNextItemWidth(Em(120.0f));
    if (EdCombo("How", &mode, kModes, 3)) {
      mGenTarget.mode = static_cast<MaskWriteMode>(mode);
    }
    ImGui::SetNextItemWidth(Em(120.0f));
    ImGui::SliderFloat("Strength", &mGenTarget.strength, 0.0f, 1.0f, "%.2f");
    ImGui::Checkbox("Only where the layers above leave it free", &mGenTarget.takeAway);
    ImGui::BeginDisabled(mGenRules.empty());
    char label[48];
    std::snprintf(label, sizeof(label), "Write into layer %d", mGenTarget.layer);
    if (ImGui::Button(label)) {
      mGenApply = true;
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
    if (Section("Sea")) {
      if (ImGui::Checkbox("The map has a sea", &mWater.enabled)) {
        mWaterChanged = true;
        mWaterFinal = true;
      }
      ImGui::BeginDisabled(!mWater.enabled);
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##level", &mWater.elevation, 0.1f, 0.0f, 512.0f, "Level %.2f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##deep", &mWater.deep, 0.1f, 0.0f, 512.0f, "Deep %.2f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##abyss", &mWater.abyss, 0.1f, 0.0f, 512.0f, "Abyss %.2f"));
      if (mWater.enabled && (mWater.deep >= mWater.elevation || mWater.abyss >= mWater.deep)) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
        ImGui::TextWrapped(
          "Deep should be below the level and abyss below deep: the water's colour runs from the level down to them."
        );
        ImGui::PopStyleColor();
      }
      Note(
        "The level is where the sea's surface is; deep and abyss are the heights the water's colour darkens towards. "
        "Units, the shore and the minimap all follow the level."
      );
      ImGui::EndDisabled();
      DrawWaterBodies();
    }
    // The water's look: greyed while the map has no sea.
    WaterNumbers& s = mWater.shader;
    if (Section("Look")) {
      ImGui::BeginDisabled(!mWater.enabled);
      ImGui::SetNextItemWidth(-1.0f);
      changed(ImGui::ColorEdit3("##watercolor", s.mWaterColor, ImGuiColorEditFlags_Float));
      ImGui::SetNextItemWidth(-1.0f);
      changed(ImGui::DragFloat2("##waterlerp", s.mWaterLerp, 0.005f, 0.0f, 1.0f, "Lerp %.3f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##refraction", &s.mRefractionScale, 0.005f, 0.0f, 2.0f, "Refraction %.3f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##fresnelbias", &s.mFresnelBias, 0.005f, 0.0f, 1.0f, "Fresnel bias %.3f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##fresnelpower", &s.mFresnelPower, 0.01f, 0.0f, 10.0f, "Fresnel power %.2f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##unitreflection", &s.mUnitReflectionAmount, 0.005f, 0.0f, 1.0f, "Unit reflection %.3f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##skyreflection", &s.mSkyReflectionAmount, 0.005f, 0.0f, 3.0f, "Sky reflection %.3f"));
      ImGui::EndDisabled();
    }
    if (Section("Sun on the water")) {
      ImGui::BeginDisabled(!mWater.enabled);
      ImGui::SetNextItemWidth(-1.0f);
      changed(ImGui::ColorEdit3("##suncolor", s.mSunColor, ImGuiColorEditFlags_Float));
      // The water keeps the way the light travels (retail maps: 0.1, -0.963, 0.252, straight down nearly); shown as
      // where the sun is, as the Lighting panel shows its sun.
      float towards[3] = {-s.mSunDirection[0], -s.mSunDirection[1], -s.mSunDirection[2]};
      float azimuth = 0.0f, elevation = 0.0f;
      SunAnglesOf(towards, azimuth, elevation);
      ImGui::SetNextItemWidth(-1.0f);
      const bool turned = FillSliderFloat("##waterazimuth", &azimuth, -180.0f, 180.0f, "Azimuth %.0f\xC2\xB0");
      changed(turned);
      ImGui::SetNextItemWidth(-1.0f);
      const bool raised = FillSliderFloat("##waterelevation", &elevation, 0.0f, 90.0f, "Elevation %.0f\xC2\xB0");
      changed(raised);
      if (turned || raised) {
        SunDirectionOf(azimuth, elevation, towards);
        for (int i = 0; i < 3; ++i) {
          s.mSunDirection[i] = -towards[i];
        }
      }
      ImGui::Checkbox("Follow the lighting sun", &mWaterSunFollows);
      EdSetItemTooltip(
        "Follow the lighting sun\nTurning the sun in the Lighting panel turns the water's sun with it, in the same "
        "undo "
        "step. Opening a map never changes it."
      );
      if (!mWaterSunFollows) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Take it now")) {
          mWaterTakeLightingSun = true;
        }
      }
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##sunstrength", &s.mSunStrength, 0.05f, 0.0f, 20.0f, "Strength %.2f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##sunshininess", &s.mSunShininess, 0.5f, 0.0f, 500.0f, "Shininess %.1f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##sunreflection", &s.mSunReflectionAmount, 0.01f, 0.0f, 10.0f, "Reflection %.2f"));
      ImGui::SetNextItemWidth(-1.0f);
      changed(FillDragFloat("##sunglow", &s.mSunGlow, 0.01f, 0.0f, 10.0f, "Glow %.2f"));
      ImGui::EndDisabled();
    }
    if (Section("Waves")) {
      ImGui::BeginDisabled(!mWater.enabled);
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
      for (int p = 0; p < kWaterMotionPresetCount; ++p) {
        if (p > 0) {
          ImGui::SameLine();
        }
        if (ImGui::SmallButton(WaterMotionPresetName(p))) {
          ApplyWaterMotionPreset(s, p);
          mWaterChanged = true;
          mWaterFinal = true; // one undo step
        }
      }
      ImGui::EndDisabled();
    }
    if (Section("Water masks", false)) {
      // A drag in the view paints the chosen mask (half the map's resolution), with the symmetry's copies; one undo
      // step a stroke. The overlay shows the mask where it isn't at its default.
      ImGui::Checkbox("Paint in the view", &mWaterMaskPaint);
      static const char* const kMasks[] = {"Foam", "Flatness", "Depth bias"};
      const int kindBefore = mWaterMaskKind;
      Segmented(kMasks, 3, mWaterMaskKind);
      if (mWaterMaskKind != kindBefore) {
        mWaterMaskValue = mWaterMaskKind == 1 ? 0 : 255; // the useful end: foam on, flatness off (calm), bias up
      }
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderInt("##watermaskvalue", &mWaterMaskValue, 0, 255, "Towards %d");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##watermaskradius", &mWaterMaskBrush.radius, 2.0f, 128.0f, "Radius %.0f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##watermaskstrength", &mWaterMaskBrush.strength, 0.01f, 1.0f, "Strength %.2f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##watermaskfalloff", &mWaterMaskBrush.falloff, 0.0f, 1.0f, "Falloff %.2f");
      DrawSymmetry(false);
      Note(
        mWaterMaskKind == 0 ? "Foam: white water on the surface, 0 none (the default) to 255 full."
          : mWaterMaskKind == 1
          ? "Flatness: how much the waves move the surface, 255 (the default) fully, 0 calm."
          : "Depth bias: kept and saved with the map; the game draws nothing with it (127 default)."
      );
    }
    if (Section("Settings file")) {
      if (ImGui::Button("Import .scmwtr...")) {
        mWaterImport = true;
      }
      ImGui::SameLine();
      if (ImGui::Button("Export...")) {
        mWaterExport = true;
      }
      Note(
        "FAForeverMapEditor's water settings file. Import takes its look (colour, reflections, sun, waves) and its "
        "textures, and keeps this map's levels."
      );
    }
    if (Section("Textures")) {
      static const char* const kTextureNames[6] = {
        "Cubemap", "Ramp", "Normals 1", "Normals 2", "Normals 3", "Normals 4"
      };
      for (int i = 0; i < 6; ++i) {
        ImGui::PushID(i);
        ImGui::TextDisabled("%s", kTextureNames[i]);
        ImGui::SameLine(Em(90.0f));
        ImGui::SetNextItemWidth(-1.0f);
        char path[260];
        (void)std::snprintf(path, sizeof(path), "%s", mWater.textures[i].c_str());
        if (
          ImGui::InputText("##texture", path, sizeof(path), ImGuiInputTextFlags_EnterReturnsTrue) &&
          mWater.textures[i] != path
        ) {
          mWater.textures[i] = path;
          mWaterChanged = true;
          mWaterFinal = true;
        }
        active = active || ImGui::IsItemActive();
        if (ImGui::IsItemHovered() && !mWater.textures[i].empty()) {
          EdSetTooltip("%s", mWater.textures[i].c_str());
        }
        ImGui::PopID();
      }
      for (int i = 0; i < 6; ++i) {
        if (i > 0) {
          ImGui::SameLine();
        }
        ImGui::PushID(100 + i);
        if (ImGui::SmallButton(kTextureNames[i])) {
          mWaterTexturePick = i;
          mWaterTexturePickOpen = true;
          mWaterTextureFilter[0] = '\0';
        }
        ImGui::PopID();
      }
      Note(
        "A game path (/textures/engine/waves.dds); Enter applies it as one undo step. The buttons pick one from the "
        "game's textures."
      );
      DrawWaterTexturePicker();
      mWaterEditing = active;
    }
    if (Section("Shore waves")) {
      {
        if (mWavePatterns.empty()) {
          mWavePatterns = BuiltInWavePatterns();
        }
        mWavePattern = std::clamp(mWavePattern, 0, static_cast<int>(mWavePatterns.size()) - 1);
        char count[64];
        (void)std::snprintf(count, sizeof(count), "%d wave generator%s", mWaveCount, mWaveCount == 1 ? "" : "s");
        ImGui::TextUnformatted(count);
        ImGui::SetNextItemWidth(-1.0f);
        if (EdBeginCombo("##wavepattern", mWavePatterns[static_cast<std::size_t>(mWavePattern)].name.c_str())) {
          for (std::size_t i = 0; i < mWavePatterns.size(); ++i) {
            if (ImGui::Selectable(mWavePatterns[i].name.c_str(), static_cast<int>(i) == mWavePattern)) {
              mWavePattern = static_cast<int>(i);
            }
            if (ImGui::IsItemHovered()) {
              EdSetTooltip("%s\n%s", mWavePatterns[i].texture.c_str(), mWavePatterns[i].ramp.c_str());
            }
          }
          ImGui::EndCombo();
        }
        ImGui::SetNextItemWidth(-1.0f);
        FillDragFloat("##wavedepth", &mWaveDepth, 0.05f, 0.0f, 50.0f, "Depth below the sea %.2f");
        ImGui::SetNextItemWidth(-1.0f);
        float percent = mWaveDensity * 100.0f;
        if (FillSliderFloat("##wavedensity", &percent, 1.0f, 100.0f, "Density %.0f%%")) {
          mWaveDensity = percent / 100.0f;
        }
        ImGui::SetNextItemWidth(-1.0f);
        FillDragFloat("##wavespacing", &mWaveSpacing, 0.1f, 0.0f, 64.0f, "Spacing %.1f");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::DragFloat2("##wavedirection", &mWaveCentre, 1.0f, 0.0f, 360.0f, "%.0f");
        ImGui::TextDisabled("Facing (degrees) and how far from it");
        ImGui::Checkbox("Symmetric", &mWaveSymmetric);
        EdSetItemTooltip(
          "Each place copied through the map's symmetry (the brushes' setting), the copies facing alike"
        );
        if (ImGui::Button("Add along the shore")) {
          mWaveAsk = WaveAsk::AddAlongShore;
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(mWaveCount == 0);
        if (ImGui::Button("Clear##waves")) {
          mWaveAsk = WaveAsk::Clear;
        }
        ImGui::EndDisabled();
        if (ImGui::Button("Load patterns...")) {
          mWaveAsk = WaveAsk::LoadPatterns;
        }
        ImGui::SameLine();
        if (ImGui::Button("Import##waves")) {
          mWaveAsk = WaveAsk::Import;
        }
        ImGui::SameLine();
        if (ImGui::Button("Export##waves")) {
          mWaveAsk = WaveAsk::Export;
        }
        ImGui::Checkbox("Pick waves in the view", &mWavePick);
        if (mWavePick) {
          mWaterMaskPaint = false;
          ImGui::SameLine();
          ImGui::BeginDisabled(mWaveSelectionCount == 0);
          if (ImGui::Button("Delete picked")) {
            mWaveDelete = true;
          }
          ImGui::EndDisabled();
          ImGui::TextDisabled(
            "%d picked: click picks (Ctrl adds), Shift+click removes, a drag moves", mWaveSelectionCount
          );
        }
        Note(
          "Waves start where the ground is the depth below the sea and travel to the shore, as the retail maps' shore "
          "waves do; the built-in patterns are SCMP_001's. Patterns load from a wavepatterns.lua "
          "(FAForeverMapEditor's); "
          "Import and Export are its .scmwaves. Each change is one undo step."
        );
      }
    }
  }

  void EdTools::DrawWaterBodies()
  {
    if (Section("Water bodies")) {
      if (!mBodiesError.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
        ImGui::TextWrapped("The scenario doesn't read: %s", mBodiesError.c_str());
        ImGui::PopStyleColor();
        return;
      }
      bool active = mBodyDragging;
      const auto changed = [&](const bool edited) {
        active = active || ImGui::IsItemActive();
        if (edited) {
          mBodiesChanged = true;
        }
        if (ImGui::IsItemDeactivatedAfterEdit()) {
          mBodiesChanged = true;
          mBodiesFinal = true;
        }
      };
      const auto clicked = [&]() {
        mBodiesChanged = true;
        mBodiesFinal = true;
      };
      const auto title = [&](const std::size_t i) {
        const WaterBody& body = mBodies[i];
        char text[96];
        if (!body.raw.empty()) {
          (void)std::snprintf(text, sizeof(text), "%zu  (as written)", i + 1);
        } else if (body.dry) {
          (void)std::snprintf(
            text, sizeof(text), "%zu  Dry below %.1f", i + 1, static_cast<double>(body.hasFillTo ? body.fillTo : 0.0f)
          );
        } else {
          (void)std::snprintf(text, sizeof(text), "%zu  Water at %.1f", i + 1, static_cast<double>(body.elevation));
        }
        return std::string(text);
      };
      const auto report = [&](const std::size_t i) {
        return i < mBodyReport.size() ? mBodyReport[i] : std::string();
      };
      const auto skipped = [](const std::string& line) {
        return line.find("skipped") != std::string::npos || line.find("can't") != std::string::npos;
      };

      // The list: each body, what the fill made of it.
      if (!mBodies.empty()) {
        const float rows = static_cast<float>(std::min<std::size_t>(mBodies.size(), 6));
        if (
          ImGui::BeginChild(
            "##bodies",
            ImVec2(0.0f, rows * ImGui::GetTextLineHeightWithSpacing() + ImGui::GetStyle().WindowPadding.y * 2.0f),
            ImGuiChildFlags_Borders
          )
        ) {
          for (std::size_t i = 0; i < mBodies.size(); ++i) {
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Selectable(title(i).c_str(), mBody == static_cast<int>(i), ImGuiSelectableFlags_AllowOverlap)) {
              mBody = static_cast<int>(i);
              mWaterPick = WaterPick::None;
            }
            const std::string line = report(i);
            if (!line.empty()) {
              ImGui::SameLine(ImGui::GetContentRegionAvail().x * 0.55f);
              if (skipped(line)) {
                ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.30f, 1.0f), "skipped");
              } else {
                ImGui::TextDisabled("%s", line.c_str());
              }
              if (ImGui::IsItemHovered()) {
                EdSetTooltip("%s", line.c_str());
              }
            }
            ImGui::PopID();
          }
        }
        ImGui::EndChild();
      }
      if (ImGui::Button("Add")) {
        AddWaterBody();
      }
      if (ImGui::IsItemHovered()) {
        EdSetTooltip("Then click the map where the water goes: its level starts a little above the ground there.");
      }
      const bool chosen = mBody >= 0 && mBody < static_cast<int>(mBodies.size());
      ImGui::SameLine();
      ImGui::BeginDisabled(!chosen);
      if (ImGui::Button("Remove")) {
        mBodies.erase(mBodies.begin() + mBody);
        mBody = std::min(mBody, static_cast<int>(mBodies.size()) - 1);
        mWaterPick = WaterPick::None;
        mBodyIsNew = false;
        clicked();
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(!chosen || mBody == 0);
      if (ImGui::ArrowButton("##bodyup", ImGuiDir_Up)) {
        std::swap(mBodies[static_cast<std::size_t>(mBody)], mBodies[static_cast<std::size_t>(mBody - 1)]);
        --mBody;
        clicked();
      }
      ImGui::EndDisabled();
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        EdSetTooltip("Earlier bodies fill first: where two meet, ground goes to the earlier one.");
      }
      ImGui::SameLine();
      ImGui::BeginDisabled(!chosen || mBody + 1 >= static_cast<int>(mBodies.size()));
      if (ImGui::ArrowButton("##bodydown", ImGuiDir_Down)) {
        std::swap(mBodies[static_cast<std::size_t>(mBody)], mBodies[static_cast<std::size_t>(mBody + 1)]);
        ++mBody;
        clicked();
      }
      ImGui::EndDisabled();

      if (mWaterPick != WaterPick::None) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.80f, 1.0f, 1.0f));
        ImGui::TextWrapped(
          "%s",
          mWaterPick == WaterPick::Seed ? "Click the map where the water starts filling. Esc cancels."
                                        : "Click the map to add outline points; Enter or a right click ends."
        );
        ImGui::PopStyleColor();
      }

      if (chosen) {
        WaterBody& body = mBodies[static_cast<std::size_t>(mBody)];
        ImGui::PushID(mBody);
        if (!body.raw.empty()) {
          ImGui::TextWrapped("The editor can't edit this one (%s); it is kept as written:", body.unreadable.c_str());
          ImGui::TextDisabled("%s", body.raw.c_str());
        } else {
          int kind = body.dry ? 1 : 0;
          bool kindChanged = ImGui::RadioButton("Water", &kind, 0);
          ImGui::SameLine();
          kindChanged = ImGui::RadioButton("Dry", &kind, 1) || kindChanged;
          if (kindChanged) {
            body.dry = kind == 1;
            if (body.dry && !body.hasFillTo) {
              body.hasFillTo = true;
              body.fillTo = body.elevation;
            }
            clicked();
          }
          if (!body.dry) {
            ImGui::SetNextItemWidth(-1.0f);
            changed(FillDragFloat("##elevation", &body.elevation, 0.05f, -100.0f, 512.0f, "Level %.2f"));
            body.hasElevation = true;
          }
          // The fill takes ground below this; the level by default (a dry body needs it).
          bool ownFill = body.hasFillTo || body.dry;
          ImGui::BeginDisabled(body.dry);
          if (ImGui::Checkbox("Fills ground below", &ownFill)) {
            body.hasFillTo = ownFill;
            body.fillTo = body.elevation;
            clicked();
          }
          ImGui::EndDisabled();
          if (ownFill) {
            ImGui::SetNextItemWidth(-1.0f);
            changed(FillDragFloat("##fillto", &body.fillTo, 0.05f, -100.0f, 512.0f, "Fill below %.2f"));
          }
          if (!body.dry) {
            bool ownShade = body.hasDeep || body.hasAbyss;
            if (ImGui::Checkbox("Own deep and abyss", &ownShade)) {
              body.hasDeep = body.hasAbyss = ownShade;
              body.deep = body.elevation - 2.5f;
              body.abyss = body.elevation - 15.0f;
              clicked();
            }
            if (ownShade) {
              ImGui::SetNextItemWidth(-1.0f);
              changed(FillDragFloat("##deep", &body.deep, 0.05f, -100.0f, 512.0f, "Deep %.2f"));
              ImGui::SetNextItemWidth(-1.0f);
              changed(FillDragFloat("##abyss", &body.abyss, 0.05f, -100.0f, 512.0f, "Abyss %.2f"));
              body.hasDeep = body.hasAbyss = true;
            }
          }
          // Seed: where the fill starts.
          if (ImGui::Checkbox("Seed", &body.hasSeed)) {
            clicked();
          }
          if (ImGui::IsItemHovered()) {
            EdSetTooltip(
              "The fill spreads from here over all connected ground below its level. An outline alone (no seed) "
              "takes every low point inside it."
            );
          }
          ImGui::SameLine();
          if (ImGui::Button(mWaterPick == WaterPick::Seed ? "Placing...##seed" : "Place##seed")) {
            mWaterPick = mWaterPick == WaterPick::Seed ? WaterPick::None : WaterPick::Seed;
            mBodyIsNew = false;
          }
          if (body.hasSeed) {
            float seed[2] = {body.seedX, body.seedZ};
            ImGui::SetNextItemWidth(-1.0f);
            changed(ImGui::DragFloat2("##seed", seed, 0.5f, 0.0f, 4096.0f, "%.1f"));
            body.seedX = seed[0];
            body.seedZ = seed[1];
          }
          // Outline: a closed curve the fill stays inside.
          ImGui::Text("Outline: %zu point%s", body.outline.size(), body.outline.size() == 1 ? "" : "s");
          ImGui::SameLine();
          if (
            ImGui::Button(
              mWaterPick == WaterPick::Outline ? "Done##outline"
                                               : (body.outline.empty() ? "Draw##outline" : "Add points##outline")
            )
          ) {
            mWaterPick = mWaterPick == WaterPick::Outline ? WaterPick::None : WaterPick::Outline;
            mBodyIsNew = false;
          }
          ImGui::SameLine();
          ImGui::BeginDisabled(body.outline.empty());
          if (ImGui::Button("Clear##outline")) {
            body.outline.clear();
            clicked();
          }
          ImGui::EndDisabled();
          if (!body.outline.empty() && body.outline.size() < 3) {
            ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.30f, 1.0f), "An outline needs 3 points or more.");
          }
          // Bounds: a rectangle of height-field vertices the fill stays inside.
          if (ImGui::Checkbox("Bounds", &body.hasBounds)) {
            if (body.hasBounds && body.x1 <= body.x0) {
              const int reach = 32;
              body.x0 = std::max(0, static_cast<int>(body.seedX) - reach);
              body.z0 = std::max(0, static_cast<int>(body.seedZ) - reach);
              body.x1 = static_cast<int>(body.seedX) + reach;
              body.z1 = static_cast<int>(body.seedZ) + reach;
            }
            clicked();
          }
          if (body.hasBounds) {
            int rect[4] = {body.x0, body.z0, body.x1, body.z1};
            ImGui::SetNextItemWidth(-1.0f);
            changed(ImGui::DragInt4("##bounds", rect, 0.5f, 0, 4096));
            body.x0 = rect[0];
            body.z0 = rect[1];
            body.x1 = rect[2];
            body.z1 = rect[3];
          }
          const std::string line = report(static_cast<std::size_t>(mBody));
          if (!line.empty()) {
            if (skipped(line)) {
              ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.65f, 0.30f, 1.0f));
              ImGui::TextWrapped("%s", line.c_str());
              ImGui::PopStyleColor();
            } else {
              ImGui::TextDisabled("%s", line.c_str());
            }
          }
        }
        ImGui::PopID();
      }
      for (const std::string& line : mBodyLog) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
        ImGui::TextWrapped("%s", line.c_str());
        ImGui::PopStyleColor();
      }
      mBodiesEditing = active;
      Note(
        "Lakes and pools at their own levels, besides the sea (docs/WATER_BODIES.md). Each fills the ground below its "
        "level "
        "that its seed reaches, inside its outline and bounds; a dry body keeps low ground dry (a polder). The game "
        "draws "
        "them when sim_FixWaterBodies is on, which Play sets."
      );
    }
  }

  void EdTools::DrawProps()
  {
    if (Section("Prop")) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputTextWithHint("##propfilter", "search", mPropFilter, sizeof(mPropFilter));
      std::string filter = mPropFilter;
      for (char& c : filter) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (mPropBlueprints.empty()) {
        Note("The prop list comes once the game's rules are built after startup.");
      } else if (
        ImGui::BeginChild(
          "##props",
          ImVec2(0.0f, FillHeight(ImGui::GetFrameHeightWithSpacing() * 10.0f, ImGui::GetFrameHeight() * 1.8f * 6.0f)),
          ImGuiChildFlags_Borders
        )
      ) {
        // Each prop with a picture of its model (only the rows in view ask for theirs).
        const float picture = ImGui::GetFrameHeight() * 1.8f;
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
          ImGui::PushID(blueprint.c_str());
          const ImVec2 at = ImGui::GetCursorScreenPos();
          if (ImGui::Selectable("##prop", blueprint == mPropBlueprint, 0, ImVec2(0.0f, picture))) {
            mPropBlueprint = blueprint;
          }
          ImGui::PopID();
          if (ImGui::IsItemVisible()) {
            ImDrawList* const draw = ImGui::GetWindowDrawList();
            if (const std::uint64_t image = PropPicture(blueprint); image != 0U) {
              draw->AddImage(static_cast<ImTextureID>(image), at, ImVec2(at.x + picture, at.y + picture));
            } else {
              draw->AddRect(at, ImVec2(at.x + picture, at.y + picture), LineU32());
            }
            draw->AddText(
              ImVec2(at.x + picture + 6.0f, at.y + (picture - ImGui::GetTextLineHeight()) * 0.5f),
              ImGui::GetColorU32(ImGuiCol_Text),
              label.c_str()
            );
          }
          if (ImGui::IsItemHovered()) {
            EdSetTooltip("%s", blueprint.c_str());
          }
        }
      }
      if (!mPropBlueprints.empty()) {
        ImGui::EndChild();
      }
      if (!mPropDetails.empty()) {
        Note(mPropDetails.c_str());
      }
    }
    if (Section("Place")) {
      static const char* const kModes[] = {"Single", "Scatter", "Erase", "Line"};
      Segmented(kModes, 4, mPropMode);
      if (mPropMode == 3) {
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##propspacing", &mPropLineSpacing, 0.5f, 64.0f, "%.1f apart");
        ImGui::Checkbox("Turned along the line", &mPropLineAlong);
        Note(
          "Drag from where the line starts to where it ends: the props go down along it when you let go, with their "
          "symmetric copies (one undo step)."
        );
      }
      if (mPropMode == 1) {
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##density", &mPropDensity, 0.5f, 60.0f, "%.1f props a second");
      }
      if (mPropMode != 1 || mPaintList.empty()) {
        ImGui::Checkbox("Random turn", &mPropRandomTurn);
      }
      if (mPropMode == 1) {
        SectionHeader("PAINT LIST");
        int remove = -1;
        for (std::size_t i = 0; i < mPaintList.size(); ++i) {
          PropPaintEntry& entry = mPaintList[i];
          ImGui::PushID(static_cast<int>(i));
          std::string label = entry.blueprint;
          if (const std::size_t props = label.find("/props/"); props != std::string::npos) {
            label = label.substr(props + 7);
          }
          if (label.size() > 8 && label.compare(label.size() - 8, 8, "_prop.bp") == 0) {
            label.resize(label.size() - 8);
          }
          ImGui::TextUnformatted(label.c_str());
          if (ImGui::IsItemHovered()) {
            EdSetTooltip("%s", entry.blueprint.c_str());
          }
          ImGui::SameLine(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - ImGui::GetFrameHeight());
          if (ImGui::SmallButton("x")) {
            remove = static_cast<int>(i);
          }
          ImGui::SetNextItemWidth(-1.0f);
          FillDragInt("##chance", &entry.chance, 1.0f, 0, 1000, "Chance %d");
          ImGui::SetNextItemWidth(-1.0f);
          ImGui::DragIntRange2("##turn", &entry.rotationMin, &entry.rotationMax, 1.0f, 0, 360, "Turn %d", "to %d");
          ImGui::SetNextItemWidth(-1.0f);
          ImGui::DragFloatRange2(
            "##scale", &entry.scaleMin, &entry.scaleMax, 0.01f, 0.05f, 10.0f, "Scale %.2f", "to %.2f"
          );
          ImGui::PopID();
        }
        if (remove >= 0) {
          mPaintList.erase(mPaintList.begin() + remove);
        }
        ImGui::BeginDisabled(mPropBlueprint.empty());
        if (ImGui::Button("Add the chosen prop")) {
          PropPaintEntry entry;
          entry.blueprint = mPropBlueprint;
          mPaintList.push_back(entry);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(mPaintList.empty());
        if (ImGui::Button("Clear##paintlist")) {
          mPaintList.clear();
        }
        ImGui::EndDisabled();
        if (ImGui::Button("Import set...")) {
          mPaintSetImport = true;
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(mPaintList.empty());
        if (ImGui::Button("Export set...")) {
          mPaintSetExport = true;
        }
        ImGui::EndDisabled();
        Note(
          "With props in the list, Scatter picks one for each prop by its chance, turned between its two angles. The "
          "scale "
          "is saved to the map but the game draws props at their own size (it reads and drops it), so the view does "
          "too. "
          "Sets are FAForeverMapEditor's .proppaintset."
        );
        // Map-wide scatter: the whole map at once, symmetric copies alike.
        SectionHeader("FILL THE MAP");
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##filldensity", &mFill.density, 1.0f, 200.0f, "%.0f per 100 x 100");
        EdSetItemTooltip("How many props each 100 by 100 units gets, before the ground and the spacing drop some.");
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##fillspacing", &mFill.spacing, 1.0f, 40.0f, "At least %.1f apart");
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##fillslope", &mFill.maxSlope, 5.0f, 90.0f, "Slopes up to %.0f degrees");
        ImGui::Checkbox("Only above the water", &mFill.dry);
        ImGui::BeginDisabled(mPaintList.empty() && mPropBlueprint.empty());
        if (ImGui::Button("Fill the map", ImVec2(-1.0f, 0.0f))) {
          mFillRequest = true;
        }
        ImGui::EndDisabled();
        if (!mFillMessage.empty()) {
          Note(mFillMessage.c_str());
        }
        Note(
          "Props from the paint list (or the chosen prop) over the playable area, drawn once in the symmetry's first "
          "part "
          "and copied to the others, so every copy matches; one undo step. A new seed each time."
        );
      }
      DrawBrush(false);
      DrawSymmetry(false);
      Note(
        "Single shows the prop under the cursor and places it at a click, Scatter while the button is held, inside the "
        "brush; Erase removes those inside it. "
        "Shift+click erases in any mode. Symmetric copies are placed and removed with them."
      );
    }
    if (Section("Map reclaim")) {
      if (mReclaimSummary.empty()) {
        Note("Counted once the game's rules are built.");
      } else {
        ImGui::TextWrapped("%s", mReclaimSummary.c_str());
        for (const std::string& row : mReclaimRows) {
          ImGui::TextDisabled("%s", row.c_str());
        }
        Note(
          "Each prop's blueprint reclaim (Economy ReclaimMassMax, ReclaimEnergyMax), the most mass first. A scenario "
          "that keeps "
          "a reclaim entry (FAForeverMapEditor's) gets these totals when it is saved."
        );
      }
    }
  }

  void EdTools::DrawWaterTexturePicker()
  {
    constexpr const char* kTitle = "Water texture";
    if (mWaterTexturePickOpen) {
      mWaterTexturePickOpen = false;
      if (mGameTextures.empty()) {
        mGameTextures = ListGameTextures("/textures");
      }
      ImGui::OpenPopup(kTitle);
    }
    ImGui::SetNextWindowSize(ImVec2(Em(640.0f), Em(520.0f)), ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal(kTitle, nullptr)) {
      return;
    }
    const int slot = std::clamp(mWaterTexturePick, 0, 5);
    static const char* const kSlots[6] = {
      "cube map", "colour ramp", "normals 1", "normals 2", "normals 3", "normals 4"
    };
    // What fits the slot by name: cube maps, ramps, wave normal maps (the search shows the rest).
    static const char* const kHints[6] = {"cube", "ramp", "wave", "wave", "wave", "wave"};
    ImGui::Text("The %s", kSlots[slot]);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(240.0f));
    ImGui::InputTextWithHint("##waterfilter", "search all textures", mWaterTextureFilter, sizeof(mWaterTextureFilter));
    ImGui::SameLine();
    if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    std::string filter = mWaterTextureFilter;
    for (char& c : filter) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (ImGui::BeginChild("##watertextures", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
      const float cell = 96.0f;
      const int columns = std::max(1, static_cast<int>(ImGui::GetContentRegionAvail().x / (cell + 12.0f)));
      int shown = 0;
      for (const std::string& path : mGameTextures) {
        std::string lower = path;
        for (char& c : lower) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        const std::size_t slash = lower.find_last_of('/');
        const std::string leaf = slash == std::string::npos ? lower : lower.substr(slash + 1);
        if (filter.empty() ? leaf.find(kHints[slot]) == std::string::npos : lower.find(filter) == std::string::npos) {
          continue;
        }
        if (shown % columns != 0) {
          ImGui::SameLine();
        }
        ++shown;
        ImGui::PushID(path.c_str());
        ImGui::BeginGroup();
        const std::uint64_t image = mLibrary.Thumbnail(path);
        const bool picked = image != 0U
          ? ImGui::ImageButton("##pick", static_cast<ImTextureID>(image), ImVec2(cell, cell))
          : ImGui::Button("...", ImVec2(cell + 6.0f, cell + 6.0f));
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + cell);
        ImGui::TextUnformatted(path.substr(path.find_last_of('/') + 1).c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndGroup();
        if (ImGui::IsItemHovered()) {
          EdSetTooltip("%s", path.c_str());
        }
        if (picked) {
          mWater.textures[slot] = path;
          mWaterChanged = true;
          mWaterFinal = true; // one undo step
          ImGui::CloseCurrentPopup();
        }
        ImGui::PopID();
      }
      if (shown == 0) {
        ImGui::TextDisabled(
          "No texture's name has \"%s\"; search for another.", filter.empty() ? kHints[slot] : filter.c_str()
        );
      }
    }
    ImGui::EndChild();
    mLibrary.Pump(6);
    ImGui::EndPopup();
  }

  void EdTools::DrawDecals()
  {
    if (Section("Mode")) {
      static const char* const kModes[] = {"Place", "Select", "Path", "Scatter", "Erase"};
      mDecalMode = std::clamp(mDecalMode, 0, 4);
      Segmented(kModes, 5, mDecalMode);
      if (mDecalMode == 3 || mDecalMode == 4) {
        ImGui::SetNextItemWidth(-1.0f);
        FillSliderFloat("##decalbrushradius", &mDecalBrush.radius, 2.0f, 256.0f, "Radius %.0f");
        if (mDecalMode == 3) {
          ImGui::SetNextItemWidth(-1.0f);
          FillSliderInt("##decalbrushcount", &mDecalBrush.count, 1, 20, "%d a dab");
          ImGui::SetNextItemWidth(-1.0f);
          FillSliderFloat("##decalbrushapart", &mDecalBrush.apart, 0.0f, 128.0f, "At least %.0f apart");
          Note(
            "Drag over the ground: the texture strewn over the circle, apart from each other, with the symmetry's "
            "copies. One undo step a stroke."
          );
        } else {
          ImGui::Checkbox("Only the chosen texture", &mDecalBrush.onlyThisTexture);
          Note(
            "Drag over the ground: the decals inside the circle go, with the symmetry's copies. One undo step a "
            "stroke."
          );
        }
      }
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
        FillSliderFloat("##decaloverlap", &mDecalOverlap, 0.0f, 0.9f, "Overlap %.2f");
        Note(
          "Click the ground to lay the curve's points; the decals follow it end to end, each its length along the "
          "curve "
          "and its width across, turned with it. Enter or Place lays them (one undo step), Backspace drops the last "
          "point, "
          "Escape clears. Symmetric copies follow."
        );
      }
      if (mDecalMode == 1) {
        char count[64];
        (void)std::snprintf(
          count, sizeof(count), "%d decal%s selected", mDecalSelectionCount, mDecalSelectionCount == 1 ? "" : "s"
        );
        ImGui::TextUnformatted(count);
        Note(
          "Click a decal to select it (Ctrl adds), drag to move, Shift+click or Delete removes. Each edit is one undo "
          "step."
        );
      }

      // The textures: each as itself on a checkerboard, filtered by name and type.
    }
    if (Section("Texture")) {
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
      if (
        ImGui::BeginChild(
          "##decaltextures",
          ImVec2(0.0f, FillHeight(ImGui::GetFrameHeightWithSpacing() * 10.0f, cell * 3.2f)),
          ImGuiChildFlags_Borders
        )
      ) {
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
              draw->AddRectFilled(
                ImVec2(p.x + x * square, p.y + y * square),
                ImVec2(p.x + (x + 1) * square, p.y + (y + 1) * square),
                (x + y) % 2 == 0 ? IM_COL32(70, 74, 80, 255) : IM_COL32(52, 55, 60, 255)
              );
            }
          }
          if (ImGui::InvisibleButton("##decal", ImVec2(cell, cell))) {
            mDecalTexture = texture.path;
            mDecalMode = 0;
          }
          // The picked one filled under its picture (selection by fill).
          if (texture.path == mDecalTexture) {
            draw->AddRectFilled(p, ImVec2(p.x + cell, p.y + cell), AccentU32(0.55f), 3.0f);
          }
          if (const std::uint64_t image = mLibrary.Thumbnail(texture.path, true); image != 0U) {
            const float inset = texture.path == mDecalTexture ? 4.0f : 0.0f;
            draw->AddImage(
              static_cast<ImTextureID>(image),
              ImVec2(p.x + inset, p.y + inset),
              ImVec2(p.x + cell - inset, p.y + cell - inset)
            );
          }
          if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
            EdSetTooltip(
              "%s\n%s, placed as %s%s",
              texture.name.c_str(),
              texture.biome.c_str(),
              DecalTypeName(texture.type),
              texture.pair.empty() ? "" : "\nwith a spec map"
            );
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
        ImGui::TextWrapped(
          "%s (%s)", mDecalTexture.substr(slash + 1).c_str(), DecalTypeName(DecalTypeForTexture(mDecalTexture))
        );
        bool hasPair = false;
        for (const DecalTexture& texture : mDecalTextures) {
          hasPair = hasPair || (texture.path == mDecalTexture && !texture.pair.empty());
        }
        ImGui::BeginDisabled(!hasPair);
        ImGui::Checkbox("With its spec map", &mDecalWithPair);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
          EdSetTooltip(
            hasPair ? "The decal's second texture is its _spec map, as the game's maps keep albedo decals"
                    : "Only an _albedo texture with a _spec next to it has one"
          );
        }
      } else {
        Note("Pick a texture to place.");
      }
    }
    if (Section("Size and turn")) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::DragFloat2("##decalsize", mDecalSize, 0.25f, 0.5f, 1024.0f, "%.1f");
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##decalturn", &mDecalTurn, -180.0f, 180.0f, "Turn %.0f deg");
      ImGui::Checkbox("Random turn", &mDecalRandomTurn);
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderFloat("##decalvariation", &mDecalSizeVariation, 0.0f, 0.9f, "Size variation %.2f");
      EdSetItemTooltip("Each decal's size times 1 plus or minus this, at random; the symmetric copies share it");
      ImGui::SetNextItemWidth(-1.0f);
      FillDragFloat(
        "##decalcutoff",
        &mDecalCutoff,
        5.0f,
        0.0f,
        5000.0f,
        mDecalCutoff <= 0.0f ? "Fade distance: from its size" : "Fade at %.0f"
      );
      DrawSymmetry(false);
      Note(
        "Place: a click puts the texture there, centred, with its symmetric copies (turned with the symmetry). "
        "Size is along and across its heading, in game units."
      );
    }
  }

  void EdTools::DrawUnits()
  {
    if (Section("Mode")) {
      static const char* const kModes[] = {"Place", "Select"};
      mUnitMode = std::clamp(mUnitMode, 0, 1);
      Segmented(kModes, 2, mUnitMode);
      if (mUnitMode == 1) {
        char count[64];
        (void)std::snprintf(
          count, sizeof(count), "%d unit%s selected", mUnitSelectionCount, mUnitSelectionCount == 1 ? "" : "s"
        );
        ImGui::TextUnformatted(count);
        Note(
          "Click a unit to select it (Ctrl adds), drag it or its arrows to move, Shift+click or Delete removes. Each "
          "edit is one undo step."
        );
        ImGui::Checkbox("Range rings", &mShowRangeRings);
        EdSetItemTooltip(
          "Around the selected units: weapons' reach in red (their least in orange), vision in green, radar "
          "in blue, from the blueprints"
        );
        ImGui::BeginDisabled(mUnitSelectionCount == 0 || mUnitArmy.empty());
        if (ImGui::Button(("Give to " + (mUnitArmy.empty() ? std::string("the army") : mUnitArmy)).c_str())) {
          mGiveUnits = true;
        }
        ImGui::EndDisabled();
        EdSetItemTooltip("The selected units change army, to the one chosen below (one undo step)");
      }

      // The army new units join: the players' and the extra armies.
    }
    if (Section("Army")) {
      std::vector<std::string> armies = mArmies;
      armies.insert(armies.end(), mExtraArmies.begin(), mExtraArmies.end());
      if (!armies.empty() && std::find(armies.begin(), armies.end(), mUnitArmy) == armies.end()) {
        mUnitArmy = armies.back();
      }
      ImGui::SetNextItemWidth(-1.0f);
      if (EdBeginCombo("##unitarmy", mUnitArmy.empty() ? "(none)" : mUnitArmy.c_str())) {
        for (const std::string& army : armies) {
          if (ImGui::Selectable(army.c_str(), army == mUnitArmy)) {
            mUnitArmy = army;
          }
        }
        ImGui::EndCombo();
      }
    }
    if (Section("Unit")) {
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputTextWithHint("##unitfilter", "search id or name", mUnitFilter, sizeof(mUnitFilter));
      std::string filter = mUnitFilter;
      for (char& c : filter) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (mUnitTypes.empty()) {
        Note("The unit list comes once the game's rules are built after startup.");
      } else if (!mUnitInfos.empty()) {
        // The browser: by faction and kind, in tech rows of build icons (or a list).
        DrawUnitBrowser();
      } else if (
        ImGui::BeginChild("##unittypes", ImVec2(0.0f, ImGui::GetFrameHeight() * 1.6f * 9.0f), ImGuiChildFlags_Borders)
      ) {
        // Each unit with its build icon, as the game's build menus show it
        // (/textures/ui/common/icons/units/<id>_icon.dds); only the rows in view ask for theirs.
        mLibrary.Pump(4);
        const float icon = ImGui::GetFrameHeight() * 1.5f;
        for (const auto& [id, name] : mUnitTypes) {
          std::string lower = id + " " + name;
          for (char& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          if (!filter.empty() && lower.find(filter) == std::string::npos) {
            continue;
          }
          ImGui::PushID(id.c_str());
          const ImVec2 at = ImGui::GetCursorScreenPos();
          if (ImGui::Selectable("##unit", id == mUnitType, 0, ImVec2(0.0f, icon))) {
            mUnitType = id;
            mUnitMode = 0;
          }
          if (ImGui::IsItemVisible()) {
            std::string idLower = id;
            for (char& c : idLower) {
              c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            ImDrawList* const draw = ImGui::GetWindowDrawList();
            const std::uint64_t image =
              mLibrary.Thumbnail("/textures/ui/common/icons/units/" + idLower + "_icon.dds", true);
            if (image != 0U) {
              draw->AddImage(static_cast<ImTextureID>(image), at, ImVec2(at.x + icon, at.y + icon));
            } else {
              draw->AddRect(at, ImVec2(at.x + icon, at.y + icon), LineU32());
            }
            const float textY = at.y + (icon - ImGui::GetTextLineHeight()) * 0.5f;
            draw->AddText(ImVec2(at.x + icon + 6.0f, textY), ImGui::GetColorU32(ImGuiCol_Text), id.c_str());
            draw->AddText(
              ImVec2(at.x + icon + 6.0f + ImGui::GetFontSize() * 4.5f, textY),
              ImGui::GetColorU32(ImGuiCol_TextDisabled),
              name.c_str()
            );
          }
          ImGui::PopID();
        }
      }
      if (!mUnitTypes.empty() && mUnitInfos.empty()) {
        ImGui::EndChild();
      }
      ImGui::Checkbox("Random turn", &mUnitRandomTurn);
      DrawSymmetry(false);
      Note(
        "Place: a click puts the unit there with its symmetric copies, in the army above, in its INITIAL group (the "
        "units the "
        "army starts with); names are UNIT_n, as the game's saves name them."
      );
    }
    if (Section("Groups")) {
      if (mUnitTreeArmy.empty() || mUnitTreeArmy != mUnitArmy) {
        Note("The army's groups show here once its units are read.");
      } else {
        // The army's groups (the INITIAL group the game starts it with, and those under it), each with its units'
        // count.
        if (
          ImGui::BeginChild(
            "##unitgroups",
            ImVec2(
              0.0f, FillHeight(ImGui::GetFrameHeightWithSpacing() * 6.0f, ImGui::GetTextLineHeightWithSpacing() * 6.0f)
            ),
            ImGuiChildFlags_Borders
          )
        ) {
          std::vector<std::string> path;
          DrawUnitGroup(mUnitTree, path);
        }
        ImGui::EndChild();
        std::string where = mUnitTreeArmy;
        for (const std::string& name : mGroupPath) {
          where += " / " + name;
        }
        ImGui::TextDisabled("%s", where.c_str());
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##groupname", "group name", mGroupName, sizeof(mGroupName));
        const bool named = mGroupName[0] != '\0';
        ImGui::BeginDisabled(!named);
        if (ImGui::Button("New group in it")) {
          mGroupAsk = GroupAsk::Add;
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(mGroupPath.empty());
        if (ImGui::Button("Rename")) {
          mGroupAsk = GroupAsk::Rename;
        }
        ImGui::EndDisabled();
        ImGui::EndDisabled();
        ImGui::BeginDisabled(mGroupPath.empty());
        if (ImGui::Button("Remove")) {
          mGroupAsk = GroupAsk::Remove;
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(mUnitSelectionCount == 0);
        if (ImGui::Button("Move the selected here")) {
          mGroupAsk = GroupAsk::MoveSelected;
        }
        ImGui::EndDisabled();
        Note(
          "A click on a group selects its units. A removed group's units and groups go up into its parent. Each change "
          "is "
          "one undo step."
        );
      }
    }
    if (Section("Unit file")) {
      ImGui::BeginDisabled(mUnitArmy.empty());
      if (ImGui::Button("Import...")) {
        mUnitFileImport = true;
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      if (ImGui::Button(mUnitSelectionCount > 0 ? "Export selected..." : "Export the army's...")) {
        mUnitFileExport = true;
      }
      Note(
        "FAForeverMapEditor's units file (.scunits): type, position, turn, orders and platoon. Import puts the units "
        "in "
        "the "
        "army above, on the ground, selected, as one undo step; units from a bigger map are moved together to its "
        "middle. "
        "Export writes the selected units, or all of the army's."
      );
    }
  }

  void EdTools::DrawUnitGroup(
    const UnitGroup& group,
    std::vector<std::string>& path
  )
  {
    for (const UnitGroup::Member& member : group.order) {
      if (member.group < 0 || static_cast<std::size_t>(member.group) >= group.groups.size()) {
        continue;
      }
      const UnitGroup& child = group.groups[static_cast<std::size_t>(member.group)];
      path.push_back(child.name);
      std::vector<const SaveUnit*> units;
      CollectUnits(child, units);
      ImGui::PushID(child.name.c_str());
      ImGuiTreeNodeFlags flags =
        ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_DefaultOpen;
      if (child.groups.empty()) {
        flags |= ImGuiTreeNodeFlags_Leaf;
      }
      if (path == mGroupPath) {
        flags |= ImGuiTreeNodeFlags_Selected;
      }
      const bool open = ImGui::TreeNodeEx("##group", flags, "%s  (%zu)", child.name.c_str(), units.size());
      if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen()) {
        mGroupPath = path;
        mGroupAsk = GroupAsk::Select;
      }
      if (open) {
        DrawUnitGroup(child, path);
        ImGui::TreePop();
      }
      ImGui::PopID();
      path.pop_back();
    }
  }

  void EdTools::DrawPlayableArea()
  {
    if (Section("Playable area")) {
      bool on = mArea.has_value();
      if (ImGui::Checkbox("The map has a playable area", &on)) {
        mAreaChanged = true;
        if (on) {
          // A border a tenth of the map in from each side, on the game's 4-unit grid.
          const int marginX = (mMapWidth / 10) / 4 * 4;
          const int marginZ = (mMapHeight / 10) / 4 * 4;
          mAreaChange =
            std::array<int, 4>{marginX, marginZ, (mMapWidth - marginX) / 4 * 4, (mMapHeight - marginZ) / 4 * 4};
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
          if (FillDragInt(kEdges[i], &area[static_cast<std::size_t>(i)], 1.0f, 0, limit, kFormats[i])) {
            area[static_cast<std::size_t>(i)] = std::clamp(area[static_cast<std::size_t>(i)] / 4 * 4, 0, limit);
            // Centred: the opposite edge as far in from its side.
            if (mBorderCentred) {
              const int opposite = (i + 2) % 4;
              area[static_cast<std::size_t>(opposite)] =
                std::clamp((limit - area[static_cast<std::size_t>(i)]) / 4 * 4, 0, limit);
            }
            if (area[0] < area[2] && area[1] < area[3]) {
              mAreaChanged = true;
              mAreaChange = area;
            }
          }
        }
        char size[64];
        (void)std::snprintf(
          size, sizeof(size), "%d x %d of %d x %d", area[2] - area[0], area[3] - area[1], mMapWidth, mMapHeight
        );
        ImGui::TextDisabled("%s", size);
        ImGui::Checkbox("Keep it centred", &mBorderCentred);
      }
      Note(
        "The game rounds each edge down to a multiple of 4. The ground outside is darkened as in the game; drag the "
        "border's "
        "edges in the view with the toolbar's border button on (or the Markers tool). Saved as an area of _save.lua "
        "that "
        "_script.lua's OnPopulate makes the playable area."
      );
    }
  }

  void EdTools::DrawMarkers()
  {
    if (Section("Draw chain", false)) {
      ImGui::Checkbox("Draw a chain", &mDrawChain);
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputTextWithHint("##chainname", "chain name", mChainName, sizeof(mChainName));
      Note(
        "Each marker placed joins this chain at its end (a route for scripts and the AI); its symmetric copies join "
        "<name>_m1, _m2... Ctrl+click on the ground starts the next chain. Chains are saved in the map's save file."
      );
    }
    if (Section("Place")) {
      const std::vector<MarkerType>& types = MarkerTypes();
      mMarkerType = std::clamp(mMarkerType, 0, static_cast<int>(types.size()) - 1);
      ImGui::SetNextItemWidth(-1.0f);
      if (EdBeginCombo("##markertype", types[static_cast<std::size_t>(mMarkerType)].type)) {
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
      Note(
        "Click the ground to place one (with its symmetric copies), click a marker to select it (Ctrl adds), drag to "
        "move, "
        "Shift+click or Delete removes. Start positions are named ARMY_1, ARMY_2... (the scenario's army list is "
        "edited "
        "with the armies)."
      );
      ImGui::Checkbox("Connect path nodes", &mConnectNodes);
      Note(
        "Clicking a path node links it to the selected nodes of its graph, or unlinks them; Ctrl+Shift+click does the "
        "same "
        "without the mode. Placing a path node links it to the selected one, so clicks lay a path. Symmetric copies "
        "follow."
      );
      DrawSymmetry(false);
    }
    if (Section("Selected")) {
      if (mMarkerSelection.empty()) {
        Note("No marker selected.");
      } else if (mMarkerSelection.size() > 1) {
        char count[48];
        (void)std::snprintf(count, sizeof(count), "%zu markers selected", mMarkerSelection.size());
        ImGui::TextUnformatted(count);
      } else {
        const SaveEntry& marker = mMarkerSelection.front();
        // Its type, changeable (the palette's types, the game's templates among them).
        {
          const std::string current = MarkerTypeOf(marker);
          ImGui::SetNextItemWidth(-1.0f);
          if (EdBeginCombo("##markerchangetype", current.c_str())) {
            for (const MarkerType& type : MarkerTypes()) {
              if (ImGui::Selectable(type.type, current == type.type) && current != type.type) {
                mMarkerEditName = marker.name;
                mMarkerEditKey = "settype";
                mMarkerEditValue = type.type;
              }
            }
            ImGui::EndCombo();
          }
          EdSetItemTooltip(
            "The marker's type: a change brings that type's colour, prop and properties (one undo step)"
          );
        }
        // The labels' column: as wide as the longest key ("orientation"), so the badges never sit on a name.
        float labelColumn = ImGui::CalcTextSize("name").x;
        for (const auto& [key, value] : marker.properties) {
          labelColumn = std::max(labelColumn, ImGui::CalcTextSize(key.c_str()).x);
        }
        labelColumn += ImGui::GetStyle().WindowPadding.x + ImGui::GetStyle().ItemSpacing.x * 2.0f;
        // A small badge of the value's kind beside its name.
        const auto badge = [](const char* const kind, const ImU32 colour) {
          const ImVec2 size = ImGui::CalcTextSize(kind);
          const ImVec2 at = ImGui::GetCursorScreenPos();
          const float h = ImGui::GetFrameHeight();
          ImDrawList* const dl = ImGui::GetWindowDrawList();
          const ImVec2 a(at.x, at.y + (h - size.y) * 0.5f - 1.0f);
          dl->AddRectFilled(
            a, ImVec2(a.x + size.x + 8.0f, a.y + size.y + 2.0f), (colour & 0x00FFFFFFu) | 0x55000000u, 3.0f
          );
          dl->AddText(ImVec2(a.x + 4.0f, a.y + 1.0f), colour, kind);
          ImGui::Dummy(ImVec2(size.x + 8.0f, h));
        };
        // Each property by its kind (user ask 2026-11-11: typed fields, not raw Lua): text, a number, a vector, a
        // switch, a colour; anything else as the save writes it. Text applies on Enter, the others when let go: one
        // undo step each.
        const auto typedField = [&](const std::string& key, const std::string& raw) {
          const MarkerValue parsed = ParseMarkerValue(raw);
          float rgba[4] = {0.0f, 0.0f, 0.0f, 0.0f};
          const bool colour = parsed.kind == MarkerValue::Kind::String && (key == "color" || key == "colour") &&
            MarkerColourText(parsed.text, rgba);
          const char* const kind = colour               ? "color"
            : parsed.kind == MarkerValue::Kind::String  ? "str"
            : parsed.kind == MarkerValue::Kind::Float   ? "num"
            : parsed.kind == MarkerValue::Kind::Bool    ? "bool"
            : parsed.kind == MarkerValue::Kind::Vector3 ? "vec3"
                                                        : "lua";
          const ImU32 kindColour = colour               ? IM_COL32(230, 120, 200, 255)
            : parsed.kind == MarkerValue::Kind::String  ? IM_COL32(206, 145, 120, 255)
            : parsed.kind == MarkerValue::Kind::Float   ? IM_COL32(181, 206, 168, 255)
            : parsed.kind == MarkerValue::Kind::Bool    ? IM_COL32(86, 156, 214, 255)
            : parsed.kind == MarkerValue::Kind::Vector3 ? IM_COL32(78, 201, 176, 255)
                                                        : IM_COL32(160, 160, 160, 255);
          if (parsed.kind == MarkerValue::Kind::Raw || (parsed.kind == MarkerValue::Kind::String && !colour)) {
            return false; // text: the text field below
          }
          ImGui::PushID(key.c_str());
          ImGui::AlignTextToFramePadding();
          ImGui::TextDisabled("%s", key.c_str());
          EdSetItemTooltip("%s", MarkerFieldUse(key));
          ImGui::SameLine(labelColumn);
          badge(kind, kindColour);
          ImGui::SameLine();
          ImGui::SetNextItemWidth(-1.0f);
          const std::string id = marker.name + "/" + key;
          const auto commit = [&](const MarkerValue& changed) {
            mMarkerEditName = marker.name;
            mMarkerEditKey = key;
            mMarkerEditValue = WriteMarkerValue(changed);
            mMarkerEditing.clear();
          };
          // While held, the field's own copy; the save's value again once let go.
          if (mMarkerEditing != id) {
            mMarkerTyped = parsed;
            if (colour) {
              std::copy(rgba, rgba + 4, mMarkerTypedColour);
            }
          }
          bool edited = false;
          if (colour) {
            edited = ImGui::ColorEdit4(
              "##value", mMarkerTypedColour, ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreviewHalf
            );
          } else if (parsed.kind == MarkerValue::Kind::Float) {
            edited = FillDragFloat("##value", &mMarkerTyped.number[0], 0.1f, 0.0f, 0.0f, "%.3f");
          } else if (parsed.kind == MarkerValue::Kind::Vector3) {
            edited = ImGui::DragFloat3("##value", mMarkerTyped.number, 0.1f, 0.0f, 0.0f, "%.2f");
          } else if (parsed.kind == MarkerValue::Kind::Bool) {
            if (ImGui::Checkbox("##value", &mMarkerTyped.flag)) {
              commit(mMarkerTyped);
            }
          }
          if (edited || ImGui::IsItemActive()) {
            mMarkerEditing = id;
          }
          if (ImGui::IsItemDeactivatedAfterEdit()) {
            MarkerValue changed = mMarkerTyped;
            if (colour) {
              changed.text = MarkerColourOf(mMarkerTypedColour);
            }
            commit(changed);
          } else if (!ImGui::IsItemActive() && mMarkerEditing == id && !edited) {
            mMarkerEditing.clear();
          }
          ImGui::PopID();
          return true;
        };
        // The name, then each property; text ones as text (Enter applies a change).
        const auto field = [&](const std::string& key, const std::string& value) {
          if (key != "name" && typedField(key, value)) {
            return;
          }
          const bool isString = key != "name" && ParseMarkerValue(value).kind == MarkerValue::Kind::String;
          const std::string shown = isString ? ParseMarkerValue(value).text : value;
          ImGui::PushID(key.c_str());
          ImGui::AlignTextToFramePadding();
          ImGui::TextDisabled("%s", key.c_str());
          if (key != "name") {
            EdSetItemTooltip("%s", MarkerFieldUse(key));
          }
          ImGui::SameLine(labelColumn);
          badge(
            key == "name" ? "name"
              : isString  ? "str"
                          : "lua",
            key == "name" ? IM_COL32(220, 220, 170, 255)
              : isString  ? IM_COL32(206, 145, 120, 255)
                          : IM_COL32(160, 160, 160, 255)
          );
          ImGui::SameLine();
          const std::string id = marker.name + "/" + key;
          if (mMarkerEditing != id) {
            (void)std::snprintf(mMarkerEditBuffer, sizeof(mMarkerEditBuffer), "%s", shown.c_str());
          }
          ImGui::SetNextItemWidth(-1.0f);
          char buffer[256];
          (void)std::snprintf(buffer, sizeof(buffer), "%s", mMarkerEditing == id ? mMarkerEditBuffer : shown.c_str());
          if (ImGui::InputText("##value", buffer, sizeof(buffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
            mMarkerEditName = marker.name;
            mMarkerEditKey = key;
            if (isString) {
              MarkerValue text;
              text.kind = MarkerValue::Kind::String;
              text.text = buffer;
              mMarkerEditValue = WriteMarkerValue(text);
            } else {
              mMarkerEditValue = buffer;
            }
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
    }
    if (Section("Air path nodes")) {
      ImGui::SetNextItemWidth(-1.0f);
      FillSliderInt("##airgrid", &mAirGridCount, 4, 32, "%d nodes a side");
      ImGui::Checkbox("Replace the map's air nodes", &mAirGridReplace);
      if (ImGui::Button("Fill the map with an air node grid", ImVec2(-1.0f, 0.0f))) {
        mAirGridAsked = true;
      }
      Note(
        "A grid of air path nodes over the playable area (the whole map without one), each linked to its 8 neighbours, "
        "as "
        "FAForeverMapEditor's air presets lay them: 16 a side on any map size. AI air units path along them. One undo "
        "step."
      );
    }
    if (Section("Marker file")) {
      if (ImGui::Button("Import...")) {
        mMarkerFileImport = true;
      }
      ImGui::SameLine();
      if (ImGui::Button(mMarkerSelection.empty() ? "Export all..." : "Export selected...")) {
        mMarkerFileExport = true;
      }
      Note(
        "FAForeverMapEditor's marker file (.fafmapmarkers): types, positions and path links. Imported markers get new "
        "names, are selected, and are one undo step; weather, effect and objective markers are left out."
      );
    }
    if (Section("Armies")) {
      {
        const bool oneFfa = mTeams.size() == 1 && mTeams.front().name == "FFA";
        const std::size_t slots = mTeams.empty() ? 0 : mTeams.front().armies.size();
        ImGui::Text(
          "%zu player slot%s, %zu extra arm%s",
          slots,
          slots == 1 ? "" : "s",
          mExtraArmies.size(),
          mExtraArmies.size() == 1 ? "y" : "ies"
        );
        if (!oneFfa && !mTeams.empty()) {
          ImGui::SameLine();
          ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "(not one FFA team)");
        }
        if (ImGui::Button("Open the Armies panel", ImVec2(-1.0f, 0.0f))) {
          mOpenArmies = true;
        }
        Note(
          "Slot order, extra armies, starting resources, faction and alliances are edited in the Armies panel (View > "
          "Armies). "
          "Placing a start position adds its army (ARMY_n) to the scenario's team and _save.lua; deleting or renaming "
          "it "
          "follows."
        );
      }
      DrawPlayableArea();
    }
  }

} // namespace faf::editor

#include "editor/ui/EdCards.h"

#include <algorithm>
#include <cfloat>
#include <cmath>

#include "editor/ui/EdFonts.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"

namespace faf::editor
{
  namespace
  {
    void TextIn(
      ImDrawList* const dl,
      ImFont* const font,
      const float size,
      const ImVec2 at,
      const ImU32 ink,
      const std::string& text,
      const float right
    )
    {
      if (text.empty()) {
        return;
      }
      dl->PushClipRect(ImVec2(at.x, at.y - size), ImVec2(right, at.y + size * 2.0f), true);
      dl->AddText(font != nullptr ? font : ImGui::GetFont(), size, at, ink, text.c_str());
      dl->PopClipRect();
    }
  } // namespace

  float KindCardHeight(
    const float pictureHeight
  )
  {
    return pictureHeight + std::round(Em(70.0f));
  }

  EdCardResult KindCard(
    const char* const id,
    const ImVec2& size,
    const float pictureHeight,
    const std::uint64_t picture,
    const char* const kind,
    const unsigned int kindRgb,
    const EdCardText& text,
    const bool picked
  )
  {
    EdCardResult result;
    const ImVec2 at = ImGui::GetCursorScreenPos();
    result.clicked = ImGui::InvisibleButton(id, size);
    result.hovered = ImGui::IsItemHovered();
    ImDrawList* const dl = ImGui::GetWindowDrawList();
    const ImVec2 to(at.x + size.x, at.y + size.y);
    const float round = Em(9.0f);
    dl->AddRectFilled(at, to, ImGui::GetColorU32(ImGuiCol_FrameBg), round);
    const ImVec2 p1(to.x, at.y + pictureHeight);
    if (picture != 0) {
      const float aspect = pictureHeight / std::max(1.0f, size.x);
      const float v0 = 0.5f - aspect * 0.5f;
      dl->AddImageRounded(
        static_cast<ImTextureID>(picture),
        at,
        p1,
        ImVec2(0.0f, v0),
        ImVec2(1.0f, v0 + aspect),
        IM_COL32_WHITE,
        round,
        ImDrawFlags_RoundCornersTop
      );
    } else {
      dl->AddRectFilled(at, p1, ChipU32(), round, ImDrawFlags_RoundCornersTop);
    }
    if (picked) {
      dl->AddRect(at, to, AccentU32(), round, 0, 2.0f);
    } else {
      dl->AddRect(
        at, to, ImGui::GetColorU32(result.hovered ? ImGuiCol_TextDisabled : ImGuiCol_TableBorderLight), round
      );
    }
    // The kind on the picture (.hm-pill.kind): a dark pill, the kind's colour, lightened to read on it.
    if (kind != nullptr) {
      const float pillSize = std::round(ImGui::GetFontSize() * 0.8f);
      const ImVec2 words = ImGui::GetFont()->CalcTextSizeA(pillSize, FLT_MAX, 0.0f, kind);
      const ImVec2 c0(at.x + Em(9.0f), at.y + Em(9.0f));
      const ImVec2 c1(c0.x + words.x + Em(16.0f), c0.y + words.y + Em(6.0f));
      dl->AddRectFilled(c0, c1, IM_COL32(0x0D, 0x10, 0x14, 0xC8), (c1.y - c0.y) * 0.5f);
      const auto lighten = [](const unsigned int channel) {
        return static_cast<int>(channel + (255U - channel) * 3U / 10U);
      };
      dl->AddText(
        ImGui::GetFont(),
        pillSize,
        ImVec2(c0.x + Em(8.0f), c0.y + Em(3.0f)),
        IM_COL32(lighten((kindRgb >> 16) & 0xFFU), lighten((kindRgb >> 8) & 0xFFU), lighten(kindRgb & 0xFFU), 0xFF),
        kind
      );
    }
    const ImVec4 bright = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    const ImU32 soft = ImGui::GetColorU32(
      ImVec4((bright.x * 2.0f + dim.x) / 3.0f, (bright.y * 2.0f + dim.y) / 3.0f, (bright.z * 2.0f + dim.z) / 3.0f, 1.0f)
    );
    const float right = to.x - Em(12.0f);
    const float tx = at.x + Em(12.0f);
    const float small = std::round(ImGui::GetFontSize() * 0.84f);
    TextIn(
      dl, gBoldFont, std::round(ImGui::GetFontSize() * 1.05f), ImVec2(tx, p1.y + Em(10.0f)), InkU32(), text.title, right
    );
    TextIn(
      dl, nullptr, small, ImVec2(tx, p1.y + Em(31.0f)), ImGui::GetColorU32(ImGuiCol_TextDisabled), text.meta, right
    );
    TextIn(dl, nullptr, small, ImVec2(tx, p1.y + Em(48.0f)), soft, text.third, right);
    if (result.hovered) {
      ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    }
    return result;
  }
} // namespace faf::editor

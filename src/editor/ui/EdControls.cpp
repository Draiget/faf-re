#include "editor/ui/EdControls.h"

#include "editor/ui/EdColourText.h"
#include "editor/ui/EdFonts.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdThemeColors.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cfloat>
#include <cstdarg>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>

namespace faf::editor
{
  namespace
  {
    /** Splits ImGui's format at its number: the name before it, the number and what follows it. */
    void SplitFormat(
      const char* const format,
      std::string& name,
      std::string& value
    )
    {
      name.clear();
      value.clear();
      if (format == nullptr) {
        return;
      }
      const char* p = format;
      while (*p != 0) {
        if (p[0] == '%' && p[1] == '%') {
          p += 2;
          continue;
        }
        if (p[0] == '%') {
          break;
        }
        ++p;
      }
      if (*p == 0) {
        name = format; // no number: the text whole ("Hard seam")
        return;
      }
      name.assign(format, static_cast<std::size_t>(p - format));
      while (!name.empty() && name.back() == ' ') {
        name.pop_back();
      }
      value = p;
    }

    /** The share of the track a value fills (logarithmic when asked). */
    [[nodiscard]] float Share(
      const double value,
      const double min,
      const double max,
      const bool logarithmic
    )
    {
      if (!(max > min)) {
        return 0.0f;
      }
      if (logarithmic && min > 0.0) {
        return static_cast<float>(std::clamp(std::log(value / min) / std::log(max / min), 0.0, 1.0));
      }
      return static_cast<float>(std::clamp((value - min) / (max - min), 0.0, 1.0));
    }

    /**
     * The fill slider for any of ImGui's number types. `speed` 0: a slider (a drag across the track moves the value
     * over its range); else a drag by `speed` a pixel.
     */
    bool Fill(
      const char* const label,
      const ImGuiDataType type,
      void* const data,
      const double min,
      const double max,
      const float speed,
      const char* const format,
      const ImGuiSliderFlags flags
    )
    {
      ImGuiWindow* const window = ImGui::GetCurrentWindow();
      if (window->SkipItems) {
        return false;
      }
      ImGuiContext& g = *GImGui;
      const ImGuiStyle& style = g.Style;
      const ImGuiID id = window->GetID(label);
      const float width = ImGui::CalcItemWidth();
      const ImVec2 at = window->DC.CursorPos;
      const ImRect frame(at, ImVec2(at.x + width, at.y + ImGui::GetFrameHeight()));
      ImGui::ItemSize(frame, style.FramePadding.y);
      if (!ImGui::ItemAdd(frame, id, &frame, ImGuiItemFlags_Inputable)) {
        return false;
      }
      const bool isInt = type == ImGuiDataType_S32;
      const auto get = [&]() -> double {
        return isInt ? static_cast<double>(*static_cast<int*>(data)) : static_cast<double>(*static_cast<float*>(data));
      };
      const auto set = [&](double v) {
        if (max > min || (flags & ImGuiSliderFlags_AlwaysClamp) != 0) {
          v = std::clamp(v, std::min(min, max), std::max(min, max));
        }
        if (isInt) {
          *static_cast<int*>(data) = static_cast<int>(std::lround(v));
        } else {
          *static_cast<float*>(data) = static_cast<float>(v);
        }
      };
      std::string name;
      std::string valueFormat;
      SplitFormat(format, name, valueFormat);

      // Typing a number: a double-click, Ctrl+click, or keyboard activation.
      const bool hovered = ImGui::ItemHoverable(frame, id, g.LastItemData.ItemFlags);
      bool typing = ImGui::TempInputIsActive(id);
      if (!typing && hovered) {
        const bool clicked = ImGui::IsMouseClicked(ImGuiMouseButton_Left, ImGuiInputFlags_None, id);
        const bool twice = g.IO.MouseClickedCount[ImGuiMouseButton_Left] == 2;
        if (clicked && (twice || g.IO.KeyCtrl)) {
          typing = true;
        } else if (clicked) {
          ImGui::SetActiveID(id, window);
          ImGui::SetFocusID(id, window);
          ImGui::FocusWindow(window);
        }
      }
      if (!typing && g.NavActivateId == id && (g.NavActivateFlags & ImGuiActivateFlags_PreferInput) != 0) {
        typing = true;
      }
      if (typing && !valueFormat.empty()) {
        if (g.ActiveId == id && !ImGui::TempInputIsActive(id)) {
          ImGui::ClearActiveID();
        }
        const double clampMin = std::min(min, max);
        const double clampMax = std::max(min, max);
        bool changed = false;
        if (isInt) {
          const int lo = static_cast<int>(clampMin);
          const int hi = static_cast<int>(clampMax);
          changed = ImGui::TempInputScalar(
            frame, id, label, type, data, valueFormat.c_str(), max > min ? &lo : nullptr, max > min ? &hi : nullptr
          );
        } else {
          const float lo = static_cast<float>(clampMin);
          const float hi = static_cast<float>(clampMax);
          changed = ImGui::TempInputScalar(
            frame, id, label, type, data, valueFormat.c_str(), max > min ? &lo : nullptr, max > min ? &hi : nullptr
          );
        }
        return changed;
      }

      // Scrubbing: relative to the track's width (a slider) or by `speed` (a drag); Shift for a tenth.
      bool changed = false;
      if (g.ActiveId == id) {
        if (g.IO.MouseDown[ImGuiMouseButton_Left]) {
          const float delta = g.IO.MouseDelta.x * (g.IO.KeyShift ? 0.1f : 1.0f);
          if (delta != 0.0f) {
            const double before = get();
            double after = before;
            if (speed > 0.0f || !(max > min)) {
              after = before + static_cast<double>(delta) * static_cast<double>(speed > 0.0f ? speed : 1.0f);
            } else if ((flags & ImGuiSliderFlags_Logarithmic) != 0 && min > 0.0) {
              const double t =
                Share(before, min, max, true) + static_cast<double>(delta) / static_cast<double>(frame.GetWidth());
              after = min * std::pow(max / min, std::clamp(t, 0.0, 1.0));
            } else {
              after = before + static_cast<double>(delta) * (max - min) / static_cast<double>(frame.GetWidth());
            }
            if (isInt) {
              // Whole steps: keep the fraction a slow drag hasn't made up yet.
              static double carry = 0.0;
              carry += after - before;
              const double whole = std::trunc(carry);
              carry -= whole;
              after = before + whole;
            }
            set(after);
            changed = get() != before;
          }
        } else {
          ImGui::ClearActiveID();
        }
      }
      if (hovered || g.ActiveId == id) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
      }
      // The wheel over a focused slider steps it (not while the panel scrolls).
      if (hovered && g.NavId == id && g.IO.MouseWheel != 0.0f && max > min) {
        const double step = isInt ? 1.0 : (max - min) / 100.0;
        const double before = get();
        set(before + (g.IO.MouseWheel > 0.0f ? step : -step));
        changed = changed || get() != before;
      }
      if (changed) {
        ImGui::MarkItemEdited(id);
      }

      // Drawing: the track, the fill, the name and the value.
      ImDrawList* const draw = window->DrawList;
      const float rounding = style.FrameRounding;
      draw->AddRectFilled(frame.Min, frame.Max, ImGui::GetColorU32(ImGuiCol_FrameBg), rounding);
      if (max > min) {
        const float share = Share(get(), min, max, (flags & ImGuiSliderFlags_Logarithmic) != 0);
        if (share > 0.0f) {
          const float right = frame.Min.x + std::max(rounding * 2.0f, frame.GetWidth() * share);
          const float alpha = g.ActiveId == id ? 0.62f : (hovered ? 0.55f : 0.45f);
          draw->AddRectFilled(
            frame.Min,
            ImVec2(std::min(right, frame.Max.x), frame.Max.y),
            AccentU32(alpha),
            rounding,
            share >= 0.999f ? ImDrawFlags_RoundCornersAll : ImDrawFlags_RoundCornersLeft
          );
        }
      }
      if (style.FrameBorderSize > 0.0f) {
        draw->AddRect(
          frame.Min,
          frame.Max,
          ImGui::GetColorU32(hovered || g.ActiveId == id ? ImGuiCol_TextDisabled : ImGuiCol_Border),
          rounding,
          0,
          style.FrameBorderSize
        );
      }
      char text[96] = "";
      if (!valueFormat.empty()) {
        if (isInt) {
          std::snprintf(text, sizeof(text), valueFormat.c_str(), *static_cast<int*>(data));
        } else {
          std::snprintf(text, sizeof(text), valueFormat.c_str(), static_cast<double>(*static_cast<float*>(data)));
        }
      }
      const float pad = style.FramePadding.x + 1.0f;
      const float textY = frame.Min.y + (frame.GetHeight() - ImGui::GetFontSize()) * 0.5f;
      const ImVec2 valueSize = ImGui::CalcTextSize(text);
      ImGui::PushClipRect(frame.Min, frame.Max, true);
      if (!name.empty()) {
        // The mockup's name colour (text-1): between the text and the dimmed text.
        const ImVec4 ink = ImGui::GetStyleColorVec4(ImGuiCol_Text);
        const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
        const ImVec4 nameInk((ink.x + dim.x) * 0.5f, (ink.y + dim.y) * 0.5f, (ink.z + dim.z) * 0.5f, 1.0f);
        draw->AddText(ImVec2(frame.Min.x + pad, textY), ImGui::ColorConvertFloat4ToU32(nameInk), name.c_str());
      }
      if (text[0] != 0) {
        draw->AddText(ImVec2(frame.Max.x - pad - valueSize.x, textY), InkU32(), text);
      }
      ImGui::PopClipRect();
      return changed;
    }
  } // namespace

  bool FillSliderFloat(
    const char* const label,
    float* const value,
    const float min,
    const float max,
    const char* const format,
    const ImGuiSliderFlags flags
  )
  {
    return Fill(label, ImGuiDataType_Float, value, min, max, 0.0f, format, flags);
  }

  bool FillSliderInt(
    const char* const label,
    int* const value,
    const int min,
    const int max,
    const char* const format,
    const ImGuiSliderFlags flags
  )
  {
    return Fill(label, ImGuiDataType_S32, value, min, max, 0.0f, format, flags);
  }

  bool FillDragFloat(
    const char* const label,
    float* const value,
    const float speed,
    const float min,
    const float max,
    const char* const format,
    const ImGuiSliderFlags flags
  )
  {
    return Fill(label, ImGuiDataType_Float, value, min, max, speed > 0.0f ? speed : 1.0f, format, flags);
  }

  bool FillDragInt(
    const char* const label,
    int* const value,
    const float speed,
    const int min,
    const int max,
    const char* const format,
    const ImGuiSliderFlags flags
  )
  {
    return Fill(label, ImGuiDataType_S32, value, min, max, speed > 0.0f ? speed : 1.0f, format, flags);
  }

  ImVec4 AccentText()
  {
    const ImVec4 accent = AccentColor(1.0f);
    const float luminance = 0.2126f * accent.x + 0.7152f * accent.y + 0.0722f * accent.z;
    return luminance > 0.45f ? ImVec4(0.04f, 0.07f, 0.125f, 1.0f) : ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
  }

  bool PrimaryButton(
    const char* const label,
    const ImVec2& size
  )
  {
    ImGui::PushStyleColor(ImGuiCol_Button, AccentColor(1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, AccentColor(0.88f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, AccentColor(0.76f));
    ImGui::PushStyleColor(ImGuiCol_Border, AccentColor(1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, AccentText());
    const bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleColor(5);
    return pressed;
  }

  bool ModeTile(
    const char* const label,
    const bool picked,
    const ImVec2& size
  )
  {
    ImGui::PushStyleColor(ImGuiCol_Button, picked ? AccentColor(0.16f) : ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    ImGui::PushStyleColor(
      ImGuiCol_ButtonHovered, picked ? AccentColor(0.22f) : ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered)
    );
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, AccentColor(0.30f));
    ImGui::PushStyleColor(ImGuiCol_Border, picked ? AccentColor(1.0f) : ImGui::GetStyleColorVec4(ImGuiCol_Border));
    const ImVec4 ink = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    ImGui::PushStyleColor(
      ImGuiCol_Text, picked ? ink : ImVec4((ink.x + dim.x) * 0.5f, (ink.y + dim.y) * 0.5f, (ink.z + dim.z) * 0.5f, 1.0f)
    );
    const bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleColor(5);
    return pressed;
  }
  bool ModeTile(
    const char* const icon,
    const char* const label,
    const bool picked,
    ImVec2 size
  )
  {
    const float fontSize = ImGui::GetFontSize();
    const float small = std::round(fontSize * 0.85f);
    if (size.y <= 0.0f) {
      size.y = std::round(fontSize * 1.15f + small + ImGui::GetStyle().FramePadding.y * 3.0f);
    }
    ImGui::PushID(label);
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const bool pressed = ImGui::InvisibleButton("##modetile", size);
    const bool hovered = ImGui::IsItemHovered();
    const bool held = ImGui::IsItemActive();
    ImGui::PopID();
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImVec4 fill = picked ? AccentColor(hovered ? 0.22f : 0.16f)
      : held                   ? AccentColor(0.30f)
      : hovered                ? ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered)
                               : ImGui::GetStyleColorVec4(ImGuiCol_FrameBg);
    const float rounding = ImGui::GetStyle().FrameRounding;
    const ImVec2 end(at.x + size.x, at.y + size.y);
    draw->AddRectFilled(at, end, ImGui::ColorConvertFloat4ToU32(fill), rounding);
    draw->AddRect(
      at,
      end,
      ImGui::ColorConvertFloat4ToU32(picked ? AccentColor(1.0f) : ImGui::GetStyleColorVec4(ImGuiCol_Border)),
      rounding
    );
    const ImVec4 ink = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    const ImU32 colour = ImGui::ColorConvertFloat4ToU32(
      picked || hovered ? ink : ImVec4((ink.x + dim.x) * 0.5f, (ink.y + dim.y) * 0.5f, (ink.z + dim.z) * 0.5f, 1.0f)
    );
    // The icon a size above the text, its name small below, both centred.
    ImFont* const font = ImGui::GetFont();
    const float iconSize = std::round(fontSize * 1.15f);
    const ImVec2 iconText = font->CalcTextSizeA(iconSize, FLT_MAX, 0.0f, icon);
    const ImVec2 labelText = font->CalcTextSizeA(small, FLT_MAX, 0.0f, label);
    const float total = iconText.y + labelText.y;
    const float top = std::round(at.y + (size.y - total) * 0.5f);
    draw->AddText(font, iconSize, ImVec2(std::round(at.x + (size.x - iconText.x) * 0.5f), top), colour, icon);
    draw->AddText(
      font, small, ImVec2(std::round(at.x + (size.x - labelText.x) * 0.5f), top + iconText.y), colour, label
    );
    return pressed;
  }

  bool Section(
    const char* const title,
    const bool openAtFirst
  )
  {
    ImGuiWindow* const window = ImGui::GetCurrentWindow();
    ImGuiStorage* const storage = ImGui::GetStateStorage();
    const ImGuiID id = window->GetID(title);
    bool open = storage->GetBool(id, openAtFirst);
    ImGui::Spacing();
    const float fontSize = ImGui::GetFontSize();
    const float small = std::round(fontSize * 0.85f);
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const float width = ImGui::GetContentRegionAvail().x;
    const float height = small + 6.0f;
    ImGui::PushID(title);
    const bool clicked = ImGui::InvisibleButton("##section", ImVec2(width, height));
    const bool hovered = ImGui::IsItemHovered();
    ImGui::PopID();
    if (clicked) {
      open = !open;
      storage->SetBool(id, open);
    }
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImU32 ink = ImGui::GetColorU32(hovered ? ImGuiCol_Text : ImGuiCol_TextDisabled);
    // The chevron: down when open, right when folded.
    const float c = std::round(small * 0.32f);
    const ImVec2 mid(at.x + c + 2.0f, at.y + height * 0.5f);
    if (open) {
      draw->AddTriangleFilled(
        ImVec2(mid.x - c, mid.y - c * 0.5f), ImVec2(mid.x + c, mid.y - c * 0.5f), ImVec2(mid.x, mid.y + c * 0.6f), ink
      );
    } else {
      draw->AddTriangleFilled(
        ImVec2(mid.x - c * 0.5f, mid.y - c), ImVec2(mid.x - c * 0.5f, mid.y + c), ImVec2(mid.x + c * 0.6f, mid.y), ink
      );
    }
    // The title in capitals, a little smaller and spaced.
    std::string caps = title;
    if (const std::size_t hash = caps.find("##"); hash != std::string::npos) {
      caps.resize(hash);
    }
    for (char& ch : caps) {
      ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    float x = at.x + c * 2.0f + 8.0f;
    const float y = at.y + (height - small) * 0.5f;
    for (const char ch : caps) {
      const char glyph[2] = {ch, 0};
      draw->AddText(nullptr, small, ImVec2(x, y), ink, glyph);
      x += ImGui::GetFont()->CalcTextSizeA(small, 1.0e9f, 0.0f, glyph).x + small * 0.06f;
    }
    return open;
  }

  void RowLabel(
    const char* const label
  )
  {
    const float width = ImGui::GetContentRegionAvail().x;
    const ImVec4 ink = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    ImGui::AlignTextToFramePadding();
    ImGui::PushStyleColor(
      ImGuiCol_Text, ImVec4((ink.x + dim.x) * 0.5f, (ink.y + dim.y) * 0.5f, (ink.z + dim.z) * 0.5f, 1.0f)
    );
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::SameLine(std::round(width * 0.38f) + ImGui::GetStyle().WindowPadding.x);
    ImGui::SetNextItemWidth(-1.0f);
  }

  bool ColourField(
    const char* const id,
    float (&rgb)[3],
    const bool brighterThanWhite
  )
  {
    bool changed = false;
    ImGui::PushID(id);
    const float scale = brighterThanWhite ? ColourBrightness(rgb) : 1.0f;
    const ImVec4 shown(rgb[0] / scale, rgb[1] / scale, rgb[2] / scale, 1.0f);
    const float side = ImGui::GetFrameHeight();
    if (
      ImGui::ColorButton(
        "##swatch", shown, ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoAlpha, ImVec2(side, side)
      )
    ) {
      ImGui::OpenPopup("##picker");
    }
    if (ImGui::BeginPopup("##picker")) {
      float picked[3] = {shown.x, shown.y, shown.z};
      if (
        ImGui::ColorPicker3("##pick", picked, ImGuiColorEditFlags_NoSidePreview | ImGuiColorEditFlags_NoSmallPreview)
      ) {
        for (int i = 0; i < 3; ++i) {
          rgb[i] = picked[i] * scale;
        }
        changed = true;
      }
      if (brighterThanWhite) {
        // A colour past white is set here (the hex can't say it); the row under the field shows it once it is.
        float brightness = scale;
        ImGui::SetNextItemWidth(-1.0f);
        if (
          FillDragFloat("##popupbrightness", &brightness, 0.01f, 0.0f, 4.0f, "Brightness %.2f") && brightness > 0.0f
        ) {
          for (int i = 0; i < 3; ++i) {
            rgb[i] = rgb[i] / scale * brightness;
          }
          changed = true;
        }
      }
      ImGui::EndPopup();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    // The hex: typed in, applied on Enter or when the field is left.
    char text[16];
    std::snprintf(text, sizeof(text), "%s", HexOfColour(rgb).c_str());
    if (
      ImGui::InputText(
        "##hex", text, sizeof(text), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll
      ) ||
      ImGui::IsItemDeactivatedAfterEdit()
    ) {
      float typed[3] = {rgb[0], rgb[1], rgb[2]};
      if (ColourOfHex(text, scale, typed)) {
        changed = changed || typed[0] != rgb[0] || typed[1] != rgb[1] || typed[2] != rgb[2];
        rgb[0] = typed[0];
        rgb[1] = typed[1];
        rgb[2] = typed[2];
      }
    }
    if (brighterThanWhite && scale > 1.0005f) {
      float brightness = scale;
      RowLabel("Brightness");
      if (FillDragFloat("##brightness", &brightness, 0.01f, 0.0f, 4.0f, "%.2f") && brightness > 0.0f) {
        for (int i = 0; i < 3; ++i) {
          rgb[i] = rgb[i] / scale * brightness;
        }
        changed = true;
      }
    }
    ImGui::PopID();
    return changed;
  }

  float PillWidth(
    const char* const label
  )
  {
    const float size = std::round(ImGui::GetFontSize() * 0.86f);
    return std::round(
      ImGui::GetFont()->CalcTextSizeA(size, FLT_MAX, 0.0f, label, ImGui::FindRenderedTextEnd(label)).x + Em(22.0f)
    );
  }

  bool PillToggle(
    const char* const label,
    const bool on
  )
  {
    const float size = std::round(ImGui::GetFontSize() * 0.86f);
    const float height = std::round(Em(26.0f));
    const float width = PillWidth(label);
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const bool clicked = ImGui::InvisibleButton(label, ImVec2(width, height));
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* const dl = ImGui::GetWindowDrawList();
    const ImVec2 to(at.x + width, at.y + height);
    const float round = height * 0.5f;
    if (on) {
      dl->AddRectFilled(at, to, AccentU32(0.16f), round);
      dl->AddRect(at, to, AccentU32(), round);
    } else {
      dl->AddRect(at, to, ImGui::GetColorU32(hovered ? ImGuiCol_TextDisabled : ImGuiCol_Border), round);
    }
    const ImVec4 bright = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    const ImU32 ink = on || hovered
      ? ImGui::GetColorU32(ImGuiCol_Text)
      : ImGui::GetColorU32(ImVec4(
          (bright.x * 2.0f + dim.x) / 3.0f, (bright.y * 2.0f + dim.y) / 3.0f, (bright.z * 2.0f + dim.z) / 3.0f, 1.0f
        ));
    const char* const end = ImGui::FindRenderedTextEnd(label);
    const ImVec2 words = ImGui::GetFont()->CalcTextSizeA(size, FLT_MAX, 0.0f, label, end);
    dl->AddText(
      ImGui::GetFont(),
      size,
      ImVec2(std::round(at.x + (width - words.x) * 0.5f), std::round(at.y + (height - words.y) * 0.5f)),
      ink,
      label,
      end
    );
    return clicked;
  }

  bool SearchField(
    const char* const id,
    const char* const hint,
    char* const buffer,
    const std::size_t size,
    const float width,
    const ImGuiInputTextFlags flags
  )
  {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(36.0f), Em(10.0f)));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, Em(8.0f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImGui::GetStyleColorVec4(ImGuiCol_WindowBg));
    ImGui::SetNextItemWidth(width);
    const bool result = ImGui::InputTextWithHint(id, hint, buffer, size, flags);
    const ImVec2 min = ImGui::GetItemRectMin();
    const ImVec2 max = ImGui::GetItemRectMax();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
    ImGui::GetWindowDrawList()->AddText(
      ImVec2(min.x + Em(14.0f), std::round((min.y + max.y - ImGui::GetFontSize()) * 0.5f)),
      ImGui::GetColorU32(ImGuiCol_TextDisabled),
      ICON_SEARCH
    );
    return result;
  }

  bool EdBeginCombo(
    const char* const label,
    const char* const preview,
    const ImGuiComboFlags flags
  )
  {
    // Where ImGui will draw the field: in this window, at the cursor, the item's width, a frame high.
    ImDrawList* const dl = ImGui::GetWindowDrawList();
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const float width = ImGui::CalcItemWidth();
    const float height = ImGui::GetFrameHeight();
    const bool open = ImGui::BeginCombo(label, preview, flags);
    if ((flags & (ImGuiComboFlags_NoArrowButton | ImGuiComboFlags_NoPreview)) != 0) {
      return open;
    }
    // Over ImGui's arrow box: the field's colour (inside its border), then the chevron.
    const float side = height;
    const ImVec2 box0(at.x + width - side, at.y);
    const ImVec2 box1(at.x + width, at.y + height);
    const bool hovered = ImGui::IsMouseHoveringRect(at, box1, true);
    const ImGuiStyle& style = ImGui::GetStyle();
    const float border = style.FrameBorderSize;
    dl->AddRectFilled(
      ImVec2(box0.x, box0.y + border),
      ImVec2(box1.x - border, box1.y - border),
      ImGui::GetColorU32(hovered || open ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg),
      std::max(0.0f, style.FrameRounding - border),
      ImDrawFlags_RoundCornersRight
    );
    const ImVec2 chevron = ImGui::CalcTextSize(ICON_CHEVRON);
    const ImVec4 bright = style.Colors[ImGuiCol_Text];
    const ImVec4 dim = style.Colors[ImGuiCol_TextDisabled];
    dl->AddText(
      ImVec2(std::round(box0.x + (side - chevron.x) * 0.5f), std::round(at.y + (height - ImGui::GetFontSize()) * 0.5f)),
      hovered || open ? ImGui::GetColorU32(ImGuiCol_Text)
                      : ImGui::GetColorU32(
                          ImVec4((bright.x + dim.x) * 0.5f, (bright.y + dim.y) * 0.5f, (bright.z + dim.z) * 0.5f, 1.0f)
                        ),
      ICON_CHEVRON
    );
    return open;
  }

  bool EdCombo(
    const char* const label,
    int* const current,
    const char* const items[],
    const int count,
    const int popupItems
  )
  {
    const char* const preview = *current >= 0 && *current < count ? items[*current] : nullptr;
    if (popupItems != -1) {
      const float rows = static_cast<float>(popupItems);
      ImGui::SetNextWindowSizeConstraints(
        ImVec2(0.0f, 0.0f),
        ImVec2(FLT_MAX, ImGui::GetTextLineHeightWithSpacing() * rows + ImGui::GetStyle().WindowPadding.y * 2.0f)
      );
    }
    if (!EdBeginCombo(label, preview, ImGuiComboFlags_None)) {
      return false;
    }
    bool changed = false;
    for (int i = 0; i < count; ++i) {
      ImGui::PushID(i);
      const bool picked = i == *current;
      if (ImGui::Selectable(items[i], picked) && !picked) {
        *current = i;
        changed = true;
      }
      if (picked) {
        ImGui::SetItemDefaultFocus();
      }
      ImGui::PopID();
    }
    ImGui::EndCombo();
    if (changed) {
      ImGui::MarkItemEdited(ImGui::GetID(label));
    }
    return changed;
  }
  bool EdBeginTooltip()
  {
    // .tooltip: background #05070a, padding .4rem .55rem, radius .35rem, a soft edge.
    ImGui::PushStyleColor(ImGuiCol_PopupBg, IM_COL32(0x05, 0x07, 0x0A, 0xF5));
    ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(0xFF, 0xFF, 0xFF, 0x1A));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(9.0f), Em(6.5f)));
    ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, Em(6.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 1.0f);
    const bool open = ImGui::BeginTooltip();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
    return open;
  }

  void EdTooltipText(
    const char* const text
  )
  {
    if (text == nullptr || *text == 0) {
      return;
    }
    // .tooltip { max-width: 22rem }
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + Em(340.0f));
    const char* const newline = std::strchr(text, '\n');
    if (newline == nullptr) {
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0xE8, 0xED, 0xF3, 0xFF));
      ImGui::TextUnformatted(text);
      ImGui::PopStyleColor();
    } else {
      // The title, semibold and bright; the rest quieter.
      if (gBoldFont != nullptr) {
        ImGui::PushFont(gBoldFont, 0.0f);
      }
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0xF2, 0xF5, 0xF8, 0xFF));
      ImGui::TextUnformatted(text, newline);
      ImGui::PopStyleColor();
      if (gBoldFont != nullptr) {
        ImGui::PopFont();
      }
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0xAE, 0xB8, 0xC4, 0xFF));
      ImGui::TextUnformatted(newline + 1);
      ImGui::PopStyleColor();
    }
    ImGui::PopTextWrapPos();
  }

  namespace
  {
    void TooltipV(
      const char* const format,
      va_list args
    )
    {
      char text[2048];
      std::vsnprintf(text, sizeof(text), format, args);
      if (EdBeginTooltip()) {
        EdTooltipText(text);
        ImGui::EndTooltip();
      }
    }
  } // namespace

  void EdSetTooltip(
    const char* const format,
    ...
  )
  {
    va_list args;
    va_start(args, format);
    TooltipV(format, args);
    va_end(args);
  }

  void EdSetItemTooltip(
    const char* const format,
    ...
  )
  {
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
      return;
    }
    va_list args;
    va_start(args, format);
    TooltipV(format, args);
    va_end(args);
  }
} // namespace faf::editor

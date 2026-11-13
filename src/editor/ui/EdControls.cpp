#include "editor/ui/EdControls.h"

#include "editor/ui/EdThemeColors.h"
#include "imgui_internal.h"

#include <algorithm>
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
} // namespace faf::editor

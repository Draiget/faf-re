#pragma once

// The panels' controls as the mockup draws them (mockup/styles.css): the fill slider (a dark track, the value as a fill
// of the accent, its name on the left and its value on the right; drag anywhere to scrub, Shift for fine steps, a
// double-click or Ctrl+click types a number), the primary button (filled with the accent) and the mode tile (a
// bordered tile, the picked one in the accent's soft fill and border). They take ImGui's own arguments, so they stand
// in for ImGui::SliderFloat / SliderInt / DragFloat / DragInt where they were.

#include "imgui.h"

namespace faf::editor
{
  /**
   * A slider drawn as a fill. `format` is ImGui's ("Radius %.0f"): the text before the number is the name shown on the
   * left, the number and what follows it the value on the right ("Hard seam", without a number, is shown whole).
   */
  bool FillSliderFloat(
    const char* label,
    float* value,
    float min,
    float max,
    const char* format = "%.3f",
    ImGuiSliderFlags flags = 0
  );
  bool
  FillSliderInt(const char* label, int* value, int min, int max, const char* format = "%d", ImGuiSliderFlags flags = 0);
  /** A drag: `speed` per pixel (the fill shows only when min < max). */
  bool FillDragFloat(
    const char* label,
    float* value,
    float speed = 1.0f,
    float min = 0.0f,
    float max = 0.0f,
    const char* format = "%.3f",
    ImGuiSliderFlags flags = 0
  );
  bool FillDragInt(
    const char* label,
    int* value,
    float speed = 1.0f,
    int min = 0,
    int max = 0,
    const char* format = "%d",
    ImGuiSliderFlags flags = 0
  );

  /** The main action of a panel: filled with the accent. */
  bool PrimaryButton(const char* label, const ImVec2& size = ImVec2(0.0f, 0.0f));

  /** A tile of a mode grid: bordered, the picked one in the accent's soft fill and border. */
  bool ModeTile(const char* label, bool picked, const ImVec2& size);

  /**
   * A section of a panel as the mockup heads it: a chevron and the title in small dimmed capitals, brighter under the
   * mouse; a click folds it. Returns whether it is open (its content follows only then). The fold is kept per panel.
   */
  bool Section(const char* title, bool openAtFirst = true);

  /** A row's label in the left 38 % of the panel (the mockup's `.row > label`); the control takes the rest. */
  void RowLabel(const char* label);

  /**
   * A colour as the mockup's fields show it: a swatch (a click opens a picker) and its hex. Colours brighter than
   * white (the map's lighting) keep their brightness: the hex is the hue at the brightest component 1, a Brightness
   * row under it the scale. Returns whether it changed.
   */
  bool ColourField(const char* id, float (&rgb)[3], bool brighterThanWhite = false);

  /** Text that reads on the accent: dark on a light accent, white on a dark one. */
  [[nodiscard]] ImVec4 AccentText();
} // namespace faf::editor

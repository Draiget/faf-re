#pragma once

// The panels' controls as the mockup draws them (mockup/styles.css): the fill slider (a dark track, the value as a fill
// of the accent, its name on the left and its value on the right; drag anywhere to scrub, Shift for fine steps, a
// double-click or Ctrl+click types a number), the primary button (filled with the accent) and the mode tile (a
// bordered tile, the picked one in the accent's soft fill and border). They take ImGui's own arguments, so they stand
// in for ImGui::SliderFloat / SliderInt / DragFloat / DragInt where they were.

#include "imgui.h"

#include <cstddef>

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
  /** The mockup's tool-mode tile: the icon above its name, bordered, the picked one in the accent (`size.y` 0: two
   * text lines and the padding). */
  bool ModeTile(const char* icon, const char* label, bool picked, ImVec2 size);

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

  /**
   * The mockup's pill toggle (.hm-chip): a rounded outline, the chosen one in the accent's soft fill and outline. True
   * when clicked.
   */
  bool PillToggle(const char* label, bool on);
  /**
   * The mockup's select: ImGui's combo with its value, and a small chevron at its right on the field's own colour where
   * ImGui draws a button-coloured box with a white triangle. Same arguments as ImGui::BeginCombo; ImGui::EndCombo ends
   * it.
   */
  bool EdBeginCombo(const char* label, const char* preview, ImGuiComboFlags flags = 0);
  /** ImGui::Combo over a list of names, drawn as EdBeginCombo. */
  bool EdCombo(const char* label, int* current, const char* const items[], int count, int popupItems = -1);

  /** A pill toggle's width, to lay a row of them out. */
  [[nodiscard]] float PillWidth(const char* label);

  /**
   * The mockup's search field (.hm-search): tall, rounded, on the panels' grey, a magnifier inside at its left.
   * `width` < 0 fills the line up to that much from its end, as ImGui's item widths do.
   */
  bool SearchField(
    const char* id,
    const char* hint,
    char* buffer,
    std::size_t size,
    float width = -1.0f,
    ImGuiInputTextFlags flags = 0
  );
  /**
   * Tooltips as the mockup draws them (styles.css .tooltip): near-black, rounded, a little padding, at most about 22 em
   * wide with the words wrapped. A text with more than one line shows its first line as a semibold title and the rest
   * in the quieter grey. EdBeginTooltip opens one for a body of the caller's own (ImGui::EndTooltip closes it).
   */
  bool EdBeginTooltip();
  void EdTooltipText(const char* text);
  void EdSetTooltip(const char* format, ...) IM_FMTARGS(1);
  /** When the last item is hovered as ImGui's SetItemTooltip waits for. */
  void EdSetItemTooltip(const char* format, ...) IM_FMTARGS(1);
} // namespace faf::editor

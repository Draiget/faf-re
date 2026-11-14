#pragma once

#include <cstdint>
#include <string>

#include "imgui.h"

namespace faf::editor
{
  /** What a card says under its picture: the title (bold), a detail line, and a third line (when, or where). */
  struct EdCardText
  {
    std::string title;
    std::string meta;
    std::string third;
  };

  struct EdCardResult
  {
    bool clicked = false;
    bool hovered = false;
  };

  /**
   * The start screen's card (the mockup's .hm-vc): the picture edge to edge at its top (its middle when the picture is
   * squarer than the space), the kind as a pill on it in the kind's colour, then the words. `picked` outlines it in the
   * accent. The card's button is the last item, so a context menu can follow it.
   */
  EdCardResult KindCard(
    const char* id,
    const ImVec2& size,
    float pictureHeight,
    std::uint64_t picture,
    const char* kind,
    unsigned int kindRgb,
    const EdCardText& text,
    bool picked = false
  );

  /** A card's height for a picture this tall (the three lines under it). */
  [[nodiscard]] float KindCardHeight(float pictureHeight);
} // namespace faf::editor

#pragma once

#include "editor/tools/EdHeightFile.h"

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /** The lobby preview's side in pixels (the game's and the retail editor's). */
  constexpr int kPreviewSide = 256;

  /** A dot drawn on the preview: a start position, a mass or hydrocarbon point. */
  struct PreviewDot
  {
    float x = 0.0f;
    float z = 0.0f;
    /** 0xAARRGGBB. */
    std::uint32_t colour = 0xFFFFFFFFu;
    float radius = 3.0f;
  };

  struct PreviewOptions
  {
    bool water = false;
    /** The sea's level in game units. */
    float waterLevel = 0.0f;
    std::vector<PreviewDot> dots;
  };

  /**
   * Where the map sits in the square preview: at its longer side's scale, centred (FAF's lobby assumes a map that
   * isn't square is centred in its preview, resmappreview.lua). Pixel = (world - 0) / scale + offset.
   */
  struct PreviewFrame
  {
    float scale = 1.0f; // game units per pixel
    float offsetX = 0.0f;
    float offsetZ = 0.0f;
  };
  [[nodiscard]] PreviewFrame PreviewFrameOf(float mapWidth, float mapDepth);

  /**
   * The preview picture, kPreviewSide squared, 0xAARRGGBB row by row from the north: the heights shaded (lit from
   * the north-west) and tinted by height (green low ground to grey and white peaks), the sea blue by its depth, the
   * dots on top; outside the map black. `heights` covers the whole map (its words 1/128 of a game unit).
   */
  [[nodiscard]] std::vector<std::uint32_t>
  PreviewPixels(const HeightImage& heights, float mapWidth, float mapDepth, const PreviewOptions& options);

  /**
   * The `.scmap` preview chunk (RWldMapPreviewChunk's layout, version 2) holding `pixels` (kPreviewSide squared,
   * 0xAARRGGBB) as a 32-bit BGRA DDS with the classic header, for a map of that size.
   */
  [[nodiscard]] std::vector<char>
  PreviewRecord(float mapWidth, float mapDepth, const std::vector<std::uint32_t>& pixels);
} // namespace faf::editor

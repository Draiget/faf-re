#pragma once

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /**
   * The water's three masks (CWldTerrainRes::GetWaterFoam / Flatness / DepthBias): a byte for every 2 x 2 units of the
   * map, saved with it. Foam and flatness go into the water map the water shader reads (RebuildWaterMapRect packs foam
   * in alpha and flatness in red); depth bias is kept and saved but nothing draws with it.
   */
  enum class WaterMask
  {
    Foam,
    Flatness,
    DepthBias,
  };

  /** What a new map's terrain gives each mask (CWldTerrainRes::CreateWaterMasks: 0, 0xFF, 0x7F). */
  [[nodiscard]] std::uint8_t WaterMaskDefault(WaterMask mask) noexcept;
  [[nodiscard]] const char* WaterMaskName(WaterMask mask) noexcept;

  struct WaterMaskBrush
  {
    float radius = 16.0f;  // map units
    float strength = 0.5f; // how far a dab moves a cell towards the value, 0..1
    float falloff = 0.5f;  // the soft outer part of the radius, 0 (hard) .. 1
    std::uint8_t value = 255;
  };

  /** The cells a dab changed, [x0, x1) x [z0, z1) in mask cells; empty when none. */
  struct WaterMaskRect
  {
    int x0 = 0, z0 = 0, x1 = 0, z1 = 0;
    [[nodiscard]] bool Empty() const noexcept
    {
      return x1 <= x0 || z1 <= z0;
    }
  };

  /**
   * One dab at (x, z) in map units on a `width` x `height` mask: each cell (whose middle is at 2i + 1, 2j + 1) moves
   * towards the brush's value by its strength, full inside the hard part of the radius, fading to nothing at its edge.
   * A cell always moves at least one step towards the value when the dab reaches it, so a weak dab still finishes.
   */
  WaterMaskRect
  PaintWaterMask(std::uint8_t* cells, int width, int height, float x, float z, const WaterMaskBrush& brush);

  /**
   * The overlay's bands: a cell at the mask's default is 0 (not drawn), any other 1 + value / 32 (1..8), for the
   * terrain-type run drawing.
   */
  [[nodiscard]] std::vector<std::uint8_t>
  WaterMaskBands(const std::uint8_t* cells, int width, int height, WaterMask mask);
} // namespace faf::editor

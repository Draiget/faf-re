#pragma once

namespace faf::editor
{
  /**
   * A terrain layer's tile size from texel density (FAF Studio's texscale.lua). A texture R pixels wide over a tile of
   * T world units shows R / T texels per unit; the closest normal view shows p screen pixels per unit (1080 px high, a
   * 45 degree view, 27 units away: p = 48.3). The best tile is the largest that stays sharp, T = R / p, rounded to
   * 0.5, at least 20 (a smaller tile repeats so often its grain shows as a pattern) and within 4 .. 64: a 1024 px
   * texture gets 21, a 2048 px one 42.5. A normal map takes its albedo's size (they share their UVs).
   */
  inline constexpr float kTexelDensity = 48.29f;

  /** The tile size for a texture `pixels` wide (1024 when it can't be read). */
  [[nodiscard]] float TileForPixels(int pixels);

  /** size * phi^steps, rounded to 0.5 and never below 4: tiles whose repeats never line up with `size`'s. */
  [[nodiscard]] float DecorrelatedTile(float size, int steps);

  /**
   * The Upper layer's tile (a macrotexture over the layers): the base tile times phi^k for k = 2 .. 5, within 32 ..
   * 256, its ratio to the base at least 0.08 from a whole number after rounding, the nearest to 128 in log scale.
   */
  [[nodiscard]] float MacroTile(float baseTile);

  /** A size nobody chose for a texture: unset, the engine's empty slot value (4, or 1), or `optimal`. */
  [[nodiscard]] bool IsDefaultTile(float size, float optimal);

  /** The pixel width in a DDS file's header (bytes), 0 when it isn't one. */
  [[nodiscard]] int DdsWidth(const void* bytes, unsigned long long count);
} // namespace faf::editor

// FAF addition, not in the shipped binary: where a scripted decal's quad starts so that it is
// centred on a point at any heading.
#pragma once

#include <cmath>

namespace moho
{
  /** The x/z corner a `CWldTerrainDecal` is placed at (its `mPosition`). */
  struct ScriptedDecalCorner
  {
    float x;
    float z;
  };

  /**
   * The corner that centres a decal of `scaleX` by `scaleZ` on (`centreX`, `centreZ`) when it is
   * turned by `heading` radians.
   *
   * `CWldTerrainDecal::ComputeCorner` (0x0089D9C0) maps the quad's (u, v) in [0, 1]^2 to
   * `position + u * scaleX * (cos h, sin h) + v * scaleZ * (-sin h, cos h)` in x/z, so its middle
   * (0.5, 0.5) is half of those two edges past the corner. At heading 0 this is the binary's
   * `centre - scale / 2` (0x0087ECE0).
   */
  [[nodiscard]] inline ScriptedDecalCorner ScriptedDecalCornerForCentre(
    const float centreX, const float centreZ, const float scaleX, const float scaleZ, const float heading
  ) noexcept
  {
    if (heading == 0.0f) {
      return {centreX - scaleX * 0.5f, centreZ - scaleZ * 0.5f};
    }

    const float cosine = std::cos(heading);
    const float sine = std::sin(heading);
    return {
      centreX - 0.5f * (scaleX * cosine - scaleZ * sine),
      centreZ - 0.5f * (scaleX * sine + scaleZ * cosine),
    };
  }
} // namespace moho

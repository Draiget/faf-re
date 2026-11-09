#pragma once

#include <algorithm>

#include "moho/render/ShadowStableFit.h"

namespace moho
{
  /**
   * Engine addition (`ren_ShadowCascades`): where one tile of the shadow atlas sits and what part of the
   * whole-view map it answers for. Pure maths, so `tests/render/ShadowStableFitTests.cpp` can run it
   * without a device.
   *
   * Every tile shares the whole-view map's light view and depth range; only the light-space box differs.
   * The effects compute the whole-view map's texture coordinate, u = (x - base.minX) / base width and
   * v = (base.maxY - y) / base height (the projection flips y), so a tile's own coordinate is a scale and
   * offset of it.
   */
  struct ShadowCascadeLookup
  {
    /** The whole-view coordinates the tile answers for: min u, min v, max u, max v. */
    float box[4];
    /** Into the atlas: atlas u = u * map[0] + map[2], atlas v = v * map[1] + map[3]. */
    float map[4];
  };

  /**
   * The lookup for a tile drawn with light-space box `tile` into the square viewport at (`originX`,
   * `originY`), `content` texels across, of an atlas `atlas` texels across. The box shrinks by `margin`
   * of the tile's texels, so the blur, which spreads a few texels into the gutter around the viewport,
   * never reaches a lookup; it is also cut to the whole-view map, past which nothing was drawn.
   */
  [[nodiscard]] inline ShadowCascadeLookup FitShadowCascadeLookup(
    const ShadowStableBox& base,
    const ShadowStableBox& tile,
    const float originX,
    const float originY,
    const float content,
    const float atlas,
    const float margin
  ) noexcept
  {
    const float baseWidth = base.maxX - base.minX;
    const float baseHeight = base.maxY - base.minY;
    const float tileWidth = tile.maxX - tile.minX;
    const float tileHeight = tile.maxY - tile.minY;

    ShadowCascadeLookup lookup{};
    const float marginU = margin * (tileWidth / content) / baseWidth;
    const float marginV = margin * (tileHeight / content) / baseHeight;
    lookup.box[0] = std::max(0.0f, (tile.minX - base.minX) / baseWidth + marginU);
    lookup.box[1] = std::max(0.0f, (base.maxY - tile.maxY) / baseHeight + marginV);
    lookup.box[2] = std::min(1.0f, (tile.maxX - base.minX) / baseWidth - marginU);
    lookup.box[3] = std::min(1.0f, (base.maxY - tile.minY) / baseHeight - marginV);

    lookup.map[0] = (baseWidth / tileWidth) * (content / atlas);
    lookup.map[1] = (baseHeight / tileHeight) * (content / atlas);
    lookup.map[2] = (originX + ((base.minX - tile.minX) / tileWidth) * content) / atlas;
    lookup.map[3] = (originY + ((tile.maxY - base.maxY) / tileHeight) * content) / atlas;
    return lookup;
  }
} // namespace moho

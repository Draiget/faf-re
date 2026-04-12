#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  class RD3DTextureResource;

  /**
   * VFTABLE: 0x00E419D4
   *
   * Base class for terrain rendering. Holds the shared decal mask texture
   * loaded from `/textures/engine/decalMask.dds`.
   */
  class TerrainCommon
  {
  public:
    /**
     * Address: 0x007FF840 (FUN_007FF840, ??0TerrainCommon@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the vtable and loads the decal mask texture from D3D resources.
     */
    TerrainCommon();

    virtual ~TerrainCommon() = default;

    boost::shared_ptr<RD3DTextureResource> mDecalMask{}; // +0x04
  };

  static_assert(offsetof(TerrainCommon, mDecalMask) == 0x04, "TerrainCommon::mDecalMask offset must be 0x04");
  static_assert(sizeof(TerrainCommon) == 0x0C, "TerrainCommon size must be 0x0C");
} // namespace moho

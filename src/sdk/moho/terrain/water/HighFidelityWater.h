#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "moho/terrain/water/WaterSurface.h"

namespace moho
{
  class CD3DIndexSheet;
  class CD3DVertexSheet;
  struct GeomCamera3;
  class ID3DTextureSheet;

  /**
   * Terrain-water owner for the high-fidelity rendering path.
   */
  class HighFidelityWater : public WaterSurface
  {
  public:
    /**
     * Address: 0x008101E0 (??0HighFidelityWater@Moho@@QAE@@Z)
     * Mangled: ??0HighFidelityWater@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes high-fidelity water runtime lanes to an empty state.
     */
    HighFidelityWater();

    /**
     * Address: 0x00810220 (??1HighFidelityWater@Moho@@QAE@@Z)
     * Mangled: ??1HighFidelityWater@Moho@@QAE@@Z
     *
     * What it does:
     * Releases retained shared-owner lanes, destroys owned render sheets, and
     * clears the bound terrain-resource lane.
     */
    ~HighFidelityWater() override;

    /**
     * Address: 0x00810300 (FUN_00810300, Moho::HighFidelityWater::InitVerts)
     *
     * What it does:
     * Builds one high-fidelity water quad vertex/index-sheet pair from the
     * current terrain map extents and water elevation.
     */
    bool InitVerts(TerrainWaterResourceView* terrainResource) override;

    /**
     * Address: 0x00810540 (FUN_00810540, Moho::HighFidelityWater::Func1)
     * Mangled: ?Func1@HighFidelityWater@Moho@@QAEXXZ
     *
     * What it does:
     * Clears the cached runtime state used by the high-fidelity water render
     * path, including both shared texture handles and owned render sheets.
     */
    void ReleaseRenderState();

    /**
     * Address: 0x008105E0 (FUN_008105E0, Moho::HighFidelityWater::Func2)
     *
     * What it does:
     * Binds water2 alpha-mask shader camera textures, selects
     * `TWaterLayAlphaMask`, and draws the retained high-fidelity water sheet.
     */
    bool RenderWaterLayerAlphaMask(const GeomCamera3* camera) override;

    /**
     * Address: 0x008106D0 (FUN_008106D0, Moho::HighFidelityWater::Func3)
     *
     * What it does:
     * Binds `water2/TWater`, updates all high-fidelity water shader lanes,
     * refreshes/uses the cached Fresnel lookup texture, and draws the water
     * vertex/index sheet.
     */
    bool RenderWaterSurface(
      std::int32_t tick,
      float tickLerp,
      const GeomCamera3* camera,
      const CWaterShaderProperties* shaderProperties,
      boost::weak_ptr<gpg::gal::TextureD3D9> refractionTexture,
      boost::weak_ptr<gpg::gal::TextureD3D9> reflectionTexture
    ) override;

    TerrainWaterResourceView* mTerrainRes = nullptr;              // +0x04
    float mWaterElevation = 0.0F;                                 // +0x08
    float mCachedFresnelBias = 0.0F;                              // +0x0C
    float mCachedFresnelPower = 0.0F;                             // +0x10
    float mCachedSunShininess = 0.0F;                             // +0x14
    float mCachedSunReflectionAmount = 0.0F;                      // +0x18
    boost::SharedPtrRaw<ID3DTextureSheet> mFresnelLookupTexture;  // +0x1C
    CD3DVertexSheet* mVertexSheet = nullptr;                      // +0x24
    CD3DIndexSheet* mIndexSheet = nullptr;                        // +0x28
    boost::SharedPtrRaw<ID3DTextureSheet> mWaterMapTexture;       // +0x2C
  };

  static_assert(
    offsetof(HighFidelityWater, mTerrainRes) == 0x04,
    "HighFidelityWater::mTerrainRes offset must be 0x04"
  );
  static_assert(
    offsetof(HighFidelityWater, mFresnelLookupTexture) == 0x1C,
    "HighFidelityWater::mFresnelLookupTexture offset must be 0x1C"
  );
  static_assert(
    offsetof(HighFidelityWater, mVertexSheet) == 0x24,
    "HighFidelityWater::mVertexSheet offset must be 0x24"
  );
  static_assert(
    offsetof(HighFidelityWater, mWaterMapTexture) == 0x2C,
    "HighFidelityWater::mWaterMapTexture offset must be 0x2C"
  );
  static_assert(sizeof(HighFidelityWater) == 0x34, "HighFidelityWater size must be 0x34");
} // namespace moho

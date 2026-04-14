#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/terrain/water/WaterSurface.h"

namespace moho
{
  class CD3DIndexSheet;
  class CD3DVertexSheet;

  class LowFidelityWater : public WaterSurface
  {
  public:
    /**
     * Address: 0x0080F970 (??1LowFidelityWater@Moho@@QAE@@Z)
     * Mangled: ??1LowFidelityWater@Moho@@QAE@@Z
     *
     * What it does:
     * Releases retained low-fidelity render sheets and clears the bound
     * terrain-resource lane.
     */
    ~LowFidelityWater() override;

    /**
     * Address: 0x0080FA10 (FUN_0080FA10)
     *
     * TerrainWaterResourceView *
     *
     * IDA signature:
     * char __thiscall Moho::LowFidelityWater::InitVerts(float *this, int terrainRes);
     *
     * What it does:
     * Rebuilds one low-fidelity water quad vertex/index-sheet pair from the
     * current terrain map dimensions and water elevation.
     */
    bool InitVerts(TerrainWaterResourceView* terrainResource) override;

    /**
     * Address: 0x0080FC40 (FUN_0080FC40)
     *
     * What it does:
     * Releases retained low-fidelity water vertex/index sheet ownership and
     * clears the bound terrain-resource lane.
     */
    std::int32_t ReleaseRenderSheets();

    /**
     * Address: 0x0080FC70 (FUN_0080FC70, Moho::LowFidelityWater::Func2)
     *
     * What it does:
     * No-op water alpha-mask lane retained for low-fidelity slot parity.
     */
    bool RenderWaterLayerAlphaMask(const GeomCamera3* camera) override;

    /**
     * Address: 0x0080FC80 (FUN_0080FC80, Moho::LowFidelityWater::Func3)
     *
     * What it does:
     * Binds `water2/TWater`, updates water shader uniforms from camera and
     * properties, binds normal/water-map textures, and draws the retained quad.
     */
    bool RenderWaterSurface(
      std::int32_t tick,
      float tickLerp,
      const GeomCamera3* camera,
      const CWaterShaderProperties* shaderProperties,
      boost::weak_ptr<gpg::gal::TextureD3D9> refractionTexture,
      boost::weak_ptr<gpg::gal::TextureD3D9> reflectionTexture
    ) override;

    TerrainWaterResourceView* mTerrainRes = nullptr; // +0x04
    float mWaterElevation = 0.0F;                    // +0x08
    CD3DVertexSheet* mVertexSheet = nullptr;         // +0x0C
    CD3DIndexSheet* mIndexSheet = nullptr;           // +0x10
  };

  static_assert(offsetof(LowFidelityWater, mTerrainRes) == 0x04, "LowFidelityWater::mTerrainRes offset must be 0x04");
  static_assert(
    offsetof(LowFidelityWater, mWaterElevation) == 0x08,
    "LowFidelityWater::mWaterElevation offset must be 0x08"
  );
  static_assert(
    offsetof(LowFidelityWater, mVertexSheet) == 0x0C,
    "LowFidelityWater::mVertexSheet offset must be 0x0C"
  );
  static_assert(offsetof(LowFidelityWater, mIndexSheet) == 0x10, "LowFidelityWater::mIndexSheet offset must be 0x10");
  static_assert(sizeof(LowFidelityWater) == 0x14, "LowFidelityWater size must be 0x14");
} // namespace moho

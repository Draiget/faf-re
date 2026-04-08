#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class CD3DIndexSheet;
  class CD3DVertexSheet;
  struct TerrainMapRuntimeView;

  /**
   * Recovered leading layout for terrain-resource lanes consumed by
   * low-fidelity water initialization.
   */
  struct TerrainWaterResourceView
  {
    void* mVtable; // +0x00
    TerrainMapRuntimeView* mMap; // +0x04
  };

  static_assert(
    offsetof(TerrainWaterResourceView, mMap) == 0x04,
    "TerrainWaterResourceView::mMap offset must be 0x04"
  );

  class LowFidelityWater
  {
  public:
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
    bool InitVerts(TerrainWaterResourceView* terrainResource);

    /**
     * Address: 0x0080FC40 (FUN_0080FC40)
     *
     * What it does:
     * Releases retained low-fidelity water vertex/index sheet ownership and
     * clears the bound terrain-resource lane.
     */
    std::int32_t ReleaseRenderSheets();

    /**
     * Address: 0x0080FC70 (FUN_0080FC70)
     *
     * std::uint32_t
     *
     * What it does:
     * No-op reserved virtual lane retained for binary slot fidelity.
     */
    void ReservedNoOp(std::uint32_t reservedToken);

    void* mVtable;                            // +0x00
    TerrainWaterResourceView* mTerrainRes;   // +0x04
    float mWaterElevation;                    // +0x08
    CD3DVertexSheet* mVertexSheet;            // +0x0C
    CD3DIndexSheet* mIndexSheet;              // +0x10
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

#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/render/camera/VTransform.h"
#include "moho/terrain/TerrainCommon.h"
#include "moho/terrain/water/Shoreline.h"

namespace moho
{
  class CD3DIndexSheet;
  class CD3DVertexSheet;
  class CTesselator;
  struct GeomCamera3;
  struct TerrainWaterResourceView;

  /**
   * High-fidelity terrain renderer and shoreline-sheet owner runtime.
   */
  class HighFidelityTerrain : public TerrainCommon
  {
  public:
    using PrimaryPatchIndexLane = gpg::core::FastVectorN<std::uint32_t, 3000>;
    using SecondaryPatchIndexLane = gpg::core::FastVectorN<std::uint32_t, 70000>;

    /**
     * Address: 0x007FF940 (??0HighFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??0HighFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes high-fidelity terrain runtime ownership lanes, shoreline
     * subobject, both inline patch-index vectors, and identity transform state.
     */
    HighFidelityTerrain();

    /**
     * Address: 0x007FFA40 (??1HighFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??1HighFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Tears down high-fidelity terrain resources, restores both inline patch
     * vector storage lanes, and then unwinds shoreline + base terrain state.
     */
    ~HighFidelityTerrain() override;

    /**
     * Address: 0x00803970 (FUN_00803970, ??3HighFidelityTerrain@Moho@@QAE@@Z)
     *
     * What it does:
     * Runs the high-fidelity terrain destructor lane and conditionally frees
     * the object storage when the delete flag requests heap release.
     */
    static HighFidelityTerrain* DeleteWithFlag(HighFidelityTerrain* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x007FFB80 (FUN_007FFB80, Moho::HighFidelityTerrain::Create)
     *
     * What it does:
     * Binds the terrain resource, clears shared high-fidelity water/texture
     * helper lanes, then dispatches initialization.
     */
    bool Create(TerrainWaterResourceView* terrainResource) override;

    /**
     * Address: 0x008002E0 (FUN_008002E0, Moho::HighFidelityTerrain::Destroy)
     *
     * What it does:
     * Releases shoreline/tessellator/render-sheet ownership and drops retained
     * decal-mask texture ownership.
     */
    void Destroy();

    /**
     * Address: 0x007FFC60 (FUN_007FFC60, Moho::HighFidelityTerrain::Init)
     *
     * What it does:
     * Rebuilds high-fidelity terrain sheets/tessellation, regenerates shoreline
     * cells, and lazily initializes shared terrain texture helpers.
     */
    bool Init();

    /**
     * Address: 0x008033E0 (FUN_008033E0, Moho::HighFidelityTerrain::DrawWaterline)
     *
     * What it does:
     * Dispatches the shared high-fidelity water alpha-mask lane, then draws
     * shoreline overlays for the active terrain camera.
     */
    void DrawWaterline(std::int32_t arg0, std::int32_t arg1);

    /**
     * Address: 0x008131D0 (FUN_008131D0, Moho::HighFidelityTerrain::DrawShoreline)
     *
     * What it does:
     * Draws shoreline vertex-sheet geometry through `water2/TShoreline`,
     * binding camera matrices and current terrain water elevation.
     */
    static void DrawShoreline(const Shoreline* shoreline, const GeomCamera3* camera);

    TerrainWaterResourceView* mTerrainResource = nullptr; // +0x0C
    std::uint8_t mUnknown10_27[0x18];                     // +0x10..+0x27
    GeomCamera3* mCamera = nullptr;                       // +0x28
    std::uint8_t mUnknown2C_3F[0x14];                     // +0x2C..+0x3F

    PrimaryPatchIndexLane mPrimaryPatchData;              // +0x40
    CTesselator* mTesselator = nullptr;                   // +0x2F30
    Shoreline mShoreline;                                 // +0x2F34
    CD3DVertexSheet* mTerrainVertexSheet = nullptr;       // +0x2FE4
    CD3DIndexSheet* mTerrainIndexSheet = nullptr;         // +0x2FE8
    std::uint32_t mPad2FEC = 0u;                          // +0x2FEC

    SecondaryPatchIndexLane mSecondaryPatchData;          // +0x2FF0
    CD3DVertexSheet* mDynamicVertexSheet = nullptr;       // +0x475C0
    CD3DIndexSheet* mDynamicIndexSheet = nullptr;         // +0x475C4
    VTransform mTerrainTransform;                         // +0x475C8
    std::uint32_t mUnknown475E4;                          // +0x475E4
  };

  static_assert(
    offsetof(HighFidelityTerrain, mTerrainResource) == 0x0C,
    "HighFidelityTerrain::mTerrainResource offset must be 0x0C"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mPrimaryPatchData) == 0x40,
    "HighFidelityTerrain::mPrimaryPatchData offset must be 0x40"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mTesselator) == 0x2F30,
    "HighFidelityTerrain::mTesselator offset must be 0x2F30"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mShoreline) == 0x2F34,
    "HighFidelityTerrain::mShoreline offset must be 0x2F34"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mTerrainVertexSheet) == 0x2FE4,
    "HighFidelityTerrain::mTerrainVertexSheet offset must be 0x2FE4"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mSecondaryPatchData) == 0x2FF0,
    "HighFidelityTerrain::mSecondaryPatchData offset must be 0x2FF0"
  );
  static_assert(
    (offsetof(HighFidelityTerrain, mSecondaryPatchData) + offsetof(HighFidelityTerrain::SecondaryPatchIndexLane, inlineVec_))
      == 0x3000,
    "HighFidelityTerrain::mSecondaryPatchData inline storage must start at 0x3000"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mDynamicVertexSheet) == 0x475C0,
    "HighFidelityTerrain::mDynamicVertexSheet offset must be 0x475C0"
  );
  static_assert(
    offsetof(HighFidelityTerrain, mTerrainTransform) == 0x475C8,
    "HighFidelityTerrain::mTerrainTransform offset must be 0x475C8"
  );
  static_assert(sizeof(HighFidelityTerrain) == 0x475E8, "HighFidelityTerrain size must be 0x475E8");
} // namespace moho

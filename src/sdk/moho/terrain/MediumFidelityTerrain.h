#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/render/camera/VTransform.h"
#include "moho/terrain/TerrainCommon.h"

namespace moho
{
  using MediumPrimaryPatchIndexLane = gpg::core::FastVectorN<std::uint32_t, 3000>;
  using MediumSecondaryPatchIndexLane = gpg::core::FastVectorN<std::uint32_t, 70000>;

  class CD3DIndexSheet;
  class CD3DVertexSheet;
  class CTesselator;
  struct GeomCamera3;
  struct TerrainWaterResourceView;

  /**
   * Medium-fidelity terrain renderer runtime.
   */
  class MediumFidelityTerrain : public TerrainCommon
  {
  public:
    /**
     * Address: 0x00803A10 (FUN_00803A10, ??0MediumFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??0MediumFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes medium-fidelity terrain ownership lanes and both inline
     * patch-index vector stores.
     */
    MediumFidelityTerrain();

    /**
     * Address: 0x00803AD0 (FUN_00803AD0, ??1MediumFidelityTerrain@Moho@@QAE@@Z)
     * Mangled: ??1MediumFidelityTerrain@Moho@@QAE@@Z
     *
     * What it does:
     * Tears down medium-fidelity terrain resources, restores inline vector
     * storage ownership, and then dispatches base teardown.
     */
    ~MediumFidelityTerrain() override;

    /**
     * Address: 0x00807990 (FUN_00807990, ??3MediumFidelityTerrain@Moho@@QAE@@Z)
     *
     * What it does:
     * Runs the medium-fidelity terrain destructor lane and conditionally frees
     * the object storage when the delete flag requests heap release.
     */
    static MediumFidelityTerrain* DeleteWithFlag(
      MediumFidelityTerrain* object,
      std::uint8_t deleteFlags
    ) noexcept;

    /**
     * Address: 0x00803C00 (FUN_00803C00, Moho::MediumFidelityTerrain::Create)
     *
     * What it does:
     * Binds the terrain resource, clears shared medium-fidelity water/texture
     * helper lanes, then dispatches initialization.
     */
    bool Create(TerrainWaterResourceView* terrainResource) override;

    /**
     * Address: 0x00804350 (FUN_00804350)
     *
     * What it does:
     * Releases all owned tesselator/sheet lanes and clears the shared decal
     * mask ownership handle.
     */
    void Destroy();

    /**
     * Address: 0x00803CE0 (FUN_00803CE0, Moho::MediumFidelityTerrain::Init)
     *
     * What it does:
     * Rebuilds medium-fidelity terrain tessellation/sheet lanes, fills dynamic
     * quad index buffers, and lazily initializes runtime texture helpers.
     */
    bool Init();

    /**
     * Address: 0x00807410 (FUN_00807410, Moho::MediumFidelityTerrain::DrawWaterLine)
     *
     * What it does:
     * Dispatches the shared medium-fidelity water alpha-mask lane for the
     * active terrain camera.
     */
    void DrawWaterLine(std::int32_t arg0, std::int32_t arg1);

    /**
     * Address: 0x00805530 (FUN_00805530, Moho::MediumFidelityTerrain::DrawTerrainSkirt)
     *
     * What it does:
     * Issues one terrain-skirt triangle-list draw for the medium-fidelity
     * terrain path when skirt rendering is enabled and index-lane constraints
     * are valid.
     */
    virtual void DrawTerrainSkirt();

    TerrainWaterResourceView* mTerrainResource;                        // +0x0C
    std::uint8_t mReserved10_27[0x18];                                // +0x10
    GeomCamera3* mCamera;                                              // +0x28
    std::uint32_t mSkirtStartIndex = 0u;                              // +0x2C
    std::uint32_t mUnknown30 = 0u;                                    // +0x30
    std::uint32_t mSkirtEndIndex = 0u;                                // +0x34
    std::int32_t mSkirtEndVertex = 0;                                 // +0x38
    std::int32_t mSkirtBaseVertex = 0;                                // +0x3C
    MediumPrimaryPatchIndexLane mPrimaryPatchIndices;                  // +0x40
    CTesselator* mTesselator;                                          // +0x2F30
    CD3DVertexSheet* mTerrainVertexSheet;                              // +0x2F34
    CD3DIndexSheet* mTerrainIndexSheet;                                // +0x2F38
    std::uint32_t mPad2F3C = 0u;                                       // +0x2F3C
    MediumSecondaryPatchIndexLane mSecondaryPatchIndices;              // +0x2F40
    CD3DVertexSheet* mOverlayVertexSheet;                              // +0x47510
    CD3DIndexSheet* mOverlayIndexSheet;                                // +0x47514
    VTransform mOverlayTransform;                                      // +0x47518
    std::uint32_t mUnknown47534;                                       // +0x47534
  };

  static_assert(
    offsetof(MediumPrimaryPatchIndexLane, inlineVec_) == 0x10,
    "FastVectorN<uint32_t,3000>::inlineVec_ offset must be 0x10"
  );

  static_assert(
    offsetof(MediumFidelityTerrain, mTerrainResource) == 0x0C,
    "MediumFidelityTerrain::mTerrainResource offset must be 0x0C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mPrimaryPatchIndices) == 0x40,
    "MediumFidelityTerrain::mPrimaryPatchIndices offset must be 0x40"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtStartIndex) == 0x2C,
    "MediumFidelityTerrain::mSkirtStartIndex offset must be 0x2C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtEndIndex) == 0x34,
    "MediumFidelityTerrain::mSkirtEndIndex offset must be 0x34"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtEndVertex) == 0x38,
    "MediumFidelityTerrain::mSkirtEndVertex offset must be 0x38"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSkirtBaseVertex) == 0x3C,
    "MediumFidelityTerrain::mSkirtBaseVertex offset must be 0x3C"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mPrimaryPatchIndices) +
        offsetof(MediumPrimaryPatchIndexLane, inlineVec_) ==
      0x50,
    "MediumFidelityTerrain primary patch inline storage must start at 0x50"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mTesselator) == 0x2F30,
    "MediumFidelityTerrain::mTesselator offset must be 0x2F30"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mSecondaryPatchIndices) == 0x2F40,
    "MediumFidelityTerrain::mSecondaryPatchIndices offset must be 0x2F40"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mOverlayVertexSheet) == 0x47510,
    "MediumFidelityTerrain::mOverlayVertexSheet offset must be 0x47510"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mOverlayTransform) == 0x47518,
    "MediumFidelityTerrain::mOverlayTransform offset must be 0x47518"
  );
  static_assert(
    offsetof(MediumFidelityTerrain, mUnknown47534) == 0x47534,
    "MediumFidelityTerrain::mUnknown47534 offset must be 0x47534"
  );
  static_assert(sizeof(MediumFidelityTerrain) == 0x47538, "MediumFidelityTerrain size must be 0x47538");
} // namespace moho

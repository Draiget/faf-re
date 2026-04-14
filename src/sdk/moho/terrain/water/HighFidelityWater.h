#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"

namespace moho
{
  class ID3DDeviceResources;
  class ID3DTextureSheet;

  class WaterSurface
  {
  public:
    virtual ~WaterSurface() = default;
  };

  /**
   * Terrain-water owner for the high-fidelity rendering path.
   *
   * The reconstructed binary evidence shows a resource-provider pointer, a
   * set of cached water parameters, two retained texture-sheet handles, and
   * two polymorphic helper subobjects that are torn down during destruction.
   */
  class HighFidelityWater : public WaterSurface
  {
  public:
    /**
     * Address: 0x00810220 (??1HighFidelityWater@Moho@@QAE@@Z)
     * Mangled: ??1HighFidelityWater@Moho@@QAE@@Z
     *
     * What it does:
     * Releases the retained shared-owner lanes, destroys the two polymorphic
     * helper subobjects, and restores the WaterSurface base vtable on exit.
     */
    virtual ~HighFidelityWater();

    /**
     * Address: 0x00810540 (FUN_00810540, Moho::HighFidelityWater::Func1)
     * Mangled: ?Func1@HighFidelityWater@Moho@@QAEXXZ
     *
     * What it does:
     * Clears the cached runtime state used by the high-fidelity water render
     * path, including both shared texture handles and the polymorphic helper
     * subobjects bound at the tail of the class.
     */
    void ReleaseRenderState();

    ID3DDeviceResources* mResources;                    // +0x04
    float mWaterElevation;                              // +0x08
    float mFresnelBias;                                 // +0x0C
    float mFresnelPower;                                // +0x10
    float mUnitReflectionAmount;                        // +0x14
    float mSkyReflectionAmount;                         // +0x18
    boost::SharedPtrRaw<ID3DTextureSheet> mFresnelMap;  // +0x1C
    void* mAuxiliarySurface0;                           // +0x24
    void* mAuxiliarySurface1;                           // +0x28
    boost::SharedPtrRaw<ID3DTextureSheet> mWaterMap;    // +0x2C
  };
} // namespace moho

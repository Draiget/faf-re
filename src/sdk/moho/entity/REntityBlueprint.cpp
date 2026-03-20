#include "moho/entity/REntityBlueprint.h"

#include <cmath>

namespace moho
{
  namespace
  {
    [[nodiscard]] std::uint8_t RoundExtentUpToCellCount(const float extent) noexcept
    {
      return static_cast<std::uint8_t>(static_cast<int>(std::ceil(static_cast<double>(extent))));
    }
  } // namespace

  /**
   * Address: 0x00512060 (FUN_00512060)
   *
   * What it does:
   * Initializes default footprint extents and inertia tensor values for
   * entity blueprints before derived blueprint init code runs.
   */
  void REntityBlueprint::OnInitBlueprint()
  {
    if (mFootprint.mSizeX == 0) {
      mFootprint.mSizeX = RoundExtentUpToCellCount(mSizeX);
    }
    if (mFootprint.mSizeZ == 0) {
      mFootprint.mSizeZ = RoundExtentUpToCellCount(mSizeZ);
    }
    if (mAltFootprint.mSizeX == 0) {
      mAltFootprint.mSizeX = RoundExtentUpToCellCount(mSizeX);
    }
    if (mAltFootprint.mSizeZ == 0) {
      mAltFootprint.mSizeZ = RoundExtentUpToCellCount(mSizeZ);
    }

    if ((mInertiaTensorX * mInertiaTensorY * mInertiaTensorZ) == 0.0f) {
      const float sizeX2 = mSizeX * mSizeX;
      const float sizeY2 = mSizeY * mSizeY;
      const float sizeZ2 = mSizeZ * mSizeZ;
      constexpr float kOneTwelfth = 0.083333336f;

      mInertiaTensorX = (sizeY2 + sizeZ2) * kOneTwelfth;
      mInertiaTensorY = (sizeX2 + sizeZ2) * kOneTwelfth;
      mInertiaTensorZ = (sizeX2 + sizeY2) * kOneTwelfth;
    }

    // NOTE:
    // The strategic icon load path in this function (0x00512230..0x00512717)
    // depends on the render-resource chain rooted at:
    // - 0x00511B80 (FUN_00511B80, helper `func_LoadStratIcon`)
    // - CD3DBatchTexture::FromFile(...)
    // That dependency chain is still under reconstruction.
  }

  /**
   * Address: 0x00511B60 (FUN_00511B60)
   *
   * What it does:
   * Base entity-blueprint mobility query. Returns false for the base type.
   */
  bool REntityBlueprint::IsMobile() const
  {
    return false;
  }

  /**
   * Address: 0x00511B70 (FUN_00511B70)
   *
   * What it does:
   * Base entity-blueprint unit cast hook. Returns nullptr for the base type.
   */
  const RUnitBlueprint* REntityBlueprint::IsUnitBlueprint() const
  {
    return nullptr;
  }
} // namespace moho

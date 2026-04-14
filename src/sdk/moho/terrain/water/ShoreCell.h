#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/mesh/Mesh.h"

namespace moho
{
  struct ShoreCellPoint2
  {
    float x; // +0x00
    float z; // +0x04
  };
  static_assert(sizeof(ShoreCellPoint2) == 0x08, "ShoreCellPoint2 size must be 0x08");

  /**
   * Runtime shoreline cell generated from one 2x2 heightfield mask.
   */
  class ShoreCell
  {
  public:
    virtual ~ShoreCell() = default;

    std::uint16_t mType;                    // +0x04
    std::uint16_t mPad06;                   // +0x06
    float mCenterX;                         // +0x08
    float mCenterZ;                         // +0x0C
    ShoreCellPoint2 mPoints[5];            // +0x10
    SpatialDB_MeshInstance mSpatialDbEntry; // +0x38
    Wm3::AxisAlignedBox3f mBounds;         // +0x40
  };

  static_assert(offsetof(ShoreCell, mType) == 0x04, "ShoreCell::mType offset must be 0x04");
  static_assert(offsetof(ShoreCell, mCenterX) == 0x08, "ShoreCell::mCenterX offset must be 0x08");
  static_assert(offsetof(ShoreCell, mPoints) == 0x10, "ShoreCell::mPoints offset must be 0x10");
  static_assert(offsetof(ShoreCell, mSpatialDbEntry) == 0x38, "ShoreCell::mSpatialDbEntry offset must be 0x38");
  static_assert(offsetof(ShoreCell, mBounds) == 0x40, "ShoreCell::mBounds offset must be 0x40");
  static_assert(sizeof(ShoreCell) == 0x58, "ShoreCell size must be 0x58");
} // namespace moho

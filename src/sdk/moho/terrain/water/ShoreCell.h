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
    /**
     * Address: 0x008126E0 (FUN_008126E0, ??0ShoreCell@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes one shoreline-cell object by setting `mType` to zero,
     * clearing the embedded spatial-db entry lanes, and zeroing all five
     * shoreline point pairs.
     */
    ShoreCell();

    /**
     * Address: 0x00812770 (FUN_00812770, sub_812770)
     *
     * What it does:
     * Runs one shoreline-cell teardown lane and releases the embedded spatial
     * DB mesh-instance binding when present.
     */
    virtual ~ShoreCell();

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

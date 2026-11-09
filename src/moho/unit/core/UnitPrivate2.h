#pragma once

// Private to moho/unit/core: helpers the pieces of the former Unit.cpp share.

#include "moho/unit/core/UnitPrivate.h"

namespace moho
{
  bool COORDS_CanMoveAt(SOCellPos* pos, COGrid* grid, Unit* moveUnit, bool disallowAttached, Unit* ignoreUnit);
}

namespace
{

  [[nodiscard]] CollisionDBRect COORDS_OgridRectToCollisionRect(const gpg::Rect2i& ogridRect) noexcept
  {
    // Address: 0x004FCAA0 (FUN_004FCAA0)
    const std::int32_t xPos = std::clamp(ogridRect.x0 >> 2, 0, 0xFFFF);
    const std::int32_t zPos = std::clamp(ogridRect.z0 >> 2, 0, 0xFFFF);
    const std::int32_t xEnd = (ogridRect.x1 + 3) >> 2;
    const std::int32_t zEnd = (ogridRect.z1 + 3) >> 2;

    CollisionDBRect collisionRect{};
    collisionRect.mStartX = static_cast<std::uint16_t>(xPos);
    collisionRect.mStartZ = static_cast<std::uint16_t>(zPos);

    const std::int32_t maxXSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.mStartX);
    const std::int32_t maxZSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.mStartZ);
    const std::int32_t xSpan = std::clamp(xEnd - static_cast<std::int32_t>(collisionRect.mStartX), std::int32_t{1}, maxXSpan);
    const std::int32_t zSpan = std::clamp(zEnd - static_cast<std::int32_t>(collisionRect.mStartZ), std::int32_t{1}, maxZSpan);

    collisionRect.mWidth = static_cast<std::uint16_t>(xSpan);
    collisionRect.mHeight = static_cast<std::uint16_t>(zSpan);
    return collisionRect;
  }

  [[maybe_unused]] [[nodiscard]] bool IsCollisionRectEquivalentToZero(const gpg::Rect2i& ogridRect) noexcept
  {
    const gpg::Rect2i zeroRect{};
    const CollisionDBRect currentCollisionRect = COORDS_OgridRectToCollisionRect(ogridRect);
    const CollisionDBRect zeroCollisionRect = COORDS_OgridRectToCollisionRect(zeroRect);
    return !currentCollisionRect.NotEqual(zeroCollisionRect);
  }

  /**
   * Address: 0x006A4BF0 (FUN_006A4BF0)
   *
   * What it does:
   * Copies this unit's reserved O-grid rectangle bounds into one `Rect2i`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::Rect2i GetReservedOgridRect(const Unit& unit) noexcept
  {
    return {
      unit.ReservedOgridRectMinX,
      unit.ReservedOgridRectMinZ,
      unit.ReservedOgridRectMaxX,
      unit.ReservedOgridRectMaxZ,
    };
  }

  /**
   * Address: 0x00565980 (FUN_00565980)
   *
   * What it does:
   * Returns the larger of the footprint X/Z side lengths.
   */
  [[maybe_unused]] [[nodiscard]] std::uint8_t FootprintMaxSide(const SFootprint& footprint) noexcept
  {
    return (footprint.mSizeX > footprint.mSizeZ) ? footprint.mSizeX : footprint.mSizeZ;
  }

  [[maybe_unused]] [[nodiscard]] bool IsMeleeCandidateCellNavigable(
    Unit& moveUnit,
    Unit* const ignoreUnit,
    const SFootprint& moverFootprint,
    const ELayer moveLayer,
    COGrid& ogrid,
    const STIMap& mapData,
    const SOCellPos& candidateCell
  )
  {
    EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(moverFootprint, mapData, candidateCell);
    if (moveLayer == LAYER_Water) {
      const std::uint8_t filteredCaps =
        static_cast<std::uint8_t>(occupancyCaps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB);
      occupancyCaps = static_cast<EOccupancyCaps>(filteredCaps);
    }

    if (static_cast<std::uint8_t>(OCCUPY_FootprintFits(ogrid, candidateCell, moverFootprint, occupancyCaps)) == 0u) {
      return false;
    }

    const gpg::Rect2i ogridRect{
      static_cast<std::int32_t>(candidateCell.x),
      static_cast<std::int32_t>(candidateCell.z),
      static_cast<std::int32_t>(candidateCell.x) + static_cast<std::int32_t>(moverFootprint.mSizeX),
      static_cast<std::int32_t>(candidateCell.z) + static_cast<std::int32_t>(moverFootprint.mSizeZ),
    };

    if (!moveUnit.CanReserveOgridRect(ogridRect)) {
      return false;
    }

    SOCellPos moveCell = candidateCell;
    return COORDS_CanMoveAt(&moveCell, &ogrid, &moveUnit, true, ignoreUnit);
  }
}


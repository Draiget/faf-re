#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"

namespace moho
{
  class CGeomSolid3;
  class CHeightField;

  enum EDepositType : std::int32_t
  {
    kNone = 0x0,
    kMass = 0x1,
    kHydrocarbon = 0x2,
  };

  struct ResourceDeposit
  {
    gpg::Rect2i footprintRect; // +0x00

    EDepositType depositType; // +0x10

    /**
     * Address: 0x00546170 (Moho::ResourceDeposit::Intersects)
     *
     * Moho::CGeomSolid3 const&, Moho::CHeightField const&
     *
     * What it does:
     * Builds a terrain-aligned AABB for the deposit corners and tests it against
     * the provided clipping solid.
     */
    [[nodiscard]] bool Intersects(const CGeomSolid3& solid, const CHeightField& field) const;
  };

  /**
   * Patch-parity payload for `GetDepositsAroundPoint` style queries.
   *
   * Carries the original deposit record plus center-distance from the query
   * point in world/grid XZ space.
   */
  struct ResourceDepositDistance
  {
    ResourceDeposit deposit; // +0x00
    float centerDistance;    // +0x14
  };

  static_assert(sizeof(ResourceDeposit) == 0x14, "ResourceDeposit size must be 0x14");
  static_assert(offsetof(ResourceDeposit, depositType) == 0x10, "ResourceDeposit::depositType offset must be 0x10");
  static_assert(sizeof(ResourceDepositDistance) == 0x18, "ResourceDepositDistance size must be 0x18");
  static_assert(
    offsetof(ResourceDepositDistance, centerDistance) == 0x14,
    "ResourceDepositDistance::centerDistance offset must be 0x14"
  );
} // namespace moho

#pragma once

#include <cstdint>

#include "moho/collision/CGeomSolid3.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  class CTesselator
  {
  public:
    virtual ~CTesselator() = default;

    /**
     * Address: 0x0080E020 (FUN_0080E020, Moho::CTesselator::GetIntersectionResult)
     *
     * int x, int z, int tier, unsigned int* activePlaneMask
     *
     * What it does:
     * Classifies one terrain-tier cell as reject/split/accept for adaptive
     * tesselation by combining frustum intersection and projected error.
     */
    [[nodiscard]] int GetIntersectionResult(int x, int z, int tier, std::uint32_t* activePlaneMask);

  private:
    CHeightField* mField;               // +0x04
    GeomCamera3* mCam;                  // +0x08
    std::uint32_t mWorkFlags;           // +0x0C
    CGeomSolid3 mGeomSolid;             // +0x10
    std::uint32_t mActivePlaneMask;     // +0x80
    std::uint32_t mCornerSelectionMask; // +0x84
    float mWaterElevation;              // +0x88
  };
} // namespace moho


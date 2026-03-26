#pragma once

#include <cstdint>

#include "wm3/Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CUnitMotion;
  class CAiPathSpline;
  struct SCollisionInfo;
  enum ECollisionType : std::int32_t;

  /**
   * VFTABLE: 0x00E1E064
   * COL:  0x00E74F9C
   */
  class IAiSteering
  {
  public:
    /**
     * Address: 0x005D1F10 (FUN_005D1F10, scalar deleting thunk)
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiSteering();

    /**
     * Address: 0x005D29C0 (FUN_005D29C0)
     *
     * What it does:
     * Replaces active steering waypoints and refreshes path-follow state.
     *
     * VFTable SLOT: 1
     */
    virtual CUnitMotion* SetWaypoints(const Wm3::Vector3f* waypoints, int waypointCount) = 0;

    /**
     * Address: 0x005D2110 (FUN_005D2110)
     *
     * What it does:
     * Copies the current waypoint buffer into `outWaypoints` and returns count.
     *
     * VFTable SLOT: 2
     */
    virtual int GetWaypoints(Wm3::Vector3f* outWaypoints) const = 0;

    /**
     * Address: 0x005D2170 (FUN_005D2170)
     *
     * What it does:
     * Returns the active target waypoint (or zero vector when no waypoints).
     *
     * VFTable SLOT: 3
     */
    virtual Wm3::Vector3f GetWaypoint() const = 0;

    /**
     * Address: 0x005D21B0 (FUN_005D21B0)
     *
     * What it does:
     * Returns true when steering consumed all queued waypoints.
     *
     * VFTable SLOT: 4
     */
    virtual bool IsDone() const = 0;

    /**
     * Address: 0x005D21C0 (FUN_005D21C0)
     *
     * What it does:
     * Returns mutable collision-avoidance state used by steering tick logic.
     *
     * VFTable SLOT: 5
     */
    virtual SCollisionInfo* GetColInfo() = 0;

    /**
     * Address: 0x005D3B40 (FUN_005D3B40)
     *
     * What it does:
     * Stores the latest collision reaction type and steering target position.
     *
     * VFTable SLOT: 6
     */
    virtual void SetCol(ECollisionType type, const Wm3::Vector3f& position) = 0;

    /**
     * Address: 0x005D21D0 (FUN_005D21D0)
     *
     * What it does:
     * Returns the current path-spline object.
     *
     * VFTable SLOT: 7
     */
    virtual CAiPathSpline* GetPath() = 0;

    /**
     * Address: 0x005D2390 (FUN_005D2390)
     *
     * What it does:
     * Updates "top-speed source #1" flag and applies composed top-speed policy.
     *
     * VFTable SLOT: 8
     */
    virtual void CalcAtTopSpeed1(bool enabled) = 0;

    /**
     * Address: 0x005D23E0 (FUN_005D23E0)
     *
     * What it does:
     * Updates "top-speed source #2" flag and applies composed top-speed policy.
     *
     * VFTable SLOT: 9
     */
    virtual void CalcAtTopSpeed2(bool enabled) = 0;

    /**
     * Address: 0x005D2430 (FUN_005D2430)
     *
     * What it does:
     * Selects whether top-speed policy comes from source #1 or source #2 flag.
     *
     * VFTable SLOT: 10
     */
    virtual void UseTopSpeed(bool enabled) = 0;

    /**
     * Address: 0x005D35E0 (FUN_005D35E0)
     *
     * What it does:
     * Stops active path-following and clears movement state.
     *
     * VFTable SLOT: 11
     */
    virtual void Stop() = 0;

  public:
    static gpg::RType* sType;
  };

  static_assert(sizeof(IAiSteering) == 0x04, "IAiSteering size must be 0x04");
} // namespace moho

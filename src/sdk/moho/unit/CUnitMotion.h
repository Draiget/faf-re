#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  struct CPathPoint;
  enum ELayer : std::int32_t;
  enum EUnitMotionVertEvent : std::int32_t
  {
    UMVE_None = 0,
    UMVE_Top = 1,
    UMVE_Unknown2 = 2,
    UMVE_Unknown3 = 3,
    UMVE_Hover = 4,
  };
  class Unit;

  /**
   * Steering-facing ABI surface used by CAiSteeringImpl.
   *
   * Address: 0x006B7800 (FUN_006B7800, CUnitMotionTypeInfo::Init)
   *
   * What it does:
   * Exposes recovered layout/entrypoints used by AI steering and motion paths.
   */
  class CUnitMotion
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006B8460 (FUN_006B8460, ?Stop@CUnitMotion@Moho@@QAEXPBV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Stops active motion; optional hold-position pointer may be null.
     */
    void Stop(const Wm3::Vector3f* holdPosition);

    /**
     * Address: 0x006B88F0 (FUN_006B88F0, ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Sets motion target position for common steering paths.
     */
    void SetTarget(const Wm3::Vector3f& target);

    /**
     * Address: 0x006B85E0 (FUN_006B85E0, ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@0W4ELayer@2@@Z)
     *
     * What it does:
     * Sets motion target with explicit steering vector and destination layer.
     */
    void SetTarget(const Wm3::Vector3f& target, const Wm3::Vector3f& steeringVector, ELayer layer);

    /**
     * Address: 0x006B9730 (FUN_006B9730, ?AtTarget@CUnitMotion@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns true when motion reached the currently requested target cell.
     */
    [[nodiscard]]
    bool AtTarget() const;

  public:
    Unit* mUnit;                    // +0x00
    CPathPoint* mNextWaypoint;      // +0x04
    CPathPoint* mFollowingWaypoint; // +0x08
    std::uint8_t mPad0C[4];         // +0x0C
    std::uint8_t mStopRequested;    // +0x10
    std::uint8_t mPad11[3];         // +0x11
    Wm3::Vector3f mTargetPosition;  // +0x14
    Wm3::Vector3f mFormationVec;    // +0x20
    std::uint8_t mPad2C[0x0C];      // +0x2C
    Wm3::Vector3f mVelocity;        // +0x38
    std::uint8_t mPad44[0x20];      // +0x44
    float mHeight;                  // +0x64
    std::uint8_t mPad68[0x0C];      // +0x68
    ELayer mLayer;                  // +0x74
    std::uint8_t mPad78[0x08];      // +0x78
    EUnitMotionVertEvent mVertEvent; // +0x80
    std::uint8_t mPad84[0x08];      // +0x84
    std::uint8_t mAlwaysUseTopSpeed; // +0x8C
    std::uint8_t mIsBeingPushed;     // +0x8D
    std::uint8_t mInStateTransition; // +0x8E
    std::uint8_t mPad8F;             // +0x8F
    std::uint8_t mPad90[0x1C];       // +0x90
    std::int32_t mPreparationTick;   // +0xAC
    std::int32_t mStateWordB0;       // +0xB0
    std::uint8_t mPadB4[0xA4];       // +0xB4
    std::int32_t mReservationMinX;   // +0x158
    std::int32_t mReservationMinZ;   // +0x15C
    std::int32_t mReservationMaxX;   // +0x160
    std::int32_t mReservationMaxZ;   // +0x164
    std::uint8_t mPad168[0x70];      // +0x168
  };

  static_assert(sizeof(CUnitMotion) == 0x1D8, "CUnitMotion size must be 0x1D8");
  static_assert(offsetof(CUnitMotion, mUnit) == 0x00, "CUnitMotion::mUnit offset must be 0x00");
  static_assert(offsetof(CUnitMotion, mNextWaypoint) == 0x04, "CUnitMotion::mNextWaypoint offset must be 0x04");
  static_assert(
    offsetof(CUnitMotion, mFollowingWaypoint) == 0x08, "CUnitMotion::mFollowingWaypoint offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitMotion, mAlwaysUseTopSpeed) == 0x8C, "CUnitMotion::mAlwaysUseTopSpeed offset must be 0x8C"
  );
  static_assert(offsetof(CUnitMotion, mIsBeingPushed) == 0x8D, "CUnitMotion::mIsBeingPushed offset must be 0x8D");
  static_assert(
    offsetof(CUnitMotion, mInStateTransition) == 0x8E, "CUnitMotion::mInStateTransition offset must be 0x8E"
  );
  static_assert(offsetof(CUnitMotion, mLayer) == 0x74, "CUnitMotion::mLayer offset must be 0x74");
  static_assert(offsetof(CUnitMotion, mHeight) == 0x64, "CUnitMotion::mHeight offset must be 0x64");
  static_assert(offsetof(CUnitMotion, mVertEvent) == 0x80, "CUnitMotion::mVertEvent offset must be 0x80");
  static_assert(
    offsetof(CUnitMotion, mPreparationTick) == 0xAC, "CUnitMotion::mPreparationTick offset must be 0xAC"
  );
} // namespace moho

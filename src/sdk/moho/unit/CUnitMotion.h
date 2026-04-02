#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EAirCombatState.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/WeakPtr.h"
#include "moho/render/camera/VTransform.h"
#include "moho/unit/EUnitMotionEnums.h"

namespace gpg
{
  class SerConstructResult;
} // namespace gpg

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
     * Address: 0x006BA280 (FUN_006BA280, Moho::CUnitMotion::MemberConstruct)
     *
     * What it does:
     * Allocates and construct-initializes one `CUnitMotion`, then publishes it
     * as an unowned construct result.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive,
      int version,
      const gpg::RRef& ownerRef,
      gpg::SerConstructResult& result
    );

    /**
     * Address: 0x006BACE0 (FUN_006BACE0, Moho::CUnitMotion::MemberDeserialize)
     *
     * What it does:
     * Loads serialized runtime motion state lanes for one `CUnitMotion`.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitMotion* motion);

    /**
     * Address: 0x006BB460 (FUN_006BB460, Moho::CUnitMotion::MemberSerialize)
     *
     * What it does:
     * Saves serialized runtime motion state lanes for one `CUnitMotion`.
     */
    static void MemberSerialize(CUnitMotion* motion, gpg::WriteArchive* archive);

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
     * Address: 0x006B89B0 (FUN_006B89B0, ?AddRecoilImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Projects requested recoil vector against current unit-facing vector and
     * accumulates damped recoil impulse into runtime motion state.
     */
    void AddRecoilImpulse(const Wm3::Vector3f& impulse);

    /**
     * Address: 0x006B9730 (FUN_006B9730, ?AtTarget@CUnitMotion@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns true when motion reached the currently requested target cell.
     */
    [[nodiscard]]
    bool AtTarget() const;

    /**
     * Address: 0x006B9940 (FUN_006B9940, ?ProcessFuelLevels@CUnitMotion@Moho@@AAEXXZ)
     *
     * What it does:
     * Ticks refueling/fuel-drain state and handles staging-platform repair
     * request bookkeeping while in top/hover motion states.
     */
    void ProcessFuelLevels();

  public:
    Unit* mUnit;                    // +0x00
    CPathPoint* mNextWaypoint;      // +0x04
    CPathPoint* mFollowingWaypoint; // +0x08
    float mFuelUseTime;              // +0x0C
    bool mStopRequested;             // +0x10
    std::uint8_t mPad11[0x03];       // +0x11
    Wm3::Vector3f mTargetPosition;   // +0x14
    Wm3::Vector3f mFormationVec;     // +0x20
    Wm3::Vector3f mPos;              // +0x2C
    Wm3::Vector3f mVelocity;         // +0x38
    Wm3::Vector3f mVector44;         // +0x44
    float mCurElevation;             // +0x50
    float mTargetElevation;          // +0x54
    float mNewElevation;             // +0x58
    float mSubElevation;             // +0x5C
    float mDivingSpeed;              // +0x60
    float mHeight;                   // +0x64
    Wm3::Vector3f mVector68;         // +0x68
    ELayer mLayer;                   // +0x74
    EUnitMotionState mMotionState;   // +0x78
    EUnitMotionHorzEvent mHorzEvent; // +0x7C
    EUnitMotionVertEvent mVertEvent; // +0x80
    EUnitMotionTurnEvent mTurnEvent; // +0x84
    EUnitMotionCarrierEvent mCarrierEvent; // +0x88
    bool mAlwaysUseTopSpeed;              // +0x8C
    bool mIsBeingPushed;                  // +0x8D
    bool mInStateTransition;              // +0x8E
    bool mUnknownBool8F;                  // +0x8F
    bool mProcessSurfaceCollision;        // +0x90
    bool mUnknownBool91;                  // +0x91
    std::uint8_t mPad92[0x02];            // +0x92
    float mUnknownFloat94;                // +0x94
    float mUnknownFloat98;                // +0x98
    float mRandomElevation;               // +0x9C
    EAirCombatState mCombatState;         // +0xA0
    std::uint32_t mUnknownA4;             // +0xA4
    std::int32_t mUnknownA8;              // +0xA8
    std::int32_t mPreparationTick;        // +0xAC
    std::int32_t mStateWordB0;            // +0xB0
    Wm3::Vector3f mVectorB4;              // +0xB4
    Wm3::Vector3f mVectorC0;              // +0xC0
    Wm3::Vector3f mRecoilImpulse;         // +0xCC
    Wm3::Vector3f mVectorD8;              // +0xD8
    Wm3::Vector3f mVectorE4;              // +0xE4
    Wm3::Vector3f mVectorF0;              // +0xF0
    Wm3::Vector3f mForce;                 // +0xFC
    Wm3::Vector3f mVector108;             // +0x108
    WeakPtr<Unit> mUnknownWeakUnit;       // +0x114
    float mUnknownFloat11C;               // +0x11C
    VTransform mLastTrans;                // +0x120
    VTransform mCurTrans;                 // +0x13C
    union
    {
      gpg::Rect2i mReservation; // +0x158
      struct
      {
        std::int32_t mReservationMinX;
        std::int32_t mReservationMinZ;
        std::int32_t mReservationMaxX;
        std::int32_t mReservationMaxZ;
      };
    };
    bool mHasDoneCallback;           // +0x168
    std::uint8_t mPad169[0x03];      // +0x169
    CEconRequest* mEconomyRequest;   // +0x16C
    SEconValue mRepairConsumption;   // +0x170
    std::uint8_t mPad178[0x60];      // +0x178
  };

  static_assert(sizeof(CUnitMotion) == 0x1D8, "CUnitMotion size must be 0x1D8");
  static_assert(offsetof(CUnitMotion, mUnit) == 0x00, "CUnitMotion::mUnit offset must be 0x00");
  static_assert(offsetof(CUnitMotion, mNextWaypoint) == 0x04, "CUnitMotion::mNextWaypoint offset must be 0x04");
  static_assert(
    offsetof(CUnitMotion, mFollowingWaypoint) == 0x08, "CUnitMotion::mFollowingWaypoint offset must be 0x08"
  );
  static_assert(offsetof(CUnitMotion, mFuelUseTime) == 0x0C, "CUnitMotion::mFuelUseTime offset must be 0x0C");
  static_assert(offsetof(CUnitMotion, mPos) == 0x2C, "CUnitMotion::mPos offset must be 0x2C");
  static_assert(
    offsetof(CUnitMotion, mAlwaysUseTopSpeed) == 0x8C, "CUnitMotion::mAlwaysUseTopSpeed offset must be 0x8C"
  );
  static_assert(offsetof(CUnitMotion, mIsBeingPushed) == 0x8D, "CUnitMotion::mIsBeingPushed offset must be 0x8D");
  static_assert(
    offsetof(CUnitMotion, mInStateTransition) == 0x8E, "CUnitMotion::mInStateTransition offset must be 0x8E"
  );
  static_assert(
    offsetof(CUnitMotion, mProcessSurfaceCollision) == 0x90,
    "CUnitMotion::mProcessSurfaceCollision offset must be 0x90"
  );
  static_assert(offsetof(CUnitMotion, mLayer) == 0x74, "CUnitMotion::mLayer offset must be 0x74");
  static_assert(offsetof(CUnitMotion, mMotionState) == 0x78, "CUnitMotion::mMotionState offset must be 0x78");
  static_assert(offsetof(CUnitMotion, mHeight) == 0x64, "CUnitMotion::mHeight offset must be 0x64");
  static_assert(offsetof(CUnitMotion, mVertEvent) == 0x80, "CUnitMotion::mVertEvent offset must be 0x80");
  static_assert(offsetof(CUnitMotion, mCombatState) == 0xA0, "CUnitMotion::mCombatState offset must be 0xA0");
  static_assert(
    offsetof(CUnitMotion, mPreparationTick) == 0xAC, "CUnitMotion::mPreparationTick offset must be 0xAC"
  );
  static_assert(offsetof(CUnitMotion, mStateWordB0) == 0xB0, "CUnitMotion::mStateWordB0 offset must be 0xB0");
  static_assert(
    offsetof(CUnitMotion, mUnknownWeakUnit) == 0x114, "CUnitMotion::mUnknownWeakUnit offset must be 0x114"
  );
  static_assert(offsetof(CUnitMotion, mLastTrans) == 0x120, "CUnitMotion::mLastTrans offset must be 0x120");
  static_assert(offsetof(CUnitMotion, mCurTrans) == 0x13C, "CUnitMotion::mCurTrans offset must be 0x13C");
  static_assert(offsetof(CUnitMotion, mReservation) == 0x158, "CUnitMotion::mReservation offset must be 0x158");
  static_assert(
    offsetof(CUnitMotion, mHasDoneCallback) == 0x168, "CUnitMotion::mHasDoneCallback offset must be 0x168"
  );
  static_assert(
    offsetof(CUnitMotion, mEconomyRequest) == 0x16C, "CUnitMotion::mEconomyRequest offset must be 0x16C"
  );
  static_assert(
    offsetof(CUnitMotion, mRepairConsumption) == 0x170, "CUnitMotion::mRepairConsumption offset must be 0x170"
  );
} // namespace moho

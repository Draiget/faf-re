#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/CAiPathSpline.h"
#include "moho/ai/IAiSteering.h"
#include "moho/task/CTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class CUnitMotion;
  class Unit;
  enum ELayer : std::int32_t;

  class MOHO_EMPTY_BASES CAiSteeringImpl : public IAiSteering, public CTask, public InstanceCounter<CAiSteeringImpl>
  {
  public:
    /**
     * Address: 0x005D2670 (FUN_005D2670, reflection default-construct path)
     */
    CAiSteeringImpl();

    /**
     * Address: 0x005D2790 (FUN_005D2790, ??0CAiSteeringImpl@Moho@@QAE@@Z)
     */
    CAiSteeringImpl(Unit* unit, CUnitMotion* motion, ELayer layer);

    /**
     * Address: 0x005D2920 (FUN_005D2920, ??1CAiSteeringImpl@Moho@@QAE@@Z)
     *
     * VFTable SLOT: 0
     */
    ~CAiSteeringImpl() override;

    /**
     * Address: 0x005D29C0 (FUN_005D29C0)
     *
     * VFTable SLOT: 1
     */
    CUnitMotion* SetWaypoints(const Wm3::Vector3f* waypoints, int waypointCount) override;

    /**
     * Address: 0x005D2110 (FUN_005D2110)
     *
     * VFTable SLOT: 2
     */
    int GetWaypoints(Wm3::Vector3f* outWaypoints) const override;

    /**
     * Address: 0x005D2170 (FUN_005D2170)
     *
     * VFTable SLOT: 3
     */
    Wm3::Vector3f GetWaypoint() const override;

    /**
     * Address: 0x005D21B0 (FUN_005D21B0)
     *
     * VFTable SLOT: 4
     */
    bool IsDone() const override;

    /**
     * Address: 0x005D21C0 (FUN_005D21C0)
     *
     * VFTable SLOT: 5
     */
    SCollisionInfo* GetColInfo() override;

    /**
     * Address: 0x005D3B40 (FUN_005D3B40)
     *
     * VFTable SLOT: 6
     */
    void SetCol(ECollisionType type, const Wm3::Vector3f& position) override;

    /**
     * Address: 0x005D21D0 (FUN_005D21D0)
     *
     * VFTable SLOT: 7
     */
    CAiPathSpline* GetPath() override;

    /**
     * Address: 0x005D2390 (FUN_005D2390)
     *
     * VFTable SLOT: 8
     */
    void CalcAtTopSpeed1(bool enabled) override;

    /**
     * Address: 0x005D23E0 (FUN_005D23E0)
     *
     * VFTable SLOT: 9
     */
    void CalcAtTopSpeed2(bool enabled) override;

    /**
     * Address: 0x005D2430 (FUN_005D2430)
     *
     * VFTable SLOT: 10
     */
    void UseTopSpeed(bool enabled) override;

    /**
     * Address: 0x005D35E0 (FUN_005D35E0)
     *
     * VFTable SLOT: 11
     */
    void Stop() override;

    /**
     * Address: 0x005D32B0 (FUN_005D32B0, Moho::CAiSteeringImpl::OnTick)
     *
     * What it does:
     * Advances waypoint steering logic once per task tick.
     *
     * VFTable SLOT (`CTask`): 1
     */
    int Execute() override;

    /**
     * Address: 0x005D2440 (FUN_005D2440, Moho::CAiSteeringImpl::GetVal)
     */
    [[nodiscard]]
    int GetVal() const;

    /**
     * Address: 0x005D2C00 (FUN_005D2C00, Moho::CAiSteeringImpl::ProcessSplineMovement)
     */
    bool ProcessSplineMovement();

    /**
     * Address: 0x005D3000 (FUN_005D3000, Moho::CAiSteeringImpl::DriveToNextWaypoint)
     */
    bool DriveToNextWaypoint();

    /**
     * Address: 0x005D3140 (FUN_005D3140, Moho::CAiSteeringImpl::FlyToNextWaypoint)
     */
    bool FlyToNextWaypoint();

    /**
     * Address: 0x005D3680 (FUN_005D3680, Moho::CAiSteeringImpl::UpdatePath)
     */
    void UpdatePath(int pathMode, const Wm3::Vector3f& destination, bool allowContinuation);

    /**
     * Address: 0x005D3740 (FUN_005D3740, Moho::CAiSteeringImpl::CheckCollisions)
     */
    void CheckCollisions();

    /**
     * Address: 0x005D48E0 (FUN_005D48E0, Moho::CAiSteeringImpl::MemberDeserialize)
     *
     * What it does:
     * Loads steering runtime fields from one archive lane in serializer order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005D4B50 (FUN_005D4B50, Moho::CAiSteeringImpl::MemberSerialize)
     *
     * What it does:
     * Saves steering runtime fields to one archive lane in serializer order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x005D2480 (FUN_005D2480, func_TrySnapPosToWaypoint)
     */
    [[nodiscard]]
    static Wm3::Vector3f TrySnapPosToWaypoint(
      const CAiSteeringImpl& steering,
      int index,
      const Wm3::Vector3f& currentPos,
      float tolerance
    );

  public:
    static gpg::RType* sType;

#if !defined(MOHO_ABI_MSVC8_COMPAT)
    // Preserve the legacy `InstanceCounter<CAiSteeringImpl>` base-subobject slot at +0x1C.
    MOHO_EBO_PADDING_FIELD(1);
#endif

    Unit* mOwnerUnit;                 // +0x20
    Wm3::Vector3f mWaypoints[4];      // +0x24
    std::int32_t mWaypointCount;      // +0x54
    std::int32_t mCurrentWaypointIndex; // +0x58
    ELayer mMovementLayer;            // +0x5C
    CUnitMotion* mUnitMotion;         // +0x60
    SCollisionInfo mCollisionInfo;    // +0x64
    CAiPathSpline* mPath;             // +0x80
    Wm3::Vector3f mCollisionAvoidTarget; // +0x84
    Wm3::Vector3f mDestination;       // +0x90
    std::uint8_t mNeedsWaypointRefresh; // +0x9C
    std::uint8_t mTopSpeedFromCalc1;  // +0x9D
    std::uint8_t mTopSpeedFromCalc2;  // +0x9E
    std::uint8_t mForceTopSpeed;      // +0x9F
    std::uint8_t mPausedForStateTransition; // +0xA0
    std::uint8_t mPadA1[3];           // +0xA1
  };

  static_assert(sizeof(CAiSteeringImpl) == 0xA4, "CAiSteeringImpl size must be 0xA4");
  static_assert(offsetof(CAiSteeringImpl, mOwnerUnit) == 0x20, "CAiSteeringImpl::mOwnerUnit offset must be 0x20");
  static_assert(offsetof(CAiSteeringImpl, mWaypoints) == 0x24, "CAiSteeringImpl::mWaypoints offset must be 0x24");
  static_assert(
    offsetof(CAiSteeringImpl, mWaypointCount) == 0x54, "CAiSteeringImpl::mWaypointCount offset must be 0x54"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mCurrentWaypointIndex) == 0x58,
    "CAiSteeringImpl::mCurrentWaypointIndex offset must be 0x58"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mMovementLayer) == 0x5C, "CAiSteeringImpl::mMovementLayer offset must be 0x5C"
  );
  static_assert(offsetof(CAiSteeringImpl, mUnitMotion) == 0x60, "CAiSteeringImpl::mUnitMotion offset must be 0x60");
  static_assert(
    offsetof(CAiSteeringImpl, mCollisionInfo) == 0x64, "CAiSteeringImpl::mCollisionInfo offset must be 0x64"
  );
  static_assert(offsetof(CAiSteeringImpl, mPath) == 0x80, "CAiSteeringImpl::mPath offset must be 0x80");
  static_assert(
    offsetof(CAiSteeringImpl, mCollisionAvoidTarget) == 0x84,
    "CAiSteeringImpl::mCollisionAvoidTarget offset must be 0x84"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mDestination) == 0x90, "CAiSteeringImpl::mDestination offset must be 0x90"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mNeedsWaypointRefresh) == 0x9C,
    "CAiSteeringImpl::mNeedsWaypointRefresh offset must be 0x9C"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mTopSpeedFromCalc1) == 0x9D,
    "CAiSteeringImpl::mTopSpeedFromCalc1 offset must be 0x9D"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mTopSpeedFromCalc2) == 0x9E,
    "CAiSteeringImpl::mTopSpeedFromCalc2 offset must be 0x9E"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mForceTopSpeed) == 0x9F, "CAiSteeringImpl::mForceTopSpeed offset must be 0x9F"
  );
  static_assert(
    offsetof(CAiSteeringImpl, mPausedForStateTransition) == 0xA0,
    "CAiSteeringImpl::mPausedForStateTransition offset must be 0xA0"
  );

  /**
   * Address: 0x005D3C30 (FUN_005D3C30, ?AI_CreateSteering@Moho@@YAPAVIAiSteering@1@PAVUnit@1@PAVCUnitMotion@1@W4ELayer@1@@Z)
   *
   * What it does:
   * Allocates and constructs CAiSteeringImpl.
   */
  IAiSteering* AI_CreateSteering(Unit* unit, CUnitMotion* motion, ELayer layer);
} // namespace moho

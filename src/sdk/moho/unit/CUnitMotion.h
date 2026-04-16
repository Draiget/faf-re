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
#include "Wm3Quaternion.h"

namespace gpg
{
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  struct CPathPoint;
  class CAiTarget;
  class Entity;
  struct SEntAttachInfo;
  struct SPhysBody;
  enum ELayer : std::int32_t;
  enum EUnitMotionVertEvent : std::int32_t
  {
    UMVE_None = 0,
    UMVE_Top = 1,
    UMVE_Up = 2,
    UMVE_Down = 3,
    UMVE_Hover = 4,
    UMVE_Unknown2 = UMVE_Up,
    UMVE_Unknown3 = UMVE_Down,
  };
  class Unit;
  struct VAxes3;

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
     * Address: 0x006B78E0 (FUN_006B78E0, Moho::CUnitMotion::CUnitMotion)
     * Mangled: ??0CUnitMotion@Moho@@QAE@XZ
     *
     * What it does:
     * Initializes default motion lanes, identity transforms, and raised-platform
     * weak-pointer runtime vector storage.
     */
    CUnitMotion();

    /**
     * Address: 0x006B8320 (FUN_006B8320, Moho::CUnitMotion::~CUnitMotion)
     * Mangled: ??1CUnitMotion@Moho@@QAE@XZ
     *
     * What it does:
     * Releases owned economy-request registration and raised-platform weak
     * pointer runtime storage.
     */
    ~CUnitMotion();

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
     * Address: 0x006B8590 (FUN_006B8590, ?SetFacing@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Normalizes one requested facing vector and stores it as formation-facing.
     */
    void SetFacing(const Wm3::Vector3f& facing);

    /**
     * Address: 0x006C35B0 (FUN_006C35B0, ?SetSplineData@CUnitMotion@Moho@@QAEXPBVCPathPoint@2@0@Z)
     *
     * What it does:
     * Stores current and look-ahead spline path waypoint pointers.
     */
    void SetSplineData(const CPathPoint* nextWaypoint, const CPathPoint* followingWaypoint);

    /**
     * Address: 0x006B85E0 (FUN_006B85E0, ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@0W4ELayer@2@@Z)
     *
     * What it does:
     * Sets motion target with explicit steering vector and destination layer.
     */
    void SetTarget(const Wm3::Vector3f& target, const Wm3::Vector3f& steeringVector, ELayer layer);

    /**
     * Address: 0x006B8920 (FUN_006B8920, ?SetNewTargetLayer@CUnitMotion@Moho@@QAEXW4ELayer@2@@Z)
     *
     * What it does:
     * Applies layer-transition side effects for sub<->water transitions, then
     * commits one new target layer lane.
     */
    void SetNewTargetLayer(ELayer newLayer);

    /**
     * Address: 0x006B93D0 (FUN_006B93D0, ?Warp@CUnitMotion@Moho@@QAEXABVVTransform@2@@Z)
     *
     * What it does:
     * Applies immediate transform warp to owning unit, retargets motion lanes
     * to the new position, and re-arms surface-collision processing for land.
     */
    void Warp(const VTransform& transform);

    /**
     * Address: 0x006B89B0 (FUN_006B89B0, ?AddRecoilImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Projects requested recoil vector against current unit-facing vector and
     * accumulates damped recoil impulse into runtime motion state.
     */
    void AddRecoilImpulse(const Wm3::Vector3f& impulse);

    /**
     * Address: 0x006B8AC0 (FUN_006B8AC0, ?AddImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@_N@Z)
     * Mangled: ?AddImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@_N@Z
     *
     * What it does:
     * Applies impulse against owner motion runtime; air units forward directly
     * into body velocity, while non-air units blend motion lanes and can force
     * ballistic transition + pending transform update when requested.
     */
    void AddImpulse(const Wm3::Vector3f& impulse, bool transitionToBallistic);

    /**
     * Address: 0x006B9460 (FUN_006B9460, ?SetImmediateVelocity@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@@Z)
     *
     * What it does:
     * Writes one immediate velocity + orientation payload into the owner's
     * physics-body runtime state.
     */
    void SetImmediateVelocity(const Wm3::Vector3f& velocity, const Wm3::Quaternionf& orientation);

    /**
     * Address: 0x006B94A0 (FUN_006B94A0, ?NotifyAttached@CUnitMotion@Moho@@QAEXABUSEntAttachInfo@2@@Z)
     * Mangled: ?NotifyAttached@CUnitMotion@Moho@@QAEXABUSEntAttachInfo@2@@Z
     *
     * What it does:
     * Forces attached-motion state and canonical attached events
     * (`Horz=Stopped`, `Vert=Top`) and emits the corresponding script callbacks.
     */
    void NotifyAttached(const SEntAttachInfo& attachInfo);

    /**
     * Address: 0x006B9570 (FUN_006B9570, ?NotifyDetached@CUnitMotion@Moho@@QAEXPAVEntity@2@_N@Z)
     *
     * Moho::Entity *, bool
     *
     * What it does:
     * Rebuilds post-detach target/motion state from detach-parent orientation,
     * then optionally forces air-layer + ballistic transition callbacks.
     */
    void NotifyDetached(Entity* detachedFromEntity, bool skipBallistic);

    /**
     * Address: 0x006B9730 (FUN_006B9730, ?AtTarget@CUnitMotion@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns true when motion reached the currently requested target cell.
     */
    [[nodiscard]]
    bool AtTarget() const;

    /**
     * Address: 0x006B98C0 (FUN_006B98C0, ?IsOnValidLayer@CUnitMotion@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns true when the owner unit's current layer is compatible with the
     * blueprint movement type.
     */
    [[nodiscard]] bool IsOnValidLayer() const;

    /**
     * Address: 0x006B9840 (FUN_006B9840, ?IsMoving@CUnitMotion@Moho@@QBE_NXZ)
     *
     * What it does:
     * Returns movement activity from air-body speed magnitude or spline
     * waypoint presence for non-air paths.
     */
    [[nodiscard]] bool IsMoving() const;

    /**
     * Address: 0x006A4C40 (FUN_006A4C40)
     *
     * What it does:
     * Copies current velocity into caller-provided output storage.
     */
    Wm3::Vector3f* GetVelocity(Wm3::Vector3f* outVelocity) const;

    /**
     * Address: 0x006C1610 (FUN_006C1610, ?SnapToGround@CUnitMotion@Moho@@AAE?AVVTransform@2@ABV32@@Z)
     *
     * What it does:
     * Snaps one transform onto sampled terrain/raised-platform points under
     * the unit footprint and tilts orientation to the computed surface normal.
     */
    [[nodiscard]] VTransform SnapToGround(const VTransform& sourceTransform);

    /**
     * Address: 0x006B9940 (FUN_006B9940, ?ProcessFuelLevels@CUnitMotion@Moho@@AAEXXZ)
     *
     * What it does:
     * Ticks refueling/fuel-drain state and handles staging-platform repair
     * request bookkeeping while in top/hover motion states.
     */
    void ProcessFuelLevels();

  private:
    /**
     * Address: 0x006C1350 (FUN_006C1350, ?CalcRollHack@CUnitMotion@Moho@@AAE?AV?$Vector3@M@Wm3@@XZ)
     *
     * What it does:
     * Updates recoil/roll damping lanes and returns one normalized roll-hack
     * tilt normal used by water-motion snapping.
     */
    [[nodiscard]] Wm3::Vector3f CalcRollHack();

    /**
     * Address: 0x006C1CB0 (FUN_006C1CB0, ?SnapToWater@CUnitMotion@Moho@@AAE?AVVTransform@2@ABV32@@Z)
     *
     * What it does:
     * Snaps one transform to terrain/water elevation rules and applies
     * roll-hack tilt while updating submerged-elevation carry state.
     */
    [[nodiscard]] VTransform SnapToWater(const VTransform& sourceTransform);

    /**
     * Address: 0x006B83F0 (FUN_006B83F0, ?ReCalcCurTargetElevation@CUnitMotion@Moho@@AAEXABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Samples map elevation at one target XY lane and stores terrain/water-clamped
     * target elevation.
     */
    void ReCalcCurTargetElevation(const Wm3::Vector3f& targetPosition);

    /**
     * Address: 0x006B8F30 (FUN_006B8F30, ?SetMotionHorzEvent@CUnitMotion@Moho@@AAEXW4EUnitMotionHorzEvent@2@@Z)
     *
     * What it does:
     * Updates horizontal event lane, emits script callback, and refreshes intel
     * when entering stopped motion.
     */
    void SetMotionHorzEvent(EUnitMotionHorzEvent event);

    /**
     * Address: 0x006B8F70 (FUN_006B8F70, ?SetMotionVertEvent@CUnitMotion@Moho@@AAEXW4EUnitMotionVertEvent@2@@Z)
     *
     * What it does:
     * Updates vertical event lane and emits vertical-motion script callback.
     */
    void SetMotionVertEvent(EUnitMotionVertEvent event);

    /**
     * Address: 0x006B8FB0 (FUN_006B8FB0, ?SetMotionTurnEvent@CUnitMotion@Moho@@AAEXW4EUnitMotionTurnEvent@2@@Z)
     *
     * What it does:
     * Current binary build keeps this lane as a no-op.
     */
    void SetMotionTurnEvent(EUnitMotionTurnEvent event);

    /**
     * Address: 0x006B8FF0 (FUN_006B8FF0, ?SetMotionState@CUnitMotion@Moho@@AAEXW4EUnitMotionState@2@@Z)
     *
     * What it does:
     * Updates motion-state lane and emits state-change script callback.
     */
    void SetMotionState(EUnitMotionState state);

    /**
     * Address: 0x006B92E0 (FUN_006B92E0, ?MoveTo@CUnitMotion@Moho@@AAEXAAVVTransform@2@M@Z)
     *
     * What it does:
     * Normalizes one pending transform quaternion, validates target lanes, and
     * commits the move request into owning `Entity` pending-transform state.
     */
    void MoveTo(VTransform& transform, float timeStep);

    /**
     * Address: 0x006BCA10 (FUN_006BCA10, ?CalcAirMovementDampingFactor@CUnitMotion@Moho@@AAEMABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Computes one air-control damping factor from desired movement magnitude,
     * formation top-speed cache, and air blueprint damping coefficients.
     */
    [[nodiscard]] float CalcAirMovementDampingFactor(const Wm3::Vector3f& movementVector);

    /**
     * Address: 0x006BCB90 (FUN_006BCB90, ?CalcDesiredTargetElevation@CUnitMotion@Moho@@ABEMABVCAiTarget@2@ABV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Computes desired vertical target offset from target entity/layer state,
     * local offset vector, and unit air-combat elevation rules.
     */
    [[nodiscard]] float
    CalcDesiredTargetElevation(const CAiTarget& target, const Wm3::Vector3f& offsetFromUnit) const;

    /**
     * Address: 0x006BC950 (FUN_006BC950, ?CalcWingedLift@CUnitMotion@Moho@@ABEMMM@Z)
     *
     * What it does:
     * Computes winged-air vertical lift from target elevation delta and air
     * blueprint lift factor.
     */
    [[nodiscard]] float CalcWingedLift(float maxLift, float wingFactor) const;

    /**
     * Address: 0x006BC8E0 (FUN_006BC8E0, ?GetElevation@CUnitMotion@Moho@@ABEMXZ)
     *
     * What it does:
     * Resolves current air-move elevation target from carrier state, absolute
     * height lane, and owner elevation attributes.
     */
    [[nodiscard]] float GetElevation() const;

    /**
     * Address: 0x006BC820 (FUN_006BC820, ?ShouldHoverInsteadOfLand@CUnitMotion@Moho@@ABE_NXZ)
     *
     * What it does:
     * Returns true when transport/hover constraints require this air unit to
     * stay hovering instead of committing to landing.
     */
    [[nodiscard]] bool ShouldHoverInsteadOfLand() const;

    /**
     * Address: 0x006C3070 (FUN_006C3070, ?TransitionBetweenLayers@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z)
     *
     * What it does:
     * Interpolates transform position/orientation between stored layer-change
     * endpoints and advances transition progress tick state.
     */
    void TransitionBetweenLayers(VTransform& transform);

    /**
     * Address: 0x006C1E20 (FUN_006C1E20, ?CalcMoveCommon@CUnitMotion@Moho@@AAE_NAAVVTransform@2@PAM@Z)
     *
     * What it does:
     * Shared land/water move integrator lane; computes one movement step into
     * `transform` and reports integration output through `outMoveDistance`.
     */
    [[nodiscard]] bool CalcMoveCommon(VTransform& transform, float* outMoveDistance);

    /**
     * Address: 0x006C3180 (FUN_006C3180, ?CalcMoveLand@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z)
     *
     * What it does:
     * Runs one land move step through `CalcMoveCommon`, conditionally snaps to
     * terrain/raised-platform state, and updates common motion events.
     */
    void CalcMoveLand(VTransform& transform, float* outMoveDistance);

    /**
     * Address: 0x006C3480 (FUN_006C3480, ?CalcMoveWater@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z)
     *
     * What it does:
     * Runs one water move step through `CalcMoveCommon`, applies dive/surface
     * transitions and water snap, and updates common horizontal motion events.
     */
    void CalcMoveWater(VTransform& transform);

    /**
     * Address: 0x006C2A40 (FUN_006C2A40, ?ProcessCommonMotionState@CUnitMotion@Moho@@AAEX_N@Z)
     *
     * What it does:
     * Updates horizontal motion-event state from move-success and speed/target
     * proximity heuristics.
     */
    void ProcessCommonMotionState(bool moveSucceeded);

    /**
     * Address: 0x006C2F00 (FUN_006C2F00, ?FindIntersectingRaisedPlatform@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z)
     *
     * What it does:
     * Selects the nearest non-dead nearby unit that exposes raised platforms
     * in its blueprint physics and stores it as the active platform candidate.
     */
    void FindIntersectingRaisedPlatform();

    /**
     * Address: 0x006C3220 (FUN_006C3220, ?HandleDivingAndSurfacing@CUnitMotion@Moho@@AAE_NXZ)
     *
     * What it does:
     * Updates submerge/surface depth while moving up/down and commits layer +
     * vertical-event transitions when crossing the dive targets.
     */
    [[nodiscard]] bool HandleDivingAndSurfacing();

    /**
     * Address: 0x006BD7B0 (FUN_006BD7B0, Moho::CUnitMotion::CalcWingedOrientation)
     *
     * What it does:
     * Rebuilds winged-air steering axes, force, and wing-orientation bias from
     * the current air-combat state and motion inputs.
     */
    void CalcWingedOrientation(
      const Wm3::Vector3f& referenceVector,
      const Wm3::Vector3f& controlVector,
      const Wm3::Vector3f& primaryVector,
      const Wm3::Vector3f& fallbackVector,
      VAxes3& outAxes,
      Wm3::Vector3f& outForce,
      float& wingOri
    );

    /**
     * Address: 0x006BE480 (FUN_006BE480, ?CalcHoverOrientation@CUnitMotion@Moho@@AAEXABUSPhysBody@2@ABV?$Vector3@M@Wm3@@AAVVAxes3@2@@Z)
     *
     * What it does:
     * Computes hover up/forward control axes from velocity delta, gravity,
     * elevation ratio, and hover-bank blueprint lanes.
     */
    void CalcHoverOrientation(const SPhysBody& body, const Wm3::Vector3f& referenceVector, VAxes3& outAxes);

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
    Wm3::Vector3f mPreviousVelocity;      // +0xB4
    Wm3::Vector3f mVectorC0;              // +0xC0
    Wm3::Vector3f mRecoilImpulse;         // +0xCC
    Wm3::Vector3f mVectorD8;              // +0xD8
    Wm3::Vector3f mVectorE4;              // +0xE4
    Wm3::Vector3f mVectorF0;              // +0xF0
    Wm3::Vector3f mForce;                 // +0xFC
    Wm3::Vector3f mVector108;             // +0x108
    WeakPtr<Unit> mRaisedPlatformUnit;    // +0x114
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
    offsetof(CUnitMotion, mPreviousVelocity) == 0xB4, "CUnitMotion::mPreviousVelocity offset must be 0xB4"
  );
  static_assert(
    offsetof(CUnitMotion, mRaisedPlatformUnit) == 0x114, "CUnitMotion::mRaisedPlatformUnit offset must be 0x114"
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

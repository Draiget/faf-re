#include "moho/unit/CUnitMotion.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/SimConVarAccess.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/math/Wm3DistanceFafExtras.h"
#include "Wm3Box3.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace moho
{
  namespace
  {
    constexpr float kStopLookAheadDistance = 100.0f;
    constexpr float kAtTargetBaseTolerance = 0.25f;
    constexpr float kNonWingedSpeedScale = 0.25f;
    constexpr float kRecoilImpulseBlendFactor = 0.1f;
    constexpr float kFuelTickScale = 0.1f;
    constexpr float kFuelDrainTicksPerSecond = 10.0f;
    constexpr float kFuelRefuelDoneThreshold = 0.99f;
    constexpr float kRollHackRetention = 0.75f;
    constexpr float kRollHackBlend = 0.25f;
    constexpr float kRollHackAxisScale = 4.0f;
    constexpr float kWaterSnapSurfaceBias = 0.25f;
    constexpr float kNoWaterElevation = -10000.0f;
    constexpr float kCommonMoveNearStopSpeedScale = 0.080000006f;
    constexpr float kCommonMoveSlavedArcEnterRadians = 0.017453292f;
    constexpr float kCommonMoveSlavedArcExitRadians = 0.0087266462f;
    constexpr float kCommonMoveHeadingAlignedDot = 0.99989998f;
    constexpr float kCommonMoveVelocityStopThresholdSq = 0.000001f;
    constexpr float kCommonMoveVelocityDamping = 0.80000001f;
    constexpr float kCommonMoveTickScale = 0.0099999998f;
    constexpr float kCommonMoveCollisionImpulseScale = 0.010000001f;
    constexpr float kLayerTransitionTickScale = 10.0f;
    constexpr float kHeightWordScale = 0.0078125f;
    constexpr float kAirTargetMinimumElevationScale = 0.5f;
    constexpr float kMoveToQuatUnitTolerance = 0.01f;
    constexpr EUnitMotionState kUnitMotionStateNone = static_cast<EUnitMotionState>(0);
    constexpr EUnitMotionState kUnitMotionStateAttached = static_cast<EUnitMotionState>(1);
    constexpr EUnitMotionState kUnitMotionStateBallistic = static_cast<EUnitMotionState>(2);
    constexpr EUnitMotionState kUnitMotionStateCrashed = static_cast<EUnitMotionState>(3);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventCruising = static_cast<EUnitMotionHorzEvent>(0);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventTopSpeed = static_cast<EUnitMotionHorzEvent>(1);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventStopping = static_cast<EUnitMotionHorzEvent>(2);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventStopped = static_cast<EUnitMotionHorzEvent>(3);
    // Hover body-tilt low-pass: 80% of the previous lean is kept and 20% of the
  // new target blended in each tick, with the acceleration lane read ten ticks
  // ahead.
  constexpr float kHoverTiltRetain = 0.80000001f;
  constexpr float kHoverTiltBlend = 0.2f;
  constexpr float kHoverTiltLeadTicks = 10.0f;
  // The wobble target is re-rolled once every five ticks.
  constexpr std::uint32_t kHoverWobbleReRollPeriodTicks = 5u;
  // Per-tick wobble acceleration is capped at a tenth of the wobble speed.
  constexpr float kHoverWobbleAccelFraction = 0.1f;
  // Wobble offset damping per tick.
  constexpr float kHoverWobbleRetain = 0.98000002f;

  /**
   * Uniform sample in `[lower, upper)` drawn straight from the simulation's
   * Mersenne twister, matching the binary's `IRand() * 2^-32` scaling (which is
   * what keeps hover wobble deterministic across a replay).
   */
  [[nodiscard]] float RandomInRange(moho::CMersenneTwister& twister, const float lower, const float upper) noexcept
  {
    constexpr double kUInt32ToUnit = 2.3283064e-10;
    return static_cast<float>(lower + ((upper - lower) * static_cast<double>(twister.NextUInt32()) * kUInt32ToUnit));
  }

  // Water surface used on maps that have no water at all: far enough below any
  // real terrain that nothing is ever classified as submerged.
  constexpr float kNoWaterSurfaceElevation = -10000.0f;
  // Ticks of current velocity the water-exit transition endpoint is led by.
  constexpr float kLayerExitLeadTicks = 10.0f;

  constexpr EUnitMotionCarrierEvent kUnitMotionCarrierEventRelativeHeight = static_cast<EUnitMotionCarrierEvent>(1);
    // `quat_45deg2` at 0x010B6178, built by register_quat_45deg2 (0x00BD7390)
    // from a half-angle of `flt_E4F8B0` = 0x3F490FDB = pi/4: it stores cos into
    // lane 0 and sin into lane 2, zeroing lanes 1 and 3 -- so the rotation is a
    // quarter turn about Y, and `Wm3::Quaternionf`'s scalar-first member order
    // puts cos in `w` and sin in `y`. Spelled `{0, cos, 0, sin}` it was a
    // zero-scalar quaternion instead: a half turn about (cos, 0, sin).
    constexpr Wm3::Quaternionf kWingedOrientationQuarterTurnRotation{0.70710677f, 0.0f, 0.70710677f, 0.0f};
    constexpr const char* kUnitMotionScriptStateNames[] = {
      "None",
      "Attached",
      "Ballistic",
      "Crashed",
      "ArmyPool",
    };
    constexpr const char* kUnitMotionScriptHorzEventNames[] = {
      "Cruise",
      "TopSpeed",
      "Stopping",
      "Stopped",
      "Top",
      "Bottom",
      "Up",
      "Down",
    };
    constexpr const char* kUnitMotionScriptVertEventNames[] = {
      "Top",
      "Bottom",
      "Up",
      "Down",
      "Hover",
    };
    // Turn-event names, the three-entry table at 0x00F58374. These used to be
    // appended to the vert-event names above, but the binary keeps four
    // separate tables back to back -- horz at 0x00F58350, vert at 0x00F58360,
    // turn at 0x00F58374, motion state at 0x00F58380 -- and both
    // SetMotionTurnEvent (0x006B8FB0) and CalcMoveAir's inlined reset index
    // this one from its own base.
    constexpr const char* kUnitMotionScriptTurnEventNames[] = {
      "Straight",
      "Turn",
      "SharpTurn",
    };
    constexpr std::size_t kUnitMotionScriptStateNameCount =
      sizeof(kUnitMotionScriptStateNames) / sizeof(kUnitMotionScriptStateNames[0]);
    constexpr std::size_t kUnitMotionScriptHorzEventNameCount =
      sizeof(kUnitMotionScriptHorzEventNames) / sizeof(kUnitMotionScriptHorzEventNames[0]);
    constexpr std::size_t kUnitMotionScriptVertEventNameCount =
      sizeof(kUnitMotionScriptVertEventNames) / sizeof(kUnitMotionScriptVertEventNames[0]);
    constexpr std::size_t kUnitMotionScriptTurnEventNameCount =
      sizeof(kUnitMotionScriptTurnEventNames) / sizeof(kUnitMotionScriptTurnEventNames[0]);
    constexpr std::uint64_t kVerticalMotionStateMask =
      (1ull << static_cast<std::uint32_t>(UNITSTATE_MovingDown)) |
      (1ull << static_cast<std::uint32_t>(UNITSTATE_MovingUp));

    struct UnitRecoilOrientationRuntimeView
    {
      std::uint8_t mUnknown00_00A4[0xA4];
      Wm3::Quatf mCurrentOrientation; // +0xA4 (mVarDat.mCurTransform.orient)
    };
    static_assert(
      offsetof(UnitRecoilOrientationRuntimeView, mCurrentOrientation) == 0xA4,
      "UnitRecoilOrientationRuntimeView::mCurrentOrientation offset must be 0xA4"
    );

    // The candidate slots hold weak references to the *entities* the collision
    // grid returned, not to units: `ProcessSurfaceCollisionFromLastMove` builds
    // each node straight from `CollisionPairResult::sourceEntity`
    // (0x006B9260 `mov ecx, [ebx+edi+4]` -> 0x006B9268 `call sub_5A6DB0`, whose
    // only adjustment is `add ecx, 4` -- Entity's `WeakObject` base, RTTI
    // mdisp=4). A candidate may therefore be a Prop as easily as a Unit, which
    // is why the consumer dispatches `Entity::IsUnit()` rather than casting.
    /**
     * Address: 0x00672B50 (FUN_00672B50, sub_672B50)
     *
     * IDA signature:
     * int __usercall sub_672B50@<eax>(Wm3::Quaternionf *transform@<ecx>, Wm3::Box3f *outBox@<esi>, Vector3f *halfExtents);
     *
     * What it does:
     * Builds one oriented bounding box centred on `transform.pos_`, whose axes
     * are the orthonormal basis expanded from `transform.orient_` and whose
     * per-axis extents are `halfExtents`. File-static in the binary (no mangled
     * name); recovered here in its only caller's translation unit.
     */
    Wm3::Box3f* BuildOrientedBoxFromTransform(
      const VTransform& transform,
      Wm3::Box3f* const outBox,
      const Wm3::Vector3f& halfExtents
    ) noexcept
    {
      const VAxes3 axes{transform.orient_};
      // VAxes3 is three contiguous orthonormal Vector3f axes (vX,vY,vZ); the
      // binary passes &axes.vX as the Box3 axis array and &halfExtents.x as the
      // extent array, matching the `Box3(center, const Vector3* axis, const Real* extent)` ctor.
      *outBox = Wm3::Box3f(transform.pos_, &axes.vX, &halfExtents.x);
      return outBox;
    }

    /**
     * Address: 0x00699600 (FUN_00699600, sub_699600)
     *
     * What it does:
     * Builds one vector opposite to `direction`, scales that length by
     * normalized distance and forward-projection attenuation, and applies the
     * result in-place to `outVector`.
     */
    [[maybe_unused]] Wm3::Vector3f* ComputeScaledOpposingVectorWithDirectionalAttenuation(
      Wm3::Vector3f* const outVector,
      Wm3::Vector3f direction,
      const float projectionAxisX,
      const float projectionAxisY,
      const float projectionAxisZ,
      const float referenceLength,
      const float outputLengthScale
    ) noexcept
    {
      outVector->x = -direction.x;
      outVector->y = -direction.y;
      outVector->z = -direction.z;

      const float directionLength = std::sqrt(
        (direction.x * direction.x) + (direction.y * direction.y) + (direction.z * direction.z)
      );
      float normalizedScale = directionLength / referenceLength;
      if (normalizedScale > 8.0f) {
        normalizedScale = 8.0f;
      }
      if (normalizedScale < 1.0f) {
        normalizedScale = 1.0f;
      }

      (void)Wm3::Vector3f::Normalize(&direction);
      float directionalProjection =
        (projectionAxisX * direction.x) + (projectionAxisY * direction.y) + (projectionAxisZ * direction.z);
      if (directionalProjection < 0.0f) {
        directionalProjection = 0.0f;
      }

      const float scaledLength =
        ((1.0f - directionalProjection) * normalizedScale) * outputLengthScale;
      (void)VecSetLength(outVector, scaledLength);
      return outVector;
    }

    /**
     * Address: 0x0069A2A0 (FUN_0069A2A0, func_VecSetLength)
     *
     * What it does:
     * Projects one vector onto one axis vector and returns the projected
     * component; returns zero when the axis has zero length.
     */
    [[nodiscard]] Wm3::Vector3f ProjectVectorOntoAxis(
      const Wm3::Vector3f& axis,
      const Wm3::Vector3f& vector
    ) noexcept
    {
      const float axisLengthSquared =
        (axis.x * axis.x) + (axis.y * axis.y) + (axis.z * axis.z);
      if (axisLengthSquared <= 0.0f) {
        return {};
      }

      const float scale =
        ((vector.x * axis.x) + (vector.y * axis.y) + (vector.z * axis.z))
        / axisLengthSquared;
      return Wm3::Vector3f{axis.x * scale, axis.y * scale, axis.z * scale};
    }

    /**
     * The third column of the rotation matrix `q` describes, i.e. the direction
     * the entity faces.
     *
     * This took a `moho::Vector4f` while the storage it was handed is a
     * `Wm3::Quatf`, whose words are (w, x, y, z) rather than (x, y, z, w). Two
     * of the three lanes were wrong as a result: against
     * `CUnitMotion::NotifyDetached` (0x006B9570), which computes this inline
     * over the four words at `Entity` +0x9C..+0xA8,
     *
     *   0x006B95A1  out.x = 2 * (word0*word2 + word3*word1)   = 2 * (wy + zx)
     *   0x006B95AD  out.y = 2 * (word3*word2 - word0*word1)   = 2 * (yz - wx)
     *   0x006B95EF  out.z = 1 - 2 * (word2*word2 + word1*word1)
     *
     * only `out.x` matched; `out.y` read `2 * (x*y - z*w)` and `out.z`
     * subtracted `w*w` where the binary subtracts `y*y`.
     */
    [[nodiscard]] Wm3::Vector3f ForwardVectorFromOrientation(const Wm3::Quatf& q) noexcept
    {
      Wm3::Vector3f out{};
      out.x = ((q.x * q.z) + (q.w * q.y)) * 2.0f;
      out.y = ((q.y * q.z) - (q.w * q.x)) * 2.0f;
      out.z = 1.0f - (((q.x * q.x) + (q.y * q.y)) * 2.0f);
      return out;
    }

    /**
     * Address: 0x006B6FE0 (FUN_006B6FE0, sub_6B6FE0)
     *
     * What it does:
     * Applies one world-space impulse into body linear velocity using inverse
     * mass scaling; zero-mass lanes use `FLT_MAX` scaling to match binary.
     */
    void ApplyImpulseToBodyVelocity(SPhysBody& body, const Wm3::Vector3f& impulse) noexcept
    {
      const float inverseMass =
        (body.mMass == 0.0f) ? std::numeric_limits<float>::max() : (1.0f / body.mMass);

      body.mVelocity.x += impulse.x * inverseMass;
      body.mVelocity.y += impulse.y * inverseMass;
      body.mVelocity.z += impulse.z * inverseMass;
    }

    [[nodiscard]] float ClampBallisticAngularRange(const float inverseInertiaAxis) noexcept
    {
      constexpr float kBallisticAngularRangeScale = 0.2f;
      constexpr float kBallisticAngularRangeMax = 2.0f;
      const float range = inverseInertiaAxis * kBallisticAngularRangeScale;
      return (range <= kBallisticAngularRangeMax) ? range : kBallisticAngularRangeMax;
    }

    /**
     * Address: 0x005BE040 (FUN_005BE040, Moho::ScaleRandomUInt32ToRange)
     *
     * What it does:
     * Samples one 32-bit MT lane and returns the high half of
     * `range * random`, preserving VC8 multiply-high range scaling behavior.
     */
    [[nodiscard]] std::uint32_t ScaleRandomUInt32ToRange(
      const std::uint32_t range,
      CRandomStream& randomStream
    ) noexcept
    {
      const std::uint32_t randomValue = randomStream.twister.NextUInt32();
      return static_cast<std::uint32_t>((static_cast<std::uint64_t>(range) * randomValue) >> 32u);
    }

    /**
     * Address: 0x005BE060 (FUN_005BE060, Moho::CUnitMotion::RandomUniformIntRange)
     *
     * What it does:
     * Samples one 32-bit MT value and scales it into the half-open integer
     * range `[minValue, maxValue)` using the binary's high-half multiply
     * trick.
     */
    [[nodiscard]] int RandomUniformIntRange(
      const int minValue,
      const int maxValue,
      CRandomStream& randomStream
    ) noexcept
    {
      const std::uint64_t range = static_cast<std::uint32_t>(maxValue - minValue);
      return minValue + static_cast<int>(ScaleRandomUInt32ToRange(static_cast<std::uint32_t>(range), randomStream));
    }

    [[nodiscard]] const char* UnitMotionStateToScriptString(const EUnitMotionState state) noexcept
    {
      const auto stateIndex = static_cast<std::int32_t>(state);
      if (stateIndex < 0) {
        return "";
      }

      const auto stateOffset = static_cast<std::size_t>(stateIndex);
      if (stateOffset >= kUnitMotionScriptStateNameCount) {
        return "";
      }
      return kUnitMotionScriptStateNames[stateOffset];
    }

    [[nodiscard]] const char* UnitMotionHorzEventToScriptString(const EUnitMotionHorzEvent event) noexcept
    {
      const auto eventIndex = static_cast<std::int32_t>(event);
      if (eventIndex < 0) {
        return "";
      }

      const auto eventOffset = static_cast<std::size_t>(eventIndex);
      if (eventOffset >= kUnitMotionScriptHorzEventNameCount) {
        return "";
      }
      return kUnitMotionScriptHorzEventNames[eventOffset];
    }

    [[nodiscard]] const char* UnitMotionVertEventToScriptString(const EUnitMotionVertEvent event) noexcept
    {
      const auto eventIndex = static_cast<std::int32_t>(event);
      if (eventIndex < 0) {
        return "";
      }

      const auto eventOffset = static_cast<std::size_t>(eventIndex);
      if (eventOffset >= kUnitMotionScriptVertEventNameCount) {
        return "";
      }
      return kUnitMotionScriptVertEventNames[eventOffset];
    }

    [[nodiscard]] const char* UnitMotionTurnEventToScriptString(const EUnitMotionTurnEvent event) noexcept
    {
      const auto eventIndex = static_cast<std::int32_t>(event);
      if (eventIndex < 0) {
        return "";
      }

      const auto eventOffset = static_cast<std::size_t>(eventIndex);
      if (eventOffset >= kUnitMotionScriptTurnEventNameCount) {
        return "";
      }
      return kUnitMotionScriptTurnEventNames[eventOffset];
    }

    [[nodiscard]] bool IsVector3fBinaryZero(const Wm3::Vector3f& value) noexcept
    {
      static constexpr Wm3::Vector3f kZeroVector{};
      return std::memcmp(&value, &kZeroVector, sizeof(Wm3::Vector3f)) == 0;
    }

    [[nodiscard]] Wm3::Vector3f ForwardVectorFromQuaternion(const Wm3::Quaternionf& orientation) noexcept
    {
      Wm3::Vector3f out{};
      out.x = ((orientation.x * orientation.z) + (orientation.w * orientation.y)) * 2.0f;
      out.y = ((orientation.y * orientation.z) - (orientation.w * orientation.x)) * 2.0f;
      out.z = 1.0f - (((orientation.x * orientation.x) + (orientation.y * orientation.y)) * 2.0f);
      return out;
    }

    [[nodiscard]] bool IsCommonMoveSteeringAligned(const SteeringParams& params) noexcept
    {
      float targetX = std::numeric_limits<float>::max();
      float targetZ = std::numeric_limits<float>::max();
      if (params.mDistance != 0.0f) {
        const float invDistance = 1.0f / params.mDistance;
        targetX = params.mDeltaX * invDistance;
        targetZ = params.mDeltaZ * invDistance;
      }

      const float alignment =
        (params.mForwardXZ.y * targetZ) + (params.mForwardXZ.x * targetX);
      return alignment >= kCommonMoveHeadingAlignedDot;
    }

    [[nodiscard]] bool RotateCommonMoveTransformTowardDestination(
      Unit* const unit,
      VTransform& transform,
      const Wm3::Vector3f& destination,
      const bool useFacingTurnRate
    ) noexcept
    {
      const SteeringParams params = BuildSteeringParamsFromTransform(unit, transform, destination);
      if (IsCommonMoveSteeringAligned(params)) {
        return false;
      }

      Wm3::Vector2f direction{};
      const float turnRate = useFacingTurnRate ? params.mTurnFacingRate : params.mTurnRate;
      (void)RotateDirectionTowardTargetLimited(
        &direction,
        turnRate,
        params.mForwardXZ.x,
        params.mForwardXZ.y,
        params.mDeltaX,
        params.mDeltaZ
      );
      (void)BuildHeadingQuaternionFromDirection2D(&direction, &transform.orient_);
      return true;
    }

    [[nodiscard]] Wm3::Vector3f ApplyCommonMoveAttackAngle(
      Unit* const unit,
      const Wm3::Vector3f& targetPosition,
      const float attackAngleDegrees
    ) noexcept
    {
      const Wm3::Vector3f unitPosition = unit->GetPosition();
      Wm3::Vector3f toTarget{
        targetPosition.x - unitPosition.x,
        targetPosition.y - unitPosition.y,
        targetPosition.z - unitPosition.z,
      };
      Wm3::Vector3f normalizedTarget = toTarget;
      (void)Wm3::Vector3f::Normalize(&normalizedTarget);

      const Wm3::Vector3f forward = ForwardVectorFromQuaternion(unit->GetTransform().orient_);
      const float signedRadians =
        ((normalizedTarget.z * forward.x) - (forward.z * normalizedTarget.x)) <= 0.0f
          ? attackAngleDegrees * -kCommonMoveSlavedArcEnterRadians
          : attackAngleDegrees * kCommonMoveSlavedArcEnterRadians;

      const Wm3::Vector3f yawAxis{0.0f, 1.0f, 0.0f};
      Wm3::Quaternionf rotation{};
      (void)EulerRollToQuat(&yawAxis, &rotation, signedRadians);
      Wm3::Vector3f rotated{};
      // Ground truth for this call site's enclosing function
      // (0x006C1E20, CalcMoveCommon, FUN_006C1E20.c) rotates via
      // Moho::MultQuadVec(&v87, &v86, &a2), not Wm3::MultiplyQuaternionVector,
      // even though `rotation` (EulerRollToQuat's own output) is genuinely
      // .w-scalar -- the engine's rotate-vector call site doesn't care what
      // convention produced its quaternion argument.
      MultQuadVec(&rotated, &normalizedTarget, &rotation);
      return Wm3::Vector3f{
        unitPosition.x + rotated.x,
        unitPosition.y + rotated.y,
        unitPosition.z + rotated.z,
      };
    }

    [[nodiscard]] bool HasQueuedHeadCommand(const CUnitCommandQueue* const commandQueue) noexcept
    {
      if (!commandQueue) {
        return false;
      }

      const WeakPtr<CUnitCommand>* const begin = commandQueue->mCommandVec.begin();
      const WeakPtr<CUnitCommand>* const end = commandQueue->mCommandVec.end();
      return begin != nullptr && begin != end && begin->HasValue();
    }

    // Ground truth for this helper's callers (0x006BD7B0 CalcWingedOrientation,
    // FUN_006BD7B0.c; 0x006C1610 SnapToGround, FUN_006C1610.c) all rotate via
    // Moho::MultQuadVec, not the generic Wm3::MultiplyQuaternionVector -- same
    // quaternion-convention mismatch as the other orient_-consuming sites.
    [[nodiscard]] Wm3::Vector3f RotateByQuaternion(
      const Wm3::Vector3f& vector,
      const Wm3::Quaternionf& quaternion
    ) noexcept
    {
      Wm3::Vector3f out{};
      MultQuadVec(&out, &vector, &quaternion);
      return out;
    }

    /**
     * Address: 0x0062B160 (FUN_0062B160)
     *
     * What it does:
     * Samples terrain elevation under a snap point, optionally clamping to the
     * map water floor for hover-path callers, then adds the unit's
     * `DistanceToOccupiedRect` adjustment when an owning unit is supplied.
     */
    [[nodiscard]] float SampleSnapElevation(
      Unit* const unit,
      Wm3::Vector3f& samplePoint,
      const STIMap& map,
      const bool includeWaterFloor
    ) noexcept
    {
      const CHeightField* const heightField = map.GetHeightField();
      float sampledElevation = heightField ? heightField->GetElevation(samplePoint.x, samplePoint.z) : samplePoint.y;

      if (includeWaterFloor && map.mWaterEnabled != 0u && map.mWaterElevation > sampledElevation) {
        sampledElevation = map.mWaterElevation;
      }

      if (unit != nullptr) {
        sampledElevation += unit->DistanceToOccupiedRect(&samplePoint);
      }

      return sampledElevation;
    }

    /**
     * Address: 0x0062B1C0 (FUN_0062B1C0)
     *
     * What it does:
     * Samples terrain elevation from one height-field lane and adds occupied
     * rectangle distance when an owning unit is provided.
     */
    [[maybe_unused]] [[nodiscard]] float SampleElevationWithOccupiedRectOffset(
      const CHeightField* const heightField,
      Unit* const unit,
      const Wm3::Vector3f& samplePoint
    ) noexcept
    {
      const float elevation = heightField ? heightField->GetElevation(samplePoint.x, samplePoint.z) : samplePoint.y;
      if (unit != nullptr) {
        return elevation + unit->DistanceToOccupiedRect(&samplePoint);
      }
      return elevation;
    }

    [[nodiscard]] gpg::RRef MakeCUnitMotionRef(CUnitMotion* const value) noexcept
    {
      gpg::RRef out{};
      out.mObj = value;
      out.mType = CUnitMotion::StaticGetClass();
      return out;
    }

    template <class TObject>
    [[nodiscard]] gpg::RType* ResolveCachedType()
    {
      static gpg::RType* sType = nullptr;
      if (!sType) {
        sType = gpg::LookupRType(typeid(TObject));
      }
      GPG_ASSERT(sType != nullptr);
      return sType;
    }

    [[nodiscard]] gpg::RRef NullOwnerRef() noexcept
    {
      return gpg::RRef{};
    }

    template <class TObject>
    [[nodiscard]] TObject* UpcastTrackedPointer(const gpg::TrackedPointerInfo& tracked, const char* const fallbackName)
    {
      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;

      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCachedType<TObject>());
      if (upcast.mObj) {
        return static_cast<TObject*>(upcast.mObj);
      }

      const char* const expectedName =
        ResolveCachedType<TObject>() ? ResolveCachedType<TObject>()->GetName() : fallbackName;
      const char* const actualName = tracked.type ? tracked.type->GetName() : "null";
      const msvc8::string message = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expectedName ? expectedName : fallbackName,
        actualName ? actualName : "null"
      );
      throw gpg::SerializationError(message.c_str());
    }

    template <class TObject>
    [[nodiscard]] TObject*
    ReadPointerUnowned(gpg::ReadArchive& archive, const gpg::RRef& ownerRef, const char* const fallbackName)
    {
      const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(&archive, ownerRef);
      if (!tracked.object) {
        return nullptr;
      }

      return UpcastTrackedPointer<TObject>(tracked, fallbackName);
    }

    template <class TObject>
    [[nodiscard]] TObject*
    ReadPointerOwned(gpg::ReadArchive& archive, const gpg::RRef& ownerRef, const char* const fallbackName)
    {
      gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(&archive, ownerRef);
      if (!tracked.object) {
        return nullptr;
      }

      if (tracked.state != gpg::TrackedPointerState::Unowned) {
        throw gpg::SerializationError("Ownership conflict while loading archive");
      }

      TObject* const object = UpcastTrackedPointer<TObject>(tracked, fallbackName);
      tracked.state = gpg::TrackedPointerState::Owned;
      return object;
    }

    template <class TObject>
    [[nodiscard]] gpg::RRef MakeTrackedRef(TObject* const object)
    {
      gpg::RRef out{};
      if (!object) {
        return out;
      }

      gpg::RType* const staticType = ResolveCachedType<TObject>();
      gpg::RType* dynamicType = staticType;
      if constexpr (std::is_polymorphic_v<TObject>) {
        try {
          if (gpg::RType* const resolved = gpg::LookupRType(typeid(*object)); resolved != nullptr) {
            dynamicType = resolved;
          }
        } catch (const std::exception&) {
          dynamicType = staticType;
        } catch (...) {
          dynamicType = staticType;
        }
      }

      std::int32_t baseOffset = 0;
      if (dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset)) {
        out.mObj =
          reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
        out.mType = dynamicType;
        return out;
      }

      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    template <class TObject>
    void ReadTypedValue(gpg::ReadArchive& archive, TObject& object, const gpg::RRef& ownerRef)
    {
      archive.Read(ResolveCachedType<TObject>(), &object, ownerRef);
    }

    template <class TObject>
    void WriteTypedValue(gpg::WriteArchive& archive, const TObject& object, const gpg::RRef& ownerRef)
    {
      archive.Write(ResolveCachedType<TObject>(), &object, ownerRef);
    }

    [[nodiscard]] bool IsRefuelVertEvent(const EUnitMotionVertEvent event) noexcept
    {
      return event == UMVE_Bottom || event == UMVE_Hover;
    }

    void DestroyEconomyRequestPointer(CEconRequest*& request) noexcept
    {
      if (!request) {
        return;
      }

      request->mNode.ListUnlink();
      delete request;
      request = nullptr;
    }

    void ReplaceEconomyRequestPointer(CEconRequest*& request, CEconRequest* const replacement) noexcept
    {
      DestroyEconomyRequestPointer(request);
      request = replacement;
    }

    void DestroyRaisedPlatformCandidateStorage(gpg::core::FastVectorN<moho::SWeakRefSlot, 10>& runtime) noexcept
    {
      // Drop each candidate's weak reference, then hand any grown block back
      // and rebind the lane on its inline window.
      if (runtime.start_ != nullptr && runtime.end_ != nullptr && runtime.end_ >= runtime.start_) {
        for (moho::SWeakRefSlot* lane = runtime.start_; lane != runtime.end_; ++lane) {
          lane->AsWeakPtr<Entity>().ResetFromObject(nullptr);
        }
      }

      if (runtime.start_ != nullptr && runtime.start_ != runtime.originalVec_) {
        ::operator delete[](static_cast<void*>(runtime.start_));
      }

      runtime.start_ = runtime.originalVec_;
      runtime.end_ = runtime.start_;
    }

    [[nodiscard]] CEconRequest* CreateEconomyRequest(const SEconValue& requested, CSimArmyEconomyInfo* const economy)
    {
      auto* const request = new CEconRequest{};
      request->mRequested = requested;
      request->mGranted.energy = 0.0f;
      request->mGranted.mass = 0.0f;

      if (economy != nullptr) {
        request->mNode.ListLinkBefore(&economy->registrationNode);
      }
      return request;
    }

    [[nodiscard]] SEconValue TakeGrantedResourcesAndReset(CEconRequest* const request) noexcept
    {
      SEconValue out{};
      out.energy = request->mGranted.energy;
      out.mass = request->mGranted.mass;
      request->mGranted.energy = 0.0f;
      request->mGranted.mass = 0.0f;
      return out;
    }

    void ClearMaintenanceCost(Unit* const unit) noexcept
    {
      unit->SharedEconomyRateEnergy = 0.0f;
      unit->SharedEconomyRateMass = 0.0f;
    }
  } // namespace

  /**
   * Address: 0x006B78E0 (FUN_006B78E0, Moho::CUnitMotion::CUnitMotion)
   * Mangled: ??0CUnitMotion@Moho@@QAE@XZ
   *
   * What it does:
   * Initializes default runtime motion state, transform lanes, and inline
   * raised-platform weak-pointer vector storage.
   */
  CUnitMotion::CUnitMotion()
    : mUnit(nullptr)
    , mNextWaypoint(nullptr)
    , mFollowingWaypoint(nullptr)
    , mFuelUseTime(0.0f)
    , mStopRequested(false)
    , mPad11{0u, 0u, 0u}
    , mTargetPosition{}
    , mFormationVec{}
    , mPos{}
    , mVelocity{}
    , mVector44{}
    , mCurElevation(0.0f)
    , mTargetElevation(0.0f)
    , mNewElevation(0.0f)
    , mSubElevation(0.0f)
    , mDivingSpeed(0.0f)
    , mHeight(std::numeric_limits<float>::infinity())
    , mVector68{}
    , mLayer(LAYER_None)
    , mMotionState(kUnitMotionStateNone)
    , mHorzEvent(kUnitMotionHorzEventStopped)
    , mVertEvent(UMVE_Top)
    , mTurnEvent(static_cast<EUnitMotionTurnEvent>(0))
    , mCarrierEvent(static_cast<EUnitMotionCarrierEvent>(0))
    , mAlwaysUseTopSpeed(false)
    , mIsBeingPushed(false)
    , mInStateTransition(false)
    , mUnknownBool8F(false)
    , mProcessSurfaceCollision(true)
    , mUnknownBool91(false)
    , mPad92{0u, 0u}
    , mUnknownFloat94(0.0f)
    , mUnknownFloat98(1.0f)
    , mRandomElevation(0.0f)
    , mCombatState(static_cast<EAirCombatState>(0))
    , mCombatStateTimeoutTick(0u)
    , mSustainedTurnTicks(0)
    , mPreparationTick(0)
    , mStateWordB0(0)
    , mPreviousVelocity{}
    , mBodyTiltOffset{}
    , mRecoilImpulse{}
    , mWobbleOffset{}
    , mWobbleVelocity{}
    , mWobbleTarget{}
    , mForce{}
    , mTorque{}
    , mRaisedPlatformUnit{}
    , mLayerTransitionTicks(0.0f)
    , mLastTrans{}
    , mCurTrans{}
    , mReservation{}
    , mHasDoneCallback(false)
    , mPad169{0u, 0u, 0u}
    , mEconomyRequest(nullptr)
    , mRepairConsumption{}
  {
    mLastTrans.orient_.w = 1.0f;
    mLastTrans.orient_.x = 0.0f;
    mLastTrans.orient_.y = 0.0f;
    mLastTrans.orient_.z = 0.0f;

    mCurTrans.orient_.w = 1.0f;
    mCurTrans.orient_.x = 0.0f;
    mCurTrans.orient_.y = 0.0f;
    mCurTrans.orient_.z = 0.0f;

    // Arm the candidate lane on its own inline window: an empty vector.
    mRaisedPlatformCandidates.RebindInlineNoFree();
  }

  /**
   * Address: 0x006B7B60 (FUN_006B7B60, ??0CUnitMotion@Moho@@QAE@PAVUnit@1@@Z)
   * Mangled: ??0CUnitMotion@Moho@@QAE@PAVUnit@1@@Z
   *
   * IDA signature:
   * Moho::CUnitMotion *__stdcall Moho::CUnitMotion::CUnitMotion(
   *     Moho::CUnitMotion *this, Moho::Unit *unit);
   *
   * What it does:
   * The gameplay constructor, used by `Unit`'s own gameplay constructor for any
   * blueprint with a real motion type. Starts from the same defaults as the
   * deserialization constructor, then binds the unit, seeds the target position
   * and facing from its spawn pose, sizes its physics body from the blueprint's
   * density and inertia tensor, primes fuel, samples ground/water elevation
   * under the spawn point, and gives aircraft a small random cruise offset so a
   * formation does not fly at one exact altitude.
   */
  CUnitMotion::CUnitMotion(Unit* const unit)
    : CUnitMotion()
  {
    mUnit = unit;
    mFollowingWaypoint = nullptr;
    mTargetPosition = unit->GetPosition();

    // Facing: the world-space forward axis of the spawn orientation, i.e. (0,0,1)
    // rotated by the quaternion, written out in the expanded form the binary uses.
    const VTransform& spawnTransform = unit->GetTransform();
    const float qx = spawnTransform.orient_.X();
    const float qy = spawnTransform.orient_.Y();
    const float qz = spawnTransform.orient_.Z();
    const float qw = spawnTransform.orient_.W();
    mFormationVec.x = ((qx * qz) + (qw * qy)) * 2.0f;
    mFormationVec.y = ((qy * qz) - (qw * qx)) * 2.0f;
    mFormationVec.z = 1.0f - (((qx * qx) + (qy * qy)) * 2.0f);

    // Physics body: mass is the blueprint's density over its bounding volume,
    // and the stored tensor is the reciprocal of mass-scaled inertia.
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    SPhysBody* const physBody = unit->GetPhysBody();
    const float mass = blueprint->mAverageDensity * blueprint->mSizeZ * blueprint->mSizeY * blueprint->mSizeX;
    physBody->mMass = mass;
    physBody->mInvInertiaTensor.x = 1.0f / (blueprint->mInertiaTensorX * mass);
    physBody->mInvInertiaTensor.y = 1.0f / (blueprint->mInertiaTensorY * physBody->mMass);
    physBody->mInvInertiaTensor.z = 1.0f / (blueprint->mInertiaTensorZ * physBody->mMass);

    physBody->mOrientation = spawnTransform.orient_;
    Wm3::Vector3f rotatedCollisionOffset{};
    (void)MultQuadVec(&rotatedCollisionOffset, &physBody->mCollisionOffset, &spawnTransform.orient_);
    physBody->mPos.x = rotatedCollisionOffset.x + spawnTransform.pos_.x;
    physBody->mPos.y = rotatedCollisionOffset.y + spawnTransform.pos_.y;
    physBody->mPos.z = rotatedCollisionOffset.z + spawnTransform.pos_.z;

    mFuelUseTime = blueprint->Physics.FuelUseTime;
    if (mFuelUseTime > 0.0f) {
      mUnit->VarDat().mFuelRatio = 1.0f;
    }

    mNextWaypoint = nullptr;
    mPos = unit->GetPosition();
    mCurTrans = unit->GetTransform();
    mLastTrans = mCurTrans;
    mPreviousVelocity = Wm3::Vector3f{};
    mVelocity = Wm3::Vector3f{};

    // Only aircraft keep a facing vector at rest; everything else starts unset.
    if (!unit->GetBlueprint()->Air.CanFly) {
      mFormationVec = Wm3::Vector3f{};
    }

    const STIMap* const map = mUnit->SimulationRef->mMapData;
    float surfaceElevation = map->mHeightField.get()->GetElevation(mPos.x, mPos.z);
    if (map->mWaterEnabled != 0 && map->mWaterElevation > surfaceElevation) {
      surfaceElevation = map->mWaterElevation;
    }
    mTargetElevation = surfaceElevation;

    if (mUnit->mVarDat.mLayerMask == LAYER_Sub) {
      mSubElevation = mUnit->GetAttributes().spawnElevationOffset;
      SetMotionVertEvent(UMVE_Bottom);
    }

    // Aircraft - but not pods, which dock rather than cruise - get a random
    // offset inside +/- the RandomElevationOffset con-var so a group of them
    // does not stack at one altitude.
    if (mUnit->mIsAir && !mUnit->IsInCategory("POD")) {
      float elevationOffset = 0.0f;
      if (ReadSimConVarValue<float>(mUnit->SimulationRef, "RandomElevationOffset", elevationOffset)) {
        mRandomElevation = mUnit->SimulationRef->mRngState->FRand(-elevationOffset, elevationOffset);
      }
    }
  }

  /**
   * Address: 0x006BA280 (FUN_006BA280, Moho::CUnitMotion::MemberConstruct)
   * Mangled: ?MemberConstruct@CUnitMotion@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z
   *
   * What it does:
   * Allocates one `CUnitMotion`, default-constructs it, and returns it as an
   * unowned reflected construct result.
   */
  void CUnitMotion::MemberConstruct(
    gpg::ReadArchive&,
    const int,
    const gpg::RRef&,
    gpg::SerConstructResult& result
  )
  {
    CUnitMotion* const motion = new (std::nothrow) CUnitMotion();
    result.SetUnowned(MakeCUnitMotionRef(motion), 0u);
  }

  /**
   * Address: 0x006B8320 (FUN_006B8320, Moho::CUnitMotion::~CUnitMotion)
   * Mangled: ??1CUnitMotion@Moho@@QAE@XZ
   *
   * What it does:
   * Releases owned economy-request registration and raised-platform weak
   * pointer runtime storage.
   */
  CUnitMotion::~CUnitMotion()
  {
    DestroyEconomyRequestPointer(mEconomyRequest);
    DestroyRaisedPlatformCandidateStorage(mRaisedPlatformCandidates);

    // The binary lane performs a second economy-request null-check after
    // raised-platform cleanup; keep the same no-op-safe shape.
    DestroyEconomyRequestPointer(mEconomyRequest);
  }

  /**
   * Address: 0x006BACE0 (FUN_006BACE0, Moho::CUnitMotion::MemberDeserialize)
   */
  void CUnitMotion::MemberDeserialize(gpg::ReadArchive* const archive, CUnitMotion* const motion)
  {
    if (archive == nullptr || motion == nullptr) {
      return;
    }

    const gpg::RRef ownerRef = NullOwnerRef();
    motion->mUnit = ReadPointerUnowned<Unit>(*archive, ownerRef, "Unit");
    motion->mNextWaypoint = ReadPointerUnowned<CPathPoint>(*archive, ownerRef, "CPathPoint");
    motion->mFollowingWaypoint = ReadPointerUnowned<CPathPoint>(*archive, ownerRef, "CPathPoint");

    archive->ReadFloat(&motion->mFuelUseTime);
    archive->ReadBool(&motion->mStopRequested);

    ReadTypedValue(*archive, motion->mTargetPosition, ownerRef);
    ReadTypedValue(*archive, motion->mFormationVec, ownerRef);
    ReadTypedValue(*archive, motion->mPos, ownerRef);
    ReadTypedValue(*archive, motion->mVelocity, ownerRef);
    ReadTypedValue(*archive, motion->mVector44, ownerRef);

    archive->ReadFloat(&motion->mCurElevation);
    archive->ReadFloat(&motion->mTargetElevation);
    archive->ReadFloat(&motion->mNewElevation);
    archive->ReadFloat(&motion->mSubElevation);
    archive->ReadFloat(&motion->mDivingSpeed);
    archive->ReadFloat(&motion->mHeight);

    ReadTypedValue(*archive, motion->mVector68, ownerRef);
    ReadTypedValue(*archive, motion->mLayer, ownerRef);
    ReadTypedValue(*archive, motion->mMotionState, ownerRef);
    ReadTypedValue(*archive, motion->mHorzEvent, ownerRef);
    ReadTypedValue(*archive, motion->mVertEvent, ownerRef);
    ReadTypedValue(*archive, motion->mTurnEvent, ownerRef);
    ReadTypedValue(*archive, motion->mCarrierEvent, ownerRef);

    archive->ReadBool(&motion->mAlwaysUseTopSpeed);
    archive->ReadBool(&motion->mIsBeingPushed);
    archive->ReadBool(&motion->mInStateTransition);
    archive->ReadBool(&motion->mUnknownBool8F);
    archive->ReadBool(&motion->mProcessSurfaceCollision);
    archive->ReadBool(&motion->mUnknownBool91);

    archive->ReadFloat(&motion->mUnknownFloat94);
    archive->ReadFloat(&motion->mUnknownFloat98);
    archive->ReadFloat(&motion->mRandomElevation);

    ReadTypedValue(*archive, motion->mCombatState, ownerRef);

    archive->ReadUInt(&motion->mCombatStateTimeoutTick);
    archive->ReadInt(&motion->mSustainedTurnTicks);
    archive->ReadInt(&motion->mPreparationTick);
    archive->ReadInt(&motion->mStateWordB0);

    ReadTypedValue(*archive, motion->mPreviousVelocity, ownerRef);
    ReadTypedValue(*archive, motion->mBodyTiltOffset, ownerRef);
    ReadTypedValue(*archive, motion->mRecoilImpulse, ownerRef);
    ReadTypedValue(*archive, motion->mWobbleOffset, ownerRef);
    ReadTypedValue(*archive, motion->mWobbleVelocity, ownerRef);
    ReadTypedValue(*archive, motion->mWobbleTarget, ownerRef);
    ReadTypedValue(*archive, motion->mForce, ownerRef);
    ReadTypedValue(*archive, motion->mTorque, ownerRef);
    ReadTypedValue(*archive, motion->mRaisedPlatformUnit, ownerRef);

    archive->ReadFloat(&motion->mLayerTransitionTicks);

    ReadTypedValue(*archive, motion->mLastTrans, ownerRef);
    ReadTypedValue(*archive, motion->mCurTrans, ownerRef);
    ReadTypedValue(*archive, motion->mReservation, ownerRef);

    archive->ReadBool(&motion->mHasDoneCallback);

    CEconRequest* const loadedRequest = ReadPointerOwned<CEconRequest>(*archive, ownerRef, "CEconRequest");
    ReplaceEconomyRequestPointer(motion->mEconomyRequest, loadedRequest);

    ReadTypedValue(*archive, motion->mRepairConsumption, ownerRef);
  }

  /**
   * Address: 0x006BB460 (FUN_006BB460, Moho::CUnitMotion::MemberSerialize)
   */
  void CUnitMotion::MemberSerialize(CUnitMotion* const motion, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr || motion == nullptr) {
      return;
    }

    const gpg::RRef ownerRef = NullOwnerRef();
    gpg::WriteRawPointer(
      archive, MakeTrackedRef(motion->mUnit), gpg::TrackedPointerState::Unowned, ownerRef
    );
    gpg::WriteRawPointer(
      archive, MakeTrackedRef(motion->mNextWaypoint), gpg::TrackedPointerState::Unowned, ownerRef
    );
    gpg::WriteRawPointer(
      archive, MakeTrackedRef(motion->mFollowingWaypoint), gpg::TrackedPointerState::Unowned, ownerRef
    );

    archive->WriteFloat(motion->mFuelUseTime);
    archive->WriteBool(motion->mStopRequested);

    WriteTypedValue(*archive, motion->mTargetPosition, ownerRef);
    WriteTypedValue(*archive, motion->mFormationVec, ownerRef);
    WriteTypedValue(*archive, motion->mPos, ownerRef);
    WriteTypedValue(*archive, motion->mVelocity, ownerRef);
    WriteTypedValue(*archive, motion->mVector44, ownerRef);

    archive->WriteFloat(motion->mCurElevation);
    archive->WriteFloat(motion->mTargetElevation);
    archive->WriteFloat(motion->mNewElevation);
    archive->WriteFloat(motion->mSubElevation);
    archive->WriteFloat(motion->mDivingSpeed);
    archive->WriteFloat(motion->mHeight);

    WriteTypedValue(*archive, motion->mVector68, ownerRef);
    WriteTypedValue(*archive, motion->mLayer, ownerRef);
    WriteTypedValue(*archive, motion->mMotionState, ownerRef);
    WriteTypedValue(*archive, motion->mHorzEvent, ownerRef);
    WriteTypedValue(*archive, motion->mVertEvent, ownerRef);
    WriteTypedValue(*archive, motion->mTurnEvent, ownerRef);
    WriteTypedValue(*archive, motion->mCarrierEvent, ownerRef);

    archive->WriteBool(motion->mAlwaysUseTopSpeed);
    archive->WriteBool(motion->mIsBeingPushed);
    archive->WriteBool(motion->mInStateTransition);
    archive->WriteBool(motion->mUnknownBool8F);
    archive->WriteBool(motion->mProcessSurfaceCollision);
    archive->WriteBool(motion->mUnknownBool91);

    archive->WriteFloat(motion->mUnknownFloat94);
    archive->WriteFloat(motion->mUnknownFloat98);
    archive->WriteFloat(motion->mRandomElevation);

    WriteTypedValue(*archive, motion->mCombatState, ownerRef);

    archive->WriteUInt(motion->mCombatStateTimeoutTick);
    archive->WriteInt(motion->mSustainedTurnTicks);
    archive->WriteInt(motion->mPreparationTick);
    archive->WriteInt(motion->mStateWordB0);

    WriteTypedValue(*archive, motion->mPreviousVelocity, ownerRef);
    WriteTypedValue(*archive, motion->mBodyTiltOffset, ownerRef);
    WriteTypedValue(*archive, motion->mRecoilImpulse, ownerRef);
    WriteTypedValue(*archive, motion->mWobbleOffset, ownerRef);
    WriteTypedValue(*archive, motion->mWobbleVelocity, ownerRef);
    WriteTypedValue(*archive, motion->mWobbleTarget, ownerRef);
    WriteTypedValue(*archive, motion->mForce, ownerRef);
    WriteTypedValue(*archive, motion->mTorque, ownerRef);
    WriteTypedValue(*archive, motion->mRaisedPlatformUnit, ownerRef);

    archive->WriteFloat(motion->mLayerTransitionTicks);

    WriteTypedValue(*archive, motion->mLastTrans, ownerRef);
    WriteTypedValue(*archive, motion->mCurTrans, ownerRef);
    WriteTypedValue(*archive, motion->mReservation, ownerRef);

    archive->WriteBool(motion->mHasDoneCallback);
    gpg::WriteRawPointer(
      archive, MakeTrackedRef(motion->mEconomyRequest), gpg::TrackedPointerState::Owned, ownerRef
    );

    WriteTypedValue(*archive, motion->mRepairConsumption, ownerRef);
  }

  /**
   * Address: 0x006B83F0 (FUN_006B83F0)
   * Mangled: ?ReCalcCurTargetElevation@CUnitMotion@Moho@@AAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Samples map elevation at one target point and clamps upward to water level
   * when water is enabled.
   */
  void CUnitMotion::ReCalcCurTargetElevation(const Wm3::Vector3f& targetPosition)
  {
    STIMap* const mapData = mUnit->SimulationRef->mMapData;
    const CHeightField* const heightField = mapData->GetHeightField();

    float targetElevation = 0.0f;
    if (heightField != nullptr) {
      targetElevation = heightField->GetElevation(targetPosition.x, targetPosition.z);
    }

    if (mapData->mWaterEnabled != 0u && mapData->mWaterElevation > targetElevation) {
      targetElevation = mapData->mWaterElevation;
    }

    mTargetElevation = targetElevation;
  }

  /**
   * Address: 0x006B8460 (FUN_006B8460)
   * Mangled: ?Stop@CUnitMotion@Moho@@QAEXPBV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Arms stop mode, optionally retargets to a hold position, and clears active
   * path waypoint pointers/state.
   */
  void CUnitMotion::Stop(const Wm3::Vector3f* const holdPosition)
  {
    Unit* const unit = mUnit;
    // TEMPORARY PROBE -- inert move order triage, delete when resolved.
    gpg::Warnf("[MOTDIAG] Stop unit=%p hold=%d state=%d", static_cast<void*>(unit), holdPosition ? 1 : 0, static_cast<int>(mMotionState));
    mStopRequested = 1;

    if (unit->mIsAir && !unit->IsUnitState(UNITSTATE_TransportUnloading) &&
        !unit->IsUnitState(UNITSTATE_TransportLoading) && !unit->IsUnitState(UNITSTATE_Ferrying)) {
      mLayer = LAYER_Air;
    }

    if (holdPosition) {
      mTargetPosition = *holdPosition;
    } else if (mAlwaysUseTopSpeed == 0u) {
      mTargetPosition = unit->GetPosition();
    } else {
      Wm3::Vector3f normalizedVelocity{};
      Wm3::Vector3f::NormalizeInto(mVelocity, &normalizedVelocity);
      mTargetPosition = unit->GetPosition() + (normalizedVelocity * kStopLookAheadDistance);
    }

    mStateWordB0 = 0;
    mNextWaypoint = nullptr;
    mFollowingWaypoint = nullptr;
  }

  /**
   * Address: 0x006B8590 (FUN_006B8590)
   * Mangled: ?SetFacing@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Copies and normalizes one requested facing vector into formation-facing.
   */
  void CUnitMotion::SetFacing(const Wm3::Vector3f& facing)
  {
    mFormationVec = facing;
    Wm3::Vector3f::Normalize(&mFormationVec);
  }

  /**
   * Address: 0x006C35B0 (FUN_006C35B0, ?SetSplineData@CUnitMotion@Moho@@QAEXPBVCPathPoint@2@0@Z)
   * Mangled: ?SetSplineData@CUnitMotion@Moho@@QAEXPBVCPathPoint@2@0@Z
   *
   * What it does:
   * Stores current and look-ahead spline waypoint lanes for movement steering.
   */
  void CUnitMotion::SetSplineData(const CPathPoint* const nextWaypoint, const CPathPoint* const followingWaypoint)
  {
    mNextWaypoint = const_cast<CPathPoint*>(nextWaypoint);
    mFollowingWaypoint = const_cast<CPathPoint*>(followingWaypoint);
  }

  /**
   * Address: 0x006B88F0 (FUN_006B88F0)
   * Mangled: ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Sets target position with a zero steering vector and no forced layer.
   */
  void CUnitMotion::SetTarget(const Wm3::Vector3f& target)
  {
    const Wm3::Vector3f zeroSteeringVector{};
    SetTarget(target, zeroSteeringVector, LAYER_None);
  }

  /**
   * Address: 0x006B85E0 (FUN_006B85E0)
   * Mangled: ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@0W4ELayer@2@@Z
   *
   * What it does:
   * Writes target/steering state, clamps target inside map bounds, clears
   * vertical transition unit-state bits for air blueprints, and resets local
   * reservation rect ownership.
   */
  void CUnitMotion::SetTarget(
    const Wm3::Vector3f& target,
    const Wm3::Vector3f& steeringVector,
    const ELayer layer
  )
  {
    // TEMPORARY PROBE -- inert move order triage, delete when resolved.
    // Bounded: this is a sim hot path (every move order, every unit, every
    // retarget), and ungated it buries every other probe in the .sclog and
    // slows the beat enough to change the timing being measured.
    {
      static int sMotDiag = 0;
      if (sMotDiag++ < 200) {
        gpg::Warnf(
          "[MOTDIAG] SetTarget unit=%p target=(%.1f,%.1f) layer=%d state=%d",
          static_cast<void*>(mUnit), target.x, target.z,
          static_cast<int>(layer), static_cast<int>(mMotionState)
        );
      }
    }
    mStopRequested = 0;
    mTargetPosition = target;

    Unit* const unit = mUnit;
    Sim* const sim = unit->SimulationRef;
    STIMap* const mapData = sim ? sim->mMapData : nullptr;

    std::int32_t minX = 0;
    std::int32_t minZ = 0;
    std::int32_t maxX = 0;
    std::int32_t maxZ = 0;
    if (unit->ArmyRef && unit->ArmyRef->UseWholeMap()) {
      const CHeightField* const heightField = mapData ? mapData->GetHeightField() : nullptr;
      maxX = heightField ? (heightField->width - 1) : 0;
      maxZ = heightField ? (heightField->height - 1) : 0;
    } else if (mapData) {
      minX = mapData->mPlayableRect.x0;
      minZ = mapData->mPlayableRect.z0;
      maxX = mapData->mPlayableRect.x1;
      maxZ = mapData->mPlayableRect.z1;
    }

    mTargetPosition.x = std::clamp(mTargetPosition.x, static_cast<float>(minX), static_cast<float>(maxX));
    mTargetPosition.z = std::clamp(mTargetPosition.z, static_cast<float>(minZ), static_cast<float>(maxZ));

    if (layer != LAYER_None) {
      mLayer = layer;
    }

    if (!HasQueuedHeadCommand(unit->CommandQueue) && sim) {
      mPreparationTick = static_cast<std::int32_t>(sim->mCurTick);
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint && blueprint->Air.CanFly != 0u) {
      unit->UnitStateMask &= ~kVerticalMotionStateMask;
    }

    Wm3::Vector3f normalizedSteeringVector = steeringVector;
    if (IsVector3fBinaryZero(normalizedSteeringVector) || Wm3::Vector3f::Normalize(&normalizedSteeringVector) == 0.0f) {
      if (blueprint && blueprint->Air.CanFly != 0u) {
        const Wm3::Vector3f currentPosition = unit->GetPosition();
        const float deltaX = target.x - currentPosition.x;
        const float deltaZ = target.z - currentPosition.z;
        const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
        if (planarDistance > blueprint->Air.StartTurnDistance) {
          if (planarDistance == 0.0f) {
            const float maxFloat = std::numeric_limits<float>::max();
            mFormationVec.x = maxFloat;
            mFormationVec.y = maxFloat;
            mFormationVec.z = maxFloat;
          } else {
            const float inverseDistance = 1.0f / planarDistance;
            mFormationVec.x = deltaX * inverseDistance;
            mFormationVec.y = 0.0f;
            mFormationVec.z = deltaZ * inverseDistance;
          }
        }
      } else {
        mFormationVec = steeringVector;
      }
    } else {
      mFormationVec = normalizedSteeringVector;
    }

    if (unit->ReservedOgridRectMinX == mReservationMinX && unit->ReservedOgridRectMinZ == mReservationMinZ &&
        unit->ReservedOgridRectMaxX == mReservationMaxX && unit->ReservedOgridRectMaxZ == mReservationMaxZ) {
      unit->FreeOgridRect();
    }

    mReservationMinX = 0;
    mReservationMinZ = 0;
    mReservationMaxX = 0;
    mReservationMaxZ = 0;
  }

  /**
   * Address: 0x006B8920 (FUN_006B8920, ?SetNewTargetLayer@CUnitMotion@Moho@@QAEXW4ELayer@2@@Z)
   * Mangled: ?SetNewTargetLayer@CUnitMotion@Moho@@QAEXW4ELayer@2@@Z
   *
   * What it does:
   * Applies sub<->water vertical-transition side effects and writes one new
   * target layer lane.
   */
  void CUnitMotion::SetNewTargetLayer(const ELayer newLayer)
  {
    Unit* const unit = mUnit;
    const ELayer oldLayer = unit->mVarDat.mLayerMask;

    if (oldLayer == LAYER_Sub) {
      if (newLayer == LAYER_Water) {
        unit->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_MovingUp));

        const EUnitMotionVertEvent previousEvent = mVertEvent;
        if (previousEvent != UMVE_Up) {
          const char* oldEventName = UnitMotionVertEventToScriptString(previousEvent);
          const char* newEventName = UnitMotionVertEventToScriptString(UMVE_Up);
          mVertEvent = UMVE_Up;
          unit->CallbackStr("OnMotionVertEventChange", &newEventName, &oldEventName);
          mLayer = LAYER_Water;
          return;
        }
      }
    } else if (oldLayer == LAYER_Water && newLayer == LAYER_Sub) {
      unit->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_MovingDown));
      SetMotionVertEvent(UMVE_Down);
    }

    mLayer = newLayer;
  }

  /**
   * Address: 0x006B92E0 (FUN_006B92E0, ?MoveTo@CUnitMotion@Moho@@AAEXAAVVTransform@2@M@Z)
   * Mangled: ?MoveTo@CUnitMotion@Moho@@AAEXAAVVTransform@2@M@Z
   *
   * What it does:
   * Normalizes one pending orientation quaternion, warns on invalid move
   * payload lanes, writes pending transform, and emits one sim move log line.
   */
  void CUnitMotion::MoveTo(VTransform& transform, const float timeStep)
  {
    transform.orient_.Normalize();

    const float pendingVelocityScale = 1.0f / timeStep;
    const float orientationNormDelta = std::fabs(Wm3::Quaternionf::LengthSq(transform.orient_) - 1.0f);
    if (!IsValidVector3f(transform.pos_) || orientationNormDelta >= kMoveToQuatUnitTolerance) {
      gpg::Logf(
        "Unit %s is attempting to move to an invalid coord",
        mUnit->GetBlueprint()->mBlueprintId.c_str()
      );
    }

    Entity& entity = *static_cast<Entity*>(mUnit);
    entity.SetPendingTransform(transform, pendingVelocityScale);
    // TEMPORARY PROBE -- inert move order triage, delete when resolved.
    {
      static int sCount = 0;
      if ((sCount++ % 20) == 0) {
        gpg::Warnf("[MOTDIAG] MoveTo unit=%p to=(%.2f,%.2f,%.2f) step=%.3f n=%d", static_cast<void*>(mUnit),
                   transform.pos_.x, transform.pos_.y, transform.pos_.z, timeStep, sCount);
      }
    }
    mUnit->SimulationRef->Logf(
      "  MoveTo(<%7.2f,%7.2f,%7.2f>)\n",
      transform.pos_.x,
      transform.pos_.y,
      transform.pos_.z
    );
  }

  /**
   * Address: 0x006B93D0 (FUN_006B93D0, ?Warp@CUnitMotion@Moho@@QAEXABVVTransform@2@@Z)
   *
   * What it does:
   * Writes immediate transform warp through owning unit/entity lanes, updates
   * current target/elevation collision paths, and forces land-collision
   * processing when the owner is on land layer.
   */
  void CUnitMotion::Warp(const VTransform& transform)
  {
    if (mUnit == nullptr) {
      return;
    }

    Entity& entity = *static_cast<Entity*>(mUnit);
    entity.SetPendingTransform(transform, 1.0f);
    entity.AdvanceCoords();
    entity.AdvanceCoords();

    const Wm3::Vector3f zeroSteering{};
    SetTarget(transform.pos_, zeroSteering, LAYER_None);
    ReCalcCurTargetElevation(transform.pos_);
    // Binary calls ProcessSurfaceCollisionFromLastMove here (FUN_006B93D0 asm
    // 0x6B9431), immediately resolving surface collisions against the newly
    // warped position and rebuilding the raised-platform candidate list.
    ProcessSurfaceCollisionFromLastMove();

    if (mUnit->mVarDat.mLayerMask == LAYER_Land) {
      mProcessSurfaceCollision = true;
    }
  }

  /**
   * Address: 0x006B9460 (FUN_006B9460)
   * Mangled: ?SetImmediateVelocity@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@ABV?$Quaternion@M@4@@Z
   *
   * What it does:
   * Resolves owner physics-body state and overwrites velocity/orientation lanes.
   */
  void CUnitMotion::SetImmediateVelocity(const Wm3::Vector3f& velocity, const Wm3::Quaternionf& orientation)
  {
    Entity& entity = *static_cast<Entity*>(mUnit);
    SPhysBody* const body = entity.GetPhysBody(false);
    if (body == nullptr) {
      return;
    }

    body->mVelocity = velocity;
    body->mOrientation = orientation;
  }

  /**
   * Address: 0x006B89B0 (FUN_006B89B0, ?AddRecoilImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Projects requested recoil impulse onto current unit forward lane and adds
   * a damped residual into `mRecoilImpulse`.
   */
  void CUnitMotion::AddRecoilImpulse(const Wm3::Vector3f& impulse)
  {
    if (mUnit == nullptr) {
      return;
    }

    const auto& unitRuntime = reinterpret_cast<const UnitRecoilOrientationRuntimeView&>(*mUnit);
    const Wm3::Quatf& orientation = unitRuntime.mCurrentOrientation;

    Wm3::Vector3f forward{};
    forward.x = ((orientation.x * orientation.z) + (orientation.w * orientation.y)) * 2.0f;
    forward.y = ((orientation.y * orientation.z) - (orientation.w * orientation.x)) * 2.0f;
    forward.z = 1.0f - (((orientation.x * orientation.x) + (orientation.y * orientation.y)) * 2.0f);

    const Wm3::Vector3f alignedImpulse = ProjectVectorOntoAxis(forward, impulse);

    mRecoilImpulse.x += (impulse.x - alignedImpulse.x) * kRecoilImpulseBlendFactor;
    mRecoilImpulse.y += (impulse.y - alignedImpulse.y) * kRecoilImpulseBlendFactor;
    mRecoilImpulse.z += (impulse.z - alignedImpulse.z) * kRecoilImpulseBlendFactor;
  }

  /**
   * Address: 0x006B8AC0 (FUN_006B8AC0, ?AddImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@_N@Z)
   * Mangled: ?AddImpulse@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@_N@Z
   *
   * What it does:
   * Applies one impulse into owner motion lanes; airborne units update body
   * velocity directly, while non-air units blend steering state and can force
   * one ballistic transition with randomized angular impulse.
   */
  void CUnitMotion::AddImpulse(const Wm3::Vector3f& impulse, const bool transitionToBallistic)
  {
    Unit* const unit = mUnit;
    if (unit->IsDead() || unit->IsBeingBuilt()) {
      return;
    }

    SPhysBody* const body = static_cast<Entity*>(unit)->GetPhysBody(false);
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint->Physics.MotionType == RULEUMT_Air) {
      ApplyImpulseToBodyVelocity(*body, impulse);
      return;
    }

    if (IsMoving()) {
      mInStateTransition = true;
    }

    mVelocity.x = impulse.x + (mVelocity.x * 0.5f);
    mVelocity.y = impulse.y + (mVelocity.y * 0.5f);
    mVelocity.z = impulse.z + (mVelocity.z * 0.5f);

    mVector44.x = impulse.x + (mVector44.x * 0.5f);
    mVector44.y = impulse.y + (mVector44.y * 0.5f);
    mVector44.z = impulse.z + (mVector44.z * 0.5f);

    if (transitionToBallistic) {
      CRandomStream* const random = unit->SimulationRef->mRngState;
      body->SetTransform(unit->GetTransform());

      const float xRange = ClampBallisticAngularRange(body->mInvInertiaTensor.x);
      const float yRange = ClampBallisticAngularRange(body->mInvInertiaTensor.y);
      const float zRange = ClampBallisticAngularRange(body->mInvInertiaTensor.z);

      const Wm3::Vector3f localAngularImpulse{
        random->FRand(-xRange, xRange) / body->mInvInertiaTensor.x,
        random->FRand(-yRange, yRange) / body->mInvInertiaTensor.y,
        random->FRand(-zRange, zRange) / body->mInvInertiaTensor.z,
      };

      // Ground truth (FUN_006B8AC0.c) rotates via
      // Moho::MultQuadVec(&v42, &v41, &v6->mOrientation), not the generic
      // Wm3::MultiplyQuaternionVector -- same quaternion-convention mismatch
      // as the other mOrientation/orient_-consuming sites.
      MultQuadVec(&mTorque, &localAngularImpulse, &body->mOrientation);

      unit->SetCurrentLayer(LAYER_Air);
      SetMotionState(kUnitMotionStateBallistic);

      ApplyImpulseToBodyVelocity(*body, impulse);

      VTransform pendingTransform(unit->GetTransform());
      const Wm3::Vector3f& currentPosition = unit->GetPosition();
      constexpr float kPendingTransformVelocityScale = 0.1f;

      pendingTransform.pos_.x = currentPosition.x + (mVelocity.x * kPendingTransformVelocityScale);
      pendingTransform.pos_.y = currentPosition.y + (mVelocity.y * kPendingTransformVelocityScale);
      pendingTransform.pos_.z = currentPosition.z + (mVelocity.z * kPendingTransformVelocityScale);

      unit->SetPendingTransform(pendingTransform, 1.0f);
      unit->AdvanceCoords();

      mProcessSurfaceCollision = false;
      mIsBeingPushed = true;
      return;
    }

    constexpr float kSurfaceImpulseSpeedScale = 0.2f;
    const float maxSurfaceSpeed = unit->mInfoCache.mFormationTopSpeed * kSurfaceImpulseSpeedScale;

    const float speed = std::sqrt(
      (mVelocity.x * mVelocity.x) +
      (mVelocity.y * mVelocity.y) +
      (mVelocity.z * mVelocity.z)
    );
    if (speed > maxSurfaceSpeed) {
      (void)VecSetLength(&mVelocity, maxSurfaceSpeed);
      mVector44 = mVelocity;
    }

    mProcessSurfaceCollision = true;
    mIsBeingPushed = true;
  }

  /**
   * Address: 0x006B8F30 (FUN_006B8F30)
   * Mangled: ?SetMotionHorzEvent@CUnitMotion@Moho@@AAEXW4EUnitMotionHorzEvent@2@@Z
   *
   * What it does:
   * Updates horizontal-motion event lane, emits callback, and refreshes intel
   * when entering the stopped event.
   */
  void CUnitMotion::SetMotionHorzEvent(const EUnitMotionHorzEvent event)
  {
    const EUnitMotionHorzEvent previousEvent = mHorzEvent;
    if (previousEvent == event) {
      return;
    }

    const char* oldEventName = UnitMotionHorzEventToScriptString(previousEvent);
    const char* newEventName = UnitMotionHorzEventToScriptString(event);
    mHorzEvent = event;

    mUnit->CallbackStr("OnMotionHorzEventChange", &newEventName, &oldEventName);
    if (mHorzEvent == kUnitMotionHorzEventStopped) {
      Entity& entity = *static_cast<Entity*>(mUnit);
      entity.UpdateIntel();
    }
  }

  /**
   * Address: 0x006B8F70 (FUN_006B8F70)
   * Mangled: ?SetMotionVertEvent@CUnitMotion@Moho@@AAEXW4EUnitMotionVertEvent@2@@Z
   *
   * What it does:
   * Updates vertical-motion event lane and emits change callback text.
   */
  void CUnitMotion::SetMotionVertEvent(const EUnitMotionVertEvent event)
  {
    const EUnitMotionVertEvent previousEvent = mVertEvent;
    if (previousEvent == event) {
      return;
    }

    const char* oldEventName = UnitMotionVertEventToScriptString(previousEvent);
    const char* newEventName = UnitMotionVertEventToScriptString(event);
    mVertEvent = event;
    mUnit->CallbackStr("OnMotionVertEventChange", &newEventName, &oldEventName);
  }

  /**
   * Address: 0x006B8FB0 (FUN_006B8FB0)
   * Mangled: ?SetMotionTurnEvent@CUnitMotion@Moho@@AAEXW4EUnitMotionTurnEvent@2@@Z
   *
   * What it does:
   * Stores the new turn event and, when it actually changed, reports it to the
   * unit's script as `OnMotionTurnEventChange(new, old)`.
   *
   * 2025.7.1 hot-patches this body out, exactly as it does the air-landing
   * ground gate: the eight bytes at 0x006B8FB9 hold `E9 22 00 00 00` followed
   * by three `90`s, which is a five-byte jump straight to the epilogue plus
   * padding, overwriting `74 25` (the "unchanged" early-out) AND the six-byte
   * store `89 81 84 00 00 00`. The `cmp` at 0x006B8FB7 still runs and its
   * result is discarded. Everything after the patch survives intact and is
   * recovered here; the unpatched sibling `SetMotionState` (0x006B8FF0) has
   * the identical shape against field +0x78, which is what pins the store's
   * position and width.
   */
  void CUnitMotion::SetMotionTurnEvent(const EUnitMotionTurnEvent event)
  {
    const EUnitMotionTurnEvent previousEvent = mTurnEvent;
    if (previousEvent == event) {
      return;
    }

    const char* oldEventName = UnitMotionTurnEventToScriptString(previousEvent);
    const char* newEventName = UnitMotionTurnEventToScriptString(event);
    mTurnEvent = event;
    mUnit->CallbackStr("OnMotionTurnEventChange", &newEventName, &oldEventName);
  }

  /**
   * Address: 0x006B8FF0 (FUN_006B8FF0)
   * Mangled: ?SetMotionState@CUnitMotion@Moho@@AAEXW4EUnitMotionState@2@@Z
   *
   * What it does:
   * Updates motion-state lane and emits `OnMotionStateChange` callback text.
   */
  void CUnitMotion::SetMotionState(const EUnitMotionState state)
  {
    const EUnitMotionState previousState = mMotionState;
    if (previousState == state) {
      return;
    }

    const char* oldStateName = UnitMotionStateToScriptString(previousState);
    const char* newStateName = UnitMotionStateToScriptString(state);
    mMotionState = state;
    mUnit->CallbackStr("OnMotionStateChange", &newStateName, &oldStateName);
  }

  /**
   * Address: 0x006B94A0 (FUN_006B94A0, ?NotifyAttached@CUnitMotion@Moho@@QAEXABUSEntAttachInfo@2@@Z)
   * Mangled: ?NotifyAttached@CUnitMotion@Moho@@QAEXABUSEntAttachInfo@2@@Z
   *
   * What it does:
   * Switches motion state to attached and normalizes horizontal/vertical event
   * lanes to stopped/top with callback side effects.
   */
  void CUnitMotion::NotifyAttached(const SEntAttachInfo& attachInfo)
  {
    (void)attachInfo;

    constexpr EUnitMotionState kUnitMotionStateAttached = static_cast<EUnitMotionState>(1);
    constexpr EUnitMotionVertEvent kUnitMotionVertEventTop = static_cast<EUnitMotionVertEvent>(1);

    SetMotionState(kUnitMotionStateAttached);
    SetMotionHorzEvent(kUnitMotionHorzEventStopped);
    SetMotionVertEvent(kUnitMotionVertEventTop);
  }

  /**
   * Address: 0x006B9570 (FUN_006B9570, ?NotifyDetached@CUnitMotion@Moho@@QAEXPAVEntity@2@_N@Z)
   * Mangled: ?NotifyDetached@CUnitMotion@Moho@@QAEXPAVEntity@2@_N@Z
   *
   * What it does:
   * Computes one detach-forward impulse from parent orientation, retargets unit
   * motion, updates motion/layer script callbacks, and re-enables surface
   * collision processing.
   */
  void CUnitMotion::NotifyDetached(Entity* const detachedFromEntity, const bool skipBallistic)
  {
    const Wm3::Vector3f detachForward = ForwardVectorFromOrientation(detachedFromEntity->mVarDat.mCurTransform.orient_);

    Unit* const unit = mUnit;
    const Wm3::Vector3f unitPosition = unit->GetPosition();

    const Wm3::Vector3f newTarget{
      unitPosition.x - detachForward.x,
      unitPosition.y - detachForward.y,
      unitPosition.z - detachForward.z,
    };

    const Wm3::Vector3f zeroSteering{};
    SetTarget(newTarget, zeroSteering, LAYER_None);

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint && blueprint->Air.CanFly == 0u && !skipBallistic) {
      const EUnitMotionState previousState = mMotionState;
      if (previousState != kUnitMotionStateBallistic) {
        const char* newStateName = UnitMotionStateToScriptString(kUnitMotionStateBallistic);
        const char* oldStateName = UnitMotionStateToScriptString(previousState);
        mMotionState = kUnitMotionStateBallistic;
        unit->CallbackStr("OnMotionStateChange", &newStateName, &oldStateName);
      }
    } else {
      const EUnitMotionState previousState = mMotionState;
      if (previousState != kUnitMotionStateNone) {
        const char* newStateName = UnitMotionStateToScriptString(kUnitMotionStateNone);
        const char* oldStateName = UnitMotionStateToScriptString(previousState);
        mMotionState = kUnitMotionStateNone;
        unit->CallbackStr("OnMotionStateChange", &newStateName, &oldStateName);
      }

      if (skipBallistic) {
        mProcessSurfaceCollision = true;
        return;
      }
    }

    const ELayer oldLayer = unit->mVarDat.mLayerMask;
    unit->mVarDat.mLayerMask = LAYER_Air;
    if (oldLayer != LAYER_Air) {
      const char* newLayerName = Entity::LayerToString(LAYER_Air);
      const char* oldLayerName =
        (static_cast<std::uint32_t>(oldLayer) > static_cast<std::uint32_t>(LAYER_Orbit))
          ? ""
          : Entity::LayerToString(oldLayer);
      unit->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
    }

    mProcessSurfaceCollision = true;
  }

  /**
   * Address: 0x006B9730 (FUN_006B9730)
   * Mangled: ?AtTarget@CUnitMotion@Moho@@QBE_NXZ
   *
   * What it does:
   * Returns true when target-layer criteria and planar-distance tolerance checks
   * report that this motion already reached its target.
   */
  bool CUnitMotion::AtTarget() const
  {
    const Unit* const unit = mUnit;
    if (mLayer != LAYER_None && unit->mVarDat.mLayerMask != mLayer) {
      return false;
    }

    const Wm3::Vector3f currentPosition = unit->GetPosition();
    const float deltaX = mTargetPosition.x - currentPosition.x;
    const float deltaZ = mTargetPosition.z - currentPosition.z;
    const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));

    float targetTolerance = kAtTargetBaseTolerance;
    if (mAlwaysUseTopSpeed != 0u) {
      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (blueprint) {
        const float speedMult = unit->GetAttributes().moveSpeedMult;
        float speedTolerance = 0.0f;
        if (blueprint->Air.CanFly != 0u) {
          speedTolerance = blueprint->Air.MaxAirspeed * speedMult;
          if (blueprint->Air.Winged == 0u) {
            speedTolerance *= kNonWingedSpeedScale;
          }
        } else {
          speedTolerance = blueprint->Physics.MaxSpeed * speedMult;
          speedTolerance *= kNonWingedSpeedScale;
        }

        if (speedTolerance > kAtTargetBaseTolerance) {
          targetTolerance = speedTolerance;
        }
      }
    }

    if (targetTolerance < planarDistance) {
      if (mVertEvent != UMVE_Hover &&
          (mVertEvent != UMVE_Bottom || mHeight == std::numeric_limits<float>::infinity())) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x006B9840 (FUN_006B9840, ?IsMoving@CUnitMotion@Moho@@QBE_NXZ)
   * Mangled: ?IsMoving@CUnitMotion@Moho@@QBE_NXZ
   *
   * What it does:
   * Returns true from physics-body speed for flying units, otherwise from
   * spline waypoint presence.
   */
  bool CUnitMotion::IsMoving() const
  {
    if (mUnit->GetBlueprint()->Air.CanFly != 0u) {
      SPhysBody* const body = static_cast<Entity*>(mUnit)->GetPhysBody(false);
      const float speed = std::sqrt(
        (body->mVelocity.x * body->mVelocity.x) +
        (body->mVelocity.y * body->mVelocity.y) +
        (body->mVelocity.z * body->mVelocity.z)
      );
      return speed > 0.001f;
    }

    return mNextWaypoint != nullptr;
  }

  /**
   * Address: 0x006A4C40 (FUN_006A4C40)
   *
   * What it does:
   * Copies current velocity into caller-provided output storage.
   */
  Wm3::Vector3f* CUnitMotion::GetVelocity(Wm3::Vector3f* const outVelocity) const
  {
    if (outVelocity == nullptr) {
      return nullptr;
    }

    *outVelocity = mVelocity;
    return outVelocity;
  }

  /**
   * Address: 0x006B98C0 (FUN_006B98C0, ?IsOnValidLayer@CUnitMotion@Moho@@QBE_NXZ)
   * Mangled: ?IsOnValidLayer@CUnitMotion@Moho@@QBE_NXZ
   *
   * What it does:
   * Validates the owner unit's current layer against blueprint motion type.
   */
  bool CUnitMotion::IsOnValidLayer() const
  {
    const ERuleBPUnitMovementType motionType = mUnit->GetBlueprint()->Physics.MotionType;
    switch (mUnit->mVarDat.mLayerMask) {
      case LAYER_Land:
        return motionType == RULEUMT_Land || motionType == RULEUMT_AmphibiousFloating || motionType == RULEUMT_Amphibious
               || motionType == RULEUMT_Biped || motionType == RULEUMT_Hover;
      case LAYER_Seabed:
        return motionType == RULEUMT_Amphibious;
      case LAYER_Sub:
        return motionType == RULEUMT_SurfacingSub;
      case LAYER_Water:
        return motionType == RULEUMT_Water || motionType == RULEUMT_AmphibiousFloating
               || motionType == RULEUMT_SurfacingSub || motionType == RULEUMT_Hover;
      default:
        return true;
    }
  }

  /**
   * Address: 0x006BC8E0 (FUN_006BC8E0, ?GetElevation@CUnitMotion@Moho@@ABEMXZ)
   * Mangled: ?GetElevation@CUnitMotion@Moho@@ABEMXZ
   *
   * What it does:
   * Resolves current air-path elevation from carrier-mode and relative-height
   * lanes using the owner's elevation attribute.
   */
  float CUnitMotion::GetElevation() const
  {
    constexpr float kCarrierRelativeHeightScale = 0.25f;

    const float ownerElevation = mUnit->GetAttributes().spawnElevationOffset;
    if (mCarrierEvent != kUnitMotionCarrierEventRelativeHeight) {
      return ownerElevation + mRandomElevation;
    }

    if (mHeight == std::numeric_limits<float>::infinity()) {
      return ownerElevation * kCarrierRelativeHeightScale;
    }

    if (mHeight <= mUnit->GetPosition().y) {
      return ownerElevation * kCarrierRelativeHeightScale;
    }

    return mHeight - mTargetElevation;
  }

  /**
   * Address: 0x006BC950 (FUN_006BC950, ?CalcWingedLift@CUnitMotion@Moho@@ABEMMM@Z)
   * Mangled: ?CalcWingedLift@CUnitMotion@Moho@@ABEMMM@Z
   *
   * What it does:
   * Converts wing-factor input into vertical lift with carrier/elevation-aware
   * low-lift bias and max-lift clamp behavior.
   */
  float CUnitMotion::CalcWingedLift(const float maxLift, const float wingFactor) const
  {
    const float targetElevation = GetElevation();
    const float lift = (wingFactor - 0.5f) * mUnit->GetBlueprint()->Air.LiftFactor;

    if (lift <= 0.0f) {
      const float halfTargetElevation = targetElevation * 0.5f;
      if (halfTargetElevation > mCurElevation) {
        return halfTargetElevation - mCurElevation;
      }
    } else if (maxLift <= lift) {
      return maxLift;
    }

    return lift;
  }

  /**
   * Address: 0x006BC820 (FUN_006BC820, ?ShouldHoverInsteadOfLand@CUnitMotion@Moho@@ABE_NXZ)
   * Mangled: ?ShouldHoverInsteadOfLand@CUnitMotion@Moho@@ABE_NXZ
   *
   * What it does:
   * Returns true when transport-hover constraints require remaining airborne
   * rather than landing.
   */
  bool CUnitMotion::ShouldHoverInsteadOfLand() const
  {
    if (mUnit->GetBlueprint()->Air.TransportHoverHeight <= 0.0f) {
      return false;
    }

    if (mUnit->IsUnitState(UNITSTATE_TransportLoading)) {
      return true;
    }

    IAiTransport* const transport = mUnit->AiTransport;
    if (transport == nullptr) {
      return false;
    }

    const EntitySetTemplate<Unit> loadedUnits = transport->TransportGetLoadedUnits(false);
    return loadedUnits.begin() != loadedUnits.end();
  }

  /**
   * Address: 0x006C2BC0 (FUN_006C2BC0, ?CalcMoveHover@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z)
   *
   * What it does:
   * See the header.
   */
  void CUnitMotion::CalcMoveHover(VTransform& transform, float* const outMoveDistance)
  {
    const bool moveSucceeded = mUnit->IsDead() ? false : CalcMoveCommon(transform, outMoveDistance);

    const RUnitBlueprintPhysics& physics = mUnit->GetBlueprint()->Physics;

    if (moveSucceeded || mProcessSurfaceCollision) {
      FindIntersectingRaisedPlatform();
    }

    // Lean into acceleration. The lean is a low-pass of the current
    // acceleration lane scaled by how much bank the blueprint asks for per
    // unit of thrust; the y lane is deliberately driven to zero, so a hovering
    // hull pitches and rolls but never bobs from this term.
    const float bankPerAcceleration = physics.BankingSlope / physics.MaxAcceleration;
    const Wm3::Vec3f bankTarget{
      mVector44.x * kHoverTiltLeadTicks * bankPerAcceleration,
      0.0f,
      mVector44.z * kHoverTiltLeadTicks * bankPerAcceleration
    };
    mBodyTiltOffset.x = (mBodyTiltOffset.x * kHoverTiltRetain) + (bankTarget.x * kHoverTiltBlend);
    mBodyTiltOffset.y = (mBodyTiltOffset.y * kHoverTiltRetain) + (bankTarget.y * kHoverTiltBlend);
    mBodyTiltOffset.z = (mBodyTiltOffset.z * kHoverTiltRetain) + (bankTarget.z * kHoverTiltBlend);

    // Re-roll the wobble target every fifth tick, in the horizontal plane only.
    Sim* const sim = mUnit->SimulationRef;
    if ((sim->mCurTick % kHoverWobbleReRollPeriodTicks) == 0u) {
      CMersenneTwister& twister = sim->mRngState->twister;
      const float wobbleAmplitude = physics.WobbleFactor;
      mWobbleTarget.x = RandomInRange(twister, -wobbleAmplitude, wobbleAmplitude);
      mWobbleTarget.z = RandomInRange(twister, -wobbleAmplitude, wobbleAmplitude);
    }

    // Chase the target: accelerate toward it (capped per tick), cap the
    // resulting velocity, then integrate with a little damping.
    Wm3::Vec3f wobbleAccel{
      mWobbleTarget.x - mWobbleOffset.x,
      mWobbleTarget.y - mWobbleOffset.y,
      mWobbleTarget.z - mWobbleOffset.z
    };
    (void)VecLimitLengthTo(&wobbleAccel, physics.WobbleSpeed * kHoverWobbleAccelFraction);

    mWobbleVelocity.x += wobbleAccel.x;
    mWobbleVelocity.y += wobbleAccel.y;
    mWobbleVelocity.z += wobbleAccel.z;
    (void)VecLimitLengthTo(&mWobbleVelocity, physics.WobbleSpeed);

    mWobbleOffset.x = (mWobbleOffset.x * kHoverWobbleRetain) + mWobbleVelocity.x;
    mWobbleOffset.y = (mWobbleOffset.y * kHoverWobbleRetain) + mWobbleVelocity.y;
    mWobbleOffset.z = (mWobbleOffset.z * kHoverWobbleRetain) + mWobbleVelocity.z;

    // A teleporting hull keeps whatever height the teleport gave it unless a
    // surface collision still has to be resolved.
    if (!mUnit->IsUnitState(UNITSTATE_Teleporting) || mProcessSurfaceCollision) {
      transform = SnapToGround(transform);
    }

    mProcessSurfaceCollision = false;
    ProcessCommonMotionState(moveSucceeded);
  }

  /**
   * Address: 0x006C3180 (FUN_006C3180, ?CalcMoveLand@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z)
   * Mangled: ?CalcMoveLand@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z
   *
   * What it does:
   * Runs one land move step via `CalcMoveCommon`, applies forced or deferred
   * ground snap/raised-platform resolution, and updates common motion events.
   */
  void CUnitMotion::CalcMoveLand(
    VTransform& transform,
    float* const outMoveDistance
  )
  {
    bool moveSucceeded = false;
    bool forceGroundResolution = false;

    if (!mUnit->IsDead()) {
      moveSucceeded = CalcMoveCommon(transform, outMoveDistance);
      if (moveSucceeded && !mUnit->IsUnitState(UNITSTATE_Teleporting)) {
        forceGroundResolution = true;
      }
    }

    if (forceGroundResolution || mProcessSurfaceCollision) {
      FindIntersectingRaisedPlatform();
      transform = SnapToGround(transform);
      mProcessSurfaceCollision = false;
    }

    ProcessCommonMotionState(moveSucceeded);
  }

  /**
   * Address: 0x006C3480 (FUN_006C3480, ?CalcMoveWater@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z)
   * Mangled: ?CalcMoveWater@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z
   *
   * What it does:
   * Runs one water move step through `CalcMoveCommon`, applies dive/surface
   * transitions and water snap, and updates common horizontal motion events.
   */
  void CUnitMotion::CalcMoveWater(VTransform& transform, float* const outMoveDistance)
  {
    bool moveSucceeded = false;
    if (!mUnit->IsDead()) {
      moveSucceeded = CalcMoveCommon(transform, outMoveDistance);
    }

    const bool transitionUpdated = HandleDivingAndSurfacing();
    if (moveSucceeded) {
      Unit* const previousPlatform = mRaisedPlatformUnit.GetObjectPtr();
      FindIntersectingRaisedPlatform();

      if (previousPlatform != nullptr && mRaisedPlatformUnit.GetObjectPtr() == nullptr) {
        const char* newLayerName = Entity::LayerToString(LAYER_Water);
        const char* oldLayerName = Entity::LayerToString(LAYER_Land);
        mUnit->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
      }
    }

    const float speedSq =
      (mVelocity.x * mVelocity.x) +
      (mVelocity.y * mVelocity.y) +
      (mVelocity.z * mVelocity.z);
    if (moveSucceeded || transitionUpdated || speedSq > 0.000001f) {
      transform = SnapToWater(transform);
    }

    ProcessCommonMotionState(moveSucceeded);
  }

  /**
   * Address: 0x006C0290 (FUN_006C0290, Moho::CUnitMotion::CalcMoveBallistic)
   * Mangled: ?CalcMoveBallistic@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z
   *
   * What it does: see header.
   */
  void CUnitMotion::CalcMoveBallistic(VTransform& transform, float* const outMoveDistance)
  {
    constexpr float kGravityTickScale = 0.01f;
    constexpr float kSpinIntegrationDt = 0.1f;
    constexpr float kUprightMinCosine = 0.667f;
    constexpr float kFootprintHalfExtentScale = 0.5f;
    constexpr float kNoWaterElevation = -10000.0f;
    constexpr float kMinMoveDistanceFraction = 0.001f;

    Unit* const unit = mUnit;
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const bool isAmphibious = (blueprint->Physics.MotionType == RULEUMT_Amphibious);

    SPhysBody* const physBody = unit->GetPhysBody();
    const Wm3::Vec3f velocity = unit->GetVelocity();
    const Wm3::Vec3f& gravity = unit->SimulationRef->mPhysConstants->mGravity;

    const Wm3::Vec3f newVelocity{
      velocity.x + (gravity.x * kGravityTickScale),
      velocity.y + (gravity.y * kGravityTickScale),
      velocity.z + (gravity.z * kGravityTickScale)
    };

    const Wm3::Vec3f currentPos = transform.pos_;
    const Wm3::Vec3f predictedPos{
      currentPos.x + newVelocity.x,
      currentPos.y + newVelocity.y,
      currentPos.z + newVelocity.z
    };

    const Wm3::Segment3f moveSegment = Wm3::MakeSegment3fFromEndpoints(currentPos, predictedPos);
    const float segmentLength = moveSegment.Extent * 2.0f;

    // Physics-body free-fall/spin step, gated on a stored angular impulse -
    // Wm3::Vector3f::Compare (FAF-mod) returns true when the operands
    // DIFFER, so this only runs when mTorque != 0.
    if (Wm3::Vector3f::Compare(&mTorque, &Wm3::Vector3f::ZERO)) {
      physBody->IntegrateFreefallStep(Wm3::Vector3f::ZERO, kSpinIntegrationDt, mTorque);
      transform.orient_ = physBody->mOrientation;
    }

    // A "forward"-axis-from-orientation / small-yaw-rotate / quaternion-
    // combine block sits here in the binary (0x6C0415-0x6C06F8), computed
    // from unit->GetTransform().orient_ and a lazily-initialized -0.1 rad
    // yaw quaternion. Its result is unconditionally overwritten (by
    // hitResult below) before any read, with no other consumer anywhere in
    // this function - confirmed dead and elided here; nothing observable
    // depends on it.

    STIMap* const mapData = unit->SimulationRef->mMapData;

    CGeomHitResult hitResult{};
    hitResult.distance = std::numeric_limits<float>::quiet_NaN();
    hitResult.v1 = std::numeric_limits<float>::quiet_NaN();

    GeomLine3 moveLine{};
    moveLine.pos = Wm3::Vec3f{
      moveSegment.Origin.x - (moveSegment.Direction.x * moveSegment.Extent),
      moveSegment.Origin.y - (moveSegment.Direction.y * moveSegment.Extent),
      moveSegment.Origin.z - (moveSegment.Direction.z * moveSegment.Extent)
    };
    moveLine.dir = moveSegment.Direction;
    moveLine.closest = 0.0f;
    moveLine.farthest = segmentLength;

    Wm3::Vec3f hitPoint{};
    if (isAmphibious) {
      // Amphibious units ray-cast the raw terrain only (water is not a hit
      // surface for them).
      hitPoint = mapData->GetHeightField()->Intersection(moveLine, &hitResult);
      (void)IsValidVector3f(hitPoint);
    } else {
      CColHitResult surfaceHit{};
      surfaceHit.distance = hitResult.distance;
      surfaceHit.v1 = hitResult.v1;
      hitPoint = mapData->SurfaceIntersection(moveLine, &surfaceHit);
      hitResult.distance = surfaceHit.distance;
      hitResult.v1 = surfaceHit.v1;
    }

    const bool waterEnabled = mapData->mWaterEnabled != 0;
    const float waterElevation = waterEnabled ? mapData->mWaterElevation : kNoWaterElevation;
    const float groundElevationAtCurrentPos = mapData->GetHeightField()->GetElevation(currentPos.x, currentPos.z);

    const ELayer oldLayer = unit->mVarDat.mLayerMask;

    Wm3::Vec3f newPos = predictedPos;
    float moveDistanceFraction = 1.0f;

    if (!IsValidVector3f(hitPoint)) {
      // No usable hit point: classify purely from ground/water elevation vs
      // the unit's current (pre-move) height.
      if (isAmphibious) {
        if (groundElevationAtCurrentPos >= currentPos.y) {
          unit->SetCurrentLayer(waterElevation > groundElevationAtCurrentPos ? LAYER_Seabed : LAYER_Land);
        }
      } else if (waterElevation >= currentPos.y) {
        unit->SetCurrentLayer(LAYER_Water);
      } else if (groundElevationAtCurrentPos >= currentPos.y) {
        unit->SetCurrentLayer(LAYER_Land);
      }
    } else {
      newPos = hitPoint;
      moveDistanceFraction = hitResult.distance / segmentLength;

      if (waterElevation >= hitPoint.y) {
        unit->SetCurrentLayer(isAmphibious ? LAYER_Seabed : LAYER_Water);
      } else {
        // This transition bypasses Entity::SetCurrentLayer() - direct field
        // write plus a hand-inlined OnLayerChange callback, matching the
        // binary exactly (every OTHER transition in this function goes
        // through the virtual setter).
        const ELayer previousLayer = unit->mVarDat.mLayerMask;
        unit->mVarDat.mLayerMask = LAYER_Land;
        if (previousLayer != LAYER_Land) {
          const char* oldLayerName =
            (static_cast<std::uint32_t>(previousLayer) > static_cast<std::uint32_t>(LAYER_Orbit))
              ? "" : Entity::LayerToString(previousLayer);
          const char* newLayerName = Entity::LayerToString(LAYER_Land);
          unit->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
        }
      }
    }

    // Everything below only runs on the tick the layer actually changed.
    if (oldLayer != unit->mVarDat.mLayerMask) {
      if (!unit->IsDead()) {
        const SFootprint& footprint = unit->GetFootprint();
        SOCellPos cellPos{};
        cellPos.x = static_cast<std::int16_t>(currentPos.x - (footprint.mSizeX * kFootprintHalfExtentScale));
        cellPos.z = static_cast<std::int16_t>(currentPos.z - (footprint.mSizeZ * kFootprintHalfExtentScale));

        COGrid* const oGrid = unit->SimulationRef->mOGrid;
        EOccupancyCaps mobileCaps = OCCUPY_MobileCheck(footprint, *mapData, cellPos);
        if (unit->mVarDat.mLayerMask == LAYER_Water) {
          mobileCaps = static_cast<EOccupancyCaps>(
            static_cast<std::uint8_t>(mobileCaps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)
          );
        }
        const EOccupancyCaps fitCaps = OCCUPY_FootprintFits(*oGrid, cellPos, footprint, mobileCaps);

        bool shouldKill = (fitCaps == static_cast<EOccupancyCaps>(0));
        if (!shouldKill) {
          const gpg::Rect2i& playableRect = mapData->mPlayableRect;
          const Wm3::Vec3f& entityPos = unit->mVarDat.mCurTransform.pos_;
          const Wm3::Quaternionf& liveOrient = unit->GetTransform().orient_;
          const float uprightCosine =
            1.0f - (2.0f * ((liveOrient.x * liveOrient.x) + (liveOrient.z * liveOrient.z)));

          if (static_cast<float>(playableRect.x0) > entityPos.x || static_cast<float>(playableRect.z0) > entityPos.z
              || entityPos.x > static_cast<float>(playableRect.x1) || entityPos.z > static_cast<float>(playableRect.z1)
              || uprightCosine < kUprightMinCosine) {
            shouldKill = true;
          }
        }
        if (shouldKill) {
          unit->Kill(nullptr, "", 0.0f);
        }
      }

      if (!unit->IsDead()) {
        const EUnitMotionState currentState = mMotionState;
        if (currentState != kUnitMotionStateNone) {
          const char* oldStateName = UnitMotionStateToScriptString(currentState);
          const char* newStateName = UnitMotionStateToScriptString(kUnitMotionStateNone);
          mMotionState = kUnitMotionStateNone;
          unit->CallbackStr("OnMotionStateChange", &newStateName, &oldStateName);
        }
      } else {
        const char* impactSurface = (unit->mVarDat.mLayerMask == LAYER_Land) ? "Terrain" : "Water";
        unit->CallbackStr("OnImpact", &impactSurface);

        const EUnitMotionState currentState = mMotionState;
        if (currentState != kUnitMotionStateCrashed) {
          const char* oldStateName = UnitMotionStateToScriptString(currentState);
          const char* newStateName = UnitMotionStateToScriptString(kUnitMotionStateCrashed);
          mMotionState = kUnitMotionStateCrashed;
          unit->CallbackStr("OnMotionStateChange", &newStateName, &oldStateName);
        }
      }
    }

    transform.pos_ = newPos;
    *outMoveDistance = (moveDistanceFraction >= kMinMoveDistanceFraction) ? moveDistanceFraction : kMinMoveDistanceFraction;
  }

  /**
   * Address: 0x006C2A40 (FUN_006C2A40, ?ProcessCommonMotionState@CUnitMotion@Moho@@AAEX_N@Z)
   * Mangled: ?ProcessCommonMotionState@CUnitMotion@Moho@@AAEX_N@Z
   *
   * What it does:
   * Updates horizontal movement event state from move-success and speed/target
   * proximity checks.
   */
  void CUnitMotion::ProcessCommonMotionState(const bool moveSucceeded)
  {
    if (!moveSucceeded) {
      if (mHorzEvent != kUnitMotionHorzEventStopped) {
        SetMotionHorzEvent(kUnitMotionHorzEventStopped);
      }
      return;
    }

    Unit* const unit = mUnit;
    const float speed = std::sqrt(
      (mVelocity.x * mVelocity.x) +
      (mVelocity.y * mVelocity.y) +
      (mVelocity.z * mVelocity.z)
    );

    if (speed > unit->mInfoCache.mFormationTopSpeed * kCommonMoveNearStopSpeedScale) {
      SetMotionHorzEvent(kUnitMotionHorzEventTopSpeed);
      return;
    }

    const Wm3::Vector3f position = unit->GetPosition();
    const float deltaX = mTargetPosition.x - position.x;
    const float deltaZ = mTargetPosition.z - position.z;
    const float targetDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
    const float maxSpeed = unit->GetBlueprint()->Physics.MaxSpeed;
    const bool isNearTarget = (unit->GetAttributes().moveSpeedMult * maxSpeed) > targetDistance;
    const bool hasPendingStopWaypoint = (mNextWaypoint != nullptr && mNextWaypoint->mState == PPS_1);

    if (mHorzEvent != kUnitMotionHorzEventStopped && (isNearTarget || hasPendingStopWaypoint)) {
      SetMotionHorzEvent(kUnitMotionHorzEventStopping);
    } else {
      SetMotionHorzEvent(kUnitMotionHorzEventCruising);
    }
  }

  /**
   * Address: 0x006C2F00 (FUN_006C2F00, ?FindIntersectingRaisedPlatform@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z)
   * Mangled: ?FindIntersectingRaisedPlatform@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z
   *
   * What it does:
   * Scans nearby weak unit candidates and keeps the closest alive unit whose
   * blueprint defines raised platforms.
   */
  void CUnitMotion::FindIntersectingRaisedPlatform()
  {
    mRaisedPlatformUnit.ResetFromObject(nullptr);

    auto& candidates = mRaisedPlatformCandidates;
    if (candidates.start_ == nullptr || candidates.end_ == nullptr || candidates.end_ < candidates.start_
        || mUnit == nullptr) {
      return;
    }

    const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
    float nearestDistanceSq = std::numeric_limits<float>::infinity();

    for (moho::SWeakRefSlot* candidate = candidates.start_; candidate != candidates.end_; ++candidate) {
      // The slot holds an Entity. Recover the unit through the virtual
      // downcast the binary uses -- Entity's vtable slot 4 (0x006C2F97
      // `mov edx, [ecx]` / 0x006C2F99 `mov eax, [edx+10h]` / 0x006C2F9C
      // `call eax`), which is `Entity::IsUnit` (Entity vftable@0xE274F4 slot 4
      // = sub_5BDB10, the base returning null). Props collide here too on the
      // staggered beat, and this null return is what filters them out;
      // casting the slot straight to `Unit*` instead type-confuses every
      // non-unit candidate and reads its blueprint through the wrong vtable.
      Entity* const candidateEntity = candidate->AsWeakPtr<Entity>().GetObjectPtr();
      if (candidateEntity == nullptr) {
        continue;
      }

      Unit* const platformUnit = candidateEntity->IsUnit();
      if (platformUnit == nullptr || platformUnit->IsDead()) {
        continue;
      }

      const RUnitBlueprint* const platformBlueprint = platformUnit->GetBlueprint();
      if (platformBlueprint == nullptr || platformBlueprint->Physics.RaisedPlatforms.empty()) {
        continue;
      }

      const Wm3::Vector3f platformPosition = platformUnit->GetPosition();
      const float deltaX = ownerPosition.x - platformPosition.x;
      const float deltaY = ownerPosition.y - platformPosition.y;
      const float deltaZ = ownerPosition.z - platformPosition.z;
      const float distanceSq = (deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ);
      if (distanceSq < nearestDistanceSq) {
        nearestDistanceSq = distanceSq;
        mRaisedPlatformUnit.ResetFromObject(platformUnit);
      }
    }
  }

  /**
   * Address: 0x006B9020 (FUN_006B9020, ?ProcessSurfaceCollisionFromLastMove@CUnitMotion@Moho@@AAEXXZ)
   * Mangled: ?ProcessSurfaceCollisionFromLastMove@CUnitMotion@Moho@@AAEXXZ
   *
   * IDA signature:
   * void __thiscall Moho::CUnitMotion::ProcessSurfaceCollisionFromLastMove(Moho::CUnitMotion *this);
   *
   * What it does:
   * Rebuilds the raised-platform candidate list and resolves surface collisions
   * after the owner unit's last move (see header).
   */
  void CUnitMotion::ProcessSurfaceCollisionFromLastMove()
  {
    // Staggered prop-inclusion cadence: larger footprints also collide against
    // props, but only on the beat where the unit id and sim tick agree mod 5
    // (asm 0x6B9177-0x6B91CE). Cheap footprint gate first (0.2 = dword_E4F8A8).
    constexpr float kHalfExtentScale = 0.5f; // flt_E4F724
    constexpr float kPropScanFootprintThreshold = 0.2f; // dword_E4F8A8
    constexpr std::uint32_t kPropScanTickPeriod = 5u;

    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();

    // Clear the previous raised-platform candidate lane: unlink every weak node
    // from its owner chain, release escaped heap storage, and rebind to inline
    // storage (asm 0x6B9055-0x6B908A; sub_61CA70 + delete[] + reset-to-inline).
    auto& candidates = mRaisedPlatformCandidates;
    UnlinkWeakPtrRangeWithoutClearing(
      reinterpret_cast<WeakPtr<void>*>(candidates.begin()),
      reinterpret_cast<WeakPtr<void>*>(candidates.end())
    );
    candidates.ResetStorageToInline();

    // Only land/water surface units re-snap here: skip air, submerged, dead,
    // being-built, attached, can-fly, and actively-pushed units
    // (asm 0x6B908D-0x6B90F0).
    const ELayer layer = mUnit->mVarDat.mLayerMask;
    if (layer == LAYER_Air || layer == LAYER_Sub || mUnit->IsDead() || mUnit->IsBeingBuilt() ||
        mUnit->IsUnitState(UNITSTATE_Attached) || blueprint->Air.CanFly != 0u || mIsBeingPushed) {
      return;
    }

    // Oriented collision box over the unit footprint: half-extents are
    // (sizeX/2, sizeY, sizeZ/2) — the vertical extent is the full blueprint
    // height (asm 0x6B90F6-0x6B9147).
    Wm3::Vector3f halfExtents{};
    halfExtents.x = blueprint->mSizeX * kHalfExtentScale;
    halfExtents.y = blueprint->mSizeY;
    halfExtents.z = blueprint->mSizeZ * kHalfExtentScale;

    Wm3::Box3f box{};
    BuildOrientedBoxFromTransform(mUnit->GetTransform(), &box, halfExtents);

    // Gather colliders in the box: units always, and props too on the staggered
    // beat for larger units (asm 0x6B914C-0x6B920C).
    Sim* const sim = mUnit->SimulationRef;
    gpg::core::FastVectorN<CollisionResult, 10> hits{};
    const bool includeProps =
      (blueprint->mSizeX * blueprint->mSizeZ) > kPropScanFootprintThreshold &&
      (static_cast<std::uint32_t>(mUnit->GetEntityId()) % kPropScanTickPeriod) ==
        (sim->mCurTick % kPropScanTickPeriod);
    const EEntityType gatherFlags =
      includeProps ? static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Prop) : ENTITYTYPE_Unit;
    sim->mOGrid->CollectEntitiesInBox(hits, gatherFlags, box);

    if (hits.begin() == hits.end()) {
      return;
    }

    // Resolve the physical collisions, then record every hit unit as a weak
    // raised-platform candidate (asm 0x6B9211-0x6B92B6). The push mirrors
    // Unit::mBlipsInRange: construct WeakPtr<Unit>(entity) and push_back it
    // through the FastVectorN weak-element grow lane (sub_5A6DB0 + sub_61C5E0).
    Sim::DoCollisionsFor(sim, mUnit, &hits);

    for (const CollisionResult& hit : hits) {
      // The node binds to the entity's own weak-link head (sub_5A6DB0's
      // `add ecx, 4`); it is NOT narrowed to a unit here -- see
      // FindIntersectingRaisedPlatform, which does the `Entity::IsUnit`
      // dispatch when the list is consumed.
      WeakPtr<Entity> candidateRef(hit.sourceEntity);
      candidates.push_back(reinterpret_cast<const SWeakRefSlot&>(candidateRef));
    }
  }

  /**
   * Address: 0x006BC460 (FUN_006BC460, Moho::CUnitMotion::HandleGroundCollision)
   * Mangled: ?HandleGroundCollision@CUnitMotion@Moho@@AAE_NXZ
   *
   * What it does: see header.
   *
   * Nothing calls this in the shipped engine; FAF patched its one call site
   * out of `CalcMoveAir` (0x006C018B). See the note at the end of that
   * function before wiring it back in.
   */
  bool CUnitMotion::HandleGroundCollision()
  {
    constexpr float kGroundCheckElevationScale = 2.0f;
    constexpr float kNoWaterElevation = -10000.0f;

    Unit* const unit = mUnit;
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();

    const float groundCheckLimit = std::max(blueprint->mSizeX, blueprint->mSizeZ) * kGroundCheckElevationScale;
    if (mCurElevation > groundCheckLimit) {
      return false;
    }

    STIMap* const mapData = unit->SimulationRef->mMapData;
    SPhysBody* const physBody = unit->GetPhysBody();

    const bool waterEnabled = mapData->mWaterEnabled != 0;
    const float waterFloor = waterEnabled ? mapData->mWaterElevation : kNoWaterElevation;

    gpg::fastvector_n<Wm3::Sphere3f, 8> collisionSpheres;
    unit->GetTerrainCollisionGeom(collisionSpheres);

    VTransform bodyTransform{};
    BuildTransformFromSPhysBody(&bodyTransform, physBody);

    VMatrix4 worldMatrix{};
    worldMatrix.Set(bodyTransform.orient_, bodyTransform.pos_);

    bool anyGroundHit = false;
    bool anyBelowWater = false;
    gpg::fastvector_n<GroundPenetrationSample, 8> hitRecords;

    for (const Wm3::Sphere3f& sphere : collisionSpheres) {
      const Vector4f localPoint{sphere.Center.x, sphere.Center.y, sphere.Center.z, 1.0f};
      const Vector4f worldPoint = localPoint * worldMatrix;

      const float terrainElevation = mapData->GetHeightField()->GetElevation(worldPoint.x, worldPoint.z);
      const float groundThreshold = sphere.Radius + terrainElevation;

      if ((groundThreshold - blueprint->Physics.GroundCollisionOffset) >= worldPoint.y) {
        hitRecords.push_back(GroundPenetrationSample{worldPoint.x, worldPoint.y, worldPoint.z, terrainElevation});
        anyGroundHit = true;
      }

      if (!blueprint->Air.FlyInWater) {
        anyBelowWater |= (waterFloor >= worldPoint.y);
      }
    }

    // TEMPORARY PROBE -- lever-arm triage for the ground-collision angular
    // runaway. Delete when resolved.
    if (anyGroundHit) {
      static int sLeverCount = 0;
      if (sLeverCount++ < 12) {
        const Wm3::Sphere3f& s0 = *collisionSpheres.begin();
        const GroundPenetrationSample& h0 = *hitRecords.begin();
        gpg::Warnf(
          "[GEOMLEVER] unit=%p spheres=%d hits=%d sphere0=(%.2f,%.2f,%.2f r=%.2f) "
          "world0=(%.2f,%.2f,%.2f) bodyPos=(%.2f,%.2f,%.2f) rel0=(%.2f,%.2f,%.2f) unitPos=(%.2f,%.2f,%.2f) "
          "bpSize=(%.3f,%.3f,%.3f) bpDensity=%.4f bodyMass=%.3f bpElev=%.2f bpGndOff=%.3f",
          static_cast<void*>(unit),
          static_cast<int>(collisionSpheres.end() - collisionSpheres.begin()),
          static_cast<int>(hitRecords.end() - hitRecords.begin()),
          s0.Center.x, s0.Center.y, s0.Center.z, s0.Radius,
          h0.x, h0.y, h0.z,
          physBody->mPos.x, physBody->mPos.y, physBody->mPos.z,
          h0.x - physBody->mPos.x, h0.y - physBody->mPos.y, h0.z - physBody->mPos.z,
          unit->GetPosition().x, unit->GetPosition().y, unit->GetPosition().z,
          blueprint->mSizeX, blueprint->mSizeY, blueprint->mSizeZ,
          blueprint->mAverageDensity, physBody->mMass,
          blueprint->Physics.Elevation, blueprint->Physics.GroundCollisionOffset
        );
      }
    }

    if (anyGroundHit) {
      physBody->ApplyGroundCollisionResponse(hitRecords);
    }

    return anyGroundHit || anyBelowWater;
  }

  /**
   * Address: 0x006C3220 (FUN_006C3220, ?HandleDivingAndSurfacing@CUnitMotion@Moho@@AAE_NXZ)
   * Mangled: ?HandleDivingAndSurfacing@CUnitMotion@Moho@@AAE_NXZ
   *
   * What it does:
   * Applies per-tick dive/surface depth updates for moving up/down states and
   * finalizes the layer transition when the depth limit is reached.
   */
  bool CUnitMotion::HandleDivingAndSurfacing()
  {
    constexpr float kNoWaterElevation = -10000.0f;
    constexpr float kSurfaceClearance = 0.25f;
    constexpr float kDiveSpeedScale = 0.1f;
    constexpr float kDiveSpeedMinFactor = 0.1f;
    constexpr float kDiveCurveHalfPoint = 0.5f;
    constexpr float kPi = 3.1415927f;

    if (mUnit == nullptr) {
      return false;
    }

    float diveDepthLimit = mUnit->GetAttributes().spawnElevationOffset;
    if (diveDepthLimit == 0.0f) {
      return false;
    }

    const bool movingUp = mUnit->IsUnitState(UNITSTATE_MovingUp);
    const bool movingDown = mUnit->IsUnitState(UNITSTATE_MovingDown);
    if (!movingUp && !movingDown) {
      mDivingSpeed = 0.0f;
      return false;
    }

    STIMap* const mapData = mUnit->SimulationRef->mMapData;
    const CHeightField* const heightField = mapData ? mapData->GetHeightField() : nullptr;
    const Wm3::Vector3f unitPosition = mUnit->GetPosition();
    const float terrainElevation =
      heightField ? heightField->GetElevation(unitPosition.x, unitPosition.z) : unitPosition.y;
    const float waterElevation = (mapData && mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : kNoWaterElevation;

    float surfaceDepthLimit = (terrainElevation + kSurfaceClearance) - waterElevation;
    if (surfaceDepthLimit > 0.0f) {
      surfaceDepthLimit = 0.0f;
    }
    if (surfaceDepthLimit > diveDepthLimit) {
      diveDepthLimit = surfaceDepthLimit;
    }

    float depthPhase = std::fabs(mSubElevation / diveDepthLimit);
    const float baseDiveSpeed = mUnit->GetBlueprint()->Physics.DiveSurfaceSpeed * kDiveSpeedScale;
    if (depthPhase > kDiveCurveHalfPoint) {
      depthPhase = 1.0f - depthPhase;
    }

    const float minDiveSpeed = baseDiveSpeed * kDiveSpeedMinFactor;
    const float curveDiveSpeed = std::sin(depthPhase * kPi) * baseDiveSpeed;
    mDivingSpeed = std::max(minDiveSpeed, curveDiveSpeed);

    if (movingUp) {
      float newSubElevation = mSubElevation + mDivingSpeed;
      if (newSubElevation > 0.0f) {
        newSubElevation = 0.0f;
      }
      mSubElevation = newSubElevation;
      if (newSubElevation == 0.0f) {
        mUnit->SetCurrentLayer(mLayer);
        mUnit->UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_MovingUp));
        SetMotionVertEvent(UMVE_Top);
      }
      return true;
    }

    if (movingDown) {
      const float newSubElevation = mSubElevation - mDivingSpeed;
      if (newSubElevation > diveDepthLimit) {
        mSubElevation = newSubElevation;
      } else {
        mSubElevation = diveDepthLimit;
        mUnit->SetCurrentLayer(mLayer);
        mUnit->UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_MovingDown));
        SetMotionVertEvent(UMVE_Bottom);
      }
      return true;
    }

    return true;
  }

  /**
   * Address: 0x006C35C0 (FUN_006C35C0, ?UpdateCurrentLayer@CUnitMotion@Moho@@AAEXXZ)
   *
   * What it does:
   * See the header. Called once per motion tick after the move integrator has
   * written the new transform.
   */
  void CUnitMotion::UpdateCurrentLayer()
  {
    Unit* const unit = mUnit;
    const VTransform currentTransform = unit->GetTransform();
    const ELayer currentLayer = unit->mVarDat.mLayerMask;
    const RUnitBlueprintPhysics& physics = unit->GetBlueprint()->Physics;
    const ERuleBPUnitMovementType motionType = physics.MotionType;

    STIMap* const mapData = unit->SimulationRef->mMapData;
    const float groundElevation =
      mapData->GetHeightField()->GetElevation(currentTransform.pos_.x, currentTransform.pos_.z);

    // Maps without water are modelled as having their surface infinitely far
    // below, so nothing ever counts as submerged.
    float waterSurface = mapData->mWaterEnabled ? mapData->mWaterElevation : kNoWaterSurfaceElevation;

    // Land-capable footprints sit on top of shallow water rather than in it,
    // so their effective surface is raised by the blueprint's layer-change
    // offset.
    if ((static_cast<std::uint8_t>(unit->GetFootprint().mOccupancyCaps) & static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND)) != 0) {
      waterSurface += physics.LayerChangeOffsetHeight;
    }

    if (groundElevation <= waterSurface) {
      // Now under water. Only a land unit needs reclassifying.
      if (waterSurface > groundElevation && currentLayer == LAYER_Land) {
        if (motionType == RULEUMT_Amphibious || motionType == RULEUMT_Land) {
          // Walks the bottom.
          unit->SetCurrentLayer(LAYER_Seabed);
        } else if (motionType == RULEUMT_Hover || motionType == RULEUMT_AmphibiousFloating) {
          // Floats. Start a layer transition that lifts it to the surface.
          if (physics.LayerTransitionDuration != 0.0f) {
            mLayerTransitionTicks = 1.0f;
            mLastTrans = currentTransform;
            mCurTrans = SnapToWater(currentTransform);
          }
          unit->SetCurrentLayer(LAYER_Water);
        }
      }
      return;
    }

    // Now above water.
    if (currentLayer == LAYER_Seabed) {
      if (motionType == RULEUMT_Amphibious || motionType == RULEUMT_Land) {
        unit->SetCurrentLayer(LAYER_Land);
      }
      return;
    }

    if (currentLayer == LAYER_Water) {
      if (motionType == RULEUMT_Hover || motionType == RULEUMT_AmphibiousFloating
          || motionType == RULEUMT_Water) {
        if (physics.LayerTransitionDuration != 0.0f) {
          mLayerTransitionTicks = 1.0f;
          mLastTrans = currentTransform;

          // Snap to the ground the unit is heading for, not the one it is
          // leaving: the endpoint is led by ten ticks of current velocity so
          // the blend does not drag it backwards up the shoreline.
          VTransform leadTransform = currentTransform;
          leadTransform.pos_.x += mVelocity.x * kLayerExitLeadTicks;
          leadTransform.pos_.y += mVelocity.y * kLayerExitLeadTicks;
          leadTransform.pos_.z += mVelocity.z * kLayerExitLeadTicks;
          mCurTrans = SnapToGround(leadTransform);
        }
        unit->SetCurrentLayer(LAYER_Land);
      }
    }
  }

  /**
   * Address: 0x006C3070 (FUN_006C3070, ?TransitionBetweenLayers@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z)
   * Mangled: ?TransitionBetweenLayers@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z
   *
   * What it does:
   * Linearly blends position and shortest-path-normalized orientation between
   * cached layer-transition endpoints, then advances transition tick progress.
   */
  void CUnitMotion::TransitionBetweenLayers(VTransform& transform)
  {
    const float transitionDurationTicks = mUnit->GetBlueprint()->Physics.LayerTransitionDuration * kLayerTransitionTickScale;
    const float transitionProgress = mLayerTransitionTicks / transitionDurationTicks;

    transform.pos_.x = mLastTrans.pos_.x + ((mCurTrans.pos_.x - mLastTrans.pos_.x) * transitionProgress);
    transform.pos_.y = mLastTrans.pos_.y + ((mCurTrans.pos_.y - mLastTrans.pos_.y) * transitionProgress);
    transform.pos_.z = mLastTrans.pos_.z + ((mCurTrans.pos_.z - mLastTrans.pos_.z) * transitionProgress);
    transform.orient_ = Wm3::Quaternionf::Nlerp(mLastTrans.orient_, mCurTrans.orient_, transitionProgress);

    mLayerTransitionTicks += 1.0f;
    mProcessSurfaceCollision = false;
    if (mLayerTransitionTicks >= transitionDurationTicks) {
      mLayerTransitionTicks = 0.0f;
    }
  }

  /**
   * Address: 0x006C1E20 (FUN_006C1E20, ?CalcMoveCommon@CUnitMotion@Moho@@AAE_NAAVVTransform@2@PAM@Z)
   * Mangled: ?CalcMoveCommon@CUnitMotion@Moho@@AAE_NAAVVTransform@2@PAM@Z
   *
   * What it does:
   * Integrates one shared surface-move tick for land/water/hover motion,
   * including slaved-target facing, braking, waypoint snap, and collision rollback.
   */
  bool CUnitMotion::CalcMoveCommon(VTransform& transform, float* const outMoveDistance)
  {
    (void)outMoveDistance;

    Unit* const unit = mUnit;
    if (unit->IsBeingBuilt()) {
      return false;
    }

    if (mLayerTransitionTicks != 0.0f) {
      TransitionBetweenLayers(transform);
      return false;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const RUnitBlueprintPhysics& physics = blueprint->Physics;
    const RUnitBlueprintAI& aiBlueprint = blueprint->AI;
    Wm3::Vector3f desiredTarget{};

    UnitWeapon* slavedWeapon = nullptr;
    CAiTarget* const slavedTarget =
      (unit->AiAttacker != nullptr) ? unit->AiAttacker->HasSlavedTarget(&slavedWeapon) : nullptr;
    if (slavedTarget != nullptr && slavedTarget->HasTarget() && slavedWeapon != nullptr) {
      if (aiBlueprint.AttackAngle > 0.0f) {
        desiredTarget = slavedTarget->GetTargetPosGun(false);
      } else if (
        slavedWeapon->mWeaponBlueprint != nullptr &&
        slavedWeapon->mWeaponBlueprint->SlavedToBodyArcRange < 180.0f
      ) {
        const Wm3::Vector3f unitPosition = unit->GetPosition();
        const Wm3::Vector3f targetPosition = slavedTarget->GetTargetPosGun(false);
        const float targetHeading =
          std::atan2(targetPosition.x - unitPosition.x, targetPosition.z - unitPosition.z);
        const Wm3::Vector3f forward = ForwardVectorFromQuaternion(unit->GetTransform().orient_);
        const float unitHeading = std::atan2(forward.x, forward.z);
        const float headingDelta = NormalizeAngleSignedRadians(targetHeading - unitHeading);
        const float absHeadingDelta = std::fabs(headingDelta);
        const float slavedArcRange = slavedWeapon->mWeaponBlueprint->SlavedToBodyArcRange;

        if (mUnknownBool91) {
          if ((slavedArcRange * kCommonMoveSlavedArcExitRadians) > absHeadingDelta) {
            mUnknownBool91 = false;
          }
        } else if (absHeadingDelta > (slavedArcRange * kCommonMoveSlavedArcEnterRadians)) {
          mUnknownBool91 = true;
        }

        if (mUnknownBool91 || (physics.MotionType == RULEUMT_Hover && mNextWaypoint != nullptr)) {
          desiredTarget = targetPosition;
        } else {
          desiredTarget = Wm3::Vector3f{
            unitPosition.x + forward.x,
            unitPosition.y + forward.y,
            unitPosition.z + forward.z,
          };
        }
      }
    } else {
      mUnknownBool91 = false;
    }

    if (!IsOnValidLayer()) {
      const float damage = -(static_cast<Entity*>(unit)->mVarDat.mMaxHealth * kCommonMoveTickScale);
      unit->AdjustHealth(nullptr, damage);
      if (static_cast<Entity*>(unit)->mVarDat.mHealth <= 0.0f) {
        unit->Kill(nullptr, "", 0.0f);
      }
      return false;
    }

    const Wm3::Vector3f originalPosition = transform.pos_;
    const bool initiallyFits = !UnitWontFitAt(originalPosition, unit);

    if (mNextWaypoint == nullptr || mIsBeingPushed) {
      bool rotated = false;
      if (!IsVector3fBinaryZero(desiredTarget)) {
        Wm3::Vector3f steeringTarget = desiredTarget;
        if (aiBlueprint.AttackAngle > 0.0f) {
          steeringTarget = ApplyCommonMoveAttackAngle(unit, steeringTarget, aiBlueprint.AttackAngle);
        }

        rotated = RotateCommonMoveTransformTowardDestination(
          unit,
          transform,
          steeringTarget,
          physics.MotionType == RULEUMT_Hover
        );
      } else {
        IAiNavigator* const navigator = unit->AiNavigator;
        if (navigator != nullptr && navigator->GetStatus() == AINAVSTATUS_Idle) {
          Wm3::Vector3f formationVector = unit->GetFormationVector();
          if (IsVector3fBinaryZero(formationVector)) {
            formationVector = mFormationVec;
          }

          if (!IsVector3fBinaryZero(formationVector)) {
            const Wm3::Vector3f formationDestination{
              originalPosition.x + formationVector.x,
              originalPosition.y + formationVector.y,
              originalPosition.z + formationVector.z,
            };
            rotated = RotateCommonMoveTransformTowardDestination(
              unit,
              transform,
              formationDestination,
              physics.MotionType == RULEUMT_Hover
            );
          }
        }
      }

      mVector44 = {};
      Wm3::Vector3f currentVelocity = unit->GetVelocity();
      const float currentSpeedSq =
        (currentVelocity.x * currentVelocity.x) +
        (currentVelocity.y * currentVelocity.y) +
        (currentVelocity.z * currentVelocity.z);
      if (!rotated && currentSpeedSq < kCommonMoveVelocityStopThresholdSq) {
        mPos = transform.pos_;
        mVelocity = {};
        return false;
      }

      const UnitAttributes& attributes = unit->GetAttributes();
      float brake = physics.MaxBrake;
      if (brake <= 0.0f) {
        brake = physics.MaxAcceleration;
      }
      brake *= attributes.accelerationMult * kCommonMoveTickScale;

      const Wm3::Vector3f dampedVelocity{
        currentVelocity.x * kCommonMoveVelocityDamping,
        currentVelocity.y * kCommonMoveVelocityDamping,
        currentVelocity.z * kCommonMoveVelocityDamping,
      };
      currentVelocity.x = -currentVelocity.x;
      currentVelocity.y = -currentVelocity.y;
      currentVelocity.z = -currentVelocity.z;
      currentVelocity.LimitLengthTo(brake);

      mVelocity = Wm3::Vector3f{
        currentVelocity.x + dampedVelocity.x,
        currentVelocity.y + dampedVelocity.y,
        currentVelocity.z + dampedVelocity.z,
      };
      transform.pos_.x += mVelocity.x;
      transform.pos_.y += mVelocity.y;
      transform.pos_.z += mVelocity.z;
      mPos = transform.pos_;
    } else {
      const CPathPoint* const waypoint = mNextWaypoint;
      transform.pos_ = waypoint->mPosition;
      if (physics.MotionType == RULEUMT_Hover) {
        Wm3::Vector3f steeringTarget = desiredTarget;
        if (IsVector3fBinaryZero(steeringTarget)) {
          steeringTarget = Wm3::Vector3f{
            waypoint->mPosition.x + waypoint->mDirection.x,
            waypoint->mPosition.y + waypoint->mDirection.y,
            waypoint->mPosition.z + waypoint->mDirection.z,
          };
        }
        (void)RotateCommonMoveTransformTowardDestination(unit, transform, steeringTarget, true);
      } else {
        transform.orient_ = COORDS_Orient(waypoint->mDirection);
      }

      const Wm3::Vector3f delta{
        transform.pos_.x - mPos.x,
        transform.pos_.y - mPos.y,
        transform.pos_.z - mPos.z,
      };
      mVector44 = Wm3::Vector3f{
        delta.x - mVelocity.x,
        delta.y - mVelocity.y,
        delta.z - mVelocity.z,
      };
      mVelocity = delta;
      mPos = waypoint->mPosition;
    }

    if (initiallyFits && UnitWontFitAt(transform.pos_, unit)) {
      // TEMPORARY PROBE -- inert move order triage, delete when resolved.
      {
        const SFootprint& fp = unit->GetFootprint();
        const SOCellPos cell = fp.ToCellPos(transform.pos_);
        const COGrid& grid = *unit->SimulationRef->mOGrid;
        const EOccupancyCaps mobileCaps = OCCUPY_MobileCheck(fp, *unit->SimulationRef->mMapData, cell);
        gpg::Warnf("[MOTDIAG] WontFit from=(%.2f,%.2f) to=(%.2f,%.2f) cell=(%d,%d) fp=%dx%d caps=0x%X terrainOcc=%d waterOcc=%d filter=0x%X",
                   originalPosition.x, originalPosition.z, transform.pos_.x, transform.pos_.z, static_cast<int>(cell.x), static_cast<int>(cell.z),
                   static_cast<int>(fp.mSizeX), static_cast<int>(fp.mSizeZ), static_cast<unsigned>(mobileCaps),
                   grid.terrainOccupation.GetRectOr(cell.x, cell.z, 1, 1, true) ? 1 : 0,
                   grid.waterOccupation.GetRectOr(cell.x, cell.z, 1, 1, true) ? 1 : 0,
                   static_cast<unsigned>(OCCUPY_Filter(fp, grid, cell, mobileCaps)));
        static bool sDumped = false;
        if (!sDumped) {
          sDumped = true;
          for (int z = static_cast<int>(cell.z) - 6; z <= static_cast<int>(cell.z) + 6; ++z) {
            char row[40] = {};
            int w = 0;
            for (int x = static_cast<int>(cell.x) - 12; x <= static_cast<int>(cell.x) + 12; ++x) {
              row[w++] = grid.terrainOccupation.GetRectOr(static_cast<std::int16_t>(x), static_cast<std::int16_t>(z), 1, 1, true) ? '#' : '.';
            }
            gpg::Warnf("[MOTDIAG] occ z=%d x=%d.. %s", z, static_cast<int>(cell.x) - 12, row);
          }
        }
      }
      mVector44 = {};
      mVelocity = {};
      if (!mIsBeingPushed) {
        Wm3::Vector3f impulse{
          originalPosition.x - transform.pos_.x,
          0.0f,
          originalPosition.z - transform.pos_.z,
        };
        (void)VecSetLength(&impulse, unit->mInfoCache.mFormationTopSpeed * kCommonMoveCollisionImpulseScale);
        AddImpulse(impulse, false);
      }

      transform.pos_ = originalPosition;
      mPos = transform.pos_;
    }

    return true;
  }

  /**
   * Address: 0x006BCA10 (FUN_006BCA10, ?CalcAirMovementDampingFactor@CUnitMotion@Moho@@AAEMABV?$Vector3@M@Wm3@@@Z)
   * Mangled: ?CalcAirMovementDampingFactor@CUnitMotion@Moho@@AAEMABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Returns air movement damping from control-vector speed, formation top-speed
   * cache, and air blueprint KMove/KMoveDamping coefficients.
   */
  float CUnitMotion::CalcAirMovementDampingFactor(const Wm3::Vector3f& movementVector)
  {
    if (mUnit->IsInCategory("TARGETCHASER")) {
      return 1.0f;
    }

    const RUnitBlueprintAir& airBlueprint = mUnit->GetBlueprint()->Air;
    const float kMove = airBlueprint.KMove;
    const float topSpeed = mUnit->mInfoCache.mFormationTopSpeed;

    float clampedSpeed = std::sqrt(
      (movementVector.x * movementVector.x) +
      (movementVector.y * movementVector.y) +
      (movementVector.z * movementVector.z)
    );
    if (clampedSpeed > topSpeed) {
      clampedSpeed = topSpeed;
    }

    float dampingDenominator = 1.0f;
    if (clampedSpeed > 1.0f) {
      dampingDenominator = clampedSpeed;
    }

    if (topSpeed <= dampingDenominator) {
      return kMove;
    }

    float movementDamping = topSpeed / dampingDenominator;
    if (movementDamping > airBlueprint.KMoveDamping) {
      movementDamping = airBlueprint.KMoveDamping;
    }

    return movementDamping;
  }

  /**
   * Address: 0x006BCB90 (FUN_006BCB90, ?CalcDesiredTargetElevation@CUnitMotion@Moho@@ABEMABVCAiTarget@2@ABV?$Vector3@M@Wm3@@@Z)
   * Mangled: ?CalcDesiredTargetElevation@CUnitMotion@Moho@@ABEMABVCAiTarget@2@ABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Samples desired target elevation from target entity state and map
   * elevation, then returns relative Y-offset from the owner unit position.
   */
  float CUnitMotion::CalcDesiredTargetElevation(const CAiTarget& target, const Wm3::Vector3f& offsetFromUnit) const
  {
    const Unit* const ownerUnit = mUnit;
    const RUnitBlueprint* const ownerBlueprint = ownerUnit->GetBlueprint();
    const RUnitBlueprintPhysics& ownerPhysics = ownerBlueprint->Physics;
    const STIMap* const mapData = ownerUnit->SimulationRef->mMapData;
    const CHeightField* const heightField = mapData->GetHeightField();

    const Wm3::Vector3f ownerPosition = ownerUnit->GetPosition();
    const Wm3::Vector3f samplePosition{
      ownerPosition.x + offsetFromUnit.x,
      ownerPosition.y + offsetFromUnit.y,
      ownerPosition.z + offsetFromUnit.z,
    };
    const std::int32_t sampleX = static_cast<std::int32_t>(samplePosition.x);
    const std::int32_t sampleZ = static_cast<std::int32_t>(samplePosition.z);

    const float sampledElevation = (ownerBlueprint->Air.FlyInWater != 0u)
                                     ? (static_cast<float>(heightField->GetHeightAt(sampleX, sampleZ)) * kHeightWordScale)
                                     : mapData->GetElevation(sampleX, sampleZ);

    if (Entity* const targetEntity = target.GetEntity();
        targetEntity != nullptr && targetEntity->mVarDat.mLayerMask == LAYER_Air) {
      float targetElevation = 0.0f;
      if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
        targetElevation = targetUnit->GetBlueprint()->Physics.Elevation + sampledElevation;
      } else {
        targetElevation = const_cast<CAiTarget&>(target).GetTargetPosGun(false).y;
      }

      const float minTargetElevation = (ownerPhysics.Elevation * kAirTargetMinimumElevationScale) + sampledElevation;
      if (targetElevation < minTargetElevation) {
        targetElevation = minTargetElevation;
      }
      return targetElevation - ownerUnit->GetPosition().y;
    }

    if (Entity* const targetEntity = target.GetEntity();
        targetEntity != nullptr && targetEntity->mVarDat.mLayerMask == LAYER_Air) {
      return 0.0f;
    }

    const float desiredOwnerElevation =
      (static_cast<std::int32_t>(mCombatState) == 1) ? ownerPhysics.AttackElevation : ownerPhysics.Elevation;
    return (sampledElevation + desiredOwnerElevation) - ownerUnit->GetPosition().y;
  }

  /**
   * Address: 0x006BD7B0 (FUN_006BD7B0, Moho::CUnitMotion::CalcWingedOrientation)
   *
   * What it does:
   * Builds the winged-air force vector and orthogonal basis from the unit's
   * current motion inputs, then updates the accumulated wing orientation bias.
   */
  void CUnitMotion::CalcWingedOrientation(
    const Wm3::Vector3f& referenceVector,
    const Wm3::Vector3f& controlVector,
    const Wm3::Vector3f& primaryVector,
    const Wm3::Vector3f& fallbackVector,
    VAxes3& outAxes,
    Wm3::Vector3f& outForce,
    float& wingOri
  )
  {
    constexpr std::int32_t kAirCombatStateNone = 0;
    constexpr std::int32_t kAirCombatStateCombat = 1;
    constexpr std::int32_t kAirCombatStateNormalTurn = 2;
    constexpr std::int32_t kAirCombatStateCombatTurn = 3;

    Unit* const unit = mUnit;
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const RUnitBlueprintPhysics& physics = blueprint->Physics;
    const RUnitBlueprintAir& air = blueprint->Air;
    const VTransform& transform = unit->GetTransform();
    const std::int32_t combatState = static_cast<std::int32_t>(mCombatState);

    // m11 - the Y component of the local up axis. The previous spelling used a
    // `w*w` diagonal term, which no matrix expansion in this binary computes.
    const float currentOrientationY =
      1.0f - (((transform.orient_.x * transform.orient_.x) + (transform.orient_.z * transform.orient_.z)) * 2.0f);

    outAxes.vX = {1.0f, 0.0f, 0.0f};
    outAxes.vY = {0.0f, 1.0f, 0.0f};
    outAxes.vZ = {0.0f, 0.0f, 1.0f};

    const float planarSpeed = std::sqrt((controlVector.z * controlVector.z) + (controlVector.x * controlVector.x));
    const float limitedSpeed = std::min(planarSpeed, unit->mInfoCache.mFormationTopSpeed);
    const bool isBelowStartTurnDistance = air.StartTurnDistance > limitedSpeed;
    const bool isGuarding = unit->IsUnitState(UNITSTATE_Guarding);

    Wm3::Vector3f selectedVector{};
    if (!isBelowStartTurnDistance || isGuarding || combatState != kAirCombatStateNone) {
      selectedVector = primaryVector;

      outForce.x = referenceVector.x * limitedSpeed;
      outForce.y = referenceVector.y * limitedSpeed;
      outForce.z = referenceVector.z * limitedSpeed;

      if (combatState <= kAirCombatStateNormalTurn) {
        const float alignment =
          (primaryVector.x * referenceVector.x) +
          (primaryVector.y * referenceVector.y) +
          (primaryVector.z * referenceVector.z);

        float forceScale = 0.5f;
        if (alignment > 0.5f) {
          forceScale = alignment;
        }

        if (isGuarding && isBelowStartTurnDistance) {
          float guardScale = limitedSpeed / air.StartTurnDistance;
          if (guardScale > 0.5f) {
            guardScale = 0.5f;
          }

          if (guardScale <= forceScale) {
            forceScale = guardScale;
          }
        }

        outForce.x *= forceScale;
        outForce.y *= forceScale;
        outForce.z *= forceScale;
      }
    } else {
      selectedVector = fallbackVector;
    }

    outForce.y = CalcWingedLift(controlVector.y, currentOrientationY);

    Wm3::Vector3f selectedPlanarVector{};
    const float selectedPlanarLength = std::sqrt((selectedVector.z * selectedVector.z) + (selectedVector.x * selectedVector.x));
    if (selectedPlanarLength > 0.0f) {
      const float inverseLength = 1.0f / selectedPlanarLength;
      selectedPlanarVector.x = selectedVector.x * inverseLength;
      selectedPlanarVector.z = selectedVector.z * inverseLength;
    }

    const Wm3::Vector3f referenceVectorQuarterTurn = RotateByQuaternion(referenceVector, kWingedOrientationQuarterTurnRotation);
    const float turnSign =
      ((referenceVectorQuarterTurn.z * selectedVector.z) +
       (referenceVectorQuarterTurn.y * selectedVector.y) +
       (referenceVectorQuarterTurn.x * selectedVector.x)) >= 0.0f
        ? 1.0f
        : -1.0f;

    float turnDelta = std::atan2(selectedPlanarVector.x, selectedPlanarVector.z) - std::atan2(referenceVector.x, referenceVector.z);
    if (turnDelta <= 3.1415927f) {
      if (turnDelta < -3.1415927f) {
        turnDelta += 6.2831855f;
      }
    } else {
      turnDelta -= 6.2831855f;
    }

    const float maxTurnSpeed = (combatState == kAirCombatStateCombatTurn) ? air.CombatTurnSpeed : air.TurnSpeed;
    const float maxTurnDelta = maxTurnSpeed * 0.1f;
    if (turnDelta > maxTurnDelta) {
      turnDelta = maxTurnDelta;
    }
    if (turnDelta < -maxTurnDelta) {
      turnDelta = -maxTurnDelta;
    }

    // 0x006BDBB5/0x006BDBBB: the clamped delta is scaled by 10.0 (dword_DFF31C)
    // and then halved (flt_E4F724), so this is the half-angle of a ten-times
    // exaggerated yaw. 0x006BDBE3 stores cos into lane 0 and 0x006BDBF6 stores
    // sin into lane 2, with lanes 1 and 3 zeroed at 0x006BDC06/0x006BDC0C --
    // the same {w, 0, y, 0} shape as `quat_45deg2`.
    const float halfTurnAngle = (turnDelta * 10.0f) * 0.5f;
    const Wm3::Quaternionf turnQuaternion{
      std::cos(halfTurnAngle),
      0.0f,
      std::sin(halfTurnAngle),
      0.0f,
    };

    // 0x006BDBFA/0x006BDC02 hand the rotate `[esp+0x2c]` and the fresh turn
    // quaternion; `[esp+0x2c]` is `referenceVector`, the airframe's CURRENT
    // heading (0x006BD800 fills it from the incoming vector, 0x006BD964 scales
    // the same lanes into `outForce`, and 0x006BDB1E feeds them to the second
    // atan2 as the angle being turned *from*). Only the result's x and z are
    // written back over `selectedVector` (0x006BDC1B / 0x006BDC2A); its y is
    // left alone.
    //
    // Rotating `selectedVector` here instead - the direction the aircraft
    // wants to go - asked the airframe to point a full turn-rate step PAST its
    // target rather than one step TOWARDS it. On a 180-degree turn that lands
    // about 90 degrees off, every tick, so the nose never converged: aircraft
    // flew straight past their move order at cruise speed and never came back.
    Wm3::Vector3f rotatedSelectedVector = selectedVector;
    const Wm3::Vector3f turnVector = RotateByQuaternion(referenceVector, turnQuaternion);
    rotatedSelectedVector.x = turnVector.x;
    rotatedSelectedVector.z = turnVector.z;
    Wm3::Vector3f::Normalize(&rotatedSelectedVector);

    const float turnScaleLimit = isBelowStartTurnDistance ? 0.5f : 1.0f;
    float turnScale = limitedSpeed / air.StartTurnDistance;
    if (turnScale > turnScaleLimit) {
      turnScale = turnScaleLimit;
    }

    float bankFactor = air.BankFactor;
    float forwardAlignment =
      (rotatedSelectedVector.x * referenceVector.x) +
      (rotatedSelectedVector.y * referenceVector.y) +
      (rotatedSelectedVector.z * referenceVector.z);

    if (combatState == kAirCombatStateNormalTurn) {
      const float alignmentSquared = forwardAlignment * forwardAlignment;
      forwardAlignment = alignmentSquared * alignmentSquared * alignmentSquared * alignmentSquared;
      bankFactor = air.BankFactor * 10.0f;
    }

    if (forwardAlignment < 0.0f) {
      forwardAlignment = 0.0f;
    }

    const float wingBlend = 1.0f - forwardAlignment;
    const float elevationScale =
      unit->IsUnitState(UNITSTATE_MovingDown) ? (mCurElevation / physics.Elevation) : 1.0f;
    const float wingOrientationBias = ((elevationScale * wingBlend) * bankFactor) * turnScale * turnSign;
    const float wingProjectionScale = rotatedSelectedVector.y * turnScale;

    const Wm3::Vector3f wingProjection{
      selectedPlanarVector.x * wingProjectionScale,
      selectedPlanarVector.y * wingProjectionScale,
      selectedPlanarVector.z * wingProjectionScale,
    };

    const Wm3::Vector3f wingAxis = RotateByQuaternion(rotatedSelectedVector, kWingedOrientationQuarterTurnRotation);
    // Lane by lane against 0x006BDD94..0x006BDDCD: `[eax]` (wingAxis.x) feeds
    // the value that ends up in `vY.x` at 0x006BDE52, `[eax+4]` (wingAxis.y)
    // the one that gets the `+1.0` (0x006BDDA8) and lands in `vY.y` at
    // 0x006BDE5D, `[eax+8]` (wingAxis.z) the one in `vY.z` at 0x006BDE62 --
    // and each subtracts the matching lane of `wingProjection`. The `+1.0` is
    // world up, so putting it in `.x` rolls every winged aircraft a quarter
    // turn and it flies on its side.
    Wm3::Vector3f wingUpVector{
      (wingOrientationBias * wingAxis.x) - wingProjection.x,
      (wingAxis.y * wingOrientationBias) + 1.0f - wingProjection.y,
      (wingOrientationBias * wingAxis.z) - wingProjection.z,
    };

    Wm3::Vector3f::Normalize(&wingUpVector);
    outAxes.vY = wingUpVector;
    outAxes.vZ = rotatedSelectedVector;

    if (combatState == kAirCombatStateCombatTurn) {
      wingOri += air.TightTurnMultiplier * wingBlend;
    } else if (combatState == kAirCombatStateCombat || combatState == kAirCombatStateNormalTurn) {
      wingOri += wingBlend;
    }
  }

  /**
   * Address: 0x006BDEE0 (FUN_006BDEE0, Moho::CUnitMotion::CalcCirclingOrientation)
   *
   * What it does: see header.
   */
  void CUnitMotion::CalcCirclingOrientation(
    const SPhysBody& body,
    VAxes3& outAxes,
    Wm3::Vector3f& outDesiredVelocity,
    CAiTarget& target
  )
  {
    // The two fixed quaternions the binary selects between at 0x006BE26C and
    // 0x006BE277: `quat_n45deg` (0x010B6158) and `quat_45deg2` (0x010B6178),
    // which pick a clockwise or counter-clockwise tangential offset from the
    // direct-to-target heading. Their static initialisers -- 0x00BD7330 and
    // 0x00BD7390 -- take the half-angle from `flt_E4FA28` (0xBF490FDB) and
    // `flt_E4F8B0` (0x3F490FDB), i.e. -+pi/4, store cos into lane 0 and sin
    // into lane 2, and zero lanes 1 and 3. So each is a quarter turn about Y,
    // not the eighth turn a half-angle of pi/8 would have given.
    static const Wm3::Quaternionf kCirclingYawNeg90{
      std::cos(-0.78539816f), 0.0f, std::sin(-0.78539816f), 0.0f};
    static const Wm3::Quaternionf kCirclingYawPos90{
      std::cos(0.78539816f), 0.0f, std::sin(0.78539816f), 0.0f};

    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
    const RUnitBlueprintPhysics& physics = blueprint->Physics;
    const RUnitBlueprintAir& air = blueprint->Air;

    const Wm3::Vec3f position = mUnit->GetPosition();
    Sim* const sim = mUnit->SimulationRef;
    CRandomStream& randomStream = *sim->mRngState;
    const std::uint32_t curTick = sim->mCurTick;

    if (curTick > mCombatStateTimeoutTick) {
      if (air.CirclingDirChange) {
        mUnknownBool8F = ScaleRandomUInt32ToRange(100, randomStream) > 50;
      }

      const float maxElevationOffset = air.CirclingElevationChangeRatio * physics.AttackElevation;
      mUnknownFloat94 =
        -maxElevationOffset + ((maxElevationOffset - -maxElevationOffset)
          * static_cast<double>(randomStream.twister.NextUInt32()) * 2.3283064e-10);

      mUnknownFloat98 = air.CirclingRadiusChangeMinRatio
        + ((air.CirclingRadiusChangeMaxRatio - air.CirclingRadiusChangeMinRatio)
          * static_cast<double>(randomStream.twister.NextUInt32()) * 2.3283064e-10);

      const auto maxChangeTicks =
        static_cast<std::int32_t>(std::lround(air.CirclingFlightChangeFrequency * 2.0f * 10.0f));
      const auto minChangeTicks =
        static_cast<std::int32_t>(std::lround(air.CirclingFlightChangeFrequency * 10.0f));
      mCombatStateTimeoutTick = curTick + minChangeTicks
        + static_cast<std::int32_t>(ScaleRandomUInt32ToRange(
            static_cast<std::uint32_t>(maxChangeTicks - minChangeTicks), randomStream));
    }

    Entity* const focusEntity = mUnit->GetFocusEntity();
    float targetX = mTargetPosition.x;
    float targetZ = mTargetPosition.z;
    float steerRadius = air.StartTurnDistance * mUnknownFloat98;

    if (focusEntity != nullptr
        && (mUnit->IsUnitState(UNITSTATE_Building) || mUnit->IsUnitState(UNITSTATE_Repairing))) {
      targetX = focusEntity->mVarDat.mCurTransform.pos_.x;
      targetZ = focusEntity->mVarDat.mCurTransform.pos_.z;
    } else if (target.HasTarget()) {
      if (mUnit->AiAttacker != nullptr) {
        const Wm3::Vec3f targetPosGun = target.GetTargetPosGun(false);
        targetX = targetPosGun.x;
        targetZ = targetPosGun.z;

        UnitWeapon* const targetWeapon = mUnit->AiAttacker->GetTargetWeapon(&target);
        if (targetWeapon != nullptr) {
          float maxRadius = targetWeapon->mAttributes.mMaxRadius;
          if (maxRadius < 0.0f) {
            maxRadius = targetWeapon->mWeaponBlueprint->MaxRadius;
          }
          steerRadius = maxRadius * mUnknownFloat98;

          Entity* const targetEntity = target.GetEntity();
          if (targetEntity != nullptr && targetEntity->mVarDat.mLayerMask == LAYER_Air) {
            steerRadius = air.CirclingRadiusVsAirMult * steerRadius;
          }
        }
      }
    }

    Wm3::Vector3f toTarget{targetX - position.x, 0.0f, targetZ - position.z};
    if (((targetZ - position.z) * (targetZ - position.z)) + ((targetX - position.x) * (targetX - position.x))
        < 0.000001f) {
      toTarget = Wm3::Vector3f{1.0f, 0.0f, 0.0f};
    }
    Wm3::Vector3f::Normalize(&toTarget);

    Wm3::Vector3f tangentDirection{};
    MultQuadVec(&tangentDirection, &toTarget, mUnknownBool8F ? &kCirclingYawNeg90 : &kCirclingYawPos90);

    Wm3::Vector3f steerOffset{
      (tangentDirection.x * air.MinAirspeed) + position.x - targetX,
      (tangentDirection.y * air.MinAirspeed) + position.y - position.y,
      (tangentDirection.z * air.MinAirspeed) + position.z - targetZ
    };
    (void)VecSetLength(&steerOffset, steerRadius);

    const float aimX = steerOffset.x + targetX;
    const float aimZ = steerOffset.z + targetZ;

    float terrainElevation;
    if (air.FlyInWater) {
      STIMap* const mapData = sim->mMapData;
      terrainElevation =
        static_cast<float>(mapData->GetHeightField()->GetHeightAt(static_cast<std::int32_t>(aimX), static_cast<std::int32_t>(aimZ)))
        * 0.0078125f;
    } else {
      terrainElevation = sim->mMapData->GetHeightField()->GetElevation(aimX, aimZ);
    }

    outDesiredVelocity.z = aimZ - position.z;
    outDesiredVelocity.x = aimX - position.x;
    outDesiredVelocity.y = (physics.AttackElevation + mUnknownFloat94 + terrainElevation) - position.y;

    float desiredSpeed = std::sqrt(
      (outDesiredVelocity.z * outDesiredVelocity.z) + (outDesiredVelocity.y * outDesiredVelocity.y)
      + (outDesiredVelocity.x * outDesiredVelocity.x));
    if (air.MaxAirspeed <= desiredSpeed) {
      desiredSpeed = air.MaxAirspeed;
    }
    (void)VecSetLength(&outDesiredVelocity, desiredSpeed);

    CalcHoverOrientation(body, toTarget, outAxes);
  }

  /**
   * Address: 0x006BE6B0 (FUN_006BE6B0, Moho::CUnitMotion::ComputeAirControl)
   * Mangled: ?ComputeAirControl@CUnitMotion@Moho@@AAEXABUSPhysBody@2@ABV?$Vector3@M@Wm3@@111PAUSControlOutput@2@AAVCAiTarget@2@@Z
   *
   * What it does: see header.
   *
   * Rotating `mWorldImpulse` through `Moho::MultQuadVec` rather than upstream
   * WildMagic's `Conjugate().Rotate()` was already right and is unchanged.
   *
   * The relative-orientation block is ordinary scalar-first. 0x006BE916 keeps
   * `[ebx+2Ch]` (lane 0) and 0x006BE93A / 0x006BE950 / 0x006BE966 negate lanes
   * 1-3, and the product that follows puts that conjugate on the LEFT. The
   * shortest-arc test at 0x006BEA17/0x006BEA1A compares zero against the value
   * bound for lane 0 - the scalar - so it reads `.w`.
   *
   * A prior revision recorded the first output lane as `.x` "the real/scalar
   * lane in this engine's convention"; that convention does not exist in the
   * binary - see `QuatToMatrix` (0x00452FD0) and `VMatrix4::Set` (0x004EE980),
   * neither of which computes a `ww` term at all.
   */
  void CUnitMotion::ComputeAirControl(
    const SPhysBody& body,
    const Wm3::Vector3f& fallbackVector,
    const Wm3::Vector3f& controlVector,
    const Wm3::Vector3f& primaryVector,
    const Wm3::Vector3f& referenceVector,
    SControlOutput* const out,
    CAiTarget& target
  )
  {
    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
    const RUnitBlueprintAir& air = blueprint->Air;

    const float loadFactor = mUnit->CalcTransportLoadFactor();
    const float invLoadFactor = 1.0f / loadFactor;

    float turnGain = air.KTurn * invLoadFactor;
    const float rollGain = air.KRoll * invLoadFactor;
    const float liftGain = air.KLift * invLoadFactor;

    VAxes3 axes{};
    axes.vX = Wm3::Vector3f{1.0f, 0.0f, 0.0f};
    axes.vY = Wm3::Vector3f{0.0f, 1.0f, 0.0f};
    axes.vZ = Wm3::Vector3f{0.0f, 0.0f, 1.0f};

    Wm3::Vector3f steeringForce = controlVector;

    // EUnitMotionCarrierEvent value 2: descending to a carrier's deck.
    constexpr auto kCarrierEventDescendToDeck = static_cast<EUnitMotionCarrierEvent>(2);

    const bool wantsHoverFamily =
      (!air.Winged || mCarrierEvent == kCarrierEventDescendToDeck)
      && (!mUnit->IsUnitState(UNITSTATE_Guarding)
        || mUnit->IsUnitState(UNITSTATE_Moving)
        || mUnit->IsUnitState(UNITSTATE_Ferrying)
        || mUnit->IsUnitState(UNITSTATE_Attacking)
        || mUnit->IsUnitState(UNITSTATE_Building)
        || mUnit->IsUnitState(UNITSTATE_Repairing));

    if (wantsHoverFamily) {
      const bool wantsCircling =
        ((!air.HoverOverAttack && mUnit->GetFocusEntity() != nullptr
          && (mUnit->IsUnitState(UNITSTATE_Building) || mUnit->IsUnitState(UNITSTATE_Repairing)
            || mUnit->IsUnitState(UNITSTATE_Reclaiming) || mUnit->IsUnitState(UNITSTATE_Capturing)))
          || target.HasTarget());

      if (wantsCircling) {
        CalcCirclingOrientation(body, axes, steeringForce, target);
        turnGain *= air.CirclingTurnMult;
      } else {
        CalcHoverOrientation(body, fallbackVector, axes);
        mCombatStateTimeoutTick = 0;
      }
    } else {
      CalcWingedOrientation(referenceVector, controlVector, primaryVector, fallbackVector, axes, steeringForce, turnGain);
    }

    axes.OrthoNormalize();

    Wm3::Quaternionf desiredOrientation{};
    MatrixColumnsToQuatCanonical(&axes.vX, &desiredOrientation);

    // 0x006BE916..0x006BE966 conjugates `body.mOrientation` by keeping
    // `[ebx+2Ch]` (lane 0) and negating lanes 1-3, then 0x006BE927..0x006BEA13
    // multiplies with the conjugate as the LEFT operand: the scalar term is
    // `D0*c0 - D1*c1 - D2*c2 - D3*c3` and the next lane is
    // `D0*c1 + D1*c0 + D3*c2 - D2*c3`, whose cross-term signs are `c * D`.
    Wm3::Quaternionf relativeOrientation =
      MultiplyQuat(ConjugateQuat(body.mOrientation), desiredOrientation);
    // Shortest-arc hemisphere flip. 0x006BEA17/0x006BEA1A compare zero against
    // the value about to be stored in lane 0 - the scalar - and negate all
    // four lanes when it is below zero.
    if (relativeOrientation.w < 0.0f) {
      relativeOrientation = relativeOrientation * -1.0f;
    }

    Wm3::Vector3f rotationAxis{};
    float rotationAngle = 0.0f;
    QuatToAxisAndAngle(relativeOrientation, &rotationAxis, &rotationAngle);
    const Wm3::Vector3f rotationError{
      rotationAxis.x * rotationAngle, rotationAxis.y * rotationAngle, rotationAxis.z * rotationAngle
    };

    const Wm3::Vector3f velocityError{-body.mVelocity.x, -body.mVelocity.y, -body.mVelocity.z};

    const Wm3::Quaternionf bodyConjugateOrientation = ConjugateQuat(body.mOrientation);
    Wm3::Vector3f bodyLocalImpulse{};
    MultQuadVec(&bodyLocalImpulse, &body.mWorldImpulse, &bodyConjugateOrientation);
    const Wm3::Vector3f dampingTerm{
      -(body.mInvInertiaTensor.x * bodyLocalImpulse.x),
      -(body.mInvInertiaTensor.y * bodyLocalImpulse.y),
      -(body.mInvInertiaTensor.z * bodyLocalImpulse.z)
    };

    const float movementDamping = CalcAirMovementDampingFactor(controlVector);

    constexpr float kCarrierDockDistance = 40.0f;
    constexpr float kCarrierDockLiftVelocityScale = 1.25f;
    constexpr float kCarrierDockVelocityScale = 2.0f;

    bool useDockingBlend = (mCarrierEvent == kCarrierEventDescendToDeck);
    Entity* dockFocusEntity = nullptr;
    if (useDockingBlend) {
      dockFocusEntity = mUnit->GetFocusEntity();
      useDockingBlend = dockFocusEntity != nullptr;
      if (useDockingBlend) {
        const Wm3::Vec3f& unitPos = mUnit->GetPosition();
        const float dz = unitPos.z - dockFocusEntity->mVarDat.mCurTransform.pos_.z;
        const float dx = unitPos.x - dockFocusEntity->mVarDat.mCurTransform.pos_.x;
        useDockingBlend = std::sqrt((dz * dz) + (dx * dx)) < kCarrierDockDistance;
      }
    }

    float accelX;
    float accelY;
    float accelZ;
    if (useDockingBlend) {
      accelY = ((velocityError.y * kCarrierDockLiftVelocityScale) + steeringForce.y) * liftGain;
      accelX = ((velocityError.x * kCarrierDockVelocityScale) + steeringForce.x) * air.KMove;
      accelZ = ((velocityError.z * kCarrierDockVelocityScale) + steeringForce.z) * air.KMove;
    } else {
      accelX = (steeringForce.x * air.KMove) + (velocityError.x * movementDamping);
      accelY = (air.KLiftDamping * velocityError.y) + (steeringForce.y * liftGain);
      accelZ = (steeringForce.z * air.KMove) + (velocityError.z * movementDamping);
    }

    const Wm3::Vec3f& gravity = mUnit->SimulationRef->mPhysConstants->mGravity;
    const float mass = body.mMass;

    const Wm3::Vector3f force{
      (accelX - gravity.x) * mass, (accelY - gravity.y) * mass, (accelZ - gravity.z) * mass
    };

    const float torqueXRaw = (dampingTerm.x * air.KTurnDamping) + (rotationError.x * turnGain);
    const float torqueYRaw = (dampingTerm.y * air.KTurnDamping) + (rotationError.y * turnGain);
    const float torqueZRaw = (dampingTerm.z * air.KRollDamping) + (rotationError.z * rollGain);

    const Wm3::Vector3f torqueLocalScaled{
      torqueXRaw / body.mInvInertiaTensor.x, torqueYRaw / body.mInvInertiaTensor.y, torqueZRaw / body.mInvInertiaTensor.z
    };

    Wm3::Vector3f torqueWorld{};
    MultQuadVec(&torqueWorld, &torqueLocalScaled, &body.mOrientation);

    // TEMPORARY PROBE -- air force runaway triage, delete when resolved.
    {
      const float accelMag = std::sqrt((accelX * accelX) + (accelY * accelY) + (accelZ * accelZ));
      if (!std::isfinite(accelMag) || accelMag > 2000.0f) {
        static int sAirBlowCount = 0;
        if (sAirBlowCount++ < 24) {
          gpg::Warnf(
            "[AIRBLOW] unit=%p load=%.5f gains(turn=%.4f roll=%.4f lift=%.4f) dampMv=%.4f "
            "KMove=%.4f KLiftDamp=%.4f KTurnDamp=%.4f steer=(%.2f,%.2f,%.2f) vel=(%.2f,%.2f,%.2f) "
            "accel=(%.2f,%.2f,%.2f) mass=%.3f topSpeed=%.3f dock=%d wImp=(%.2f,%.2f,%.2f) "
            "rotErr=(%.3f,%.3f,%.3f) invI=(%.4f,%.4f,%.4f)",
            static_cast<void*>(mUnit), loadFactor, turnGain, rollGain, liftGain, movementDamping,
            air.KMove, air.KLiftDamping, air.KTurnDamping, steeringForce.x, steeringForce.y, steeringForce.z,
            body.mVelocity.x, body.mVelocity.y, body.mVelocity.z, accelX, accelY, accelZ, mass,
            mUnit->mInfoCache.mFormationTopSpeed, useDockingBlend ? 1 : 0,
            body.mWorldImpulse.x, body.mWorldImpulse.y, body.mWorldImpulse.z,
            rotationError.x, rotationError.y, rotationError.z,
            body.mInvInertiaTensor.x, body.mInvInertiaTensor.y, body.mInvInertiaTensor.z
          );
        }
      }
    }

    out->force = force;
    out->torque = torqueWorld;

    mForce = force;
    mTorque = Wm3::Vector3f{torqueXRaw, torqueYRaw, torqueZRaw};
  }

  /**
   * Address: 0x006BCDB0 (FUN_006BCDB0, Moho::CUnitMotion::ComputeAirCombatTactics)
   * Mangled: ?ComputeAirCombatTactics@CUnitMotion@Moho@@AAEXABV?$Vector3@M@Wm3@@ABVCAiTarget@2@AAV34@@Z
   *
   * What it does: see header.
   */
  void CUnitMotion::ComputeAirCombatTactics(
    const Wm3::Vector3f& currentHeading,
    const CAiTarget& target,
    Wm3::Vector3f& outDesiredVelocity
  )
  {
    constexpr float kAirCombatTightAlignCosine = 0.866f; // ~30 deg; sqrt(3)/2

    Unit* const unit = mUnit;
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const RUnitBlueprintAir& air = blueprint->Air;
    Sim* const sim = unit->SimulationRef;
    CRandomStream& randomStream = *sim->mRngState;
    const std::uint32_t curTick = sim->mCurTick;

    const UnitAttributes& attributes = unit->GetAttributes();
    const float maxAirSpeed = attributes.moveSpeedMult * air.MaxAirspeed;
    const bool useWholeMap = unit->ArmyRef->UseWholeMap();

    const Wm3::Vec3f targetPos = const_cast<CAiTarget&>(target).GetTargetPosGun(false);
    const Wm3::Vec3f unitPos = unit->GetPosition();

    const float dx = targetPos.x - unitPos.x;
    const float dy = targetPos.y - unitPos.y;
    const float dz = targetPos.z - unitPos.z;

    const float targetDist = std::sqrt((dx * dx) + (dz * dz) + (dy * dy));
    const float horzTargetDist = std::sqrt((dz * dz) + (dx * dx));

    Wm3::Vector3f targetDirNorm{0.0f, 0.0f, 0.0f};
    if (targetDist > 0.0f) {
      const float invDist = 1.0f / targetDist;
      targetDirNorm = Wm3::Vector3f{dx * invDist, dy * invDist, dz * invDist};
    }

    const float breakOffTrigger = attributes.breakOffTriggerMult * air.BreakOffTrigger;
    const float breakOffDist = attributes.breakOffDistanceMult * air.BreakOffDistance;
    const EAirCombatState combatState = mCombatState;

    const auto rollBreakOff = [&]() {
      mCombatState = ACS_BreakOff;
      const auto minTicks = static_cast<int>(std::ceil((breakOffDist / maxAirSpeed) * 10.0f));
      const auto maxTicks = static_cast<int>(static_cast<float>(minTicks) * air.RandomBreakOffDistanceMult);
      mCombatStateTimeoutTick = curTick + static_cast<std::uint32_t>(RandomUniformIntRange(minTicks, maxTicks, randomStream));
    };

    bool skipDecision = false;
    if (combatState == ACS_ReturnToMap) {
      if (!sim->mMapData->IsWithin(unit->mVarDat.mCurTransform.pos_, 5.0f, useWholeMap)) {
        skipDecision = true;
      }
    }

    Wm3::Vector3f horzTargetDirNorm{};
    bool isHeadingAlignedWithTarget = false;
    if (!skipDecision) {
      const Wm3::Vector3f horzTargetDirDenorm{targetDirNorm.x, 0.0f, targetDirNorm.z};
      Wm3::Vector3f::NormalizeInto(horzTargetDirDenorm, &horzTargetDirNorm);

      const float horzHeadingDot = (horzTargetDirNorm.x * currentHeading.x) + (horzTargetDirNorm.z * currentHeading.z)
        + (horzTargetDirNorm.y * currentHeading.y);

      const float alignThreshold = (combatState == ACS_CombatTurn) ? 0.0f : kAirCombatTightAlignCosine;
      isHeadingAlignedWithTarget = horzHeadingDot > alignThreshold;

      if (Entity* const resolvedForLayerCheck = const_cast<CAiTarget&>(target).GetEntity();
          resolvedForLayerCheck != nullptr && resolvedForLayerCheck->mVarDat.mLayerMask == LAYER_Air) {
        if (!sim->mMapData->IsWithin(unit->mVarDat.mCurTransform.pos_, 0.0f, useWholeMap)) {
          mCombatState = ACS_ReturnToMap;
          skipDecision = true;
        }
      }

      if (!skipDecision) {
        bool triggerBreakOff = false;
        if (combatState == ACS_Combat && breakOffTrigger > targetDist) {
          triggerBreakOff = true;
        } else if (air.BreakOffIfNearNewTarget != 0 && combatState == ACS_None && breakOffDist > horzTargetDist) {
          triggerBreakOff = true;
        } else if (combatState == ACS_NormalTurn && horzHeadingDot < 0.0f) {
          triggerBreakOff = true;
        }

        if (!triggerBreakOff) {
          const auto sustainedTurnThresholdTicks = static_cast<int>(std::floor(air.SustainedTurnThreshold * 10.0f));
          if (mSustainedTurnTicks > sustainedTurnThresholdTicks) {
            triggerBreakOff = true;
          }
        }

        if (triggerBreakOff) {
          rollBreakOff();
          skipDecision = true;
        }
      }

      if (!skipDecision) {
        const bool timeoutActive = mCombatStateTimeoutTick >= curTick;
        if (timeoutActive && (!isHeadingAlignedWithTarget || combatState == ACS_BreakOff)) {
          skipDecision = true;
        } else if (!isHeadingAlignedWithTarget) {
          bool rollNewTurn = true;
          if (timeoutActive || combatState == ACS_NormalTurn) {
            const float fullHeadingDot = (targetDirNorm.x * currentHeading.x) + (currentHeading.z * targetDirNorm.z)
              + (currentHeading.y * targetDirNorm.y);
            if (fullHeadingDot >= 0.0f) {
              rollNewTurn = false;
            } else if (combatState < ACS_NormalTurn || combatState > ACS_Realign) {
              rollNewTurn = false;
            }
          }

          if (rollNewTurn) {
            mCombatState = static_cast<EAirCombatState>(RandomUniformIntRange(ACS_CombatTurn, ACS_BreakOff, randomStream));
            const int minTicks = FloorSecondsToTicks(air.RandomMinChangeCombatStateTime);
            const int maxTicks = FloorSecondsToTicks(air.RandomMaxChangeCombatStateTime);
            mCombatStateTimeoutTick = curTick + static_cast<std::uint32_t>(RandomUniformIntRange(minTicks, maxTicks, randomStream));
          }
        } else {
          mCombatState = ACS_Combat;
          if (CAiTargetEntityIsAirLayer(target)) {
            Entity* const rawTargetEntity = target.targetEntity.GetObjectPtr();
            if (Wm3::Vector3f::Compare(&rawTargetEntity->mVarDat.mCurTransform.pos_, &rawTargetEntity->mVarDat.mLastTransform.pos_)) {
              // The entity's own orientation quaternion. This used to be
              // rebuilt lane by lane, because the lane was declared a plain
              // (x,y,z,w) `moho::Vector4f` over the w-first quaternion words it
              // actually stores; it is a `Wm3::Quatf` now.
              const Wm3::Quaternionf& targetOrientation = rawTargetEntity->mVarDat.mCurTransform.orient_;
              const Wm3::Vector3f targetForward = VAxes3(targetOrientation).vZ;
              const float facingDot = (targetForward.x * currentHeading.x) + (targetForward.z * currentHeading.z)
                + (targetForward.y * currentHeading.y);
              if (facingDot > 0.0f) {
                mCombatState = ACS_NormalTurn;
              }
            }
          }
        }
      }
    }

    switch (mCombatState) {
      case ACS_Combat:
      case ACS_NormalTurn: {
        unit->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_MakingAttackRun));

        Entity* const rawTargetEntity = target.targetEntity.GetObjectPtr();
        bool wroteBombDropVelocity = false;
        if (rawTargetEntity != nullptr && target.targetIsMobile) {
          if (Entity* const resolvedEntity = const_cast<CAiTarget&>(target).GetEntity(); resolvedEntity != nullptr) {
            float precision = 1.0f;
            if (air.PredictAheadForBombDrop > 0.0f && resolvedEntity->mVarDat.mLayerMask != LAYER_Air) {
              precision = air.PredictAheadForBombDrop;
            }
            Unit* const targetAsUnit = resolvedEntity->IsUnit();
            Wm3::Vector3f predictScratch{};
            const Wm3::Vector3f* const predicted = targetAsUnit->PredictAheadBomb(&predictScratch, precision);
            outDesiredVelocity.x = predicted->x - unitPos.x;
            outDesiredVelocity.y = predicted->y - unitPos.y;
            outDesiredVelocity.z = predicted->z - unitPos.z;
            wroteBombDropVelocity = true;
          }
        }
        if (!wroteBombDropVelocity) {
          outDesiredVelocity.x = targetDirNorm.x * targetDist;
          outDesiredVelocity.y = targetDirNorm.y * targetDist;
          outDesiredVelocity.z = targetDirNorm.z * targetDist;
        }
        outDesiredVelocity.y = CalcDesiredTargetElevation(target, outDesiredVelocity);

        float speedLimit = maxAirSpeed;
        if (mCombatState == ACS_NormalTurn && CAiTargetEntityIsAirLayer(target)) {
          Entity* const rawEntity2 = target.targetEntity.GetObjectPtr();
          if (!Wm3::Vector3f::Compare(&rawEntity2->mVarDat.mCurTransform.pos_, &rawEntity2->mVarDat.mLastTransform.pos_)) {
            speedLimit = (air.MinAirspeed > targetDist) ? air.MinAirspeed : targetDist;
          }
        }
        (void)VecSetLength(&outDesiredVelocity, speedLimit);
        break;
      }

      case ACS_CombatTurn:
      case ACS_CombatTurnB: {
        ++mSustainedTurnTicks;
        outDesiredVelocity.x = targetDirNorm.x * targetDist;
        outDesiredVelocity.y = targetDirNorm.y * targetDist;
        outDesiredVelocity.z = targetDirNorm.z * targetDist;
        outDesiredVelocity.y = CalcDesiredTargetElevation(target, outDesiredVelocity);
        (void)VecSetLength(&outDesiredVelocity, air.MinAirspeed);
        break;
      }

      case ACS_Realign: {
        ++mSustainedTurnTicks;
        outDesiredVelocity.x = targetDirNorm.x * targetDist;
        outDesiredVelocity.y = targetDirNorm.y * targetDist;
        outDesiredVelocity.z = targetDirNorm.z * targetDist;
        outDesiredVelocity.y = CalcDesiredTargetElevation(target, outDesiredVelocity);
        (void)VecSetLength(&outDesiredVelocity, maxAirSpeed);
        break;
      }

      case ACS_BreakOff: {
        unit->UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_MakingAttackRun));
        mSustainedTurnTicks = 0;
        outDesiredVelocity.x = currentHeading.x * maxAirSpeed;
        outDesiredVelocity.y = currentHeading.y * maxAirSpeed;
        outDesiredVelocity.z = currentHeading.z * maxAirSpeed;
        outDesiredVelocity.y = CalcDesiredTargetElevation(target, outDesiredVelocity);
        return;
      }

      case ACS_ReturnToMap: {
        mSustainedTurnTicks = 0;
        const Wm3::Vec3f unitPosNow = unit->GetPosition();
        const Wm3::Vec3f centerOfMap = sim->CenterOfMap();
        outDesiredVelocity.x = centerOfMap.x - unitPosNow.x;
        outDesiredVelocity.y = centerOfMap.y - unitPosNow.y;
        outDesiredVelocity.z = centerOfMap.z - unitPosNow.z;
        outDesiredVelocity.y = CalcDesiredTargetElevation(target, outDesiredVelocity);
        (void)VecSetLength(&outDesiredVelocity, maxAirSpeed);
        break;
      }

      default:
        return;
    }
  }

  /**
   * Address: 0x006BEE50 (FUN_006BEE50, Moho::CUnitMotion::CalcMoveAir)
   * Mangled: ?CalcMoveAir@CUnitMotion@Moho@@AAEXAAVVTransform@2@PAM@Z
   *
   * What it does: see header.
   */
  void CUnitMotion::CalcMoveAir(VTransform& outTransform, float* const /*outMoveDistance*/)
  {
    // EUnitMotionCarrierEvent value 2: dropped from / descending to a
    // carrier's deck (same local-constant convention as ComputeAirControl).
    constexpr auto kCarrierEventDescendToDeck = static_cast<EUnitMotionCarrierEvent>(2);
    constexpr float kFixedIntegrationDt = 0.1f;

    Unit* const unit = mUnit;
    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const RUnitBlueprintAir& air = blueprint->Air;
    Sim* const sim = unit->SimulationRef;
    STIMap* const mapData = sim->mMapData;
    SPhysBody* const physBody = unit->GetPhysBody();
    const bool useWholeMap = unit->ArmyRef->UseWholeMap();

    // Horizontal (Y=0) forward heading extracted from the incoming
    // orientation - used both as the phase-1 fallback formation vector and
    // as the "current heading" reference for combat tactics / turn events.
    Wm3::Vector3f headingVector = VAxes3(outTransform.orient_).vZ;
    headingVector.y = 0.0f;
    Wm3::Vector3f::Normalize(&headingVector);

    // 0x006BF20D-0x006BF24A zeroes all six floats of the local SControlOutput
    // before either branch runs, and the shared tail integrates from *this*
    // local (force at frame 0x94/0x98/0x9C, torque at 0xA0) - never from
    // `mForce`/`mTorque`. That distinction matters: `ComputeAirControl`
    // writes `out->torque` as the inertia-scaled, world-space torque, while it
    // stashes the raw body-local torque in `mTorque` for
    // `CalcMoveBallistic`. Feeding `mTorque` to the angular integrator
    // spins the airframe on an unscaled body-local axis.
    SControlOutput control{};

    // Fliers that cannot fly in water measure their elevation against the
    // water surface, not the sea bed. 0x006BF041 `cmp byte [ecx+36Ah], 0`
    // tests `Air.FlyInWater` (Air at blueprint+0x368, FlyInWater at +0x02);
    // only when it is clear does the binary fall through to
    //   0x006BF074  80 BF 34 15 00 00 00     cmp    byte [edi+1534h], 0
    //   0x006BF083  F3 0F 10 8F 38 15 00 00  movss  xmm1, [edi+1538h]
    //   0x006BF08B  0F 2F C8 / 76 03         comiss xmm1, xmm0 / jbe
    //   0x006BF091  0F 28 C1                 movaps xmm0, xmm1
    // i.e. clamp the sample up to `mWaterElevation` when water is enabled and
    // stands above the terrain. Without it `mCurElevation` reads too large over
    // water, so `(mCurElevation - mNewElevation) < 0.1f` never holds and a
    // flier never settles there.
    float sampleElevation = mapData->GetHeightField()->GetElevation(outTransform.pos_.x, outTransform.pos_.z);
    if (air.FlyInWater == 0u && mapData->mWaterEnabled != 0u && mapData->mWaterElevation > sampleElevation) {
      sampleElevation = mapData->mWaterElevation;
    }

    Wm3::Vector3f desiredVelocity{
      mTargetPosition.x - outTransform.pos_.x, 0.0f, mTargetPosition.z - outTransform.pos_.z
    };
    const float horizontalDistance = std::sqrt((desiredVelocity.x * desiredVelocity.x) + (desiredVelocity.z * desiredVelocity.z));
    const float topSpeedTarget =
      mAlwaysUseTopSpeed ? unit->mInfoCache.mFormationTopSpeed : std::min(horizontalDistance, unit->mInfoCache.mFormationTopSpeed);
    (void)VecSetLength(&desiredVelocity, topSpeedTarget);

    // The fourth vector `ComputeAirControl` takes, and the one this recovery
    // had no local for at all: the frame's `{a1.y, a1.z, var_AC}` triple, handed
    // over in EAX at 0x006BFE15. It is whatever this beat decided the airframe
    // should fall back to when it is too slow or too close to steer -- the
    // formation vector on the near/landing path, and a snapshot of the raw
    // steering vector on the far path.
    Wm3::Vector3f fallbackVector{};

    bool enteredLandingPhase = false;

    // 0x006BF150 `mov ecx,[ebp+0]` / `cmp [ecx+120h], esi` -- the guard reads
    // the UNIT's layer, not the motion's. Unit's Entity base sits at +0x08 and
    // Entity::mCurrentLayer at +0x118, so +0x120 from a Unit* is that field.
    if (!unit->IsDead() || (unit->mVarDat.mLayerMask != LAYER_Air && !ShouldHoverInsteadOfLand())) {
      if (horizontalDistance <= air.StartTurnDistance || mCarrierEvent == kCarrierEventDescendToDeck) {
        enteredLandingPhase = (mLayer != LAYER_None && mLayer != LAYER_Air);
        const auto autoLandTicks = static_cast<std::int32_t>(air.AutoLandTime * 10.0f);

        if (!enteredLandingPhase && mPreparationTick > 0 && autoLandTicks > 0) {
          const std::uint32_t curTick = sim->mCurTick;
          if (curTick > static_cast<std::uint32_t>(autoLandTicks) + static_cast<std::uint32_t>(mPreparationTick)) {
            if (mHeight == std::numeric_limits<float>::infinity()) {
              gpg::Rect2f skirt{};
              if (unit->PrepareMove(0, &mTargetPosition, &skirt, useWholeMap)) {
                if (unit->IsUnitState(UNITSTATE_CannotFindPlaceToLand)) {
                  unit->UnitStateMask &= ~(1ull << UNITSTATE_CannotFindPlaceToLand);
                  unit->UpdateSpeedThroughStatus();
                }

                const SFootprint& footprint = unit->GetFootprint();
                COORDS_ToGridRect(&mReservation, SCoordsVec2{mTargetPosition.x, mTargetPosition.z}, footprint);
                unit->ReserveOgridRect(mReservation);

                enteredLandingPhase = true;
                const float landElevation = mapData->GetHeightField()->GetElevation(mTargetPosition.x, mTargetPosition.z);
                const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;
                mLayer = (landElevation <= waterElevation) ? LAYER_Water : LAYER_Land;
              } else {
                mPreparationTick = static_cast<std::int32_t>(curTick);
                unit->UnitStateMask |= (1ull << UNITSTATE_CannotFindPlaceToLand);
                unit->UpdateSpeedThroughStatus();
              }
            } else {
              if (unit->IsUnitState(UNITSTATE_CannotFindPlaceToLand)) {
                unit->UnitStateMask &= ~(1ull << UNITSTATE_CannotFindPlaceToLand);
                unit->UpdateSpeedThroughStatus();
              }
              enteredLandingPhase = true;
              mLayer = LAYER_Land;
            }
          }
        }

        // Formation-vector selection, 0x006BF685..0x006BF732. The chosen vector
        // is what this branch leaves in `fallbackVector`: a live formation
        // vector if the unit has one (which is also stored back into
        // `mFormationVec`), else the stored lane normalized, else the phase-1
        // heading. `GetFormationVector` returns by value straight into the
        // local -- `lea ebx, [esp+a1.y]` at 0x006BF688 is its return slot.
        fallbackVector = unit->GetFormationVector();
        if (Wm3::Vector3f::Compare(&fallbackVector, &Wm3::Vector3f::ZERO)) {
          mFormationVec = fallbackVector;
        } else if (Wm3::Vector3f::Compare(&mFormationVec, &Wm3::Vector3f::ZERO)) {
          // 0x006BF6ED normalizes into a scratch (esi) from the member (edi);
          // `mFormationVec` itself is left alone.
          Wm3::Vector3f::NormalizeInto(mFormationVec, &fallbackVector);
        } else {
          fallbackVector = headingVector;
        }

        if (enteredLandingPhase) {
          // 0x006BF740: `or dword ptr [eax+4A0h], 400h` -- bit 10 of the LOW
          // state dword, UNITSTATE_MovingDown. Not BlockCommandQueue (42),
          // which lives in the high dword and which this function never
          // writes at all. Setting it here stopped
          // IAiCommandDispatchImpl::TaskTick from dispatching anything to the
          // aircraft -- 0x00598F99 tests state 42 and bails -- so it could
          // never be given a move order and never left the ground.
          unit->UnitStateMask |= (1ull << UNITSTATE_MovingDown);
          if (mHeight == std::numeric_limits<float>::infinity()) {
            if (ShouldHoverInsteadOfLand() || mVertEvent == UMVE_Hover) {
              mNewElevation = air.TransportHoverHeight;
            } else if (horizontalDistance < 0.5f || mVertEvent == UMVE_Bottom) {
              mNewElevation = 0.0f;
            } else {
              mNewElevation = GetElevation() * 0.5f;
            }
          } else {
            mNewElevation = mHeight - sampleElevation;
          }
        } else {
          mNewElevation = GetElevation();
          // 0x006BF7E3: `and [eax+4A0h], 0FFFFF7FFh` clears low bit 11,
          // UNITSTATE_MovingUp.
          unit->UnitStateMask &= ~(1ull << UNITSTATE_MovingUp);
        }
      } else {
        // 0x006BF3E9..0x006BF409: too far to be landing, so the fallback is a
        // snapshot of the steering vector taken here -- before the look-ahead
        // shaping below narrows it and before the elevation term fills in y.
        fallbackVector = desiredVelocity;

        mNewElevation = GetElevation();
        // 0x006BF422 / 0x006BF43B clear low bits 11 and 10 -- MovingUp then
        // MovingDown. Something far from its target is neither climbing to
        // reach it nor descending onto it.
        unit->UnitStateMask &= ~(1ull << UNITSTATE_MovingUp);
        unit->UnitStateMask &= ~(1ull << UNITSTATE_MovingDown);
        if (unit->IsUnitState(UNITSTATE_CannotFindPlaceToLand)) {
          unit->UnitStateMask &= ~(1ull << UNITSTATE_CannotFindPlaceToLand);
          unit->UpdateSpeedThroughStatus();
        }
      }

      // ---- Terrain/water look-ahead elevation shaping ----------------------
      const float maxAirSpeed = unit->GetAttributes().moveSpeedMult * air.MaxAirspeed * 5.0f;
      const float lookAheadSpeed = std::min(maxAirSpeed, horizontalDistance);

      float airLookAheadMult = 1.0f;
      (void)ReadSimConVarValue<float>(sim, "AirLookAheadMult", airLookAheadMult);
      float lookAheadElevation =
        mapData->LookAheadForMaxTerrain(outTransform.pos_, air.FlyInWater != 0, airLookAheadMult * lookAheadSpeed);
      const float liftClearance = std::max(lookAheadElevation - outTransform.pos_.y, 0.0f);

      if (liftClearance > air.LiftFactor && lookAheadSpeed > 1.0f) {
        const float halfSpeed = lookAheadSpeed * 0.5f;
        float airLookAheadMult2 = 1.0f;
        (void)ReadSimConVarValue<float>(sim, "AirLookAheadMult", airLookAheadMult2);
        const float lookAhead2 =
          mapData->LookAheadForMaxTerrain(outTransform.pos_, air.FlyInWater != 0, halfSpeed * airLookAheadMult2) * 1.5f;
        const float liftClearance2 = std::max(lookAhead2 - outTransform.pos_.y, 0.0f);
        const float shrink = std::max(0.2f, (halfSpeed - liftClearance2) / halfSpeed);
        desiredVelocity.x *= shrink * shrink;
        desiredVelocity.z *= shrink * shrink;
      }

      float band = air.LiftFactor * 0.1f;
      if (mTargetElevation > lookAheadElevation && !enteredLandingPhase) {
        band *= 0.5f;
      }
      const float upperBound = std::min(mTargetElevation + band, lookAheadElevation);
      const float lowerBound = mTargetElevation - band;
      mTargetElevation = std::max(lowerBound, upperBound);

      mCurElevation = outTransform.pos_.y - sampleElevation;
      desiredVelocity.y = (mTargetElevation + mNewElevation) - outTransform.pos_.y;

      // These are MINIMUM descent rates, not maximums -- both arms store the
      // constant when the computed value compares *greater* than it:
      //
      //   0x006BFA5F  movss  xmm1, [esp+28h]          ; desiredVelocity.y
      //   0x006BFA65  comiss xmm1, xmm0               ; xmm0 = [0x00E4F754] = -3.0
      //   0x006BFA68  jbe    ...                      ; y <= -3.0 -> leave alone
      //   0x006BFA6A  movss  [esp+28h], xmm0          ; else y = -3.0
      //
      //   0x006BFA78  mulss  xmm0, [0x00E4F724]       ; * 0.5
      //   0x006BFA88  comiss xmm0, xmm1               ; xmm1 = [0x00E4F9D4] = -0.25
      //   0x006BFA8B  jbe    0x006BFA6A               ; t <= -0.25 -> store t
      //   0x006BFA8D  movss  [esp+28h], xmm1          ; else y = -0.25
      //
      // So each is `min`, and the constants were read out of the PE. With
      // `max` the sense inverted twice over: a shallow descent was slowed to
      // the floor value instead of being pushed down to it, and a steep one
      // was capped at 3.0/tick instead of being left alone. A transport that
      // should drop at 3 units a tick crawled.
      if (enteredLandingPhase && desiredVelocity.y < 0.0f) {
        if (unit->IsInCategory("TRANSPORTATION")) {
          desiredVelocity.y = std::min(desiredVelocity.y, -3.0f);
        } else {
          desiredVelocity.y = std::min(desiredVelocity.y * 0.5f, -0.25f);
        }
      }

      // ---- Combat-state layer/vertical-event resolution --------------------
      if (mCombatState == ACS_None) {
        if (enteredLandingPhase
            && (mNewElevation == 0.0f || mHeight != std::numeric_limits<float>::infinity() || ShouldHoverInsteadOfLand())) {
          if (horizontalDistance < 0.5f && ((mCurElevation - mNewElevation) < 0.1f || unit->mVarDat.mLayerMask == mLayer)) {
            mReservation = gpg::Rect2i{};
            unit->FreeOgridRect();
            unit->SetCurrentLayer(mLayer);
            // 0x006BFB5C / 0x006BFB75: low bits 11 and 10 again -- it has
            // arrived, so it is neither climbing nor descending.
            unit->UnitStateMask &= ~(1ull << UNITSTATE_MovingUp);
            unit->UnitStateMask &= ~(1ull << UNITSTATE_MovingDown);

            if (!ShouldHoverInsteadOfLand()) {
              SetMotionVertEvent(UMVE_Bottom);
              mTargetPosition = unit->GetPosition();
              mPreviousVelocity = physBody->mVelocity;
              physBody->mVelocity = Wm3::Vector3f::ZERO;
              physBody->mWorldImpulse = Wm3::Vector3f::ZERO;
              return; // binary returns here without ever writing outTransform.
            }
            SetMotionVertEvent(UMVE_Hover);
          }
        } else {
          if (mVertEvent == UMVE_Bottom || mVertEvent == UMVE_Hover) {
            // 0x006BFC53: `or [eax+4A0h], 800h` -- low bit 11,
            // UNITSTATE_MovingUp. Coming off a deck or out of a hover is a
            // climb.
            unit->UnitStateMask |= (1ull << UNITSTATE_MovingUp);
          }

          if (mNewElevation > 0.0f && mCurElevation < mNewElevation * 0.5f) {
            const float bodySpeed = Wm3::Vector3f::Length(physBody->mVelocity);
            if (unit->mInfoCache.mFormationTopSpeed * 0.08f > bodySpeed) {
              const float ratio = std::min(mCurElevation / mNewElevation, 1.0f);
              desiredVelocity.x *= ratio;
              desiredVelocity.z *= ratio;
            }
          }
        }
      }
      unit->UnitStateMask &= ~(1ull << UNITSTATE_MakingAttackRun);

      // ---- Steering / combat-target / motion-event dispatch ----------------
      CAiTarget combatTarget{};
      if (CAiAttackerImpl* const attacker = unit->AiAttacker) {
        if (CAiTarget* const desired = attacker->GetDesiredTarget()) {
          combatTarget = *desired;
        }
        if (combatTarget.HasTarget() && attacker->CanAttackTarget(&combatTarget) && air.Winged) {
          ComputeAirCombatTactics(headingVector, combatTarget, desiredVelocity);
        }
      }
      if (!combatTarget.HasTarget()) {
        mSustainedTurnTicks = 0;
        mCombatState = ACS_None;
      }

      // Argument order read off the pushes at 0x006BFDEC..0x006BFE19. Stack
      // args, lowest address first, are `this`, the body, `desiredVelocity`,
      // its normalization, and `headingVector`; the fallback lane travels in
      // EAX. So the desired direction is the *primary* vector and the nose is
      // the *reference* -- which is what makes the airframe steer. Handing the
      // heading to both slots, as this did, told CalcWingedOrientation the
      // aircraft already pointed where it wanted to: `selectedVector` came back
      // as the current heading, `vZ` with it, the turn delta collapsed to zero,
      // and nothing ever asked the airframe to rotate.
      const Wm3::Vector3f desiredVelocityNorm = Wm3::Vector3f::NormalizeOrZero(desiredVelocity);
      ComputeAirControl(
        *physBody, fallbackVector, desiredVelocity, desiredVelocityNorm, headingVector, &control, combatTarget
      );

      // Turn-sharpness classification, 0x006BFE28-0x006BFF22. The thresholds
      // and their senses are read off the two compares; both constants come
      // from the PE:
      //
      //   0x006BFEEB  movss  xmm1, [0x00E4F724]   ; = 0.5
      //   0x006BFEF3  comiss xmm1, xmm0           ; 0.5 vs dot
      //   0x006BFEF8  jbe    0x6BFF06             ;   0.5 <= dot -> next test
      //   0x006BFEFA  mov    eax, 2               ;   dot <  0.5 -> SharpTurn
      //   0x006BFF06  comiss xmm0, [0x00E4F99C]   ; dot vs 0.95
      //   0x006BFF0D  jbe    0x6BFF18             ;   dot <= 0.95 -> Turn
      //   0x006BFF0F  xor    eax, eax             ;   dot >  0.95 -> Straight
      //   0x006BFF18  mov    eax, 1               ; Turn
      //
      // What was here read `> 0.5 -> Straight`, `> -0.05 -> Right`, else
      // `Left`, which inverts the 0.5 test, invents -0.05 (no such constant is
      // loaded), and drops 0.95 entirely. Combined with the old enum order it
      // reported "SharpTurn" for an aircraft flying straight at its goal and
      // "Straight" for one pointing away from it.
      if (horizontalDistance > air.StartTurnDistance) {
        Wm3::Vector3f flatDesired{desiredVelocity.x, 0.0f, desiredVelocity.z};
        Wm3::Vector3f::Normalize(&flatDesired);
        if (Wm3::Vector3f::LengthSq(headingVector) > 0.000001f && Wm3::Vector3f::LengthSq(flatDesired) > 0.000001f) {
          const float turnDot = (headingVector.x * flatDesired.x) + (headingVector.z * flatDesired.z) + (headingVector.y * flatDesired.y);
          if (turnDot < 0.5f) {
            SetMotionTurnEvent(UMTE_SharpTurn);
          } else if (turnDot > 0.95f) {
            SetMotionTurnEvent(UMTE_Straight);
          } else {
            SetMotionTurnEvent(UMTE_Turn);
          }
        }
      } else {
        // 0x006BFE2F `jbe 0x6BFF24` -- inside StartTurnDistance the event is
        // reset to Straight. MSVC inlined this one call (0x006BFF24-0x006BFF50,
        // itself hot-patched at 0x006BFF2C), folding `table[0]` into the
        // literal `push 0xF58374`. Without it a flier keeps whichever turn
        // event its last long leg left behind for the rest of its life.
        SetMotionTurnEvent(UMTE_Straight);
      }

      const float groundSpeed = std::sqrt((physBody->mVelocity.x * physBody->mVelocity.x) + (physBody->mVelocity.z * physBody->mVelocity.z));

      if (unit->IsUnitState(UNITSTATE_MovingDown)) {
        SetMotionVertEvent(UMVE_Down);
      } else if (unit->IsUnitState(UNITSTATE_MovingUp)) {
        SetMotionVertEvent(UMVE_Up);
      } else if (mVertEvent != UMVE_Hover) {
        // 0x006BFFB9 is `xor eax, eax`, not a literal 1: the event is UMVE_Top.
        // Level flight has no vertical event, and the UMVE_Hover guard just above
        // is what keeps a deliberate hover from being cleared by it.
        SetMotionVertEvent(UMVE_Top);
      }

      if (horizontalDistance > air.StartTurnDistance || mAlwaysUseTopSpeed) {
        SetMotionHorzEvent(
          (groundSpeed > unit->mInfoCache.mFormationTopSpeed * 0.08f) ? kUnitMotionHorzEventTopSpeed : kUnitMotionHorzEventCruising
        );
      } else if (mCombatState == ACS_None) {
        SetMotionHorzEvent(
          (unit->mInfoCache.mFormationTopSpeed * 0.005f <= groundSpeed) ? kUnitMotionHorzEventStopping : kUnitMotionHorzEventStopped
        );
      } else {
        SetMotionHorzEvent(kUnitMotionHorzEventCruising);
      }
    } else {
      // ---- Dead / not-flying: force LAYER_Air + UMS_Ballistic tumble -------
      // 0x006BF16D `mov eax,[edx+120h]` then 0x006BF178 `mov [edx+118h], esi`
      // with edx advanced to the Entity subobject at +0x08 -- both halves are
      // `unit->mVarDat.mLayerMask`, not the motion's `mLayer`. An exhaustive scan
      // for writes to `mLayer` ([ebp+0x74]) finds exactly three, all in the
      // preparation block, so this branch never touches it. Writing `mLayer`
      // here both fabricated that write and dropped the real one, and `mLayer`
      // is one half of the landing arrival test.
      const ELayer previousLayer = unit->mVarDat.mLayerMask;
      unit->mVarDat.mLayerMask = LAYER_Air;
      if (previousLayer != LAYER_Air) {
        const char* oldLayerName =
          (static_cast<std::uint32_t>(previousLayer) > static_cast<std::uint32_t>(LAYER_Orbit)) ? "" : Entity::LayerToString(previousLayer);
        const char* newLayerName = Entity::LayerToString(LAYER_Air);
        unit->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
      }

      if (mMotionState != kUnitMotionStateBallistic) {
        const EUnitMotionState previousState = mMotionState;
        mMotionState = kUnitMotionStateBallistic;
        const char* oldStateName = UnitMotionStateToScriptString(previousState);
        const char* newStateName = UnitMotionStateToScriptString(kUnitMotionStateBallistic);
        unit->CallbackStr("OnMotionStateChange", &newStateName, &oldStateName);
      }

      // Random per-axis torque impulse, clamped to [0.25, 4.0] against
      // 1/mInvInertiaTensor, rotated by the current orientation, and stashed
      // as mTorque for CalcMoveBallistic's later impulse step.
      CRandomStream& randomStream = *sim->mRngState;
      const auto clampAxis = [](const float invInertia) {
        return std::clamp(std::min(invInertia, 4.0f), 0.25f, 4.0f);
      };
      const float halfRangeX = clampAxis(physBody->mInvInertiaTensor.x);
      const float halfRangeY = clampAxis(physBody->mInvInertiaTensor.y);
      const float halfRangeZ = clampAxis(physBody->mInvInertiaTensor.z);
      const Wm3::Vector3f randomAngularAccel{
        RandomUniformIntRange(static_cast<int>(-halfRangeX * 1000.0f), static_cast<int>(halfRangeX * 1000.0f), randomStream)
          / (1000.0f * physBody->mInvInertiaTensor.x),
        RandomUniformIntRange(static_cast<int>(-halfRangeY * 1000.0f), static_cast<int>(halfRangeY * 1000.0f), randomStream)
          / (1000.0f * physBody->mInvInertiaTensor.y),
        RandomUniformIntRange(static_cast<int>(-halfRangeZ * 1000.0f), static_cast<int>(halfRangeZ * 1000.0f), randomStream)
          / (1000.0f * physBody->mInvInertiaTensor.z),
      };
      MultQuadVec(&mTorque, &randomAngularAccel, &physBody->mOrientation);
    }

    // ---- Shared tail: physics integration + layer + writeback ----
    // 0x006C0073-0x006C0186: both branches land here, and the dead/ballistic
    // one arrives with `control` still zeroed - it contributes no force and no
    // torque this beat, having handed its tumble to `mTorque` for
    // `CalcMoveBallistic` to pick up on the next.
    //
    // 0x006C0073-0x006C0093 copies the pre-integration velocity into
    // `mPreviousVelocity` (+0xB4) every beat, not just on the landing return.
    mPreviousVelocity = physBody->mVelocity;

    // TEMPORARY PROBE -- angular runaway triage. Snapshots mWorldImpulse around
    // its writer so the growth can be attributed. Delete when resolved.
    const Wm3::Vector3f wImpBeforeIntegrate = physBody->mWorldImpulse;

    physBody->IntegrateFreefallStep(control.force, kFixedIntegrationDt, control.torque);

    {
      const float pre = Wm3::Vector3f::Length(wImpBeforeIntegrate);
      const float post = Wm3::Vector3f::Length(physBody->mWorldImpulse);
      if (!std::isfinite(post) || post > 1000.0f || (pre > 1.0f && post > (pre * 1.3f))) {
        static int sSpinCount = 0;
        if (sSpinCount++ < 40) {
          gpg::Warnf(
            "[AIRSPIN] unit=%p |wImp| pre=%.3f afterIntegrate=%.3f (integrateGain=%.3f) "
            "torque=(%.1f,%.1f,%.1f) invI=(%.6f,%.6f,%.6f) mass=%.2f curElev=%.2f speed=%.2f",
            static_cast<void*>(unit), pre, post, (pre > 0.0f) ? (post / pre) : 0.0f,
            control.torque.x, control.torque.y, control.torque.z,
            physBody->mInvInertiaTensor.x, physBody->mInvInertiaTensor.y, physBody->mInvInertiaTensor.z,
            physBody->mMass, mCurElevation, Wm3::Vector3f::Length(physBody->mVelocity)
          );
        }
      }
    }

    // TEMPORARY PROBE -- "collides with ground then flees at insane speed"
    // triage. Reports the tick's whole velocity history so the runaway can be
    // attributed to the control force or the freefall step. Delete when
    // resolved.
    {
      const float postSpeed = Wm3::Vector3f::Length(physBody->mVelocity);
      const float preSpeed = Wm3::Vector3f::Length(mPreviousVelocity);
      if (!std::isfinite(postSpeed) || postSpeed > 250.0f) {
        static int sFleeCount = 0;
        if (sFleeCount++ < 24) {
          gpg::Warnf(
            "[AIRFLEE] unit=%p preSpeed=%.2f postSpeed=%.2f pre=(%.2f,%.2f,%.2f) "
            "post=(%.2f,%.2f,%.2f) force=(%.1f,%.1f,%.1f) torque=(%.1f,%.1f,%.1f) "
            "pos=(%.1f,%.1f,%.1f) curElev=%.2f tgtElev=%.2f newElev=%.2f layer=%d vert=%d",
            static_cast<void*>(unit), preSpeed, postSpeed,
            mPreviousVelocity.x, mPreviousVelocity.y, mPreviousVelocity.z,
            physBody->mVelocity.x, physBody->mVelocity.y, physBody->mVelocity.z,
            control.force.x, control.force.y, control.force.z,
            control.torque.x, control.torque.y, control.torque.z,
            physBody->mPos.x, physBody->mPos.y, physBody->mPos.z,
            mCurElevation, mTargetElevation, mNewElevation,
            static_cast<int>(mLayer), static_cast<int>(mVertEvent)
          );
        }
      }
    }

    // No terrain collision for a flier: every FAF build, 2025.7.1 included,
    // hot-patches it out of this tail, and FAF's scripts depend on that.
    //
    // The GPG build called HandleGroundCollision (0x006BC460) here, and
    // latched the landing layer when it reported contact inside 0.5 of the
    // goal during the landing phase. The six patched bytes were
    // `push ebp / call 0x006BC460` (the callee ends `ret 4`); what they fed
    // survives, unreachable, right behind the patch:
    //
    //   0x006C018B  EB 2E 90 90 90 90        jmp 0x006C01BB   ; FAF
    //   0x006C0191  84 C0                    test  al, al      ; ground hit
    //   0x006C0195  80 7C 24 17 00           cmp   byte [esp+17h], 0  ; landing phase
    //   0x006C019C  F3 0F 10 05 24 F7 E4 00  movss xmm0, [0x00E4F724]  ; 0.5
    //   0x006C01A4  0F 2F 44 24 44           comiss xmm0, [esp+44h]    ; distance
    //   0x006C01B4  E8 37 AE FB FF           call  Entity::SetCurrentLayer(mLayer)
    //
    // Nothing else in the image references 0x006BC460 -- no rel32 call or jump
    // and no pointer in any section, FAF's `.exxt` included -- so the shipped
    // engine never runs it. (The call at 0x006C0186 is the tail of the freefall
    // step above, `SPhysBody::IntegrateAngularImpulse`, not this one.)
    //
    // Restoring the GPG call is not neutral. FAF's Cybran build drones
    // (URA0001O/URA0002O/URA0003O, `Air.CanFly = true`) call
    // `SetCollisionShape('None')` in OnCreate, and HandleGroundCollision reads
    // `CollisionExtents` unguarded through Entity::GetTerrainCollisionGeom
    // (0x0067AA57). URA0001O cruises at Elevation 2 on a 1x1 footprint, right
    // on HandleGroundCollision's `2 * max(SizeX, SizeZ)` early-out, so the sim
    // thread crashed on the first tick it sat at or below 2.0.
    if (mVertEvent != UMVE_Hover) {
      const ELayer previousLayer2 = unit->mVarDat.mLayerMask;
      unit->mVarDat.mLayerMask = LAYER_Air;
      if (previousLayer2 != LAYER_Air) {
        const char* oldLayerName =
          (static_cast<std::uint32_t>(previousLayer2) > static_cast<std::uint32_t>(LAYER_Orbit)) ? "" : Entity::LayerToString(previousLayer2);
        const char* newLayerName = Entity::LayerToString(LAYER_Air);
        unit->CallbackStr("OnLayerChange", &newLayerName, &oldLayerName);
      }
    }

    VTransform builtTransform{};
    BuildTransformFromSPhysBody(&builtTransform, physBody);
    outTransform.orient_ = builtTransform.orient_;
    outTransform.pos_ = builtTransform.pos_;
  }

  /**
   * Address: 0x006B9D10 (FUN_006B9D10, Moho::CUnitMotion::MotionTick)
   * Mangled: ?MotionTick@CUnitMotion@Moho@@QAE?AW4ETaskStatus@2@XZ
   *
   * What it does: see header.
   */
  ETaskStatus CUnitMotion::MotionTick()
  {
    // TEMPORARY PROBE -- inert move order triage, delete when resolved.
    {
      static int sCount = 0;
      if ((sCount++ % 100) == 0) {
        gpg::Warnf("[MOTDIAG] CUnitMotion::MotionTick unit=%p state=%d target=(%.1f,%.1f,%.1f) n=%d",
                   static_cast<void*>(mUnit), static_cast<int>(mMotionState), mTargetPosition.x, mTargetPosition.y,
                   mTargetPosition.z, sCount);
      }
    }
    if (mUnit->IsBeingBuilt()) {
      if (mUnit->mVarDat.mLayerMask == LAYER_Sub) {
        SetMotionVertEvent(UMVE_Bottom);
      }
      return TASKSTATUS_Wait;
    }

    VTransform transform = mUnit->GetTransform();

    if (Wm3::Vector3f::LengthSq(mVelocity) > 0.000001f || mProcessSurfaceCollision) {
      ProcessSurfaceCollisionFromLastMove();
    }

    CUnitCommandQueue* const commandQueue = mUnit->CommandQueue;
    if (commandQueue != nullptr && !commandQueue->mCommandVec.empty() && commandQueue->mCommandVec.front().HasValue()) {
      mPreparationTick = 0;
    } else if (mPreparationTick == 0) {
      mPreparationTick = static_cast<std::int32_t>(mUnit->SimulationRef->mCurTick);
    }

    ProcessFuelLevels();

    // 0x006B9D10: one shared out-lane, seeded to 1.0 before the state switch.
    // The CalcMove* steps only overwrite it when the unit actually moved, so an
    // idle unit still hands MoveTo a whole-tick fraction. MoveTo divides by it
    // to derive the transform interpolation rate; a zero here (the previous
    // per-case `= 0.0f` seed) produced an infinite rate and NaN-poisoned every
    // interpolated user-side transform.
    float moveTimeFraction = 1.0f;

    switch (mMotionState) {
      case kUnitMotionStateAttached: {
        mVelocity = Wm3::Vector3f::ZERO;
        mVector44 = Wm3::Vector3f::ZERO;
        mPos = mUnit->GetPosition();

        if (mUnit->mAttachInfo.HasAttachTarget()) {
          Entity* const attachTargetEntity = mUnit->mAttachInfo.GetAttachTargetEntity();
          Unit* const attachTargetUnit = attachTargetEntity->IsUnit();
          if (attachTargetUnit == nullptr || attachTargetUnit->GetFocusEntity() != static_cast<Entity*>(mUnit)) {
            mUnit->SetCurrentLayer(attachTargetEntity->mVarDat.mLayerMask);
          }
          return TASKSTATUS_Wait;
        }

        const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
        SetMotionState(blueprint->Air.CanFly ? kUnitMotionStateNone : kUnitMotionStateBallistic);
        mUnit->SetCurrentLayer(LAYER_Air);
        mProcessSurfaceCollision = true;
        MoveTo(transform, 1.0f);
        return TASKSTATUS_Wait;
      }

      case kUnitMotionStateBallistic: {
        CalcMoveBallistic(transform, &moveTimeFraction);
        MoveTo(transform, moveTimeFraction);
        return TASKSTATUS_Wait;
      }

      case kUnitMotionStateCrashed:
        return TASKSTATUS_Wait;

      default: {
        const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();

        if (blueprint->Air.CanFly) {
          if (mUnit->IsUnitState(UNITSTATE_Immobile) || mUnit->StunnedState) {
            SetMotionHorzEvent(kUnitMotionHorzEventStopped);
            return TASKSTATUS_Wait;
          }

          CalcMoveAir(transform, &moveTimeFraction);
          MoveTo(transform, moveTimeFraction);
          return TASKSTATUS_Wait;
        }

        if (mUnit->IsUnitState(UNITSTATE_Immobile) || mUnit->StunnedState) {
          mFollowingWaypoint = nullptr;
          mNextWaypoint = nullptr;

          const bool moveSucceeded = mUnit->IsDead() ? false : CalcMoveCommon(transform, nullptr);
          ProcessCommonMotionState(moveSucceeded);
          if (mLayerTransitionTicks != 0.0f) {
            MoveTo(transform, 1.0f);
          }
          return TASKSTATUS_Wait;
        }

        if (Wm3::Vector3f::LengthSq(mVelocity) > 0.000001f) {
          UpdateCurrentLayer();
          mUnit->UpdateTerrainType(transform.pos_);
        }

        if (blueprint->Physics.MotionType == RULEUMT_Hover) {
          CalcMoveHover(transform, &moveTimeFraction);
          MoveTo(transform, moveTimeFraction);
          return TASKSTATUS_Wait;
        }

        if (mUnit->mVarDat.mLayerMask == LAYER_Land || mUnit->mVarDat.mLayerMask == LAYER_Seabed) {
          CalcMoveLand(transform, &moveTimeFraction);
        } else {
          CalcMoveWater(transform, &moveTimeFraction);
        }
        MoveTo(transform, moveTimeFraction);
        return TASKSTATUS_Wait;
      }
    }
  }

  /**
   * Address: 0x006BE480 (FUN_006BE480, ?CalcHoverOrientation@CUnitMotion@Moho@@AAEXABUSPhysBody@2@ABV?$Vector3@M@Wm3@@AAVVAxes3@2@@Z)
   * Mangled: ?CalcHoverOrientation@CUnitMotion@Moho@@AAEXABUSPhysBody@2@ABV?$Vector3@M@Wm3@@AAVVAxes3@2@@Z
   *
   * What it does:
   * Builds hover-control axes from body velocity delta, gravity compensation,
   * and blueprint bank-factor/elevation scaling.
   */
  void CUnitMotion::CalcHoverOrientation(
    const SPhysBody& body,
    const Wm3::Vector3f& referenceVector,
    VAxes3& outAxes
  )
  {
    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
    const RUnitBlueprintPhysics& physics = blueprint->Physics;
    const RUnitBlueprintAir& air = blueprint->Air;

    const Wm3::Vector3f gravity = mUnit->SimulationRef->mPhysConstants->mGravity;
    Wm3::Vector3f velocityDelta{
      body.mVelocity.x - mPreviousVelocity.x,
      body.mVelocity.y - mPreviousVelocity.y,
      body.mVelocity.z - mPreviousVelocity.z,
    };

    if (air.BankForward == 0u) {
      const float forwardX = ((body.mOrientation.x * body.mOrientation.z) + (body.mOrientation.w * body.mOrientation.y)) * 2.0f;
      const float forwardY = ((body.mOrientation.y * body.mOrientation.z) - (body.mOrientation.w * body.mOrientation.x)) * 2.0f;
      const float forwardZ =
        1.0f - (((body.mOrientation.x * body.mOrientation.x) + (body.mOrientation.y * body.mOrientation.y)) * 2.0f);

      const float forwardLengthSq = (forwardX * forwardX) + (forwardY * forwardY) + (forwardZ * forwardZ);
      if (forwardLengthSq > 0.0f) {
        const float projectionScale =
          ((forwardX * velocityDelta.x) + (forwardY * velocityDelta.y) + (forwardZ * velocityDelta.z)) /
          forwardLengthSq;
        velocityDelta.x -= forwardX * projectionScale;
        velocityDelta.y -= forwardY * projectionScale;
        velocityDelta.z -= forwardZ * projectionScale;
      }
    }

    float elevationRatio = mCurElevation / physics.Elevation;
    if (elevationRatio > 1.0f) {
      elevationRatio = 1.0f;
    }

    const float bankScale = air.BankFactor * elevationRatio;
    outAxes.vY.x = (velocityDelta.x * bankScale) - (gravity.x * 0.1f);
    outAxes.vY.y = (velocityDelta.y * bankScale) - (gravity.y * 0.1f);
    outAxes.vY.z = (velocityDelta.z * bankScale) - (gravity.z * 0.1f);
    outAxes.vZ = referenceVector;
  }

  /**
   * Address: 0x006C1350 (FUN_006C1350, ?CalcRollHack@CUnitMotion@Moho@@AAE?AV?$Vector3@M@Wm3@@XZ)
   *
   * What it does:
   * Applies roll recoil damping/integration and derives one smoothed tilt axis
   * from current dive state plus unit-facing orientation.
   */
  Wm3::Vector3f CUnitMotion::CalcRollHack()
  {
    const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();

    mBodyTiltOffset.y = 0.0f;
    mRecoilImpulse.y = 0.0f;

    const float rollDampingScale = 1.0f - blueprint->Physics.RollDamping;
    mRecoilImpulse.x *= rollDampingScale;
    mRecoilImpulse.y *= rollDampingScale;
    mRecoilImpulse.z *= rollDampingScale;

    mBodyTiltOffset.x += mRecoilImpulse.x;
    mBodyTiltOffset.y += mRecoilImpulse.y;
    mBodyTiltOffset.z += mRecoilImpulse.z;

    const float rollStability = blueprint->Physics.RollStability;
    mRecoilImpulse.x -= mBodyTiltOffset.x * rollStability;
    mRecoilImpulse.y -= mBodyTiltOffset.y * rollStability;
    mRecoilImpulse.z -= mBodyTiltOffset.z * rollStability;

    float rollTargetX = 0.0f;
    float rollTargetY = 0.0f;
    float rollTargetZ = 0.0f;

    if (mUnit->IsUnitState(UNITSTATE_MovingDown)) {
      const auto& unitRuntime = reinterpret_cast<const UnitRecoilOrientationRuntimeView&>(*mUnit);
      const VAxes3 axes(unitRuntime.mCurrentOrientation);
      const float rollScale = mDivingSpeed * kRollHackAxisScale;
      rollTargetX = -axes.vZ.x * rollScale;
      rollTargetY = 0.0f;
      rollTargetZ = -axes.vZ.z * rollScale;
    } else if (mUnit->IsUnitState(UNITSTATE_MovingUp)) {
      const auto& unitRuntime = reinterpret_cast<const UnitRecoilOrientationRuntimeView&>(*mUnit);
      const VAxes3 axes(unitRuntime.mCurrentOrientation);
      const float rollScale = mDivingSpeed * kRollHackAxisScale;
      rollTargetX = axes.vZ.x * rollScale;
      rollTargetY = 0.0f;
      rollTargetZ = axes.vZ.z * rollScale;
    }

    mVector68.x = (rollTargetX * kRollHackBlend) + (mVector68.x * kRollHackRetention);
    mVector68.y = (rollTargetY * kRollHackBlend) + (mVector68.y * kRollHackRetention);
    mVector68.z = (rollTargetZ * kRollHackBlend) + (mVector68.z * kRollHackRetention);

    Wm3::Vector3f rollNormal{};
    rollNormal.x = mVector68.x + mBodyTiltOffset.x;
    rollNormal.y = mVector68.y + (mBodyTiltOffset.y + 1.0f);
    rollNormal.z = mVector68.z + mBodyTiltOffset.z;
    Wm3::Vector3f::Normalize(&rollNormal);
    return rollNormal;
  }

  /**
   * Address: 0x006C1CB0 (FUN_006C1CB0, ?SnapToWater@CUnitMotion@Moho@@AAE?AVVTransform@2@ABV32@@Z)
   * Mangled: ?SnapToWater@CUnitMotion@Moho@@AAE?AVVTransform@2@ABV32@@Z
   *
   * What it does:
   * Snaps one transform onto water/terrain elevation while incorporating roll
   * hack tilt and submerged-elevation carry behavior.
   */
  VTransform CUnitMotion::SnapToWater(const VTransform& sourceTransform)
  {
    VTransform snapped = sourceTransform;

    const Wm3::Vector3f rollNormal = CalcRollHack();
    STIMap* const mapData = mUnit->SimulationRef->mMapData;
    CHeightField* const heightField = mapData->GetHeightField();

    const float terrainElevation = heightField->GetElevation(snapped.pos_.x, snapped.pos_.z);

    Unit* const raisedPlatformUnit = mRaisedPlatformUnit.GetObjectPtr();
    const float occupiedRectElevation = heightField->GetElevation(snapped.pos_.x, snapped.pos_.z);
    float footprintElevation = occupiedRectElevation;
    if (raisedPlatformUnit != nullptr) {
      footprintElevation += raisedPlatformUnit->DistanceToOccupiedRect(&snapped.pos_);
    }

    float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : kNoWaterElevation;
    if (footprintElevation > terrainElevation) {
      waterElevation += footprintElevation - terrainElevation;
    }

    float snappedElevation = terrainElevation + kWaterSnapSurfaceBias;
    const float submergedElevation = waterElevation + mSubElevation;
    if (submergedElevation > snappedElevation) {
      snappedElevation = submergedElevation;
    }

    snapped.pos_.y = snappedElevation;

    if (mSubElevation < 0.0f) {
      const float clampedElevation = (snappedElevation <= waterElevation) ? snappedElevation : waterElevation;
      snapped.pos_.y = clampedElevation;
      mSubElevation = clampedElevation - waterElevation;
    }

    COORDS_Tilt(&snapped.orient_, rollNormal);
    return snapped;
  }

  /**
   * Address: 0x006C1610 (FUN_006C1610, ?SnapToGround@CUnitMotion@Moho@@AAE?AVVTransform@2@ABV32@@Z)
   * Mangled: ?SnapToGround@CUnitMotion@Moho@@AAE?AVVTransform@2@ABV32@@Z
   *
   * What it does:
   * Samples four terrain/raised-platform points under one oriented footprint,
   * recenters Y to their average, applies stand/sink correction, then tilts
   * orientation to the recovered ground normal.
   */
  VTransform CUnitMotion::SnapToGround(const VTransform& sourceTransform)
  {
    VTransform snapped = sourceTransform;

    Unit* const unit = mUnit;
    if (unit == nullptr) {
      return snapped;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    Sim* const sim = unit->SimulationRef;
    STIMap* const mapData = sim ? sim->mMapData : nullptr;
    if (blueprint == nullptr || mapData == nullptr) {
      return snapped;
    }

    const float halfSizeX = blueprint->mSizeX * 0.5f;
    const float halfSizeZ = blueprint->mSizeZ * 0.5f;

    Wm3::Vector3f frontRight = snapped.pos_ + RotateByQuaternion({halfSizeX, 0.0f, halfSizeZ}, snapped.orient_);
    Wm3::Vector3f frontLeft = snapped.pos_ + RotateByQuaternion({-halfSizeX, 0.0f, halfSizeZ}, snapped.orient_);
    Wm3::Vector3f backLeft = snapped.pos_ + RotateByQuaternion({-halfSizeX, 0.0f, -halfSizeZ}, snapped.orient_);
    Wm3::Vector3f backRight = snapped.pos_ + RotateByQuaternion({halfSizeX, 0.0f, -halfSizeZ}, snapped.orient_);

    const bool hoverMotion = blueprint->Physics.MotionType == RULEUMT_Hover;
    frontRight.y = SampleSnapElevation(unit, frontRight, *mapData, hoverMotion);
    frontLeft.y = SampleSnapElevation(unit, frontLeft, *mapData, hoverMotion);
    backLeft.y = SampleSnapElevation(unit, backLeft, *mapData, hoverMotion);
    backRight.y = SampleSnapElevation(unit, backRight, *mapData, hoverMotion);

    snapped.pos_.y = (frontRight.y + frontLeft.y + backLeft.y + backRight.y) * 0.25f;

    Wm3::Vector3f surfaceNormal{};
    if (blueprint->Physics.StandUpright != 0u) {
      surfaceNormal = {0.0f, 1.0f, 0.0f};
    } else {
      const float deltaDiagonalY0 = backRight.y - frontLeft.y;
      const float deltaDiagonalY1 = backLeft.y - frontRight.y;
      surfaceNormal.x =
        (deltaDiagonalY0 * (backLeft.z - frontRight.z)) - ((backRight.z - frontLeft.z) * deltaDiagonalY1);
      surfaceNormal.y =
        ((backRight.z - frontLeft.z) * (backLeft.x - frontRight.x)) -
        ((backLeft.z - frontRight.z) * (backRight.x - frontLeft.x));
      surfaceNormal.z =
        (deltaDiagonalY1 * (backRight.x - frontLeft.x)) - (deltaDiagonalY0 * (backLeft.x - frontRight.x));
    }

    if (blueprint->Physics.StandUpright != 0u || blueprint->Physics.SinkLower != 0u) {
      const CHeightField* const heightField = mapData->GetHeightField();
      const float centerElevation =
        heightField ? heightField->GetElevation(snapped.pos_.x, snapped.pos_.z) : snapped.pos_.y;

      float minElevation = std::min(backRight.y, backLeft.y);
      minElevation = std::min(minElevation, std::min(frontLeft.y, frontRight.y));
      minElevation = std::min(minElevation, centerElevation);

      float maxElevation = std::max(backRight.y, backLeft.y);
      maxElevation = std::max(maxElevation, std::max(frontLeft.y, frontRight.y));
      maxElevation = std::max(maxElevation, centerElevation);

      snapped.pos_.y -= (maxElevation - minElevation) * 0.25f;
    }

    if (hoverMotion) {
      snapped.pos_.y += unit->GetAttributes().spawnElevationOffset;
      CUnitMotion* const unitMotion = unit->UnitMotion;
      if (unitMotion != nullptr) {
        surfaceNormal.x += unitMotion->mBodyTiltOffset.x + unitMotion->mWobbleOffset.x;
        surfaceNormal.y += unitMotion->mBodyTiltOffset.y + unitMotion->mWobbleOffset.y;
        surfaceNormal.z += unitMotion->mBodyTiltOffset.z + unitMotion->mWobbleOffset.z;
      }
    }

    COORDS_Tilt(&snapped.orient_, surfaceNormal);
    return snapped;
  }

  /**
   * Address: 0x006B9940 (FUN_006B9940, ?ProcessFuelLevels@CUnitMotion@Moho@@AAEXXZ)
   *
   * What it does:
   * Ticks fuel consumption/refueling state, drives refuel callbacks, and
   * manages the per-motion maintenance economy request lane used for
   * staging-platform repair while refueling.
   */
  void CUnitMotion::ProcessFuelLevels()
  {
    Unit* const unit = mUnit;
    if (unit->IsDead() || mFuelUseTime <= 0.0f) {
      return;
    }

    const float previousFuelRatio = unit->FuelRatio;
    float nextFuelRatio = previousFuelRatio;

    if (IsRefuelVertEvent(mVertEvent)) {
      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      float fuelDelta = (unitBlueprint->Physics.FuelRechargeRate / mFuelUseTime) * kFuelTickScale;
      const bool needsRepair = unit->mVarDat.mMaxHealth > unit->mVarDat.mHealth;
      Unit* const stagingPlatform = unit->GetStagingPlatform();

      if (stagingPlatform != nullptr) {
        const RUnitBlueprint* const stagingBlueprint = stagingPlatform->GetBlueprint();
        fuelDelta *= stagingBlueprint->AI.RefuelingMultiplier;

        if (!mHasDoneCallback && previousFuelRatio < 1.0f) {
          mHasDoneCallback = true;
          (void)unit->RunScript("OnStartRefueling");
        }

        if (needsRepair) {
          if (mEconomyRequest != nullptr) {
            if (mEconomyRequest->mGranted.energy >= mRepairConsumption.energy &&
                mEconomyRequest->mGranted.mass >= mRepairConsumption.mass) {
              const SEconValue granted = TakeGrantedResourcesAndReset(mEconomyRequest);
              unit->mBeatResourceAccumulators.resourcesSpentEnergy += granted.energy;
              unit->mBeatResourceAccumulators.resourcesSpentMass += granted.mass;
              static_cast<Entity*>(unit)->AdjustHealth(
                static_cast<Entity*>(stagingPlatform), stagingBlueprint->AI.RefuelingRepairAmount * kFuelTickScale
              );
            }
          } else {
            mHasDoneCallback = true;
            mRepairConsumption.energy = stagingBlueprint->AI.RepairConsumeEnergy;
            mRepairConsumption.mass = stagingBlueprint->AI.RepairConsumeMass;

            CSimArmyEconomyInfo* const economy = unit->ArmyRef ? unit->ArmyRef->GetEconomy() : nullptr;
            ReplaceEconomyRequestPointer(mEconomyRequest, CreateEconomyRequest(mRepairConsumption, economy));

            unit->SharedEconomyRateEnergy = mRepairConsumption.energy;
            unit->SharedEconomyRateMass = mRepairConsumption.mass;
          }
        }
      } else {
        fuelDelta *= kFuelTickScale;
      }

      if (mHasDoneCallback && previousFuelRatio > kFuelRefuelDoneThreshold && !needsRepair) {
        ReplaceEconomyRequestPointer(mEconomyRequest, nullptr);
        ClearMaintenanceCost(unit);
        mHasDoneCallback = false;
      }

      nextFuelRatio = std::min(previousFuelRatio + fuelDelta, 1.0f);
      if (previousFuelRatio == 0.0f && nextFuelRatio > 0.0f) {
        (void)unit->RunScript("OnGotFuel");
      }
    } else {
      if (mHasDoneCallback) {
        ReplaceEconomyRequestPointer(mEconomyRequest, nullptr);
        ClearMaintenanceCost(unit);
        mHasDoneCallback = false;
      }

      const float fuelDrainPerTick = 1.0f / (mFuelUseTime * kFuelDrainTicksPerSecond);
      nextFuelRatio = std::max(previousFuelRatio - fuelDrainPerTick, 0.0f);
      if (nextFuelRatio == 0.0f && previousFuelRatio > 0.0f) {
        (void)unit->RunScript("OnRunOutOfFuel");
      }
    }

    unit->FuelRatio = nextFuelRatio;
  }
} // namespace moho

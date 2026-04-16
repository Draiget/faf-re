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
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/CAiTarget.h"
#include "moho/math/MathReflection.h"
#include "moho/math/Vector3f.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

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
    constexpr float kLayerTransitionTickScale = 10.0f;
    constexpr float kHeightWordScale = 0.0078125f;
    constexpr float kAirTargetMinimumElevationScale = 0.5f;
    constexpr float kMoveToQuatUnitTolerance = 0.01f;
    constexpr EUnitMotionState kUnitMotionStateNone = static_cast<EUnitMotionState>(0);
    constexpr EUnitMotionState kUnitMotionStateBallistic = static_cast<EUnitMotionState>(2);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventCruising = static_cast<EUnitMotionHorzEvent>(0);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventTopSpeed = static_cast<EUnitMotionHorzEvent>(1);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventStopping = static_cast<EUnitMotionHorzEvent>(2);
    constexpr EUnitMotionHorzEvent kUnitMotionHorzEventStopped = static_cast<EUnitMotionHorzEvent>(3);
    constexpr EUnitMotionCarrierEvent kUnitMotionCarrierEventRelativeHeight = static_cast<EUnitMotionCarrierEvent>(1);
    constexpr Wm3::Quaternionf kWingedOrientationQuarterTurnRotation{0.0f, 0.70710677f, 0.0f, 0.70710677f};
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

    struct CUnitMotionRaisedPlatformCandidatesRuntimeView
    {
      WeakPtr<Unit>* mBegin;
      WeakPtr<Unit>* mEnd;
      WeakPtr<Unit>* mCapacityEnd;
      WeakPtr<Unit>* mInlineBegin;
    };
    static_assert(
      sizeof(CUnitMotionRaisedPlatformCandidatesRuntimeView) == 0x10,
      "CUnitMotionRaisedPlatformCandidatesRuntimeView size must be 0x10"
    );
    static_assert(
      offsetof(CUnitMotionRaisedPlatformCandidatesRuntimeView, mBegin) == 0x00,
      "CUnitMotionRaisedPlatformCandidatesRuntimeView::mBegin offset must be 0x00"
    );
    static_assert(
      offsetof(CUnitMotionRaisedPlatformCandidatesRuntimeView, mEnd) == 0x04,
      "CUnitMotionRaisedPlatformCandidatesRuntimeView::mEnd offset must be 0x04"
    );
    static_assert(
      offsetof(CUnitMotionRaisedPlatformCandidatesRuntimeView, mCapacityEnd) == 0x08,
      "CUnitMotionRaisedPlatformCandidatesRuntimeView::mCapacityEnd offset must be 0x08"
    );
    static_assert(
      offsetof(CUnitMotionRaisedPlatformCandidatesRuntimeView, mInlineBegin) == 0x0C,
      "CUnitMotionRaisedPlatformCandidatesRuntimeView::mInlineBegin offset must be 0x0C"
    );

    [[nodiscard]] CUnitMotionRaisedPlatformCandidatesRuntimeView&
    AsRaisedPlatformCandidatesRuntimeView(CUnitMotion& motion) noexcept
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(&motion);
      return *reinterpret_cast<CUnitMotionRaisedPlatformCandidatesRuntimeView*>(base + offsetof(CUnitMotion, mPad178));
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

    [[nodiscard]] Wm3::Vector3f ForwardVectorFromOrientation(const moho::Vector4f& orientation) noexcept
    {
      Wm3::Vector3f out{};
      out.x = ((orientation.x * orientation.z) + (orientation.w * orientation.y)) * 2.0f;
      out.y = ((orientation.w * orientation.z) - (orientation.x * orientation.y)) * 2.0f;
      out.z = 1.0f - (((orientation.z * orientation.z) + (orientation.y * orientation.y)) * 2.0f);
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

    [[nodiscard]] bool IsVector3fBinaryZero(const Wm3::Vector3f& value) noexcept
    {
      static constexpr Wm3::Vector3f kZeroVector{};
      return std::memcmp(&value, &kZeroVector, sizeof(Wm3::Vector3f)) == 0;
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

    [[nodiscard]] Wm3::Vector3f RotateByQuaternion(
      const Wm3::Vector3f& vector,
      const Wm3::Quaternionf& quaternion
    ) noexcept
    {
      Wm3::Vector3f out{};
      Wm3::MultiplyQuaternionVector(&out, vector, quaternion);
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
      return event == UMVE_Top || event == UMVE_Hover;
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

    void DestroyRaisedPlatformCandidateStorage(CUnitMotionRaisedPlatformCandidatesRuntimeView& runtime) noexcept
    {
      if (runtime.mBegin != nullptr && runtime.mEnd != nullptr && runtime.mEnd >= runtime.mBegin) {
        for (WeakPtr<Unit>* lane = runtime.mBegin; lane != runtime.mEnd; ++lane) {
          lane->ResetFromObject(nullptr);
        }
      }

      if (runtime.mBegin != nullptr && runtime.mBegin != runtime.mInlineBegin) {
        ::operator delete[](static_cast<void*>(runtime.mBegin));
      }

      runtime.mBegin = runtime.mInlineBegin;
      runtime.mEnd = runtime.mBegin;
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
    , mVertEvent(UMVE_None)
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
    , mUnknownA4(0u)
    , mUnknownA8(0)
    , mPreparationTick(0)
    , mStateWordB0(0)
    , mPreviousVelocity{}
    , mVectorC0{}
    , mRecoilImpulse{}
    , mVectorD8{}
    , mVectorE4{}
    , mVectorF0{}
    , mForce{}
    , mVector108{}
    , mRaisedPlatformUnit{}
    , mUnknownFloat11C(0.0f)
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

    CUnitMotionRaisedPlatformCandidatesRuntimeView& candidates = AsRaisedPlatformCandidatesRuntimeView(*this);
    auto* const inlineBegin = reinterpret_cast<WeakPtr<Unit>*>(mPad178 + 0x10);
    candidates.mBegin = inlineBegin;
    candidates.mEnd = inlineBegin;
    candidates.mCapacityEnd = reinterpret_cast<WeakPtr<Unit>*>(mPad178 + 0x60);
    candidates.mInlineBegin = inlineBegin;
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
    CUnitMotionRaisedPlatformCandidatesRuntimeView& candidates = AsRaisedPlatformCandidatesRuntimeView(*this);
    DestroyRaisedPlatformCandidateStorage(candidates);

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

    archive->ReadUInt(&motion->mUnknownA4);
    archive->ReadInt(&motion->mUnknownA8);
    archive->ReadInt(&motion->mPreparationTick);
    archive->ReadInt(&motion->mStateWordB0);

    ReadTypedValue(*archive, motion->mPreviousVelocity, ownerRef);
    ReadTypedValue(*archive, motion->mVectorC0, ownerRef);
    ReadTypedValue(*archive, motion->mRecoilImpulse, ownerRef);
    ReadTypedValue(*archive, motion->mVectorD8, ownerRef);
    ReadTypedValue(*archive, motion->mVectorE4, ownerRef);
    ReadTypedValue(*archive, motion->mVectorF0, ownerRef);
    ReadTypedValue(*archive, motion->mForce, ownerRef);
    ReadTypedValue(*archive, motion->mVector108, ownerRef);
    ReadTypedValue(*archive, motion->mRaisedPlatformUnit, ownerRef);

    archive->ReadFloat(&motion->mUnknownFloat11C);

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

    archive->WriteUInt(motion->mUnknownA4);
    archive->WriteInt(motion->mUnknownA8);
    archive->WriteInt(motion->mPreparationTick);
    archive->WriteInt(motion->mStateWordB0);

    WriteTypedValue(*archive, motion->mPreviousVelocity, ownerRef);
    WriteTypedValue(*archive, motion->mVectorC0, ownerRef);
    WriteTypedValue(*archive, motion->mRecoilImpulse, ownerRef);
    WriteTypedValue(*archive, motion->mVectorD8, ownerRef);
    WriteTypedValue(*archive, motion->mVectorE4, ownerRef);
    WriteTypedValue(*archive, motion->mVectorF0, ownerRef);
    WriteTypedValue(*archive, motion->mForce, ownerRef);
    WriteTypedValue(*archive, motion->mVector108, ownerRef);
    WriteTypedValue(*archive, motion->mRaisedPlatformUnit, ownerRef);

    archive->WriteFloat(motion->mUnknownFloat11C);

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
    const ELayer oldLayer = unit->mCurrentLayer;

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
    FindIntersectingRaisedPlatform();

    if (mUnit->mCurrentLayer == LAYER_Land) {
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
    forward.y = ((orientation.w * orientation.z) - (orientation.x * orientation.y)) * 2.0f;
    forward.z = 1.0f - (((orientation.z * orientation.z) + (orientation.y * orientation.y)) * 2.0f);

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

      Wm3::MultiplyQuaternionVector(&mVector108, localAngularImpulse, body->mOrientation);

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
   * Current binary implementation is a no-op lane.
   */
  void CUnitMotion::SetMotionTurnEvent(const EUnitMotionTurnEvent event)
  {
    (void)event;
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
    const Wm3::Vector3f detachForward = ForwardVectorFromOrientation(detachedFromEntity->Orientation);

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

    const ELayer oldLayer = unit->mCurrentLayer;
    unit->mCurrentLayer = LAYER_Air;
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
    if (mLayer != LAYER_None && unit->mCurrentLayer != mLayer) {
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
          (mVertEvent != UMVE_Top || mHeight == std::numeric_limits<float>::infinity())) {
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
    switch (mUnit->mCurrentLayer) {
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
   * Address: 0x006C3480 (FUN_006C3480, ?CalcMoveWater@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z)
   * Mangled: ?CalcMoveWater@CUnitMotion@Moho@@AAEXAAVVTransform@2@@Z
   *
   * What it does:
   * Runs one water move step through `CalcMoveCommon`, applies dive/surface
   * transitions and water snap, and updates common horizontal motion events.
   */
  void CUnitMotion::CalcMoveWater(VTransform& transform)
  {
    bool moveSucceeded = false;
    if (!mUnit->IsDead()) {
      moveSucceeded = CalcMoveCommon(transform, nullptr);
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

    CUnitMotionRaisedPlatformCandidatesRuntimeView& candidates = AsRaisedPlatformCandidatesRuntimeView(*this);
    if (candidates.mBegin == nullptr || candidates.mEnd == nullptr || candidates.mEnd < candidates.mBegin || mUnit == nullptr) {
      return;
    }

    const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
    float nearestDistanceSq = std::numeric_limits<float>::infinity();

    for (WeakPtr<Unit>* candidate = candidates.mBegin; candidate != candidates.mEnd; ++candidate) {
      Unit* const platformUnit = candidate->GetObjectPtr();
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
        SetMotionVertEvent(UMVE_None);
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
        SetMotionVertEvent(UMVE_Top);
      }
      return true;
    }

    return true;
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
    const float transitionProgress = mUnknownFloat11C / transitionDurationTicks;

    transform.pos_.x = mLastTrans.pos_.x + ((mCurTrans.pos_.x - mLastTrans.pos_.x) * transitionProgress);
    transform.pos_.y = mLastTrans.pos_.y + ((mCurTrans.pos_.y - mLastTrans.pos_.y) * transitionProgress);
    transform.pos_.z = mLastTrans.pos_.z + ((mCurTrans.pos_.z - mLastTrans.pos_.z) * transitionProgress);
    transform.orient_ = Wm3::Quaternionf::Nlerp(mLastTrans.orient_, mCurTrans.orient_, transitionProgress);

    mUnknownFloat11C += 1.0f;
    mProcessSurfaceCollision = false;
    if (mUnknownFloat11C >= transitionDurationTicks) {
      mUnknownFloat11C = 0.0f;
    }
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
        targetEntity != nullptr && targetEntity->mCurrentLayer == LAYER_Air) {
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
        targetEntity != nullptr && targetEntity->mCurrentLayer == LAYER_Air) {
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

    const float currentOrientationY =
      1.0f - (((transform.orient_.w * transform.orient_.w) + (transform.orient_.y * transform.orient_.y)) * 2.0f);

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

    const float halfTurnAngle = turnDelta * 5.0f;
    const Wm3::Quaternionf turnQuaternion{
      0.0f,
      std::cos(halfTurnAngle),
      0.0f,
      std::sin(halfTurnAngle),
    };

    Wm3::Vector3f rotatedSelectedVector = selectedVector;
    const Wm3::Vector3f turnVector = RotateByQuaternion(selectedVector, turnQuaternion);
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
    Wm3::Vector3f wingUpVector{
      (wingAxis.y * wingOrientationBias) + 1.0f - wingProjection.y,
      (wingOrientationBias * wingAxis.x) - wingProjection.x,
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
      const float forwardY = ((body.mOrientation.w * body.mOrientation.z) - (body.mOrientation.x * body.mOrientation.y)) * 2.0f;
      const float forwardZ =
        1.0f - (((body.mOrientation.z * body.mOrientation.z) + (body.mOrientation.y * body.mOrientation.y)) * 2.0f);

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

    mVectorC0.y = 0.0f;
    mRecoilImpulse.y = 0.0f;

    const float rollDampingScale = 1.0f - blueprint->Physics.RollDamping;
    mRecoilImpulse.x *= rollDampingScale;
    mRecoilImpulse.y *= rollDampingScale;
    mRecoilImpulse.z *= rollDampingScale;

    mVectorC0.x += mRecoilImpulse.x;
    mVectorC0.y += mRecoilImpulse.y;
    mVectorC0.z += mRecoilImpulse.z;

    const float rollStability = blueprint->Physics.RollStability;
    mRecoilImpulse.x -= mVectorC0.x * rollStability;
    mRecoilImpulse.y -= mVectorC0.y * rollStability;
    mRecoilImpulse.z -= mVectorC0.z * rollStability;

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
    rollNormal.x = mVector68.x + mVectorC0.x;
    rollNormal.y = mVector68.y + (mVectorC0.y + 1.0f);
    rollNormal.z = mVector68.z + mVectorC0.z;
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
        surfaceNormal.x += unitMotion->mVectorC0.x + unitMotion->mVectorD8.x;
        surfaceNormal.y += unitMotion->mVectorC0.y + unitMotion->mVectorD8.y;
        surfaceNormal.z += unitMotion->mVectorC0.z + unitMotion->mVectorD8.z;
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
      const bool needsRepair = unit->MaxHealth > unit->Health;
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

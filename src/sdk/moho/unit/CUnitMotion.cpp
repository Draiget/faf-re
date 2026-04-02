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
#include "moho/ai/CAiPathSpline.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
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

    [[nodiscard]] Wm3::Vector3f SetVectorLength(const Wm3::Vector3f& direction, const float targetLength) noexcept
    {
      Wm3::Vector3f out = direction;
      if (Wm3::Vector3f::Normalize(&out) > 0.0f) {
        out.x *= targetLength;
        out.y *= targetLength;
        out.z *= targetLength;
      } else {
        out = {};
      }
      return out;
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
      unit->MaintainenceCostEnergy = 0.0f;
      unit->MaintainenceCostMass = 0.0f;
    }
  } // namespace

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

    ReadTypedValue(*archive, motion->mVectorB4, ownerRef);
    ReadTypedValue(*archive, motion->mVectorC0, ownerRef);
    ReadTypedValue(*archive, motion->mRecoilImpulse, ownerRef);
    ReadTypedValue(*archive, motion->mVectorD8, ownerRef);
    ReadTypedValue(*archive, motion->mVectorE4, ownerRef);
    ReadTypedValue(*archive, motion->mVectorF0, ownerRef);
    ReadTypedValue(*archive, motion->mForce, ownerRef);
    ReadTypedValue(*archive, motion->mVector108, ownerRef);
    ReadTypedValue(*archive, motion->mUnknownWeakUnit, ownerRef);

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

    WriteTypedValue(*archive, motion->mVectorB4, ownerRef);
    WriteTypedValue(*archive, motion->mVectorC0, ownerRef);
    WriteTypedValue(*archive, motion->mRecoilImpulse, ownerRef);
    WriteTypedValue(*archive, motion->mVectorD8, ownerRef);
    WriteTypedValue(*archive, motion->mVectorE4, ownerRef);
    WriteTypedValue(*archive, motion->mVectorF0, ownerRef);
    WriteTypedValue(*archive, motion->mForce, ownerRef);
    WriteTypedValue(*archive, motion->mVector108, ownerRef);
    WriteTypedValue(*archive, motion->mUnknownWeakUnit, ownerRef);

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

    const Wm3::Vector3f alignedImpulse = SetVectorLength(forward, impulse.Length());

    mRecoilImpulse.x += (impulse.x - alignedImpulse.x) * kRecoilImpulseBlendFactor;
    mRecoilImpulse.y += (impulse.y - alignedImpulse.y) * kRecoilImpulseBlendFactor;
    mRecoilImpulse.z += (impulse.z - alignedImpulse.z) * kRecoilImpulseBlendFactor;
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

            unit->MaintainenceCostEnergy = mRepairConsumption.energy;
            unit->MaintainenceCostMass = mRepairConsumption.mass;
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

#include "moho/unit/tasks/CUnitRefuel.h"

#include <cstdint>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitRefuelType()
  {
    gpg::RType* type = moho::CUnitRefuel::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitRefuel));
      moho::CUnitRefuel::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00622460 (FUN_00622460, CUnitRefuel::MemberDeserialize thunk)
   *
   * What it does:
   * Forwards one serializer load callback lane to `CUnitRefuel::MemberDeserialize`.
   */
  [[maybe_unused]] void CUnitRefuelDeserializeThunkPrimary(
    moho::CUnitRefuel* const task,
    gpg::ReadArchive* const archive
  )
  {
    if (task != nullptr) {
      task->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x006224B0 (FUN_006224B0, CUnitRefuel::MemberDeserialize thunk)
   *
   * What it does:
   * Secondary load-callback forwarder to `CUnitRefuel::MemberDeserialize`.
   */
  [[maybe_unused]] void CUnitRefuelDeserializeThunkSecondary(
    moho::CUnitRefuel* const task,
    gpg::ReadArchive* const archive
  )
  {
    if (task != nullptr) {
      task->MemberDeserialize(archive);
    }
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitRefuel::sType = nullptr;

  /**
   * Address: 0x00620F50 (FUN_00620F50, ??0CUnitRefuel@Moho@@QAE@@Z)
   */
  CUnitRefuel::CUnitRefuel(Unit* const targetUnit, IAiCommandDispatchImpl* const dispatchTask)
    : CCommandTask(static_cast<CCommandTask*>(dispatchTask))
    , mTargetUnit{}
    , mHasTransportReservation(false)
    , mIsCarrier(false)
    , mPad3A{}
  {
    mTargetUnit.ResetFromObject(targetUnit);

    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= (1ull << UNITSTATE_Refueling);
      mUnit->UpdateSpeedThroughStatus();
    }

    Unit* const linkedTarget = mTargetUnit.GetObjectPtr();
    mIsCarrier = (linkedTarget != nullptr) && linkedTarget->IsInCategory("CARRIER");

    if (mUnit != nullptr && mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->IgnoreFormation(true);
    }
  }

  /**
   * Address: 0x00621060 (FUN_00621060, ??1CUnitRefuel@Moho@@QAE@@Z)
   */
  CUnitRefuel::~CUnitRefuel()
  {
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_ForceSpeedThrough);
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_Refueling);
    mUnit->UpdateSpeedThroughStatus();

    if (mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->IgnoreFormation(false);
    }

    Unit* const targetUnit = mTargetUnit.GetObjectPtr();
    if (mHasTransportReservation) {
      if (mUnit->UnitMotion != nullptr) {
        mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
      }

      if (targetUnit != nullptr && !targetUnit->IsDead() && !mIsCarrier) {
        targetUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
      }
    }

    bool targetIsCarrier = false;
    if (targetUnit != nullptr && !targetUnit->IsDead()) {
      targetIsCarrier = targetUnit->IsInCategory("CARRIER");
    }

    if (targetIsCarrier) {
      targetUnit->AiTransport->TransportResetReservation();
    }

    *mDispatchResult = static_cast<EAiResult>(1);
    mTargetUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00622680 (FUN_00622680, Moho::CUnitRefuel::MemberDeserialize)
   *
   * What it does:
   * Reads `CCommandTask` base state, then reads target weak pointer and
   * refuel-mode booleans from archive lanes.
   */
  void CUnitRefuel::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef baseRef{};
    archive->Read(CachedCCommandTaskType(), this, baseRef);

    const gpg::RRef targetRef{};
    archive->Read(CachedWeakPtrUnitType(), &mTargetUnit, targetRef);

    archive->ReadBool(&mHasTransportReservation);
    archive->ReadBool(&mIsCarrier);
  }

  /**
   * Address: 0x00622710 (FUN_00622710, Moho::CUnitRefuel::MemberSerialize)
   *
   * What it does:
   * Writes `CCommandTask` base state, then writes target weak pointer and
   * refuel-mode booleans into archive lanes.
   */
  void CUnitRefuel::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef baseRef{};
    archive->Write(CachedCCommandTaskType(), this, baseRef);

    const gpg::RRef targetRef{};
    archive->Write(CachedWeakPtrUnitType(), &mTargetUnit, targetRef);

    archive->WriteBool(mHasTransportReservation);
    archive->WriteBool(mIsCarrier);
  }

  int CUnitRefuel::Execute()
  {
    return -1;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006224D0 (FUN_006224D0, gpg::RRef_CUnitRefuel)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitRefuel*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitRefuel(gpg::RRef* const outRef, moho::CUnitRefuel* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitRefuelType());
    return outRef;
  }
} // namespace gpg

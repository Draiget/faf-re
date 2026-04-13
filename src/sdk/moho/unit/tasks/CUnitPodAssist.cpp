#include "moho/unit/tasks/CUnitPodAssist.h"

#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiTransport.h"
#include "moho/entity/EntityFastVectorReflection.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitPodAssistType()
  {
    gpg::RType* type = moho::CUnitPodAssist::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitPodAssist));
      moho::CUnitPodAssist::sType = type;
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
  gpg::RType* CUnitPodAssist::sType = nullptr;

  /**
   * Address: 0x0061D3B0 (FUN_0061D3B0, ??0CUnitPodAssist@Moho@@QAE@@Z)
   */
  CUnitPodAssist::CUnitPodAssist(
    CCommandTask* const dispatchTask
  )
    : CCommandTask(dispatchTask)
    , mDispatchTask(dispatchTask)
    , mAssistTarget{}
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= (1ull << UNITSTATE_AssistingCommander);
    }

    Unit* const creatorUnit = (mUnit != nullptr) ? mUnit->CreatorRef.ResolveObjectPtr<Unit>() : nullptr;
    mAssistTarget.ResetFromObject(creatorUnit);

    bool detachAssistTarget = true;
    Unit* const assistTarget = mAssistTarget.GetObjectPtr();
    if (assistTarget != nullptr) {
      detachAssistTarget = !assistTarget->IsInCategory("PODSTAGINGPLATFORM");
    }

    if (detachAssistTarget) {
      mAssistTarget.ResetFromObject(nullptr);
    }

    mTaskState = TASKSTATE_Waiting;
  }

  /**
   * Address: 0x0061D7D0 (FUN_0061D7D0, Moho::CUnitPodAssist::operator new)
   */
  CUnitPodAssist* CUnitPodAssist::Create(
    CCommandTask* const dispatchTask
  )
  {
    return new (std::nothrow) CUnitPodAssist(dispatchTask);
  }

  /**
   * Address: 0x0061D4F0 (FUN_0061D4F0, ??1CUnitPodAssist@Moho@@QAE@@Z)
   */
  CUnitPodAssist::~CUnitPodAssist()
  {
    Kill();
    mUnit->UnitStateMask &= ~(1ull << UNITSTATE_AssistingCommander);
    mAssistTarget.UnlinkFromOwnerChain();
  }

  int CUnitPodAssist::Execute()
  {
    return 1;
  }

  /**
   * Address: 0x0061D820 (FUN_0061D820, Moho::CUnitPodAssist::Kill)
   *
   * What it does:
   * Stops active pod-assist motion/transport work, rebinds expired assist
   * target weak-link to creator when needed, and returns this task to
   * preparing state.
   */
  void CUnitPodAssist::Kill()
  {
    if (mUnit->IsMobile()) {
      Unit* const creatorUnit = mUnit->GetCreator();
      if (creatorUnit == nullptr || creatorUnit->IsDead()) {
        mUnit->Kill(nullptr, "", 0.0f);
      } else {
        Unit* const assistTarget = mAssistTarget.GetObjectPtr();
        if (assistTarget == nullptr || assistTarget->IsDead()) {
          mAssistTarget.Set(creatorUnit);
        } else {
          if (mUnit->GetTransportedBy() == assistTarget) {
            IAiTransport* const targetTransport = assistTarget->AiTransport;
            if (targetTransport != nullptr) {
              (void)targetTransport->TransportDetachUnit(mUnit);
            }
          } else {
            IAiTransport* const targetTransport = assistTarget->AiTransport;
            if (targetTransport != nullptr) {
              targetTransport->TransportRemovePickupUnit(mUnit, true);
            }
          }
        }
      }

      if (mUnit->UnitMotion != nullptr) {
        mUnit->UnitMotion->Stop(nullptr);
        mUnit->UnitMotion->mHeight = std::numeric_limits<float>::infinity();
      }

      mTaskState = TASKSTATE_Preparing;
    }
  }

  /**
   * Address: 0x0061D9C0 (FUN_0061D9C0, Moho::CUnitPodAssist::HasNextCommand)
   *
   * What it does:
   * Returns true when owner command queue has at least two entries and the
   * next entry resolves to a live command object.
   */
  bool CUnitPodAssist::HasNextCommand() const
  {
    const msvc8::vector<WeakPtr<CUnitCommand>>& commands = mUnit->CommandQueue->mCommandVec;
    if (commands.size() < 2u) {
      return false;
    }

    return commands[1].GetObjectPtr() != nullptr;
  }

  /**
   * Address: 0x0061E970 (FUN_0061E970, Moho::CUnitPodAssist::MemberDeserialize)
   *
   * What it does:
   * Reads CCommandTask base via cached `CCommandTask` RType, then reads
   * `mDispatchTask` (raw owned ptr) and `mAssistTarget` (WeakPtr<Unit>)
   * from the archive.
   */
  void CUnitPodAssist::MemberDeserialize(
    gpg::ReadArchive* const archive
  )
  {
    const gpg::RRef baseRef{};
    archive->Read(CachedCCommandTaskType(), this, baseRef);

    const gpg::RRef ptrRef{};
    archive->ReadPointer_CCommandTask(&mDispatchTask, &ptrRef);

    const gpg::RRef weakRef{};
    archive->Read(CachedWeakPtrUnitType(), &mAssistTarget, weakRef);
  }

  /**
   * Address: 0x0061EA10 (FUN_0061EA10, Moho::CUnitPodAssist::MemberSerialize)
   *
   * What it does:
   * Writes CCommandTask base via cached RType, then writes `mDispatchTask`
   * as an UNOWNED raw pointer ref, then writes `mAssistTarget` weak ref.
   */
  void CUnitPodAssist::MemberSerialize(
    gpg::WriteArchive* const archive
  ) const
  {
    const gpg::RRef baseRef{};
    archive->Write(CachedCCommandTaskType(), const_cast<CUnitPodAssist*>(this), baseRef);

    gpg::RRef ptrRef{};
    (void)gpg::RRef_CCommandTask(&ptrRef, mDispatchTask);
    gpg::WriteRawPointer(archive, ptrRef, gpg::TrackedPointerState::Unowned, baseRef);

    const gpg::RRef weakRef{};
    archive->Write(CachedWeakPtrUnitType(), const_cast<WeakPtr<Unit>*>(&mAssistTarget), weakRef);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061E7C0 (FUN_0061E7C0, gpg::RRef_CUnitPodAssist)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitPodAssist*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitPodAssist(gpg::RRef* const outRef, moho::CUnitPodAssist* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitPodAssistType());
    return outRef;
  }
} // namespace gpg

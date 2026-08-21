#include "moho/unit/tasks/CUnitWaitForFerryTask.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitCallTransport.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskWaitForFerry = (1ull << 21);

  // Advances a wait-for-ferry task state by one step, matching the binary's
  // `++this->mTaskState` increments seen in FUN_0060FCA0.
  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] gpg::RType* CachedCUnitWaitForFerryTaskType()
  {
    gpg::RType* type = moho::CUnitWaitForFerryTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitWaitForFerryTask));
      moho::CUnitWaitForFerryTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskTypeForFerrySerializer()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitTypeForFerrySerializer()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSNavGoalTypeForFerrySerializer()
  {
    gpg::RType* type = moho::SNavGoal::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SNavGoal));
      moho::SNavGoal::sType = type;
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
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
}

namespace moho
{
  gpg::RType* CUnitWaitForFerryTask::sType = nullptr;

  /**
   * Address: 0x0060FAA0 (FUN_0060FAA0, Moho::CUnitWaitForFerryTask::CUnitWaitForFerryTask)
   * Mangled: ??0CUnitWaitForFerryTask@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes wait-for-ferry task state from dispatch context, stores ferry
   * unit weak-link ownership, snapshots move goal payload, and sets owner unit
   * focus/state for ferry assignment.
   */
  CUnitWaitForFerryTask::CUnitWaitForFerryTask(
    Unit* const ferryUnit,
    IAiCommandDispatchImpl* const dispatch,
    const SNavGoal& moveGoal
  )
    : CCommandTask(static_cast<CCommandTask*>(dispatch))
    , mDispatch(dispatch)
    , mFerryUnit()
    , mMoveGoal(moveGoal)
  {
    mFerryUnit.Set(ferryUnit);

    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      ownerUnit->UnitStateMask |= kUnitStateMaskWaitForFerry;
      ownerUnit->SetFocusEntity(ferryUnit);
    }
  }

  /**
   * Address: 0x0060FB90 (FUN_0060FB90, Moho::CUnitWaitForFerryTask::~CUnitWaitForFerryTask)
   * Address: 0x0060FA80 (FUN_0060FA80, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   * Mangled: ??1CUnitWaitForFerryTask@Moho@@QAE@@Z
   *
   * What it does:
   * Clears owner assigned-transport/focus weak-link lanes, frees pending
   * occupancy-grid reservation, and drops wait-for-ferry state ownership.
   */
  CUnitWaitForFerryTask::~CUnitWaitForFerryTask()
  {
    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      ownerUnit->AssignedTransportRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
      ownerUnit->SetFocusEntity(nullptr);
      ownerUnit->FreeOgridRect();
      ownerUnit->UnitStateMask &= ~kUnitStateMaskWaitForFerry;
    }

    mFerryUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060FCA0 (FUN_0060FCA0, Moho::CUnitWaitForFerryTask::TaskTick)
   * VFTable SLOT: 1 (CTask::Execute)
   *
   * IDA signature:
   * int __thiscall Moho::CUnitWaitForFerryTask::TaskTick(Moho::CUnitWaitForFerryTask *this);
   *
   * What it does:
   * Per-tick state machine for the wait-for-ferry command lane.
   *
   * Preface: resolve `mFerryUnit` to a live `Unit*`; if the ferry weak slot is
   * empty/sentinel, or the resolved unit is dead, abort with -1.
   *
   * Per-state dispatch on `mTaskState`:
   *   - TASKSTATE_Preparing: capture the ferry beacon position, plan owner unit
   *     movement to that position (`Unit::PrepareMove`), reserve the destination
   *     O-grid rectangle, build a one-cell `SNavGoal` from the destination
   *     footprint cell, and queue a child `NewMoveTask` driving `mDispatch`.
   *     Advance state and return 1.
   *   - TASKSTATE_Waiting: release the staging O-grid reservation
   *     (`Unit::FreeOgridRect`), advance state, and return 0 so the scheduler
   *     re-enters next tick.
   *   - TASKSTATE_Starting: when the owner unit is NOT in `UNITSTATE_Attached`
   *     and its `Unit::GetFerryUnit()` (a.k.a. `AssignedTransportRef`) resolves
   *     to a unit categorised as `TRANSPORTATION`, queue
   *     `NewCallTransportCommand(mDispatch, ferryUnit)`, advance state, return 1.
   *     Otherwise fall through to the default scheduler delay return (10).
   *   - TASKSTATE_Processing: if the owner unit lost its transport carrier
   *     (`Unit::GetTransportedBy()` is null), abort with -1; otherwise fall
   *     through to the default scheduler delay return (10).
   *   - default: return 10 (idle scheduler delay).
   */
  int CUnitWaitForFerryTask::Execute()
  {
    Unit* const ferryUnit = mFerryUnit.GetObjectPtr();
    if (ferryUnit == nullptr || ferryUnit->IsDead()) {
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        Wm3::Vector3f targetPos = ferryUnit->GetPosition();

        CArmyImpl* const ownerArmy = mUnit->ArmyRef;
        const bool useWholeMap = (ownerArmy != nullptr) ? ownerArmy->UseWholeMap() : false;

        gpg::Rect2f skirtRect = ferryUnit->GetSkirtRect();
        (void)mUnit->PrepareMove(0, &targetPos, &skirtRect, useWholeMap);

        const SCoordsVec2 reserveCenterXZ{targetPos.x, targetPos.z};
        gpg::Rect2i reserveRect{};
        (void)COORDS_ToGridRect(&reserveRect, reserveCenterXZ, mUnit->GetFootprint());
        mUnit->ReserveOgridRect(reserveRect);

        const SOCellPos destCell = mUnit->GetFootprint().ToCellPos(targetPos);
        NewMoveTask(SNavGoal(destCell), mDispatch, 0, nullptr, 0);

        mTaskState = NextTaskState(mTaskState);
        return 1;
      }

      case TASKSTATE_Waiting: {
        mUnit->FreeOgridRect();
        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Starting: {
        bool shouldStartTransport = false;
        if (!mUnit->IsUnitState(UNITSTATE_Attached)) {
          if (Unit* const assignedFerry = mUnit->GetFerryUnit(); assignedFerry != nullptr) {
            if (assignedFerry->Entity::IsInCategory("TRANSPORTATION")) {
              shouldStartTransport = true;
            }
          }
        }

        if (!shouldStartTransport) {
          return 10;
        }

        Unit* const assignedFerry = mUnit->GetFerryUnit();
        NewCallTransportCommand(mDispatch, assignedFerry);
        mTaskState = NextTaskState(mTaskState);
        return 1;
      }

      case TASKSTATE_Processing: {
        if (mUnit->GetTransportedBy() == nullptr) {
          return -1;
        }
        return 10;
      }

      default:
        return 10;
    }
  }

  /**
   * Address: 0x0060FF50 (FUN_0060FF50, Moho::CUnitWaitForFerryTask::operator new)
   * Mangled: ??2CUnitWaitForFerryTask@Moho@@QAE@@Z
   *
   * What it does:
   * Allocates one wait-for-ferry task object and forwards dispatch, move-goal,
   * and ferry-unit context into in-place construction.
   */
  CUnitWaitForFerryTask* CUnitWaitForFerryTask::Create(
    IAiCommandDispatchImpl* const dispatch,
    const SNavGoal& moveGoal,
    Unit* const ferryUnit
  )
  {
    void* const storage = ::operator new(sizeof(CUnitWaitForFerryTask));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitWaitForFerryTask(ferryUnit, dispatch, moveGoal);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x00610D30 (FUN_00610D30, Moho::CUnitWaitForFerryTaskSerializer::Serialize body)
   *
   * IDA signature:
   * void __usercall sub_610D30(Moho::CUnitWaitForFerryTask *a1@<eax>, BinaryWriteArchive *a2@<edi>);
   *
   * What it does:
   * Writes wait-for-ferry task state to an archive in binary lane order:
   *   1. base `CCommandTask` subobject (by reflected type).
   *   2. raw `CCommandTask* mDispatch` as `unowned` tracked-pointer.
   *   3. `WeakPtr<Unit> mFerryUnit` slot (by reflected type).
   *   4. `SNavGoal mMoveGoal` slot (by reflected type).
   */
  void CUnitWaitForFerryTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(
      CachedCCommandTaskTypeForFerrySerializer(),
      static_cast<const CCommandTask*>(this),
      ownerRef
    );

    gpg::RRef dispatchRef{};
    (void)gpg::RRef_CCommandTask(&dispatchRef, static_cast<CCommandTask*>(mDispatch));
    gpg::WriteRawPointer(archive, dispatchRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrUnitTypeForFerrySerializer(), &mFerryUnit, ownerRef);
    archive->Write(CachedSNavGoalTypeForFerrySerializer(), &mMoveGoal, ownerRef);
  }

  /**
   * Address: 0x00610C60 (FUN_00610C60, Moho::CUnitWaitForFerryTask::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall sub_610C60(
   *   Moho::CCommandTask **obj@<ecx>, gpg::ReadArchive *a2@<eax>);
   *
   * What it does:
   * Loads wait-for-ferry task state from an archive in binary lane order:
   *   1. base `CCommandTask` subobject (by reflected type).
   *   2. raw `CCommandTask* mDispatch` via `ReadPointer_CCommandTask`.
   *   3. `WeakPtr<Unit> mFerryUnit` slot (by reflected type).
   *   4. `SNavGoal mMoveGoal` slot (by reflected type).
   */
  void CUnitWaitForFerryTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(
      CachedCCommandTaskTypeForFerrySerializer(),
      static_cast<CCommandTask*>(this),
      ownerRef
    );

    // Dispatch back-pointer arrives as an unowned tracked pointer. Because
    // `IAiCommandDispatchImpl` has `CCommandTask` as its first base, the
    // storage at `&mDispatch` aliases the `CCommandTask*` slot the binary
    // writes into (same address, identity conversion).
    static_assert(
      offsetof(CUnitWaitForFerryTask, mDispatch) == 0x30,
      "CUnitWaitForFerryTask::mDispatch offset must be 0x30"
    );
    archive->ReadPointer_CCommandTask(reinterpret_cast<CCommandTask**>(&mDispatch), &ownerRef);

    archive->Read(CachedWeakPtrUnitTypeForFerrySerializer(), &mFerryUnit, ownerRef);
    archive->Read(CachedSNavGoalTypeForFerrySerializer(), &mMoveGoal, ownerRef);
  }
} // namespace moho

namespace
{
  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes, matching every other SerHelperBase-derived serializer in
  // this codebase); `gpg::SerSaveLoadHelperListRuntime` only models the
  // leading 0x0C-byte intrusive-list header shared by all of them.
  struct CUnitWaitForFerryTaskSerializerHelperNode
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(CUnitWaitForFerryTaskSerializerHelperNode, mNext) == 0x04,
    "CUnitWaitForFerryTaskSerializerHelperNode::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTaskSerializerHelperNode, mPrev) == 0x08,
    "CUnitWaitForFerryTaskSerializerHelperNode::mPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTaskSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "CUnitWaitForFerryTaskSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitWaitForFerryTaskSerializerHelperNode, mSerSaveFunc) == 0x10,
    "CUnitWaitForFerryTaskSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitWaitForFerryTaskSerializerHelperNode) == 0x14,
    "CUnitWaitForFerryTaskSerializerHelperNode size must be 0x14"
  );

  CUnitWaitForFerryTaskSerializerHelperNode gCUnitWaitForFerryTaskSerializer{};

  [[nodiscard]] gpg::SerSaveLoadHelperListRuntime& AsSerSaveLoadHelperListRuntime(
    CUnitWaitForFerryTaskSerializerHelperNode& helper
  ) noexcept
  {
    return *reinterpret_cast<gpg::SerSaveLoadHelperListRuntime*>(&helper);
  }

  /**
   * Address: 0x0060F9E0 (FUN_0060F9E0)
   *
   * What it does:
   * Unlinks `CUnitWaitForFerryTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitWaitForFerryTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gCUnitWaitForFerryTaskSerializer));
  }

  /**
   * Address: 0x0060FA10 (FUN_0060FA10)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitWaitForFerryTaskSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitWaitForFerryTaskSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(AsSerSaveLoadHelperListRuntime(gCUnitWaitForFerryTaskSerializer));
  }

  /**
   * Address: 0x0060F990 (FUN_0060F990, Moho::CUnitWaitForFerryTaskSerializer::Deserialize)
   * Address: 0x00610590 (FUN_00610590, COMDAT/jmp alias)
   * Address: 0x00610630 (FUN_00610630, COMDAT/jmp alias)
   *
   * What it does:
   * Serializer-load callback registered with the reflected
   * `Moho::CUnitWaitForFerryTask` type. Forwards the reflected object
   * pointer into `CUnitWaitForFerryTask::MemberDeserialize` (FUN_00610C60
   * body); `version` and the owner-ref lane are unused by the member
   * (mirrors the binary tail-jump).
   */
  void DeserializeCUnitWaitForFerryTaskSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitWaitForFerryTask*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0060F9A0 (FUN_0060F9A0, Moho::CUnitWaitForFerryTaskSerializer::Serialize)
   * Address: 0x006105A0 (FUN_006105A0, COMDAT/jmp alias)
   * Address: 0x00610640 (FUN_00610640, COMDAT/jmp alias)
   *
   * What it does:
   * Serializer-save callback registered with the reflected
   * `Moho::CUnitWaitForFerryTask` type. Forwards the reflected object
   * pointer into `CUnitWaitForFerryTask::MemberSerialize` (FUN_00610D30
   * body); `version` and the owner-ref lane are unused by the member
   * (mirrors the binary tail-jump).
   */
  void SerializeCUnitWaitForFerryTaskSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const task = reinterpret_cast<moho::CUnitWaitForFerryTask*>(objectPtr);
    if (task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF9E30 (FUN_00BF9E30, Moho::CUnitWaitForFerryTaskSerializer::~CUnitWaitForFerryTaskSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `CUnitWaitForFerryTaskSerializer`
   * helper node, matching the sibling unlink lanes used across other
   * serializer registrars.
   */
  void cleanup_CUnitWaitForFerryTaskSerializer_atexit()
  {
    (void)UnlinkCUnitWaitForFerryTaskSerializerNodePrimary();
  }

  /**
   * Address: 0x00BD0960 (FUN_00BD0960, register_CUnitWaitForFerryTaskSerializer)
   *
   * What it does:
   * Initializes the global `CUnitWaitForFerryTask` serializer helper's
   * load/save callback lanes (self-linking the intrusive helper node) and
   * installs process-exit cleanup via `atexit`.
   */
  void register_CUnitWaitForFerryTaskSerializer()
  {
    gpg::SerHelperBase* const self =
      reinterpret_cast<gpg::SerHelperBase*>(&gCUnitWaitForFerryTaskSerializer.mNext);
    gCUnitWaitForFerryTaskSerializer.mNext = self;
    gCUnitWaitForFerryTaskSerializer.mPrev = self;
    gCUnitWaitForFerryTaskSerializer.mSerLoadFunc = &DeserializeCUnitWaitForFerryTaskSerializerCallback;
    gCUnitWaitForFerryTaskSerializer.mSerSaveFunc = &SerializeCUnitWaitForFerryTaskSerializerCallback;
    (void)std::atexit(&cleanup_CUnitWaitForFerryTaskSerializer_atexit);
  }

  struct CUnitWaitForFerryTaskSerializerStartupBootstrap
  {
    CUnitWaitForFerryTaskSerializerStartupBootstrap()
    {
      register_CUnitWaitForFerryTaskSerializer();
    }
  };

  [[maybe_unused]] CUnitWaitForFerryTaskSerializerStartupBootstrap gCUnitWaitForFerryTaskSerializerStartupBootstrap;
} // namespace

namespace gpg
{
  /**
   * Address: 0x00610800 (FUN_00610800, gpg::RRef_CUnitWaitForFerryTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitWaitForFerryTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitWaitForFerryTask(gpg::RRef* const outRef, moho::CUnitWaitForFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitWaitForFerryTaskType());
    return outRef;
  }

  /**
   * Address: 0x006105E0 (FUN_006105E0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary
   * `RRef_CUnitWaitForFerryTask` and copies object/type fields into the
   * destination reference record.
   */
  gpg::RRef* AssignCUnitWaitForFerryTaskRef(gpg::RRef* const outRef, moho::CUnitWaitForFerryTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitWaitForFerryTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg

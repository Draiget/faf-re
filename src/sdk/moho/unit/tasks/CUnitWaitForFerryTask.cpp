#include "moho/unit/tasks/CUnitWaitForFerryTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskWaitForFerry = (1ull << 21);

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
  gpg::SerSaveLoadHelperListRuntime gCUnitWaitForFerryTaskSerializer{};

  /**
   * Address: 0x0060F9E0 (FUN_0060F9E0)
   *
   * What it does:
   * Unlinks `CUnitWaitForFerryTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitWaitForFerryTaskSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitWaitForFerryTaskSerializer);
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
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitWaitForFerryTaskSerializer);
  }

  /**
   * Address: 0x0060F9A0 (FUN_0060F9A0, Moho::CUnitWaitForFerryTaskSerializer::Serialize)
   * Address: 0x006105A0 (FUN_006105A0, COMDAT/jmp alias)
   * Address: 0x00610640 (FUN_00610640, COMDAT/jmp alias)
   *
   * What it does:
   * Serializer-save callback registered with the reflected
   * `Moho::CUnitWaitForFerryTask` type. Forwards one `(task, archive)` pair
   * into `CUnitWaitForFerryTask::MemberSerialize` (FUN_00610D30 body).
   */
  void CUnitWaitForFerryTaskSerializerSave(
    gpg::WriteArchive* const archive,
    const moho::CUnitWaitForFerryTask* const task
  )
  {
    if (task != nullptr) {
      task->MemberSerialize(archive);
    }
  }

  using CUnitWaitForFerryTaskSerializerSaveFn =
    void (*)(gpg::WriteArchive*, const moho::CUnitWaitForFerryTask*);

  // ODR-used function-pointer anchor. Its volatile-store ensures the
  // serializer-save callback participates in link-time symbol resolution
  // and cannot be stripped. The original binary wires this exact callback
  // pointer into the reflected serializer helper chain through
  // `Moho::CUnitWaitForFerryTaskSerializer::Serialize` (FUN_0060F9A0).
  CUnitWaitForFerryTaskSerializerSaveFn volatile gCUnitWaitForFerryTaskSerializerSaveCallback =
    &CUnitWaitForFerryTaskSerializerSave;

  /**
   * Address: 0x0060F990 (FUN_0060F990, Moho::CUnitWaitForFerryTaskSerializer::Deserialize)
   * Address: 0x00610590 (FUN_00610590, COMDAT/jmp alias)
   * Address: 0x00610630 (FUN_00610630, COMDAT/jmp alias)
   *
   * What it does:
   * Serializer-load callback registered with the reflected
   * `Moho::CUnitWaitForFerryTask` type. Forwards one `(task, archive)` pair
   * into `CUnitWaitForFerryTask::MemberDeserialize` (FUN_00610C60 body).
   */
  void CUnitWaitForFerryTaskSerializerLoad(
    gpg::ReadArchive* const archive,
    moho::CUnitWaitForFerryTask* const task
  )
  {
    if (task != nullptr) {
      task->MemberDeserialize(archive);
    }
  }

  using CUnitWaitForFerryTaskSerializerLoadFn =
    void (*)(gpg::ReadArchive*, moho::CUnitWaitForFerryTask*);

  // ODR-used function-pointer anchor for the deserialize callback so link
  // resolution preserves the symbol. The original binary wires this exact
  // callback into the reflected serializer helper chain through
  // `Moho::CUnitWaitForFerryTaskSerializer::Deserialize` (FUN_0060F990).
  CUnitWaitForFerryTaskSerializerLoadFn volatile gCUnitWaitForFerryTaskSerializerLoadCallback =
    &CUnitWaitForFerryTaskSerializerLoad;
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

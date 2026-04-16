#include "CUnitCommandQueue.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/entity/Entity.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* gQueueBaseType = nullptr;
  gpg::RType* gQueueWeakCommandVectorType = nullptr;
  gpg::RType* gQueueCommandTypeEnumType = nullptr;
  gpg::RType* gQueueUnitType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(TObject));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }

  template <class TObject>
  [[nodiscard]] TObject* ReadTrackedPointerAs(gpg::ReadArchive& archive, gpg::RType*& cache)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(&archive, gpg::RRef{});
    if (tracked.object == nullptr) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCachedType<TObject>(cache));
    return static_cast<TObject*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RRef MakeQueueRef(CUnitCommandQueue* const queue)
  {
    gpg::RRef out{};
    out.mObj = queue;
    out.mType = CUnitCommandQueue::StaticGetClass();
    return out;
  }

  [[nodiscard]] bool ShouldMarkOwnerSyncStateForQueueHead(const CUnitCommandQueue& queue)
  {
    if (queue.mCommandVec.empty()) {
      return false;
    }

    const CUnitCommand* const headCommand = queue.mCommandVec.front().GetObjectPtr();
    if (!headCommand) {
      return false;
    }

    switch (headCommand->mVarDat.mCmdType) {
    case EUnitCommandType::UNITCOMMAND_BuildSiloTactical:
    case EUnitCommandType::UNITCOMMAND_BuildSiloNuke:
    case EUnitCommandType::UNITCOMMAND_BuildFactory:
    case EUnitCommandType::UNITCOMMAND_Reclaim:
    case EUnitCommandType::UNITCOMMAND_Repair:
    case EUnitCommandType::UNITCOMMAND_Capture:
    case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
    case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
    case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
    case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
    case EUnitCommandType::UNITCOMMAND_Upgrade:
    case EUnitCommandType::UNITCOMMAND_Dock:
      return true;
    default:
      return false;
    }
  }

  void EmitQueueEvent(CUnitCommandQueue& queue, const EUnitCommandQueueStatus event)
  {
    queue.BroadcastEvent(event);
  }

  void MarkOwningUnitSyncDirty(Unit* const unit)
  {
    if (!unit) {
      return;
    }
    unit->MarkNeedsSyncGameData();
  }

  void ReleaseCommandVectorStorage(msvc8::vector<WeakPtr<CUnitCommand>>& commandVec)
  {
    while (!commandVec.empty()) {
      commandVec.back().ResetFromObject(nullptr);
      commandVec.pop_back();
    }
    commandVec = msvc8::vector<WeakPtr<CUnitCommand>>{};
  }
} // namespace

gpg::RType* CUnitCommandQueue::sType = nullptr;

/**
 * Address: 0x006A4CD0 (FUN_006A4CD0, ??0CUnitCommandQueue@Moho@@QAE@PAVUnit@1@@Z)
 *
 * What it does:
 * Initializes queue owner pointer, command lanes, and queue-head state.
 */
CUnitCommandQueue::CUnitCommandQueue(Unit* const unit)
  : mUnit(unit)
  , mCommandVec()
  , mCommandType(EUnitCommandType::UNITCOMMAND_None)
  , unk0(0)
  , mNeedsRefresh(true)
  , pad_25{0u, 0u, 0u}
{}

/**
 * Address: 0x006A4D40 (FUN_006A4D40, ??1CUnitCommandQueue@Moho@@QAE@XZ)
 *
 * What it does:
 * Clears queued commands, releases weak-command storage, and unlinks the
 * queue from broadcaster intrusive lanes.
 */
CUnitCommandQueue::~CUnitCommandQueue()
{
  ClearCommandQueue();
  ReleaseCommandVectorStorage(mCommandVec);
  ListUnlink();
}

/**
 * Address: 0x006EE8C0 (FUN_006EE8C0,
 * ?MemberSaveConstructArgs@CUnitCommandQueue@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
 *
 * What it does:
 * Saves construct payload (`Unit*` owner) as unowned tracked-pointer data.
 */
void CUnitCommandQueue::MemberSaveConstructArgs(
  gpg::WriteArchive& archive,
  const int,
  const gpg::RRef& ownerRef,
  gpg::SerSaveConstructArgsResult& result
)
{
  gpg::RRef unitRef{};
  unitRef.mObj = mUnit;
  unitRef.mType = mUnit ? ResolveCachedType<Unit>(gQueueUnitType) : nullptr;
  gpg::WriteRawPointer(&archive, unitRef, gpg::TrackedPointerState::Unowned, ownerRef);
  result.SetUnowned(0u);
}

/**
 * Address: 0x006EEAC0 (FUN_006EEAC0,
 * ?MemberConstruct@CUnitCommandQueue@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
 *
 * What it does:
 * Reads construct payload and allocates one `CUnitCommandQueue`.
 */
void CUnitCommandQueue::MemberConstruct(
  gpg::ReadArchive& archive,
  const int,
  const gpg::RRef&,
  gpg::SerConstructResult& result
)
{
  Unit* const ownerUnit = ReadTrackedPointerAs<Unit>(archive, gQueueUnitType);
  CUnitCommandQueue* const queue = new (std::nothrow) CUnitCommandQueue(ownerUnit);
  result.SetUnowned(MakeQueueRef(queue), 0u);
}

/**
 * Address: 0x006F9690 (FUN_006F9690, sub_6F9690)
 *
 * What it does:
 * Loads queue base/vector/type lanes and marks UI refresh state dirty.
 */
void CUnitCommandQueue::MemberDeserialize(gpg::ReadArchive& archive)
{
  gpg::RRef ownerRef{};
  archive.Read(ResolveCachedType<Broadcaster>(gQueueBaseType), this, ownerRef);
  archive.Read(ResolveCachedType<msvc8::vector<WeakPtr<CUnitCommand>>>(gQueueWeakCommandVectorType), &mCommandVec, ownerRef);
  archive.Read(ResolveCachedType<EUnitCommandType>(gQueueCommandTypeEnumType), &mCommandType, ownerRef);

  unsigned int decodedCounter = 0u;
  archive.ReadUInt(&decodedCounter);
  unk0 = static_cast<std::int32_t>(decodedCounter);
  mNeedsRefresh = true;
}

/**
 * Address: 0x006F8D60 (FUN_006F8D60, serializer load thunk alias)
 *
 * What it does:
 * Tail-forwards one CUnitCommandQueue deserialize thunk alias into
 * `CUnitCommandQueue::MemberDeserialize`.
 */
void DeserializeCUnitCommandQueueThunkVariantA(
  const gpg::RRef* const, const int, CUnitCommandQueue* const queue, gpg::ReadArchive* const archive
)
{
  if (!queue || !archive) {
    return;
  }

  queue->MemberDeserialize(*archive);
}

/**
 * Address: 0x006F93B0 (FUN_006F93B0, serializer load thunk alias)
 *
 * What it does:
 * Tail-forwards a second CUnitCommandQueue deserialize thunk alias into
 * `CUnitCommandQueue::MemberDeserialize`.
 */
void DeserializeCUnitCommandQueueThunkVariantB(
  const gpg::RRef* const, const int, CUnitCommandQueue* const queue, gpg::ReadArchive* const archive
)
{
  if (!queue || !archive) {
    return;
  }

  queue->MemberDeserialize(*archive);
}

/**
 * Address: 0x006F9750 (FUN_006F9750, sub_6F9750)
 *
 * What it does:
 * Saves queue base/vector/type lanes and queue local counter lane.
 */
void CUnitCommandQueue::MemberSerialize(gpg::WriteArchive& archive) const
{
  gpg::RRef ownerRef{};
  archive.Write(ResolveCachedType<Broadcaster>(gQueueBaseType), this, ownerRef);
  archive.Write(ResolveCachedType<msvc8::vector<WeakPtr<CUnitCommand>>>(gQueueWeakCommandVectorType), &mCommandVec, ownerRef);
  archive.Write(ResolveCachedType<EUnitCommandType>(gQueueCommandTypeEnumType), &mCommandType, ownerRef);
  archive.WriteUInt(static_cast<unsigned int>(unk0));
}

/**
 * Address: 0x006F8D70 (FUN_006F8D70, serializer save thunk alias)
 *
 * What it does:
 * Tail-forwards one CUnitCommandQueue serialize thunk alias into
 * `CUnitCommandQueue::MemberSerialize`.
 */
void SerializeCUnitCommandQueueThunkVariantA(
  gpg::RRef* const, CUnitCommandQueue* const queue, gpg::WriteArchive* const archive
)
{
  if (!queue || !archive) {
    return;
  }

  queue->MemberSerialize(*archive);
}

/**
 * Address: 0x006F93C0 (FUN_006F93C0, serializer save thunk alias)
 * Address: 0x005958B0 (FUN_005958B0)
 *
 * What it does:
 * Tail-forwards a second CUnitCommandQueue serialize thunk alias into
 * `CUnitCommandQueue::MemberSerialize`.
 */
void SerializeCUnitCommandQueueThunkVariantB(
  gpg::RRef* const, CUnitCommandQueue* const queue, gpg::WriteArchive* const archive
)
{
  if (!queue || !archive) {
    return;
  }

  queue->MemberSerialize(*archive);
}

/**
  * Alias of FUN_006EDAA0 (non-canonical helper lane).
 *
 * What it does:
 * Resolves/refetches reflection descriptor for CUnitCommandQueue.
 */
gpg::RType* CUnitCommandQueue::StaticGetClass()
{
  return ResolveCachedType<CUnitCommandQueue>(sType);
}

/**
 * Address: 0x006EDD30 (FUN_006EDD30)
 *
 * What it does:
 * Finds the first queued command with the requested command id.
 */
int CUnitCommandQueue::FindCommandIndex(const CmdId cmdId) const
{
  for (std::size_t i = 0; i < mCommandVec.size(); ++i) {
    const CUnitCommand* const command = mCommandVec[i].GetObjectPtr();
    if (command && command->mConstDat.cmd == cmdId) {
      return static_cast<int>(i);
    }
  }

  return -1;
}

/**
 * Address: 0x006EDBF0 (FUN_006EDBF0, ?GetCurrentCommand@CUnitCommandQueue@Moho@@QAEPAVCUnitCommand@2@XZ)
 *
 * What it does:
 * Returns the active head command when present.
 */
CUnitCommand* CUnitCommandQueue::GetCurrentCommand()
{
  if (mCommandVec.empty()) {
    return nullptr;
  }

  return mCommandVec.front().GetObjectPtr();
}

/**
 * Address: 0x006EDC20 (FUN_006EDC20, ?GetNextCommand@CUnitCommandQueue@Moho@@QAEPAVCUnitCommand@2@XZ)
 *
 * What it does:
 * Returns the queued command immediately after the head command when present.
 */
CUnitCommand* CUnitCommandQueue::GetNextCommand()
{
  if (mCommandVec.size() < 2u) {
    return nullptr;
  }

  return mCommandVec[1].GetObjectPtr();
}

/**
 * Address: 0x006EDC50 (FUN_006EDC50, ?GetLastCommand@CUnitCommandQueue@Moho@@QAEPAVCUnitCommand@2@XZ)
 *
 * What it does:
 * Returns the current queue-tail command when present.
 */
CUnitCommand* CUnitCommandQueue::GetLastCommand()
{
  if (mCommandVec.empty()) {
    return nullptr;
  }

  return mCommandVec.back().GetObjectPtr();
}

/**
 * Address: 0x006EDC80 (FUN_006EDC80, ?GetCommandInQueue@CUnitCommandQueue@Moho@@QBEPAVCUnitCommand@2@I@Z)
 *
 * What it does:
 * Returns one queued command by index when that slot is valid.
 */
CUnitCommand* CUnitCommandQueue::GetCommandInQueue(const unsigned int index) const
{
  const std::size_t queueIndex = static_cast<std::size_t>(index);
  if (queueIndex >= mCommandVec.size()) {
    return nullptr;
  }

  return mCommandVec[queueIndex].GetObjectPtr();
}

/**
 * Address: 0x00598B90 (FUN_00598B90, ?Finished@CUnitCommandQueue@Moho@@QAE_NXZ)
 *
 * What it does:
 * Returns true when no queued command entries remain.
 */
bool CUnitCommandQueue::Finished() const
{
  return mCommandVec.empty();
}

/**
 * Address: 0x006EDCB0 (FUN_006EDCB0, ?InsertCommandToQueue@CUnitCommandQueue@Moho@@QAEXPAVCUnitCommand@2@H@Z)
 *
 * What it does:
 * Inserts one command into this queue at `index`, updates command digest lanes,
 * marks refresh state, and emits inserted-event.
 */
void CUnitCommandQueue::InsertCommandToQueue(CUnitCommand* const command, const int index)
{
  if (!command || !mUnit) {
    return;
  }

  Sim* const sim = command->mSim;
  if (sim != nullptr) {
    const EntId unitId = mUnit->GetEntityId();
    const CmdId commandId = command->mConstDat.cmd;
    sim->Logf(
      "InsertCommandToQueue, mUnit=0x%08x, cmd=0x%08x\n",
      static_cast<std::uint32_t>(unitId),
      static_cast<std::uint32_t>(commandId)
    );
    sim->mContext.Update(&unitId, sizeof(unitId));
    sim->mContext.Update(&commandId, sizeof(commandId));
  }

  command->AddUnit(mUnit, mCommandVec, index);
  mNeedsRefresh = true;
  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_CommandInserted);
}

/**
 * Address: 0x006EDD80 (FUN_006EDD80, ?AddCommandToQueue@CUnitCommandQueue@Moho@@QAEXPAVCUnitCommand@2@@Z)
 *
 * What it does:
 * Selects insertion lane for one command (including patrol-chain ordering)
 * and forwards into `InsertCommandToQueue`.
 */
void CUnitCommandQueue::AddCommandToQueue(CUnitCommand* const command)
{
  const int queueSize = static_cast<int>(mCommandVec.size());
  int insertIndex = queueSize;

  if (
    command != nullptr && queueSize > 1
    && (command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Patrol
        || command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_FormPatrol)
  ) {
    const CUnitCommand* const head = GetCurrentCommand();
    if (
      head != nullptr && (head->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Patrol
                          || head->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_FormPatrol)
    ) {
      int minSerialIndex = 0;
      std::uint32_t minSerial = std::numeric_limits<std::uint32_t>::max();

      for (int i = 0; i < queueSize; ++i) {
        const CUnitCommand* const queued = mCommandVec[static_cast<std::size_t>(i)].GetObjectPtr();
        if (!queued) {
          continue;
        }

        const std::uint32_t serial = static_cast<std::uint32_t>(queued->mInstanceSerial);
        if (serial < minSerial) {
          minSerial = serial;
          minSerialIndex = i;
        }
      }

      insertIndex = (minSerialIndex > 0) ? minSerialIndex : queueSize;
    }
  }

  InsertCommandToQueue(command, insertIndex);
}

/**
 * Address: 0x006EDE70 (FUN_006EDE70, ?RemoveFirstCommandFromQueue@CUnitCommandQueue@Moho@@QAEXXZ)
 *
 * What it does:
 * Removes the head command and emits needs-refresh/changed events.
 */
void CUnitCommandQueue::RemoveFirstCommandFromQueue()
{
  if (GetCurrentCommand() == nullptr) {
    return;
  }

  if (NeedsUIRefresh()) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  mNeedsRefresh = true;
  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_NeedsRefresh);

  if (CUnitCommand* const command = GetCurrentCommand()) {
    command->RemoveUnit(mUnit, mCommandVec);
    mNeedsRefresh = true;
    EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_Changed);
  }
}

/**
 * Address: 0x006EE260 (FUN_006EE260, ?NeedsUIRefresh@CUnitCommandQueue@Moho@@AAE_NXZ)
 *
 * What it does:
 * Checks whether current queue-head command type requires owner sync/UI
 * refresh signaling during queue-head transitions.
 */
bool CUnitCommandQueue::NeedsUIRefresh()
{
  return ShouldMarkOwnerSyncStateForQueueHead(*this);
}

/**
 * Address: 0x006EDF80 (FUN_006EDF80)
 *
 * What it does:
 * Finds and removes a queued command by pointer identity.
 */
bool CUnitCommandQueue::RemoveCommandFromQueue(const CUnitCommand* command)
{
  for (std::size_t i = 0; i < mCommandVec.size(); ++i) {
    if (mCommandVec[i].GetObjectPtr() == command) {
      return RemoveCommandFromQueue(static_cast<unsigned int>(i));
    }
  }

  return false;
}

/**
 * Address: 0x006EDEF0 (FUN_006EDEF0)
 *
 * What it does:
 * Removes a queued command by index and marks queue refresh state.
 */
bool CUnitCommandQueue::RemoveCommandFromQueue(const unsigned int index)
{
  if (static_cast<std::size_t>(index) >= mCommandVec.size()) {
    return false;
  }

  const std::size_t queueIndex = static_cast<std::size_t>(index);
  if (queueIndex == 0u) {
    if (NeedsUIRefresh()) {
      MarkOwningUnitSyncDirty(mUnit);
    }
    mNeedsRefresh = true;
    EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_NeedsRefresh);
  }

  CUnitCommand* const command = mCommandVec[queueIndex].GetObjectPtr();
  if (command) {
    command->RemoveUnit(mUnit, mCommandVec);
  } else {
    EraseWeakVectorEntry(mCommandVec, queueIndex);
  }

  mNeedsRefresh = true;
  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_Changed);
  return true;
}

/**
 * Address: 0x006EDFC0 (FUN_006EDFC0, ?MoveFirstCommandToBackOfQueue@CUnitCommandQueue@Moho@@QAEXXZ)
 *
 * What it does:
 * Rotates the current queue-head entry to queue tail and emits a reorder event.
 */
void CUnitCommandQueue::MoveFirstCommandToBackOfQueue()
{
  if (mCommandVec.size() <= 1u) {
    return;
  }

  CUnitCommand* const command = mCommandVec.front().GetObjectPtr();
  EraseWeakVectorEntry(mCommandVec, 0u);
  InsertWeakPtrVectorObjectAt(mCommandVec, command, mCommandVec.size());

  mNeedsRefresh = true;
  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_Reordered);
}

/**
 * Address: 0x006EE0B0 (FUN_006EE0B0, ?MoveCommandToBackOfQueue@CUnitCommandQueue@Moho@@QAE_NI@Z)
 *
 * What it does:
 * Finds one queue entry matching the selected command-object identity, moves
 * it to queue tail, and emits one reorder event.
 */
bool CUnitCommandQueue::MoveCommandToBackOfQueue(const unsigned int index)
{
  const std::size_t queueSize = mCommandVec.size();
  const std::size_t requestedIndex = static_cast<std::size_t>(index);
  if (queueSize == 0u || requestedIndex >= queueSize) {
    return false;
  }

  CUnitCommand* const targetCommand = mCommandVec[requestedIndex].GetObjectPtr();

  std::size_t matchedIndex = queueSize;
  for (std::size_t i = 0; i < queueSize; ++i) {
    if (mCommandVec[i].GetObjectPtr() == targetCommand) {
      matchedIndex = i;
      break;
    }
  }

  if (matchedIndex == queueSize) {
    return false;
  }

  EraseWeakVectorEntry(mCommandVec, matchedIndex);
  InsertWeakPtrVectorObjectAt(mCommandVec, targetCommand, mCommandVec.size());

  mNeedsRefresh = true;
  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_Reordered);
  return true;
}

/**
 * Address: 0x006EE220 (FUN_006EE220)
 *
 * What it does:
 * Finds the first queued slot matching `command` and moves that entry to tail.
 */
bool CUnitCommandQueue::MoveCommandToBackOfQueue(const CUnitCommand* const command)
{
  for (std::size_t i = 0; i < mCommandVec.size(); ++i) {
    if (mCommandVec[i].GetObjectPtr() == command) {
      return MoveCommandToBackOfQueue(static_cast<unsigned int>(i));
    }
  }

  return false;
}

/**
 * Address: 0x006EE2D0 (FUN_006EE2D0)
 *
 * What it does:
 * Clears queued commands in reverse order, marks owner sync dirty when needed,
 * and resets queue-local cleanup state.
 */
void CUnitCommandQueue::ClearCommandQueue()
{
  if (NeedsUIRefresh()) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_Cleared);

  while (!mCommandVec.empty()) {
    CUnitCommand* const command = mCommandVec.back().GetObjectPtr();
    if (command) {
      command->RemoveUnit(mUnit, mCommandVec);
    } else {
      EraseWeakVectorEntry(mCommandVec, mCommandVec.size() - 1u);
    }
  }

  mCommandType = EUnitCommandType::UNITCOMMAND_None;
  mNeedsRefresh = true;
}

/**
  * Alias of FUN_006EE2D0 (non-canonical helper lane).
 *
 * What it does:
 * Runs pre-destroy queue cleanup only.
 */
void CUnitCommandQueue::MarkForUnitKillCleanup()
{
  ClearCommandQueue();
}

/**
  * Alias of FUN_006A4D40 (non-canonical helper lane).
 *
 * What it does:
 * Runs full queue teardown (clear + vector storage release + broadcaster unlink reset).
 */
void CUnitCommandQueue::DestroyForUnitKillCleanup()
{
  ClearCommandQueue();
  ReleaseCommandVectorStorage(mCommandVec);
  ListUnlink();
}

/**
 * Address: 0x006EE360 (FUN_006EE360, ?AbortActiveTask@CUnitCommandQueue@Moho@@QAEXXZ)
 *
 * What it does:
 * Marks queue refresh state and emits one needs-refresh event.
 */
void CUnitCommandQueue::AbortActiveTask()
{
  if (NeedsUIRefresh()) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  mNeedsRefresh = true;
  EmitQueueEvent(*this, EUnitCommandQueueStatus::UCQS_NeedsRefresh);
}

/**
 * Address: 0x006EE3C0 (FUN_006EE3C0, ?SetCommandCount@CUnitCommandQueue@Moho@@QAEXII@Z)
 *
 * What it does:
 * Sets queued-command count data for one slot, marks command dirty state, and
 * applies zero-count head/removal transitions.
 */
void CUnitCommandQueue::SetCommandCount(const unsigned int index, const unsigned int count)
{
  CUnitCommand* const command = GetCommandInQueue(index);
  if (!command) {
    mNeedsRefresh = true;
    return;
  }

  command->mVarDat.mCount = static_cast<std::int32_t>(count);
  command->mNeedsUpdate = true;

  if (index == 0u) {
    if (count == 0u) {
      AbortActiveTask();
    }
    mNeedsRefresh = true;
    return;
  }

  if (count == 0u) {
    CUnitCommandQueue* const ownerQueue = (mUnit != nullptr) ? mUnit->CommandQueue : this;
    if (ownerQueue != nullptr) {
      (void)ownerQueue->RemoveCommandFromQueue(index);
    }
  }

  mNeedsRefresh = true;
}

/**
 * Address: 0x006EE470 (FUN_006EE470)
 *
 * What it does:
 * Rebinds one queued command target from `targetEntity` and marks this queue
 * refresh lane dirty.
 */
void CUnitCommandQueue::SetCommandTarget(const unsigned int index, Entity* const targetEntity)
{
  if (targetEntity == nullptr || targetEntity->Dead != 0u) {
    return;
  }

  CUnitCommand* const command = GetCommandInQueue(index);
  if (command == nullptr) {
    return;
  }

  CAiTarget targetPayload{};
  (void)targetPayload.UpdateTarget(targetEntity);
  command->SetTarget(targetPayload);
  mNeedsRefresh = true;
}

/**
 * Address: 0x006A4DD0 (FUN_006A4DD0)
 *
 * What it does:
 * Returns whether this queue has a pending refresh lane.
 */
bool CUnitCommandQueue::IsRefreshPending() const
{
  return mNeedsRefresh;
}

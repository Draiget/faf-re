#include "CUnitCommandQueue.h"

#include <cstddef>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/Unit.h"

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

  void RefreshQueueHeadType(CUnitCommandQueue& queue)
  {
    if (queue.mCommandVec.empty()) {
      queue.mCommandType = EUnitCommandType::UNITCOMMAND_None;
      return;
    }

    CUnitCommand* const headCommand = queue.mCommandVec.front().GetObjectPtr();
    queue.mCommandType = headCommand ? headCommand->mVarDat.mCmdType : EUnitCommandType::UNITCOMMAND_None;
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
 * Address: 0x006EDAA0 (FUN_006EDAA0, constructor preregisters RTTI)
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
 * Address: 0x006EDF80 (FUN_006EDF80)
 *
 * What it does:
 * Finds and removes a queued command by pointer identity.
 */
bool CUnitCommandQueue::RemoveCommandFromQueue(const CUnitCommand* command)
{
  for (std::size_t i = 0; i < mCommandVec.size(); ++i) {
    if (mCommandVec[i].GetObjectPtr() == command) {
      return RemoveCommandFromQueue(static_cast<int>(i));
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
bool CUnitCommandQueue::RemoveCommandFromQueue(const int index)
{
  if (index < 0 || static_cast<std::size_t>(index) >= mCommandVec.size()) {
    return false;
  }

  const std::size_t queueIndex = static_cast<std::size_t>(index);
  if (queueIndex == 0u && ShouldMarkOwnerSyncStateForQueueHead(*this)) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  CUnitCommand* const command = mCommandVec[queueIndex].GetObjectPtr();
  if (command) {
    command->RemoveUnit(mUnit, mCommandVec);
  } else {
    EraseWeakVectorEntry(mCommandVec, queueIndex);
  }

  RefreshQueueHeadType(*this);
  mNeedsRefresh = true;
  return true;
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
  if (ShouldMarkOwnerSyncStateForQueueHead(*this)) {
    MarkOwningUnitSyncDirty(mUnit);
  }

  while (!mCommandVec.empty()) {
    CUnitCommand* const command = mCommandVec.back().GetObjectPtr();
    if (command) {
      command->RemoveUnit(mUnit, mCommandVec);
    } else {
      EraseWeakVectorEntry(mCommandVec, mCommandVec.size() - 1u);
    }
  }

  mCommandType = EUnitCommandType::UNITCOMMAND_None;
  unk0 = 0;
  mNeedsRefresh = true;
}

/**
 * Address: 0x006EE2D0 (FUN_006EE2D0)
 *
 * What it does:
 * Runs pre-destroy queue cleanup only.
 */
void CUnitCommandQueue::MarkForUnitKillCleanup()
{
  ClearCommandQueue();
}

/**
 * Address: 0x006A4D40 (FUN_006A4D40)
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

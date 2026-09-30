
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/EAiAttackerEvent.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "legacy/containers/Vector.h"

using namespace moho;

namespace
{
  using WeaponPointerVector = msvc8::vector<moho::UnitWeapon*>;
  using AcquireTargetTaskPointerVector = msvc8::vector<moho::CAcquireTargetTask*>;

  template <typename T>
  void ResizePointerVector(msvc8::vector<T*>& storage, const unsigned int count)
  {
    storage.clear();
    storage.resize(static_cast<std::size_t>(count));
    for (T*& value : storage) {
      value = nullptr;
    }
  }

  [[nodiscard]] gpg::RType* CachedIAiAttackerType()
  {
    gpg::RType* cached = moho::IAiAttacker::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IAiAttacker));
      moho::IAiAttacker::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCTaskStageType()
  {
    gpg::RType* cached = moho::CTaskStage::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CTaskStage));
      moho::CTaskStage::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrCTaskThreadType()
  {
    gpg::RType* cached = moho::WeakPtr<moho::CTaskThread>::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::CTaskThread>));
      moho::WeakPtr<moho::CTaskThread>::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* cached = moho::CAiTarget::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAiTarget));
      moho::CAiTarget::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEAiAttackerEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EAiAttackerEvent));
    }
    return cached;
  }

} // namespace

/**
 * Address: 0x005D85B0 (FUN_005D85B0, Moho::CAiAttackerImpl::DeserializePointerVectors)
 *
 * What it does:
 * Loads owned `UnitWeapon*` and `CAcquireTargetTask*` pointer vectors from the
 * archive and rewrites vector lanes to match serialized counts.
 */
void CAiAttackerImpl::DeserializePointerVectors(gpg::ReadArchive* const archive, CAiAttackerImpl* const object)
{
  if (!archive || !object) {
    return;
  }


  unsigned int weaponCount = 0;
  archive->ReadUInt(&weaponCount);
  ResizePointerVector(object->mWeapons, weaponCount);

  for (unsigned int i = 0; i < weaponCount; ++i) {
    gpg::RRef ownerRef{};
    archive->ReadPointerOwned(&object->mWeapons[static_cast<std::size_t>(i)], &ownerRef);
  }

  unsigned int taskCount = 0;
  archive->ReadUInt(&taskCount);
  ResizePointerVector(object->mTasks, taskCount);

  for (unsigned int i = 0; i < taskCount; ++i) {
    gpg::RRef ownerRef{};
    archive->ReadPointerOwned(&object->mTasks[static_cast<std::size_t>(i)], &ownerRef);
  }
}

/**
 * Address: 0x005D84E0 (FUN_005D84E0, Moho::CAiAttackerImpl::SerializePointerVectors)
 *
 * What it does:
 * Saves owned `UnitWeapon*` and `CAcquireTargetTask*` pointer vectors using
 * tracked-pointer ownership mode.
 */
void CAiAttackerImpl::SerializePointerVectors(gpg::WriteArchive* const archive, const CAiAttackerImpl* const object)
{
  if (!archive || !object) {
    return;
  }

  const gpg::RRef ownerRef{};

  const unsigned int weaponCount = static_cast<unsigned int>(object->mWeapons.size());
  archive->WriteUInt(weaponCount);
  for (unsigned int i = 0; i < weaponCount; ++i) {
    archive->WritePointer<moho::UnitWeapon>(object->mWeapons[static_cast<std::size_t>(i)], gpg::TrackedPointerState::Owned, ownerRef);
  }

  const unsigned int taskCount = static_cast<unsigned int>(object->mTasks.size());
  archive->WriteUInt(taskCount);
  for (unsigned int i = 0; i < taskCount; ++i) {
    archive->WritePointer<moho::CAcquireTargetTask>(object->mTasks[static_cast<std::size_t>(i)], gpg::TrackedPointerState::Owned, ownerRef);
  }
}

/**
 * Address: 0x005E13B0 (FUN_005E13B0, Moho::CAiAttackerImpl::MemberDeserialize)
 *
 * What it does:
 * Restores attacker base/interface payload plus serialized member lanes in the
 * original read order.
 */
void CAiAttackerImpl::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  gpg::RType* const attackerType = CachedIAiAttackerType();
  gpg::RType* const stageType = CachedCTaskStageType();
  gpg::RType* const threadType = CachedWeakPtrCTaskThreadType();
  gpg::RType* const targetType = CachedCAiTargetType();
  gpg::RType* const reportingType = CachedEAiAttackerEventType();

  GPG_ASSERT(attackerType != nullptr);
  GPG_ASSERT(stageType != nullptr);
  GPG_ASSERT(threadType != nullptr);
  GPG_ASSERT(targetType != nullptr);
  GPG_ASSERT(reportingType != nullptr);
  if (!attackerType || !stageType || !threadType || !targetType || !reportingType) {
    return;
  }

  const gpg::RRef trackedStageRef(&mStage, stageType);
  (void)archive->TrackPointer(trackedStageRef);

  gpg::RRef ownerRef{};
  archive->Read(attackerType, static_cast<IAiAttacker*>(this), ownerRef);

  ownerRef = gpg::RRef{};
  archive->ReadPointer(&mUnit, &ownerRef);

  DeserializePointerVectors(archive, this);

  ownerRef = gpg::RRef{};
  archive->Read(stageType, &mStage, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Read(threadType, &mThread, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Read(targetType, &mDesiredTarget, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Read(reportingType, &mReportingState, ownerRef);
}

/**
 * Address: 0x005E1520 (FUN_005E1520, Moho::CAiAttackerImpl::MemberSerialize)
 *
 * What it does:
 * Serializes attacker base/interface payload plus serialized member lanes in
 * the original write order.
 */
void CAiAttackerImpl::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  auto* const mutableObject = const_cast<CAiAttackerImpl*>(this);
  gpg::RType* const attackerType = CachedIAiAttackerType();
  gpg::RType* const stageType = CachedCTaskStageType();
  gpg::RType* const threadType = CachedWeakPtrCTaskThreadType();
  gpg::RType* const targetType = CachedCAiTargetType();
  gpg::RType* const reportingType = CachedEAiAttackerEventType();

  GPG_ASSERT(attackerType != nullptr);
  GPG_ASSERT(stageType != nullptr);
  GPG_ASSERT(threadType != nullptr);
  GPG_ASSERT(targetType != nullptr);
  GPG_ASSERT(reportingType != nullptr);
  if (!attackerType || !stageType || !threadType || !targetType || !reportingType) {
    return;
  }

  const gpg::RRef trackedStageRef(&mutableObject->mStage, stageType);
  (void)archive->PreCreatedPtr(trackedStageRef);

  gpg::RRef ownerRef{};
  archive->Write(attackerType, static_cast<const IAiAttacker*>(this), ownerRef);

  archive->WritePointer<moho::Unit>(mUnit, gpg::TrackedPointerState::Unowned, ownerRef);

  SerializePointerVectors(archive, this);

  ownerRef = gpg::RRef{};
  archive->Write(stageType, &mStage, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Write(threadType, &mThread, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Write(targetType, &mDesiredTarget, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Write(reportingType, &mReportingState, ownerRef);
}

// Addresses 0x005DEBB0/0x005E04B0 (deserialize "ThunkA"/"ThunkB" pair) and
// 0x005DEBC0 (serialize "ThunkA") formerly modeled here are dead: zero
// data_refs and zero call_edges in the callgraph index for all three, and no
// source-level caller anywhere in src/sdk/**. `CAiAttackerImplSerializer::
// Deserialize`/`Serialize` below already call `CAiAttackerImpl::
// MemberDeserialize`/`MemberSerialize` directly.

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CAiAttackerImpl>`, vtable 0x00E1EAE4.
   *
   * Address: 0x00BCE8D0 (FUN_00BCE8D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF8430 (FUN_00BF8430 -- the global's destructor.)
   * Address: 0x005D8480 (FUN_005D8480 -- an unreferenced copy of the global's destructor.)
   * Address: 0x005D84B0 (FUN_005D84B0 -- an unreferenced copy of the global's destructor.)
   * Address: 0x005DC0D0 (FUN_005DC0D0 -- `Init`.)
   * Address: 0x005D8430 (FUN_005D8430 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005D8440 (FUN_005D8440 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CAiAttackerImplSerializer : gpg::SerSaveLoadHelper<CAiAttackerImpl>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B01E4 -- process-global `CAiAttackerImplSerializer` singleton.
  moho::CAiAttackerImplSerializer gCAiAttackerImplSerializer;
} // namespace

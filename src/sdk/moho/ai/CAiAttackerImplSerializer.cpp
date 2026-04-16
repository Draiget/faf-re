#include "moho/ai/CAiAttackerImplSerializer.h"

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

  struct CAiAttackerImplSerializationView
  {
    std::uint8_t pad_00[0x40];
    moho::Unit* mUnit;                           // +0x40
    moho::CTaskStage mStage;                     // +0x44
    WeaponPointerVector mWeapons;                // +0x58
    moho::WeakPtr<moho::CTaskThread> mThread;    // +0x68
    AcquireTargetTaskPointerVector mTasks;       // +0x70
    moho::CAiTarget mDesiredTarget;              // +0x80
    moho::EAiAttackerEvent mReportingState;      // +0xA0
  };

  static_assert(offsetof(CAiAttackerImplSerializationView, mUnit) == 0x40, "CAiAttackerImpl::mUnit offset must be 0x40");
  static_assert(offsetof(CAiAttackerImplSerializationView, mStage) == 0x44, "CAiAttackerImpl::mStage offset must be 0x44");
  static_assert(
    offsetof(CAiAttackerImplSerializationView, mWeapons) == 0x58, "CAiAttackerImpl::mWeapons offset must be 0x58"
  );
  static_assert(offsetof(CAiAttackerImplSerializationView, mThread) == 0x68, "CAiAttackerImpl::mThread offset must be 0x68");
  static_assert(offsetof(CAiAttackerImplSerializationView, mTasks) == 0x70, "CAiAttackerImpl::mTasks offset must be 0x70");
  static_assert(
    offsetof(CAiAttackerImplSerializationView, mDesiredTarget) == 0x80,
    "CAiAttackerImpl::mDesiredTarget offset must be 0x80"
  );
  static_assert(
    offsetof(CAiAttackerImplSerializationView, mReportingState) == 0xA0,
    "CAiAttackerImpl::mReportingState offset must be 0xA0"
  );
  static_assert(sizeof(CAiAttackerImplSerializationView) == 0xA4, "CAiAttackerImpl serialized view size must be 0xA4");

  alignas(CAiAttackerImplSerializer) unsigned char gCAiAttackerImplSerializerStorage[sizeof(CAiAttackerImplSerializer)];
  bool gCAiAttackerImplSerializerConstructed = false;

  [[nodiscard]] CAiAttackerImplSerializationView* AsSerializationView(moho::CAiAttackerImpl* const object)
  {
    return reinterpret_cast<CAiAttackerImplSerializationView*>(object);
  }

  [[nodiscard]] const CAiAttackerImplSerializationView* AsSerializationView(const moho::CAiAttackerImpl* const object)
  {
    return reinterpret_cast<const CAiAttackerImplSerializationView*>(object);
  }

  template <typename T>
  void ResizePointerVector(msvc8::vector<T*>& storage, const unsigned int count)
  {
    storage.clear();
    storage.resize(static_cast<std::size_t>(count));
    for (T*& value : storage) {
      value = nullptr;
    }
  }

  [[nodiscard]] CAiAttackerImplSerializer* AcquireCAiAttackerImplSerializer()
  {
    if (!gCAiAttackerImplSerializerConstructed) {
      new (gCAiAttackerImplSerializerStorage) CAiAttackerImplSerializer();
      gCAiAttackerImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiAttackerImplSerializer*>(gCAiAttackerImplSerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedCAiAttackerImplType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAiAttackerImpl));
    }
    return cached;
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

  /**
   * Address: 0x005D8480 (FUN_005D8480)
   *
   * What it does:
   * Unlinks the global `CAiAttackerImplSerializer` helper node from the
   * intrusive serializer chain and restores it to a self-linked node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiAttackerImplSerializerStartupThunkA()
  {
    return UnlinkSerializerNode(*AcquireCAiAttackerImplSerializer());
  }

  /**
   * Address: 0x005D84B0 (FUN_005D84B0)
   *
   * What it does:
   * Secondary unlink/reset thunk for the global
   * `CAiAttackerImplSerializer` helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiAttackerImplSerializerStartupThunkB()
  {
    return UnlinkSerializerNode(*AcquireCAiAttackerImplSerializer());
  }

  /**
   * Address: 0x00BF8430 (FUN_00BF8430, cleanup thunk)
   *
   * What it does:
   * Tears down recovered static `CAiAttackerImplSerializer` storage.
   */
  void cleanup_CAiAttackerImplSerializer()
  {
    if (!gCAiAttackerImplSerializerConstructed) {
      return;
    }

    CAiAttackerImplSerializer* const serializer = AcquireCAiAttackerImplSerializer();
    (void)cleanup_CAiAttackerImplSerializerStartupThunkA();

    serializer->~CAiAttackerImplSerializer();
    gCAiAttackerImplSerializerConstructed = false;
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

  CAiAttackerImplSerializationView* const view = AsSerializationView(object);

  unsigned int weaponCount = 0;
  archive->ReadUInt(&weaponCount);
  ResizePointerVector(view->mWeapons, weaponCount);

  for (unsigned int i = 0; i < weaponCount; ++i) {
    gpg::RRef ownerRef{};
    archive->ReadPointerOwned_UnitWeapon(&view->mWeapons[static_cast<std::size_t>(i)], &ownerRef);
  }

  unsigned int taskCount = 0;
  archive->ReadUInt(&taskCount);
  ResizePointerVector(view->mTasks, taskCount);

  for (unsigned int i = 0; i < taskCount; ++i) {
    gpg::RRef ownerRef{};
    archive->ReadPointerOwned_CAcquireTargetTask(&view->mTasks[static_cast<std::size_t>(i)], &ownerRef);
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

  const CAiAttackerImplSerializationView* const view = AsSerializationView(object);
  const gpg::RRef ownerRef{};

  const unsigned int weaponCount = static_cast<unsigned int>(view->mWeapons.size());
  archive->WriteUInt(weaponCount);
  for (unsigned int i = 0; i < weaponCount; ++i) {
    gpg::RRef pointerRef{};
    gpg::RRef_UnitWeapon(&pointerRef, view->mWeapons[static_cast<std::size_t>(i)]);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Owned, ownerRef);
  }

  const unsigned int taskCount = static_cast<unsigned int>(view->mTasks.size());
  archive->WriteUInt(taskCount);
  for (unsigned int i = 0; i < taskCount; ++i) {
    gpg::RRef pointerRef{};
    gpg::RRef_CAcquireTargetTask(&pointerRef, view->mTasks[static_cast<std::size_t>(i)]);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Owned, ownerRef);
  }
}

/**
 * Address: 0x005E13B0 (FUN_005E13B0, Moho::CAiAttackerImpl::MemberDeserialize)
 *
 * What it does:
 * Restores attacker base/interface payload plus serialized member lanes in the
 * original read order.
 */
void CAiAttackerImpl::MemberDeserialize(CAiAttackerImpl* const object, gpg::ReadArchive* const archive)
{
  if (!archive || !object) {
    return;
  }

  CAiAttackerImplSerializationView* const view = AsSerializationView(object);
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

  const gpg::RRef trackedStageRef(&view->mStage, stageType);
  (void)archive->TrackPointer(trackedStageRef);

  gpg::RRef ownerRef{};
  archive->Read(attackerType, object, ownerRef);

  ownerRef = gpg::RRef{};
  archive->ReadPointer_Unit(&view->mUnit, &ownerRef);

  DeserializePointerVectors(archive, object);

  ownerRef = gpg::RRef{};
  archive->Read(stageType, &view->mStage, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Read(threadType, &view->mThread, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Read(targetType, &view->mDesiredTarget, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Read(reportingType, &view->mReportingState, ownerRef);
}

/**
 * Address: 0x005E1520 (FUN_005E1520, Moho::CAiAttackerImpl::MemberSerialize)
 *
 * What it does:
 * Serializes attacker base/interface payload plus serialized member lanes in
 * the original write order.
 */
void CAiAttackerImpl::MemberSerialize(const CAiAttackerImpl* const object, gpg::WriteArchive* const archive)
{
  if (!archive || !object) {
    return;
  }

  const CAiAttackerImplSerializationView* const view = AsSerializationView(object);
  auto* const mutableView = const_cast<CAiAttackerImplSerializationView*>(view);
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

  const gpg::RRef trackedStageRef(&mutableView->mStage, stageType);
  (void)archive->PreCreatedPtr(trackedStageRef);

  gpg::RRef ownerRef{};
  archive->Write(attackerType, object, ownerRef);

  gpg::RRef unitRef{};
  gpg::RRef_Unit(&unitRef, view->mUnit);
  gpg::WriteRawPointer(archive, unitRef, gpg::TrackedPointerState::Unowned, ownerRef);

  SerializePointerVectors(archive, object);

  ownerRef = gpg::RRef{};
  archive->Write(stageType, &view->mStage, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Write(threadType, &view->mThread, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Write(targetType, &view->mDesiredTarget, ownerRef);

  ownerRef = gpg::RRef{};
  archive->Write(reportingType, &view->mReportingState, ownerRef);
}

/**
 * Address: 0x005DEBB0 (FUN_005DEBB0)
 *
 * What it does:
 * Tail-thunk alias that forwards attacker-load callback lanes into
 * `CAiAttackerImpl::MemberDeserialize`.
 */
[[maybe_unused]] void DeserializeCAiAttackerImplMemberThunkA(
  CAiAttackerImpl* const object,
  gpg::ReadArchive* const archive
)
{
  CAiAttackerImpl::MemberDeserialize(object, archive);
}

/**
 * Address: 0x005DEBC0 (FUN_005DEBC0)
 *
 * What it does:
 * Tail-thunk alias that forwards attacker-save callback lanes into
 * `CAiAttackerImpl::MemberSerialize`.
 */
[[maybe_unused]] void SerializeCAiAttackerImplMemberThunkA(
  const CAiAttackerImpl* const object,
  gpg::WriteArchive* const archive
)
{
  CAiAttackerImpl::MemberSerialize(object, archive);
}

/**
 * Address: 0x005E04B0 (FUN_005E04B0)
 *
 * What it does:
 * Secondary tail-thunk alias that forwards attacker-load callback lanes into
 * `CAiAttackerImpl::MemberDeserialize`.
 */
[[maybe_unused]] void DeserializeCAiAttackerImplMemberThunkB(
  CAiAttackerImpl* const object,
  gpg::ReadArchive* const archive
)
{
  CAiAttackerImpl::MemberDeserialize(object, archive);
}

/**
 * Address: 0x005D8430 (FUN_005D8430, Moho::CAiAttackerImplSerializer::Deserialize)
 *
 * What it does:
 * Forwards one serializer load callback into `CAiAttackerImpl::MemberDeserialize`.
 */
void CAiAttackerImplSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
)
{
  auto* const object = reinterpret_cast<CAiAttackerImpl*>(static_cast<std::uintptr_t>(objectPtr));
  CAiAttackerImpl::MemberDeserialize(object, archive);
}

/**
 * Address: 0x005D8440 (FUN_005D8440, Moho::CAiAttackerImplSerializer::Serialize)
 *
 * What it does:
 * Forwards one serializer save callback into `CAiAttackerImpl::MemberSerialize`.
 */
void CAiAttackerImplSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
)
{
  const auto* const object = reinterpret_cast<const CAiAttackerImpl*>(static_cast<std::uintptr_t>(objectPtr));
  CAiAttackerImpl::MemberSerialize(object, archive);
}

/**
 * Address: 0x005DC0D0 (FUN_005DC0D0)
 *
 * What it does:
 * Lazily resolves `CAiAttackerImpl` RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiAttackerImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiAttackerImplType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  if (!type) {
    return;
  }

  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE8D0 (FUN_00BCE8D0, register_CAiAttackerImplSerializer)
 *
 * What it does:
 * Registers `CAiAttackerImpl` serializer callbacks and installs process-exit
 * cleanup.
 */
void moho::register_CAiAttackerImplSerializer()
{
  CAiAttackerImplSerializer* const serializer = AcquireCAiAttackerImplSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &CAiAttackerImplSerializer::Deserialize;
  serializer->mSaveCallback = &CAiAttackerImplSerializer::Serialize;
  (void)std::atexit(&cleanup_CAiAttackerImplSerializer);
}

#include "IAniManipulator.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniActor.h"

namespace
{
  constexpr std::uint16_t kWatchBoneActiveFlag = 0x8000;

  [[nodiscard]] moho::SAniManipBinding* InlineWatchBoneStorage(moho::IAniManipulator* const manipulator) noexcept
  {
    return &manipulator->mWatchBones.mInlineEntries[0];
  }

  [[nodiscard]] std::int32_t BindingPointerToInt32(const moho::SAniManipBinding* const binding) noexcept
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(binding));
  }

  [[nodiscard]] moho::SAniManipBinding* Int32ToBindingPointer(const std::int32_t value) noexcept
  {
    return reinterpret_cast<moho::SAniManipBinding*>(static_cast<std::uintptr_t>(value));
  }

  void InitializeWatchBoneStorage(moho::IAniManipulator* const manipulator)
  {
    auto* const inlineStorage = InlineWatchBoneStorage(manipulator);
    manipulator->mWatchBones.mInlineStorage = inlineStorage;
    manipulator->mWatchBones.mBegin = inlineStorage;
    manipulator->mWatchBones.mEnd = inlineStorage;
    manipulator->mWatchBones.mCapacityEnd = inlineStorage + 2;
  }

  [[nodiscard]] moho::SAniManipBinding* CopyBindingRange(
    moho::SAniManipBinding* destination,
    const moho::SAniManipBinding* sourceEnd,
    const moho::SAniManipBinding* sourceBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination) {
        *destination = *sourceBegin;
      }
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x0063C950 (FUN_0063C950, sub_63C950)
   *
   * What it does:
   * Allocates a new watch-bone buffer, inserts one contiguous range at
   * `insertPosition`, then updates/cleans old storage and writes the new
   * `{begin,end,capacity}` triple.
   */
  std::int32_t ReallocateWatchBoneStorageForInsert(
    moho::SAniManipBinding* const insertPosition,
    moho::SAniManipBindingStorage* const storage,
    std::int32_t newCapacity,
    const moho::SAniManipBinding* const insertBegin,
    const moho::SAniManipBinding* const insertEnd
  )
  {
    auto* const newStorage = new moho::SAniManipBinding[newCapacity];
    auto* const afterPrefix = CopyBindingRange(newStorage, insertPosition, storage->mBegin);
    auto* const afterInserted = CopyBindingRange(afterPrefix, insertEnd, insertBegin);
    auto* const newEnd = CopyBindingRange(afterInserted, storage->mEnd, insertPosition);

    if (storage->mBegin == storage->mInlineStorage) {
      // Mirrors the inline-buffer sentinel write in FUN_0063C950.
      storage->mInlineStorage->mBoneIndex = BindingPointerToInt32(storage->mCapacityEnd);
    } else {
      delete[] storage->mBegin;
    }

    storage->mBegin = newStorage;
    storage->mEnd = newEnd;
    storage->mCapacityEnd = newStorage + newCapacity;
    return newCapacity;
  }

  /**
   * Address: 0x0063C5F0 (FUN_0063C5F0, func_AppendBone)
   *
   * What it does:
   * Appends one binding and grows storage with the original doubling policy
   * when the watch-bone buffer is full.
   */
  void AppendWatchBoneBinding(moho::SAniManipBindingStorage* const storage, const moho::SAniManipBinding& binding)
  {
    auto* const end = storage->mEnd;
    if (end == storage->mCapacityEnd) {
      const auto currentSize = static_cast<std::int32_t>(storage->mEnd - storage->mBegin);
      const auto currentCapacity = static_cast<std::int32_t>(storage->mCapacityEnd - storage->mBegin);
      std::int32_t newCapacity = currentSize + 1;
      const std::int32_t doubledCapacity = currentCapacity * 2;
      if (newCapacity < doubledCapacity) {
        newCapacity = doubledCapacity;
      }

      ReallocateWatchBoneStorageForInsert(end, storage, newCapacity, &binding, &binding + 1);
      return;
    }

    if (end) {
      *end = binding;
    }
    ++storage->mEnd;
  }

  /**
   * Address: 0x0063ACE0 (FUN_0063ACE0, sub_63ACE0)
   *
   * What it does:
   * Inserts `manipulator` into CAniActor's intrusive order list sorted by
   * ascending `mPrecedence`.
   */
  void RegisterWithOwnerActorOrderList(moho::CAniActor* const ownerActor, moho::IAniManipulator* const manipulator)
  {
    auto* const listHead =
      static_cast<moho::TDatListItem<moho::IAniManipulator, void>*>(&ownerActor->mManipulatorsByPrecedence);
    auto* insertBefore = ownerActor->mManipulatorsByPrecedence.mNext;
    while (insertBefore != listHead) {
      auto* const current = reinterpret_cast<moho::IAniManipulator*>(
        reinterpret_cast<std::uintptr_t>(insertBefore) - offsetof(moho::IAniManipulator, mActorOrderLink)
      );
      if (manipulator->mPrecedence < current->mPrecedence) {
        break;
      }
      insertBefore = insertBefore->mNext;
    }

    manipulator->mActorOrderLink.ListUnlink();
    manipulator->mActorOrderLink.ListLinkBefore(insertBefore);
  }

  gpg::RType* CachedIAniManipulatorType()
  {
    if (!moho::IAniManipulator::sType) {
      moho::IAniManipulator::sType = gpg::LookupRType(typeid(moho::IAniManipulator));
    }
    return moho::IAniManipulator::sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  void AddCScriptEventBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(moho::CScriptEvent));
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace

namespace moho
{
  gpg::RType* IAniManipulator::sType = nullptr;

  /**
   * Address: 0x0063B5D0 (FUN_0063B5D0, ??0IAniManipulator@Moho@@QAE@XZ)
   */
  IAniManipulator::IAniManipulator()
    : mOwnerActor(nullptr)
    , mOwnerSim(nullptr)
    , mPrecedence(0)
  {
    InitializeWatchBoneStorage(this);
  }

  /**
   * Address: 0x0063B640 (FUN_0063B640, ??0IAniManipulator@Moho@@QAE@PAVSim@1@PAVCAniActor@1@H@Z)
   */
  IAniManipulator::IAniManipulator(Sim* const sim, CAniActor* const ownerActor, const int precedence)
    : mOwnerActor(ownerActor)
    , mOwnerSim(sim)
    , mPrecedence(precedence)
  {
    mEnabled = true;
    InitializeWatchBoneStorage(this);
    RegisterWithOwnerActorOrderList(ownerActor, this);
  }

  /**
   * Address: 0x0062FC70 (FUN_0062FC70, ??1IAniManipulator@Moho@@UAE@XZ)
   */
  IAniManipulator::~IAniManipulator()
  {
    ResetWatchBoneStorage();
    mActorOrderLink.ListUnlink();
  }

  /**
   * Address: 0x0062FC30 (FUN_0062FC30, ?GetClass@IAniManipulator@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* IAniManipulator::GetClass() const
  {
    return CachedIAniManipulatorType();
  }

  /**
   * Address: 0x0062FC50 (FUN_0062FC50, ?GetDerivedObjectRef@IAniManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef IAniManipulator::GetDerivedObjectRef()
  {
    return MakeTypedRef(this, CachedIAniManipulatorType());
  }

  /**
   * Address: 0x0063B6D0 (FUN_0063B6D0, ?AddWatchBone@IAniManipulator@Moho@@QAEHH@Z)
   */
  int IAniManipulator::AddWatchBone(const int boneIndex)
  {
    SAniManipBinding watchBone{};
    watchBone.mBoneIndex = boneIndex;
    watchBone.mFlags = kWatchBoneActiveFlag;
    AppendWatchBoneBinding(&mWatchBones, watchBone);
    return static_cast<int>(mWatchBones.mEnd - mWatchBones.mBegin - 1);
  }

  void IAniManipulator::ResetWatchBoneStorage()
  {
    auto& storage = mWatchBones;
    auto* const inlineStorage = storage.mInlineStorage;
    if (storage.mBegin != inlineStorage) {
      delete[] storage.mBegin;
      storage.mBegin = inlineStorage;
      storage.mCapacityEnd = Int32ToBindingPointer(inlineStorage->mBoneIndex);
    }

    storage.mEnd = storage.mBegin;
  }

  /**
   * Address: 0x0063C540 (FUN_0063C540, sub_63C540)
   */
  void IAniManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedIAniManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x0063B520 (FUN_0063B520, scalar deleting destructor thunk)
   */
  IAniManipulatorTypeInfo::~IAniManipulatorTypeInfo() = default;

  /**
   * Address: 0x0063B510 (FUN_0063B510, ?GetName@IAniManipulatorTypeInfo@Moho@@UBEPBDXZ)
   */
  const char* IAniManipulatorTypeInfo::GetName() const
  {
    return "IAniManipulator";
  }

  /**
   * Address: 0x0063B4E0 (FUN_0063B4E0, ?Init@IAniManipulatorTypeInfo@Moho@@UAEXXZ)
   */
  void IAniManipulatorTypeInfo::Init()
  {
    size_ = sizeof(IAniManipulator);
    gpg::RType::Init();
    AddCScriptEventBase(this);
    Finish();
  }
} // namespace moho

#include "StatItem.h"

#include <algorithm>
#include <cfloat>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/timeb.h>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/streams/FileStream.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/UserArmy.h"
#include "moho/ui/CUIManager.h"
#include "platform/Platform.h"

#pragma init_seg(lib)

namespace
{
  struct StatIntrusiveNode
  {
    StatIntrusiveNode* prev;
    StatIntrusiveNode* next;
    moho::StatItem* parent;
    moho::StatItem* owner;
  };

  constexpr const char* kRootStatName = "Root";
  constexpr const char* kBeginLoggingStatsLuaHelpText = "Begin logging stats";
  constexpr const char* kEndLoggingStatsLuaHelpText = "EndLoggingStats(bool exit) - End logging stats and optionally exit app";

  moho::EStatTypeTypeInfo gEStatTypeTypeInfo;
  moho::EPulseModeTypeInfo gEPulseModeTypeInfo;
  moho::EStatTypePrimitiveSerializer gEStatTypePrimitiveSerializer;
  moho::EPulseModePrimitiveSerializer gEPulseModePrimitiveSerializer;
  moho::StatItemTypeInfo gStatItemTypeInfo;
  moho::StatItemSerializer gStatItemSerializer;
  moho::StatsRType<moho::StatItem> gStatsRTypeStatItem;
  gpg::RType* gEStatTypeRuntimeType = nullptr;
  gpg::RType* gEPulseModeRuntimeType = nullptr;

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  template <typename TObject>
  void MaterializeReflectionSingleton(TObject& singleton)
  {
    (void)singleton;
  }

  [[nodiscard]] gpg::RType* CachedStatItemType()
  {
    if (!moho::StatItem::sType) {
      moho::StatItem::sType = gpg::LookupRType(typeid(moho::StatItem));
    }
    return moho::StatItem::sType;
  }

  [[nodiscard]] gpg::RType* CachedStatsStatItemType()
  {
    if (!moho::Stats<moho::StatItem>::sType) {
      moho::Stats<moho::StatItem>::sType = gpg::LookupRType(typeid(moho::Stats<moho::StatItem>));
    }
    return moho::Stats<moho::StatItem>::sType;
  }

  [[nodiscard]] gpg::RType* CachedEStatTypeType()
  {
    if (!gEStatTypeRuntimeType) {
      gEStatTypeRuntimeType = gpg::LookupRType(typeid(moho::EStatType));
    }
    return gEStatTypeRuntimeType;
  }

  [[nodiscard]] gpg::RType* CachedEPulseModeType()
  {
    if (!gEPulseModeRuntimeType) {
      gEPulseModeRuntimeType = gpg::LookupRType(typeid(moho::EPulseMode));
    }
    return gEPulseModeRuntimeType;
  }

  /**
   * Address: 0x00419A50 (FUN_00419A50, gpg::PrimitiveSerHelper_EStatType::Deserialize)
   *
   * What it does:
   * Reads one archive `int` and stores it as `EStatType`.
   */
  void DeserializeEStatType(gpg::ReadArchive* archive, moho::EStatType* value)
  {
    std::int32_t rawValue = 0;
    archive->ReadInt(&rawValue);
    *value = static_cast<moho::EStatType>(rawValue);
  }

  /**
   * Address: 0x00419A70 (FUN_00419A70, gpg::PrimitiveSerHelper_EStatType::Serialize)
   *
   * What it does:
   * Writes one `EStatType` value as archive `int`.
   */
  void SerializeEStatType(gpg::WriteArchive* archive, const moho::EStatType* value)
  {
    archive->WriteInt(static_cast<std::int32_t>(*value));
  }

  /**
   * Address: 0x00419AC0 (FUN_00419AC0, gpg::PrimitiveSerHelper_EPulseModeTypeInfo::Deserialize)
   *
   * What it does:
   * Reads one archive `int` and stores it as `EPulseMode`.
   */
  void DeserializeEPulseMode(gpg::ReadArchive* archive, moho::EPulseMode* value)
  {
    std::int32_t rawValue = 0;
    archive->ReadInt(&rawValue);
    *value = static_cast<moho::EPulseMode>(rawValue);
  }

  /**
   * Address: 0x00419AE0 (FUN_00419AE0, gpg::PrimitiveSerHelper_EPulseModeTypeInfo::Serialize)
   *
   * What it does:
   * Writes one `EPulseMode` value as archive `int`.
   */
  void SerializeEPulseMode(gpg::WriteArchive* archive, const moho::EPulseMode* value)
  {
    archive->WriteInt(static_cast<std::int32_t>(*value));
  }

  template <class TObject>
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

    int baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x0041A8B0 (FUN_0041A8B0, gpg::RRef_StatItem)
   *
   * What it does:
   * Builds a typed reflected reference for `StatItem*`.
   */
  [[nodiscard]] gpg::RRef MakeStatItemRef(moho::StatItem* object)
  {
    return MakeTypedRef(object, CachedStatItemType());
  }

  /**
   * Address: 0x0041AB50 (FUN_0041AB50, gpg::RRef_Stats_StatItem)
   *
   * What it does:
   * Builds a typed reflected reference for `Stats<StatItem>*`.
   */
  [[nodiscard]] gpg::RRef MakeStatsStatItemRef(moho::Stats<moho::StatItem>* object)
  {
    return MakeTypedRef(object, CachedStatsStatItemType());
  }

  /**
   * Address: 0x0041AA60 (FUN_0041AA60, gpg::RRef::Upcast_StatItem)
   *
   * What it does:
   * Upcasts one reflected reference lane to `StatItem*`.
   */
  [[nodiscard]] moho::StatItem* CastStatItemFromRef(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedStatItemType());
    return static_cast<moho::StatItem*>(upcast.mObj);
  }

  [[nodiscard]] moho::StatItem* ReadArchiveStatItemPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    moho::StatItem* const item = CastStatItemFromRef(source);
    if (!item) {
      const char* const expectedName = CachedStatItemType()->GetName();
      const char* const actualName = tracked.type ? tracked.type->GetName() : "null";
      const msvc8::string msg = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expectedName ? expectedName : "StatItem",
        actualName ? actualName : "null"
      );
      throw std::runtime_error(msg.c_str());
    }
    return item;
  }

  /**
   * Address: 0x0041A3D0 (FUN_0041A3D0, gpg::ReadArchive::ReadPointerOwned_StatItem)
   *
   * What it does:
   * Reads one tracked pointer lane, enforces `Unowned -> Owned` transition, and
   * upcasts to `StatItem`.
   */
  [[nodiscard]] moho::StatItem* ReadOwnedArchiveStatItemPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.state != gpg::TrackedPointerState::Unowned) {
      throw gpg::SerializationError("Ownership conflict while loading archive");
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    moho::StatItem* const item = CastStatItemFromRef(source);
    if (!item) {
      const char* const expectedName = CachedStatItemType()->GetName();
      const char* const actualName = tracked.type ? tracked.type->GetName() : "null";
      const msvc8::string msg = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expectedName ? expectedName : "StatItem",
        actualName ? actualName : "null"
      );
      throw gpg::SerializationError(msg.c_str());
    }

    tracked.state = gpg::TrackedPointerState::Owned;
    return item;
  }

  /**
   * Address: 0x00418FE0 (FUN_00418FE0, Moho::StatItemSerializer::Deserialize)
   */
  void DeserializeStatItem(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const item = reinterpret_cast<moho::StatItem*>(objectPtr);
    GPG_ASSERT(item != nullptr);
    if (item) {
      item->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00418FF0 (FUN_00418FF0, Moho::StatItemSerializer::Serialize)
   */
  void SerializeStatItem(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const item = reinterpret_cast<moho::StatItem*>(objectPtr);
    GPG_ASSERT(item != nullptr);
    if (item) {
      item->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00419DE0 (FUN_00419DE0, func_ReadArchive_Stats_StatItem)
   */
  void DeserializeStatsStatItem(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const stats = reinterpret_cast<moho::Stats<moho::StatItem>*>(objectPtr);
    GPG_ASSERT(stats != nullptr);

    boost::mutex::scoped_lock lock(*stats->mLock);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    moho::StatItem* const loadedRoot = ReadArchiveStatItemPointer(archive, owner);

    moho::StatItem* const previousRoot = stats->mItem;
    stats->mItem = loadedRoot;
    delete previousRoot;
  }

  /**
   * Address: 0x00419E70 (FUN_00419E70, func_WriteArchive_Stats_StatItem)
   */
  void SerializeStatsStatItem(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const stats = reinterpret_cast<moho::Stats<moho::StatItem>*>(objectPtr);
    GPG_ASSERT(stats != nullptr);

    boost::mutex::scoped_lock lock(*stats->mLock);
    const gpg::RRef rootRef = MakeStatItemRef(stats->mItem);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::WriteRawPointer(archive, rootRef, gpg::TrackedPointerState::Owned, owner);
  }

  /**
   * Address: 0x00419F00 (FUN_00419F00, func_NewStats_StatItem)
   */
  void ConstructStatsStatItem(void* objectStorage)
  {
    if (!objectStorage) {
      return;
    }
    new (objectStorage) moho::Stats<moho::StatItem>();
  }

  /**
   * Address: 0x0041A4E0 (FUN_0041A4E0, func_Delete_Stats_StatItem)
   */
  void DeleteStatsStatItem(void* object)
  {
    delete static_cast<moho::Stats<moho::StatItem>*>(object);
  }

  /**
   * Address: 0x0041A0F0 (FUN_0041A0F0, sub_41A0F0)
   */
  [[nodiscard]] gpg::RRef CreateStatItemRefOwned()
  {
    auto* const item = new moho::StatItem(kRootStatName);
    return MakeStatItemRef(item);
  }

  /**
   * Address: 0x0041A170 (FUN_0041A170, sub_41A170)
   */
  void DeleteStatItemOwned(void* object)
  {
    delete static_cast<moho::StatItem*>(object);
  }

  /**
   * Address: 0x0041A190 (FUN_0041A190, sub_41A190)
   */
  [[nodiscard]] gpg::RRef ConstructStatItemRefInPlace(void* objectStorage)
  {
    auto* const item = static_cast<moho::StatItem*>(objectStorage);
    if (item) {
      new (item) moho::StatItem(kRootStatName);
    }
    return MakeStatItemRef(item);
  }

  /**
   * Address: 0x0041A210 (FUN_0041A210, sub_41A210)
   */
  void DestroyStatItemInPlace(void* object)
  {
    auto* const item = static_cast<moho::StatItem*>(object);
    if (item) {
      item->~StatItem();
    }
  }

  /**
   * Address: 0x004193E0 (FUN_004193E0)
   *
   * What it does:
   * Returns first dword lane from one runtime view pointer.
   */
  [[nodiscard]] std::uint32_t ReadFirstDwordLane(const std::uint32_t* value) noexcept
  {
    return value ? value[0] : 0U;
  }

  /**
   * Address: 0x00419B30 (FUN_00419B30)
   *
   * What it does:
   * Assigns `newRef` + `ctorRef` callback lanes for `StatItem` reflected type.
   */
  void AssignStatItemTypeCreateCallbacks(gpg::RType* type) noexcept
  {
    if (!type) {
      return;
    }

    type->newRefFunc_ = &CreateStatItemRefOwned;
    type->ctorRefFunc_ = &ConstructStatItemRefInPlace;
  }

  /**
   * Address: 0x00419B40 (FUN_00419B40)
   *
   * What it does:
   * Assigns `delete` + `dtr` callback lanes for `StatItem` reflected type.
   */
  void AssignStatItemTypeDestroyCallbacks(gpg::RType* type) noexcept
  {
    if (!type) {
      return;
    }

    type->deleteFunc_ = &DeleteStatItemOwned;
    type->dtrFunc_ = &DestroyStatItemInPlace;
  }

  /**
   * Address: 0x004193C0 (FUN_004193C0)
   *
   * What it does:
   * Patches all `StatItem` lifecycle callback lanes in one reflected type view.
   */
  void AssignStatItemTypeLifecycleCallbacks(gpg::RType* type) noexcept
  {
    if (!type) {
      return;
    }

    GPG_ASSERT(ReadFirstDwordLane(reinterpret_cast<const std::uint32_t*>(type)) != 0U);
    AssignStatItemTypeCreateCallbacks(type);
    AssignStatItemTypeDestroyCallbacks(type);
  }

  [[nodiscard]] StatIntrusiveNode* AsSelfNode(moho::StatItem* item) noexcept
  {
    return reinterpret_cast<StatIntrusiveNode*>(&item->head1Prev);
  }

  [[nodiscard]] StatIntrusiveNode* AsChildHead(moho::StatItem* item) noexcept
  {
    return reinterpret_cast<StatIntrusiveNode*>(&item->head2Prev);
  }

  /**
   * Address: 0x0040D0C0 (FUN_0040D0C0, sub_40D0C0)
   *
   * What it does:
   * Walks one stat-path token vector through direct-child chains and optionally
   * creates missing child nodes segment-by-segment.
   */
  [[nodiscard]] moho::StatItem* WalkStatPath(
    moho::StatItem* root, const msvc8::vector<msvc8::string>& tokens, const bool allowCreate, bool* const didCreate
  )
  {
    if (didCreate != nullptr) {
      *didCreate = false;
    }
    if (root == nullptr) {
      return nullptr;
    }

    const std::size_t tokenCount = tokens.size();
    if (tokenCount == 0u) {
      return root;
    }

    moho::StatItem* current = root;
    std::size_t index = 0u;
    for (; index < tokenCount; ++index) {
      moho::StatItem* const found = current->FindDirectChildByName(tokens[index]);
      if (found == nullptr) {
        break;
      }
      current = found;
    }

    if (index == tokenCount) {
      return current;
    }
    if (!allowCreate) {
      return nullptr;
    }

    if (didCreate != nullptr) {
      *didCreate = true;
    }

    moho::StatItem* parent = current;
    moho::StatItem* lastCreated = nullptr;
    for (; index < tokenCount; ++index) {
      moho::StatItem* const child = new moho::StatItem(tokens[index].c_str());
      parent->AttachChild(child);
      parent = child;
      lastCreated = child;
    }
    return lastCreated;
  }

  [[nodiscard]] std::int32_t ReadAtomicI32(volatile std::int32_t* value)
  {
#if defined(_WIN32)
    return static_cast<std::int32_t>(InterlockedCompareExchange(reinterpret_cast<volatile long*>(value), 0, 0));
#else
    return *value;
#endif
  }

  void AtomicStoreI32(volatile std::int32_t* value, const std::int32_t wanted)
  {
#if defined(_WIN32)
    for (;;) {
      const std::int32_t observed = ReadAtomicI32(value);
      const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(value), static_cast<long>(wanted), static_cast<long>(observed)
      ));
      if (exchanged == observed) {
        return;
      }
    }
#else
    *value = wanted;
#endif
  }

  [[nodiscard]] std::int32_t AtomicExchangeI32(volatile std::int32_t* value, const std::int32_t wanted)
  {
#if defined(_WIN32)
    for (;;) {
      const std::int32_t observed = ReadAtomicI32(value);
      const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(value), static_cast<long>(wanted), static_cast<long>(observed)
      ));
      if (exchanged == observed) {
        return exchanged;
      }
    }
#else
    const std::int32_t previous = *value;
    *value = wanted;
    return previous;
#endif
  }

  [[nodiscard]] std::int32_t AtomicStoreSlotFromPtr(volatile std::int32_t* const slot, const std::int32_t* const wanted)
  {
    const std::int32_t target = wanted ? *wanted : 0;
#if defined(_WIN32)
    for (;;) {
      const std::int32_t observed = ReadAtomicI32(slot);
      const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(slot), static_cast<long>(target), static_cast<long>(observed)
      ));
      if (exchanged == observed) {
        return exchanged;
      }
    }
#else
    const std::int32_t previous = *slot;
    *slot = target;
    return previous;
#endif
  }

  /**
   * Address: 0x00417990 (FUN_00417990, sub_417990)
   */
  [[nodiscard]] std::int32_t StorePrimaryValueBits_IntPath(moho::StatItem* const item, const std::int32_t* wanted)
  {
    return AtomicStoreSlotFromPtr(&item->mPrimaryValueBits, wanted);
  }

  /**
   * Address: 0x004179C0 (FUN_004179C0, sub_4179C0)
   */
  [[nodiscard]] std::int32_t StorePrimaryValueBits_FloatPath(moho::StatItem* const item, const std::int32_t* wanted)
  {
    return AtomicStoreSlotFromPtr(&item->mPrimaryValueBits, wanted);
  }

  /**
   * Address: 0x00418060 (FUN_00418060, sub_418060)
   */
  [[nodiscard]] std::int32_t SyncRealtimeValueBitsFromPrimary(moho::StatItem* const item)
  {
#if defined(_WIN32)
    for (;;) {
      const std::int32_t observedRealtime = ReadAtomicI32(&item->mRealtimeValueBits);
      const std::int32_t observedPrimary = ReadAtomicI32(&item->mPrimaryValueBits);
      const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(&item->mRealtimeValueBits),
        static_cast<long>(observedPrimary),
        static_cast<long>(observedRealtime)
      ));
      if (exchanged == observedRealtime) {
        return exchanged;
      }
    }
#else
    const std::int32_t previous = item->mRealtimeValueBits;
    item->mRealtimeValueBits = item->mPrimaryValueBits;
    return previous;
#endif
  }

  [[nodiscard]] std::int32_t ReadNumericSlot(moho::StatItem* item, const bool useRealtimeValue)
  {
    volatile std::int32_t* const slot = useRealtimeValue ? &item->mRealtimeValueBits : &item->mPrimaryValueBits;
    return ReadAtomicI32(slot);
  }

  [[nodiscard]] float AsFloatBits(const std::int32_t value)
  {
    float out = 0.0f;
    std::memcpy(&out, &value, sizeof(out));
    return out;
  }

  void EnsureStatSampleCapacity(moho::StatSampleBuffer& sampleBuffer, const std::size_t requiredCount)
  {
    const std::size_t currentCount =
      sampleBuffer.begin ? static_cast<std::size_t>(sampleBuffer.end - sampleBuffer.begin) : 0u;
    const std::size_t currentCapacity =
      sampleBuffer.begin ? static_cast<std::size_t>(sampleBuffer.capacityEnd - sampleBuffer.begin) : 0u;
    if (currentCapacity >= requiredCount) {
      return;
    }

    std::size_t targetCapacity = (currentCapacity == 0u) ? 1u : (currentCapacity + (currentCapacity >> 1));
    if (targetCapacity < requiredCount) {
      targetCapacity = requiredCount;
    }

    auto* const newStorage = static_cast<moho::StatSamplePoint*>(operator new(targetCapacity * sizeof(moho::StatSamplePoint)));
    if (currentCount != 0u && sampleBuffer.begin != nullptr) {
      std::memcpy(newStorage, sampleBuffer.begin, currentCount * sizeof(moho::StatSamplePoint));
    }

    operator delete(sampleBuffer.begin);
    sampleBuffer.begin = newStorage;
    sampleBuffer.end = newStorage + currentCount;
    sampleBuffer.capacityEnd = newStorage + targetCapacity;
  }

  /**
   * Address: 0x004169A0 (FUN_004169A0, stats sample append helper)
   *
   * What it does:
   * Appends one `(frameIndex, value)` sample into the stat item's logging
   * sample history range, growing capacity when needed.
   */
  void AppendStatSample(moho::StatItem* item, const std::int32_t frameIndex, const float value)
  {
    if (!item) {
      return;
    }

    moho::StatSampleBuffer& sampleBuffer = item->mSampleHistory;
    const std::size_t sampleCount =
      sampleBuffer.begin ? static_cast<std::size_t>(sampleBuffer.end - sampleBuffer.begin) : 0u;

    EnsureStatSampleCapacity(sampleBuffer, sampleCount + 1u);
    moho::StatSamplePoint* const dst = sampleBuffer.end;
    dst->frameIndex = frameIndex;
    dst->value = value;
    sampleBuffer.end = dst + 1;
  }

  /**
   * Address: 0x00415290 (FUN_00415290, recursive stat-tree sample capture)
   *
   * What it does:
   * Recursively traverses the stat tree and appends one sample for each
   * non-string, non-zero numeric stat item.
   */
  void CaptureNonZeroSamplesRecursive(moho::StatItem* item, const std::int32_t frameIndex)
  {
    if (!item) {
      return;
    }

    const moho::EStatType type = item->mType;
    if (type != moho::EStatType::kNone && type != moho::EStatType::kString) {
      const bool useRealtimeValue = (item->mUseRealtimeSlot == static_cast<std::int32_t>(moho::EPulseMode::kTick));
      const float sampleValue = item->GetFloat(useRealtimeValue);
      if (sampleValue != 0.0f) {
        AppendStatSample(item, frameIndex, sampleValue);
      }
    }

    for (StatIntrusiveNode* node = AsChildHead(item)->next; node != nullptr; node = node->next) {
      moho::StatItem* const child = node->owner;
      if (!child) {
        break;
      }
      CaptureNonZeroSamplesRecursive(child, frameIndex);
    }
  }

  /**
   * Address: 0x00415310 (FUN_00415310, recursive stat sample commit helper)
   *
   * What it does:
   * Commits one logging batch by rebasing every item's sample-end lane to the
   * sample-begin lane across the full stat tree.
   */
  [[maybe_unused]] void CommitStatSampleRangesRecursive(moho::StatItem* item)
  {
    if (!item) {
      return;
    }

    item->mSampleHistory.Clear();
    for (StatIntrusiveNode* node = AsChildHead(item)->next; node != nullptr; node = node->next) {
      moho::StatItem* const child = node->owner;
      if (!child) {
        break;
      }
      CommitStatSampleRangesRecursive(child);
    }
  }

  /**
   * Address: 0x00418D00 (FUN_00418D00, stat sample aggregate helper)
   *
   * What it does:
   * Computes `(avg, max, min, count)` over one stat item's captured sample
   * history lane.
   */
  [[maybe_unused]] bool TryComputeStatSampleAggregate(
    const moho::StatItem* item,
    float* outAverage,
    float* outMaximum,
    float* outMinimum,
    int* outCount
  )
  {
    if (!outAverage || !outMaximum || !outMinimum || !outCount || !item) {
      return false;
    }

    const moho::StatSamplePoint* const begin = item->mSampleHistory.begin;
    const moho::StatSamplePoint* const end = item->mSampleHistory.end;

    float sum = 0.0f;
    *outMinimum = FLT_MAX;
    *outMaximum = -FLT_MAX;
    *outAverage = 0.0f;

    for (const moho::StatSamplePoint* it = begin; it != end; ++it) {
      const float sampleValue = it->value;
      if (*outMinimum > sampleValue) {
        *outMinimum = sampleValue;
      }
      if (sampleValue > *outMaximum) {
        *outMaximum = sampleValue;
      }
      sum += sampleValue;
    }

    const int count = begin ? static_cast<int>(end - begin) : 0;
    *outCount = count;
    if (count <= 0) {
      return false;
    }

    *outAverage = sum / static_cast<float>(count);
    return true;
  }

  /**
   * Address: 0x00418D90 (FUN_00418D90, recursive stat log formatter)
   *
   * What it does:
   * Emits one depth-tagged stat report line per node with captured samples and
   * tracks maximum name width per depth for later formatting passes.
   */
  [[maybe_unused]] bool BuildStatReportRecursive(
    moho::StatItem* item,
    std::string& report,
    const unsigned int depth,
    std::vector<int>& depthNameWidths
  )
  {
    if (!item) {
      return false;
    }

    float average = 0.0f;
    float maximum = -FLT_MAX;
    float minimum = FLT_MAX;
    int sampleCount = 0;

    const bool hasSamples =
      TryComputeStatSampleAggregate(item, &average, &maximum, &minimum, &sampleCount);
    const std::size_t insertionOffset = report.size();

    bool wroteAnyLine = hasSamples;
    if (hasSamples) {
      if (depth == 1u) {
        report.append("\r\n");
      }
      report.append(
        gpg::STR_Printf(
             "*COLDEPTH%d*%s $$: calls[%6d] min[%9.2f] max[%9.2f] avg[%10.3f]\r\n",
             depth,
             item->mName.c_str(),
             sampleCount,
             minimum,
             maximum,
             average
          )
          .to_std()
      );
    }

    bool childWroteLine = false;
    for (StatIntrusiveNode* node = AsChildHead(item)->next; node != nullptr; node = node->next) {
      moho::StatItem* const child = node->owner;
      if (!child) {
        break;
      }
      if (BuildStatReportRecursive(child, report, depth + 1u, depthNameWidths)) {
        childWroteLine = true;
      }
    }

    if (!hasSamples) {
      if (!childWroteLine || depth == 0u) {
        return false;
      }

      report.insert(insertionOffset, gpg::STR_Printf("*COLDEPTH%d*%s\r\n", depth, item->mName.c_str()).to_std());
      wroteAnyLine = true;
      if (depth == 1u) {
        report.insert(insertionOffset, "\r\n");
      }
    }

    if (depthNameWidths.size() <= depth) {
      depthNameWidths.resize(depth + 1u, 0);
    }

    const int nameWidth = static_cast<int>(item->mName.size());
    if (depthNameWidths[depth] < nameWidth) {
      depthNameWidths[depth] = nameWidth;
    }

    return wroteAnyLine;
  }

  /**
   * Address: 0x004E9CF0 (FUN_004E9CF0, Moho::CTimeStamp::GetString)
   *
   * What it does:
   * Builds one ctime-style timestamp string and strips trailing newline.
   */
  [[nodiscard]] msvc8::string BuildCurrentTimestampString()
  {
    const __time64_t now = _time64(nullptr);
    char timestampBuffer[32]{};
    if (_ctime64_s(timestampBuffer, sizeof(timestampBuffer), &now) != 0) {
      return {};
    }

    msvc8::string timestamp(timestampBuffer);
    const std::size_t newlinePos = timestamp.find('\n');
    if (newlinePos != msvc8::string::npos) {
      timestamp.erase(newlinePos, 1u);
    }
    return timestamp;
  }

  /**
   * Address: 0x00415A50..0x00415B98 (FUN_00415660 local formatting pass)
   *
   * What it does:
   * Replaces `*COLDEPTHN*` tags with depth indentation and aligns `$$` marker
   * lanes using dot fill to produce fixed-width stat report columns.
   */
  void ApplyDepthPlaceholderFormatting(std::string& report, const std::vector<int>& depthNameWidths)
  {
    int totalNameWidth = 1;
    for (const int width : depthNameWidths) {
      totalNameWidth += width;
    }

    int indent = 0;
    for (std::size_t depth = 0; depth < depthNameWidths.size(); ++depth) {
      const std::string placeholder = gpg::STR_Printf("*COLDEPTH%d*", static_cast<int>(depth)).to_std();

      std::size_t searchPos = 0u;
      for (;;) {
        const std::size_t placeholderPos = report.find(placeholder, searchPos);
        if (placeholderPos == std::string::npos) {
          break;
        }

        report.erase(placeholderPos, placeholder.size());
        report.insert(placeholderPos, static_cast<std::size_t>(indent), ' ');

        const std::size_t newlinePos = report.find('\n', placeholderPos);
        const std::size_t alignPos = report.find("$$", placeholderPos);
        if (alignPos < newlinePos) {
          report.erase(alignPos, 2u);

          const std::size_t dotCount = placeholderPos + static_cast<std::size_t>(totalNameWidth) - alignPos;
          report.insert(alignPos, dotCount, '.');
        }

        searchPos = placeholderPos;
      }

      indent += depthNameWidths[depth];
    }
  }
} // namespace

namespace moho
{
  gpg::RType* StatItem::sType = nullptr;
  gpg::RType* Stats<StatItem>::sType = nullptr;
  EngineStats* sEngineStats = nullptr;
  static StatItem* sPrintStatsBoogers = nullptr;
  static StatItem* sPrintStatsBoogersFarts = nullptr;
  static StatItem* sPrintStatsInsert = nullptr;
  static StatItem* sPrintStatsDoubleFarts = nullptr;
  static StatItem* sPrintStatsBoogersSquirtInit = nullptr;
  static StatItem* sPrintStatsAnother = nullptr;
  static StatItem* sPrintStatsDeepStuff = nullptr;
  static StatItem* sPrintStatsBoogersSquirt = nullptr;
  static StatItem* sPrintStatsDouble = nullptr;

  /**
   * Address: 0x0040AB20 (FUN_0040AB20, sub_40AB20)
   *
   * What it does:
   * Swaps the global engine-stats singleton pointer with the caller slot.
   */
  static EngineStats** SwapEngineStatsSingleton(EngineStats** slot)
  {
    EngineStats* const previous = sEngineStats;
    sEngineStats = *slot;
    *slot = previous;
    return slot;
  }

  void StatSampleBuffer::Reset() noexcept
  {
    if (begin) {
      operator delete(begin);
      begin = nullptr;
    }
    end = nullptr;
    capacityEnd = nullptr;
  }

  void StatSampleBuffer::Clear() noexcept
  {
    end = begin;
  }

  std::size_t StatSampleBuffer::Size() const noexcept
  {
    return begin ? static_cast<std::size_t>(end - begin) : 0u;
  }

  StatSampleBuffer::~StatSampleBuffer() noexcept
  {
    Reset();
  }

  void StatItem::ResetTreeLinks()
  {
    StatIntrusiveNode* const selfNode = AsSelfNode(this);
    selfNode->prev = selfNode;
    selfNode->next = selfNode;
    selfNode->parent = nullptr;
    selfNode->owner = this;

    StatIntrusiveNode* const childHead = AsChildHead(this);
    childHead->prev = childHead;
    childHead->next = childHead;
    owner2 = this;
    mTreeMeta = 0;
  }

  void StatItem::DetachSelfNode()
  {
    StatIntrusiveNode* const selfNode = AsSelfNode(this);
    if (selfNode->next != nullptr && selfNode->prev != nullptr) {
      selfNode->next->prev = selfNode->prev;
      selfNode->prev->next = selfNode->next;
    }
    selfNode->prev = selfNode;
    selfNode->next = selfNode;
    selfNode->parent = nullptr;
  }

  void StatItem::AttachChild(StatItem* const child)
  {
    if (child == nullptr) {
      return;
    }

    child->DetachSelfNode();

    StatIntrusiveNode* const childNode = AsSelfNode(child);
    childNode->parent = this;

    StatIntrusiveNode* const parentHead = AsChildHead(this);
    childNode->prev = parentHead->prev;
    childNode->next = parentHead;
    parentHead->prev = childNode;
    childNode->prev->next = childNode;
  }

  StatItem* StatItem::FindDirectChildByName(const msvc8::string& token)
  {
    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr; node = node->next) {
      StatItem* const child = node->owner;
      if (child == nullptr) {
        break;
      }
      if (child->mName == token) {
        return child;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x0040A0A0 (FUN_0040A0A0, Moho::Stats_StatItem::Stats_StatItem)
   */
  Stats<StatItem>::Stats()
    : mItem(new StatItem(kRootStatName))
    , mLock(new boost::mutex())
    , pad_000D{0, 0, 0}
  {}

  /**
   * Address: 0x00406600 (FUN_00406600, Moho::Stats_StatItem::~Stats_StatItem)
   */
  Stats<StatItem>::~Stats()
  {
    delete mItem;
    mItem = nullptr;
    delete mLock;
    mLock = nullptr;
  }

  /**
   * Address: 0x0040B2E0 (FUN_0040B2E0, Moho::Stats_StatItem::Delete)
   */
  void Stats<StatItem>::Delete(const char* statPath)
  {
    boost::mutex::scoped_lock lock(*mLock);
    StatItem* const item = GetItem(statPath, false);
    if (item == mItem) {
      throw std::runtime_error("Don't be doing that, chief.");
    }
    if (item) {
      delete item;
    }
  }

  /**
   * Address: 0x0040C200 (FUN_0040C200, Moho::Stats_StatItem::GetItem)
   */
  StatItem* Stats<StatItem>::GetItem(const gpg::StrArg statPath, const bool allowCreate)
  {
    boost::mutex::scoped_lock lock(*mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    StatItem* const item = WalkStatPath(mItem, tokens, allowCreate, &didCreate);
    if (didCreate && item != nullptr) {
      item->SynchronizeAsInt();
    }
    return item;
  }

  /**
   * Address: 0x00417B60 (FUN_00417B60, Moho::EngineStats::GetItem3)
   */
  StatItem* Stats<StatItem>::GetFloatItem(const gpg::StrArg statPath)
  {
    boost::mutex::scoped_lock lock(*mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    StatItem* const item = WalkStatPath(mItem, tokens, true, &didCreate);
    if (didCreate && item != nullptr) {
      item->SynchronizeAsFloat();
    }
    return item;
  }

  /**
   * Address: 0x00417C50 (FUN_00417C50, Moho::EngineStats::GetItem_0)
   */
  StatItem* Stats<StatItem>::GetStringItem(const gpg::StrArg statPath)
  {
    boost::mutex::scoped_lock lock(*mLock);

    msvc8::vector<msvc8::string> tokens;
    gpg::STR_GetTokens(statPath, "_", tokens);

    bool didCreate = false;
    StatItem* const item = WalkStatPath(mItem, tokens, true, &didCreate);
    if (didCreate && item != nullptr) {
      boost::mutex::scoped_lock itemLock(item->mLock);
      item->mType = EStatType::kString;
    }
    return item;
  }

  /**
   * Address: 0x00436290 (FUN_00436290, Moho::EngineStats::GetItem2)
   */
  StatItem* Stats<StatItem>::GetIntItem(const gpg::StrArg statPath)
  {
    return GetItem(statPath, true);
  }

  /**
   * Address: 0x004088C0 (FUN_004088C0, Moho::EngineStats::EngineStats)
   */
  EngineStats::EngineStats()
    : Stats<StatItem>()
    , mLogFileName("stats.log")
    , mResolvedLogFilePath()
    , mLogFrameCount(0)
    , mIsLogging(0)
    , mPad4D{0, 0, 0}
  {}

  /**
   * Address: 0x00407DC0 (FUN_00407DC0, Moho::EngineStats::~EngineStats)
   */
  EngineStats::~EngineStats() = default;

  /**
   * Address: 0x00417B60 (FUN_00417B60, Moho::EngineStats::GetItem3)
   */
  StatItem* EngineStats::GetItem3(const gpg::StrArg statPath)
  {
    return GetFloatItem(statPath);
  }

  /**
   * Address: 0x00417C50 (FUN_00417C50, Moho::EngineStats::GetItem_0)
   */
  StatItem* EngineStats::GetItem_0(const gpg::StrArg statPath)
  {
    return GetStringItem(statPath);
  }

  /**
   * Address: 0x00417D60 (FUN_00417D60, Moho::EngineStats::FindItem)
   */
  StatItem* EngineStats::FindItem(const char* const statPath)
  {
    return GetFloatItem(statPath ? statPath : "");
  }

  /**
   * Address: 0x00436290 (FUN_00436290, Moho::EngineStats::GetItem2)
   */
  StatItem* EngineStats::GetItem2(const gpg::StrArg statPath)
  {
    return GetIntItem(statPath);
  }

  /**
   * Address: 0x00408940 (FUN_00408940, Moho::GetEngineStats)
   */
  EngineStats* GetEngineStats()
  {
    EngineStats* result = sEngineStats;
    if (result != nullptr) {
      return result;
    }

    EngineStats* candidate = new (std::nothrow) EngineStats();
    (void)SwapEngineStatsSingleton(&candidate);
    if (candidate != nullptr) {
      delete candidate;
    }
    return sEngineStats;
  }

  /**
   * Address: 0x0047A5E0 (FUN_0047A5E0, Moho::LOG_GenerateFilenamePrefix)
   *
   * What it does:
   * Builds a local-time filename prefix as `YYYY-MM-DD.HH-MM`.
   */
  msvc8::string LOG_GenerateFilenamePrefix()
  {
    const __time64_t now = _time64(nullptr);

    __timeb64 currentTime{};
    currentTime.time = now;
    currentTime.millitm = 0;
    (void)_ftime64_s(&currentTime);

    std::tm localTime{};
    __time64_t wallClockSeconds = currentTime.time;
    if (_localtime64_s(&localTime, &wallClockSeconds) != 0) {
      wallClockSeconds = now;
      (void)_localtime64_s(&localTime, &wallClockSeconds);
    }

    return gpg::STR_Printf(
      "%4d-%02d-%02d.%02d-%02d",
      localTime.tm_year + 1900,
      localTime.tm_mon + 1,
      localTime.tm_mday,
      localTime.tm_hour,
      localTime.tm_min
    );
  }

  /**
   * Address: 0x00415660 (FUN_00415660, Moho::EngineStats::EndLogging)
   *
   * What it does:
   * Resolves the final log file path, writes SupComMark summary + per-stat
   * report, clears captured sample history, and returns composite score.
   */
  float EngineStats::EndLogging()
  {
    if (mIsLogging == 0 || mLogFileName.empty()) {
      mIsLogging = 0;
      return 0.0f;
    }

    const msvc8::string prefix = LOG_GenerateFilenamePrefix();
    mResolvedLogFilePath = prefix + "-" + mLogFileName;

    gpg::FileStream logFile(mResolvedLogFilePath.c_str(), gpg::Stream::ModeSend, 0u, 0x1000);
    gpg::TextWriter writer(&logFile, 2);
    writer.WriteCString("Stats Log Report \n\n");
    writer.Printf("Logged frames          : %d\n", mLogFrameCount);

    const msvc8::string timestampText = BuildCurrentTimestampString();
    writer.Printf("Timestamp              : %s\n\n", timestampText.c_str());

    StatItem* const simSyncItem = GetEngineStats()->GetItem("Sim_Sync", false);
    StatItem* const simDispatchItem = GetEngineStats()->GetItem("Sim_Dispatch", false);
    StatItem* const frameTimeItem = GetEngineStats()->GetItem("Frame_Time", false);
    (void)GetEngineStats()->GetItem("Frame_FPS", false);

    float average = 0.0f;
    float maximum = 0.0f;
    float minimum = 0.0f;
    int sampleCount = 0;

    float simSampleAverage = 0.0f;
    float renderSampleAverage = 0.0f;
    if (simSyncItem &&
        TryComputeStatSampleAggregate(simSyncItem, &average, &maximum, &minimum, &sampleCount)) {
      simSampleAverage = average;
    }
    if (simDispatchItem &&
        TryComputeStatSampleAggregate(simDispatchItem, &average, &maximum, &minimum, &sampleCount)) {
      simSampleAverage += average;
    }
    if (frameTimeItem &&
        TryComputeStatSampleAggregate(frameTimeItem, &average, &maximum, &minimum, &sampleCount)) {
      renderSampleAverage = average;
    }

    const float simScore = 10000.0f - (simSampleAverage * 50.0f);
    const float renderScore = 10000.0f - (renderSampleAverage * 75.757576f);
    const float compositeScore = simScore + renderScore;

    writer.Printf("SupComMark (sim)       : %7.0f\n", simScore);
    writer.Printf("SupComMark (render)    : %7.0f\n", renderScore);
    writer.Printf("SupComMark (composite) : %7.0f\n", compositeScore);
    writer.Printf("(Note: SupComMark scores represent overall system performance.  Higher is better.)\n\n");

    StatItem* const rootItem = GetEngineStats()->mItem;
    std::string reportBody;
    std::vector<int> depthNameWidths;
    BuildStatReportRecursive(rootItem, reportBody, 0u, depthNameWidths);
    ApplyDepthPlaceholderFormatting(reportBody, depthNameWidths);

    writer.WriteString(msvc8::string(reportBody.c_str()));

    if (rootItem) {
      CommitStatSampleRangesRecursive(rootItem);
    }

    mIsLogging = 0;
    return compositeScore;
  }

  /**
   * Address: 0x0041B390 (FUN_0041B390, Moho::STAT_GetLuaTable)
   *
   * What it does:
   * Builds one Lua table node for the requested stat item and recursively
   * emits children into `Children`.
   */
  void STAT_GetLuaTable(LuaPlus::LuaState* const state, StatItem* const item, LuaPlus::LuaObject& outObject)
  {
    GPG_ASSERT(state != nullptr);
    GPG_ASSERT(item != nullptr);
    if (state == nullptr || item == nullptr) {
      return;
    }

    boost::mutex::scoped_lock lock(item->mLock);

    outObject.AssignNewTable(state, 0, 0);
    item->ToLua(state, &outObject);

    StatIntrusiveNode* const childHead = AsChildHead(item);
    if (childHead == nullptr || childHead->next == childHead) {
      return;
    }

    LuaPlus::LuaObject children(state);
    children.AssignNewTable(state, 0, 0);

    std::int32_t childIndex = 1;
    for (StatIntrusiveNode* node = childHead->next; node != nullptr;) {
      StatIntrusiveNode* const next = node->next;
      StatItem* const child = node->owner;
      if (child == nullptr) {
        break;
      }

      LuaPlus::LuaObject childObject(state);
      STAT_GetLuaTable(state, child, childObject);
      children.SetObject(childIndex, childObject);
      ++childIndex;

      node = next;
    }

    outObject.SetObject("Children", children);
  }

  /**
   * Address: 0x004162C0 (FUN_004162C0, Moho::CON_ClearStats)
   */
  void CON_ClearStats(void* const commandArgs)
  {
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);

    const msvc8::string* targetPath = nullptr;
    if (args.Count() >= 2u) {
      targetPath = args.At(1u);
    }

    const char* const statPath = targetPath ? targetPath->c_str() : "";
    GetEngineStats()->Delete(statPath);
  }

  /**
   * Address: 0x004163A0 (FUN_004163A0, Moho::CON_BeginLoggingStats)
   */
  void CON_BeginLoggingStats(void* const commandArgs)
  {
    EngineStats* const engineStats = GetEngineStats();
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);

    const msvc8::string* requestedPath = nullptr;
    if (args.Count() >= 2u) {
      requestedPath = args.At(1u);
    } else {
      requestedPath = &engineStats->mLogFileName;
    }

    if (requestedPath && !requestedPath->empty()) {
      engineStats->mLogFileName.assign(*requestedPath, 0, msvc8::string::npos);
    }

    engineStats->mLogFrameCount = 0;
    engineStats->mIsLogging = 1;
  }

  /**
   * Address: 0x00415C70 (FUN_00415C70, recursive stats print helper)
   *
   * What it does:
   * Walks one stats subtree and logs `name: value` lines with depth-based
   * indentation.
   */
  static void DumpStatsTreeRecursive(StatItem* const root, const int depth)
  {
    if (!root) {
      return;
    }

    for (StatIntrusiveNode* node = AsChildHead(root)->next; node != nullptr; node = node->next) {
      StatItem* const child = node->owner;
      if (!child) {
        break;
      }

      msvc8::string valueText;
      child->GetString(false, &valueText);

      msvc8::string indent;
      indent.assign(static_cast<std::size_t>(depth * 4), ' ');

      const msvc8::string line = indent + child->mName + ": " + valueText;
      gpg::Logf("%s", line.c_str());

      DumpStatsTreeRecursive(child, depth + 1);
    }
  }

  /**
   * Address: 0x00417A00 (FUN_00417A00, atomic stat-slot set helper)
   *
   * What it does:
   * Atomically stores one 32-bit payload into the cached `Double` stat item
   * primary numeric slot and returns the previous lane value.
   */
  static std::int32_t StorePrintStatsDoubleSlotBits(const std::int32_t* const valueBits)
  {
    if (!sPrintStatsDouble) {
      return 0;
    }
    return AtomicStoreSlotFromPtr(&sPrintStatsDouble->mPrimaryValueBits, valueBits);
  }

  /**
   * Address: 0x00415EC0 (FUN_00415EC0, Moho::CON_PrintStats)
   *
   * What it does:
   * Populates one debug stats subtree with representative values and emits a
   * recursive text dump to the log sink.
   */
  void CON_PrintStats(void* const /*commandArgs*/)
  {
    if (!sPrintStatsBoogers) {
      sPrintStatsBoogers = GetEngineStats()->GetItem("Boogers", true);
      if (sPrintStatsBoogers) {
        (void)sPrintStatsBoogers->Release(0);
      }
    }
    if (sPrintStatsBoogers) {
      const std::int32_t bits = 1;
      (void)StorePrimaryValueBits_IntPath(sPrintStatsBoogers, &bits);
    }

    if (!sPrintStatsBoogersFarts) {
      sPrintStatsBoogersFarts = GetEngineStats()->GetItem3("Boogers_Farts");
      if (sPrintStatsBoogersFarts) {
        (void)sPrintStatsBoogersFarts->Release(0);
      }
    }
    if (sPrintStatsBoogersFarts) {
      const float value = 1.0f;
      std::int32_t bits = 0;
      std::memcpy(&bits, &value, sizeof(bits));
      (void)StorePrimaryValueBits_FloatPath(sPrintStatsBoogersFarts, &bits);
    }

    if (!sPrintStatsInsert) {
      sPrintStatsInsert = GetEngineStats()->GetItem("Insert", true);
      if (sPrintStatsInsert) {
        (void)sPrintStatsInsert->Release(0);
      }
    }
    if (sPrintStatsInsert) {
      const std::int32_t bits = 54;
      (void)StorePrimaryValueBits_IntPath(sPrintStatsInsert, &bits);
    }

    if (!sPrintStatsDoubleFarts) {
      sPrintStatsDoubleFarts = GetEngineStats()->GetItem_0("Boogers_Farts_DoubleFarts");
      if (sPrintStatsDoubleFarts) {
        (void)sPrintStatsDoubleFarts->Release(0);
      }
    }
    if (sPrintStatsDoubleFarts) {
      const msvc8::string value("Boogers!");
      sPrintStatsDoubleFarts->SetValue(value);
    }

    if (!sPrintStatsBoogersSquirtInit) {
      sPrintStatsBoogersSquirtInit = GetEngineStats()->GetItem("Boogers_Squirt", true);
      if (sPrintStatsBoogersSquirtInit) {
        (void)sPrintStatsBoogersSquirtInit->Release(0);
      }
    }
    if (sPrintStatsBoogersSquirtInit) {
      const std::int32_t bits = 27;
      (void)StorePrimaryValueBits_IntPath(sPrintStatsBoogersSquirtInit, &bits);
    }

    if (!sPrintStatsAnother) {
      sPrintStatsAnother = GetEngineStats()->GetItem3("Another");
      if (sPrintStatsAnother) {
        (void)sPrintStatsAnother->Release(0);
      }
    }
    if (sPrintStatsAnother) {
      const float value = 15.0f;
      std::int32_t bits = 0;
      std::memcpy(&bits, &value, sizeof(bits));
      (void)StorePrimaryValueBits_FloatPath(sPrintStatsAnother, &bits);
    }

    if (!sPrintStatsDeepStuff) {
      sPrintStatsDeepStuff = GetEngineStats()->GetItem_0("Really_Deeep_Stuff_And_Stuff");
      if (sPrintStatsDeepStuff) {
        (void)sPrintStatsDeepStuff->Release(0);
      }
    }
    if (sPrintStatsDeepStuff) {
      const msvc8::string value("woohoo!");
      sPrintStatsDeepStuff->SetValue(value);
    }

    if (!sPrintStatsBoogersSquirt) {
      sPrintStatsBoogersSquirt = GetEngineStats()->GetItem("Boogers_Squirt", true);
      if (sPrintStatsBoogersSquirt) {
        (void)sPrintStatsBoogersSquirt->Release(0);
      }
    }
    if (sPrintStatsBoogersSquirt) {
#if defined(_WIN32)
      (void)InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&sPrintStatsBoogersSquirt->mPrimaryValueBits), 1L);
#else
      ++sPrintStatsBoogersSquirt->mPrimaryValueBits;
#endif
    }

    if (!sPrintStatsDouble) {
      sPrintStatsDouble = GetEngineStats()->FindItem("Double");
      if (sPrintStatsDouble) {
        (void)sPrintStatsDouble->Release(0);
      }
    }
    {
      const float value = 15.0f;
      std::int32_t bits = 0;
      std::memcpy(&bits, &value, sizeof(bits));
      (void)StorePrintStatsDoubleSlotBits(&bits);
    }

    EngineStats* const engineStats = GetEngineStats();
    DumpStatsTreeRecursive(engineStats ? engineStats->mItem : nullptr, 0);
  }

  /**
   * Address: 0x00834F90 (FUN_00834F90, Moho::ShowStats)
   */
  void ShowStats(void* const commandArgs)
  {
    CUIManager* const uiManager = g_UIManager;
    if (!uiManager || uiManager->mFrames.Empty() || !uiManager->mFrames[0]) {
      return;
    }

    LuaPlus::LuaState* const state = uiManager->mLuaState;
    LuaPlus::LuaObject moduleObject = SCR_Import(state, "/lua/debug/EngineStats.lua");
    if (!moduleObject.IsTable()) {
      LuaPlus::LuaState::Error(state, "failed to load \"/lua/debug/EngineStats.lua\" module");
    }

    msvc8::string mode = "all";
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() > 1u) {
      if (const msvc8::string* const requestedMode = args.At(1u); requestedMode != nullptr) {
        mode.assign(*requestedMode, 0, msvc8::string::npos);
      }
    }

    LuaPlus::LuaObject toggleFunction = moduleObject.GetByName("Toggle");
    LuaPlus::LuaFunction<void> toggleCallable(toggleFunction);
    toggleCallable(mode.c_str());
  }

  /**
   * Address: 0x00835160 (FUN_00835160, Moho::ShowArmyStats)
   */
  void ShowArmyStats(void* const commandArgs)
  {
    CUIManager* const uiManager = g_UIManager;
    if (!uiManager || uiManager->mFrames.Empty() || !uiManager->mFrames[0]) {
      return;
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (!session) {
      return;
    }

    UserArmy* const focusArmy = session->GetFocusUserArmy();
    if (!focusArmy) {
      return;
    }

    LuaPlus::LuaState* const state = uiManager->mLuaState;
    LuaPlus::LuaObject moduleObject = SCR_Import(state, "/lua/debug/ArmyStats.lua");
    if (!moduleObject.IsTable()) {
      LuaPlus::LuaState::Error(state, "failed to load \"/lua/debug/ArmyStats.lua\" module");
    }

    int armyIndex = static_cast<int>(focusArmy->mArmyIndex);
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() > 1u) {
      if (const msvc8::string* const requestedArmy = args.At(1u); requestedArmy != nullptr) {
        armyIndex = std::atoi(requestedArmy->c_str());
      }
    }

    msvc8::string mode = "all";
    if (args.Count() > 2u) {
      if (const msvc8::string* const requestedMode = args.At(2u); requestedMode != nullptr) {
        mode.assign(*requestedMode, 0, msvc8::string::npos);
      }
    }

    LuaPlus::LuaObject showFunction = moduleObject.GetByName("Show");
    LuaPlus::LuaFunction<void> showCallable(showFunction);
    showCallable(armyIndex, mode.c_str());
  }

  /**
   * Address: 0x00416480 (FUN_00416480, Moho::CON_EndLoggingStats)
   */
  void CON_EndLoggingStats(void* const /*commandArgs*/)
  {
    (void)GetEngineStats()->EndLogging();
  }

  /**
   * Address: 0x00415640 (FUN_00415640, frame-side logging traversal helper)
   *
   * What it does:
   * Captures one logging frame worth of non-zero stat samples and advances the
   * running log-frame index.
   */
  static void CaptureLoggingFrameSamples(EngineStats* const engineStats)
  {
    if (!engineStats) {
      return;
    }

    StatItem* const rootItem = GetEngineStats()->mItem;
    if (rootItem) {
      CaptureNonZeroSamplesRecursive(rootItem, engineStats->mLogFrameCount);
    }
    ++engineStats->mLogFrameCount;
  }

  /**
   * Address: 0x00415E60 (FUN_00415E60, Moho::STAT_Frame)
   *
   * What it does:
   * Applies frame-pulse clears across the stat tree and captures one logging
   * sample frame when logging is active.
   */
  void STAT_Frame()
  {
    EngineStats* const engineStats = GetEngineStats();
    StatItem* const rootItem = engineStats ? engineStats->mItem : nullptr;
    if (rootItem) {
      rootItem->ClearChildren(static_cast<std::int32_t>(EPulseMode::kFrame));
    }

    if (engineStats && engineStats->mIsLogging != 0) {
      CaptureLoggingFrameSamples(engineStats);
    }
  }

  /**
   * Address: 0x00416510 (FUN_00416510, cfunc_BeginLoggingStatsL)
   */
  int cfunc_BeginLoggingStatsL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      luaL_error(rawState, "%s\n  expected %d args, but got %d", kBeginLoggingStatsLuaHelpText, 1, argumentCount);
    }

    LuaPlus::LuaStackObject stackArg(state, 1);
    const char* const argPath = stackArg.GetString();

    EngineStats* const engineStats = GetEngineStats();
    const char* selectedPath = argPath;
    if (!selectedPath || *selectedPath == '\0') {
      selectedPath = engineStats->mLogFileName.c_str();
    }

    if (selectedPath && *selectedPath != '\0') {
      engineStats->mLogFileName = selectedPath;
    }

    engineStats->mIsLogging = 1;
    engineStats->mLogFrameCount = 0;
    return 0;
  }

  /**
   * Address: 0x00416490 (FUN_00416490, cfunc_BeginLoggingStats)
   */
  int cfunc_BeginLoggingStats(lua_State* const luaContext)
  {
    return cfunc_BeginLoggingStatsL(luaContext ? luaContext->stateUserData : nullptr);
  }

  /**
   * Address: 0x004164B0 (FUN_004164B0, func_BeginLoggingStats_LuaFuncDef)
   */
  CScrLuaInitForm* func_BeginLoggingStats_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "BeginLoggingStats",
      &moho::cfunc_BeginLoggingStats,
      nullptr,
      "<global>",
      kBeginLoggingStatsLuaHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x004166C0 (FUN_004166C0, cfunc_EndLoggingStatsL)
   */
  int cfunc_EndLoggingStatsL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 0 || argumentCount > 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kEndLoggingStatsLuaHelpText,
        0,
        1,
        argumentCount
      );
    }

    lua_settop(rawState, 1);
    const float compositeScore = GetEngineStats()->EndLogging();

    const int argType = lua_type(rawState, 1);
    bool shouldExit = (argType == LUA_TNIL);
    if (!shouldExit) {
      LuaPlus::LuaStackObject stackArg(state, 1);
      shouldExit = stackArg.GetBoolean();
    }

    if (shouldExit) {
      const char* const logPath = GetEngineStats()->mResolvedLogFilePath.c_str();
      const msvc8::string message = gpg::STR_Printf(
        "Performance test run complete!\n"
        "\n"
        "Your 'SupComMark' composite score is: %7.0f   (higher is better)\n"
        "\n"
        "Complete performance results can be found at: %s\n",
        compositeScore,
        logPath ? logPath : ""
      );
      WIN_OkBox("Complete!", message.c_str());

      if (wxTheApp != nullptr) {
        wxTheApp->ExitMainLoop();
      }
    }

    return 0;
  }

  /**
   * Address: 0x00416640 (FUN_00416640, cfunc_EndLoggingStats)
   */
  int cfunc_EndLoggingStats(lua_State* const luaContext)
  {
    return cfunc_EndLoggingStatsL(luaContext ? luaContext->stateUserData : nullptr);
  }

  /**
   * Address: 0x00416660 (FUN_00416660, func_EndLoggingStats_LuaFuncDef)
   */
  CScrLuaInitForm* func_EndLoggingStats_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      CoreLuaInitSet(),
      "EndLoggingStats",
      &moho::cfunc_EndLoggingStats,
      nullptr,
      "<global>",
      kEndLoggingStatsLuaHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00BC3540 (FUN_00BC3540, register_BeginLoggingStats_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_BeginLoggingStats_LuaFuncDef`.
   */
  void register_BeginLoggingStats_LuaFuncDef()
  {
    (void)func_BeginLoggingStats_LuaFuncDef();
  }

  /**
   * Address: 0x00BC3550 (FUN_00BC3550, register_EndLoggingStats_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_EndLoggingStats_LuaFuncDef`.
   */
  CScrLuaInitForm* register_EndLoggingStats_LuaFuncDef()
  {
    return func_EndLoggingStats_LuaFuncDef();
  }

  /**
   * Address: 0x00408730 (FUN_00408730, Moho::StatItem::StatItem)
   */
  StatItem::StatItem(const char* name)
    : mPrimaryValueBits(0)
    , mValue()
    , mRealtimeValueBits(0)
    , mScratchValue()
    , mSampleTag(0)
    , mSampleHistory{}
    , mName(name ? name : "")
    , mType(EStatType::kNone)
    , mUseRealtimeSlot(0)
    , mLock()
  {
    ResetTreeLinks();
  }

  /**
   * Address: 0x00408840 (FUN_00408840, deleting dtor thunk)
   * Address: 0x00418610 (FUN_00418610, destructor core)
   */
  StatItem::~StatItem()
  {
    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr;) {
      StatItem* const child = node->owner;
      if (child == nullptr) {
        break;
      }

      StatIntrusiveNode* const next = node->next;
      delete child;
      node = next;
    }

    DetachSelfNode();
    ResetTreeLinks();
  }

  /**
   * Address: 0x00417FE0 (FUN_00417FE0, Moho::StatItem::SetValue_0)
   */
  void StatItem::SetValueCopy(msvc8::string* outValue)
  {
    boost::mutex::scoped_lock lock(mLock);
    outValue->assign(mValue, 0, msvc8::string::npos);
  }

  /**
   * Address: 0x00415220 (FUN_00415220, Moho::StatItem::SetValue)
   */
  void StatItem::SetValue(const msvc8::string& value)
  {
    boost::mutex::scoped_lock lock(mLock);
    mValue.assign(value, 0, msvc8::string::npos);
  }

  /**
   * Address: 0x004151E0 (FUN_004151E0, Moho::StatItem::Release)
   */
  std::int32_t StatItem::Release(const std::int32_t value)
  {
    return AtomicExchangeI32(&mUseRealtimeSlot, value);
  }

  /**
   * Address: 0x00418B00 (FUN_00418B00, Moho::StatItem::Clear)
   */
  void StatItem::Clear(const bool recursive)
  {
    constexpr std::int32_t kZeroBits = 0;
    switch (mType) {
    case EStatType::kFloat:
      (void)StorePrimaryValueBits_FloatPath(this, &kZeroBits);
      break;
    case EStatType::kInt:
      (void)StorePrimaryValueBits_IntPath(this, &kZeroBits);
      break;
    case EStatType::kString: {
      boost::mutex::scoped_lock lock(mLock);
      mValue.clear();
      break;
    }
    default:
      break;
    }

    if (!recursive) {
      return;
    }

    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr; node = node->next) {
      StatItem* const child = node->owner;
      if (!child) {
        break;
      }
      child->Clear(true);
    }
  }

  /**
   * Address: 0x00418A90 (FUN_00418A90, Moho::StatItem::ClearChildren)
   */
  void StatItem::ClearChildren(const std::int32_t pulseMode)
  {
    if (mUseRealtimeSlot == pulseMode) {
      if (pulseMode == static_cast<std::int32_t>(EPulseMode::kTick) && mType != EStatType::kString) {
        (void)SyncRealtimeValueBitsFromPrimary(this);
      }
      Clear(false);
    }

    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr; node = node->next) {
      StatItem* const child = node->owner;
      if (!child) {
        break;
      }
      child->ClearChildren(pulseMode);
    }
  }

  /**
   * Address: 0x00419090 (FUN_00419090, Moho::StatItem::SerializeList)
   */
  void StatItem::SerializeList(gpg::WriteArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    for (StatIntrusiveNode* node = AsChildHead(this)->next; node != nullptr; node = node->next) {
      StatItem* const child = node->owner;
      if (!child) {
        break;
      }
      const gpg::RRef childRef = MakeStatItemRef(child);
      gpg::WriteRawPointer(archive, childRef, gpg::TrackedPointerState::Owned, nullOwner);
    }

    const gpg::RRef nullChild = MakeStatItemRef(nullptr);
    gpg::WriteRawPointer(archive, nullChild, gpg::TrackedPointerState::Owned, nullOwner);
  }

  /**
   * Address: 0x00419110 (FUN_00419110, Moho::StatItem::DeserializeList)
   */
  void StatItem::DeserializeList(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    for (;;) {
      StatItem* const child = ReadOwnedArchiveStatItemPointer(archive, nullOwner);
      if (!child) {
        break;
      }
      AttachChild(child);
    }
  }

  /**
   * Address: 0x0041AD70 (FUN_0041AD70, Moho::StatItem::MemberDeserialize)
   */
  void StatItem::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    boost::mutex::scoped_lock lock(mLock);

    static gpg::RType* sEStatType = nullptr;
    static gpg::RType* sEPulseMode = nullptr;
    if (!sEStatType) {
      sEStatType = gpg::LookupRType(typeid(EStatType));
    }
    if (!sEPulseMode) {
      sEPulseMode = gpg::LookupRType(typeid(EPulseMode));
    }

    archive->Read(sEStatType, &mType, gpg::RRef{});
    switch (mType) {
    case EStatType::kNone:
      break;
    case EStatType::kFloat: {
      float primary = 0.0f;
      float realtime = 0.0f;
      archive->ReadFloat(&primary);
      archive->ReadFloat(&realtime);
      std::memcpy(const_cast<std::int32_t*>(&mPrimaryValueBits), &primary, sizeof(primary));
      std::memcpy(const_cast<std::int32_t*>(&mRealtimeValueBits), &realtime, sizeof(realtime));
      break;
    }
    case EStatType::kInt: {
      int primary = 0;
      int realtime = 0;
      archive->ReadInt(&primary);
      archive->ReadInt(&realtime);
      mPrimaryValueBits = primary;
      mRealtimeValueBits = realtime;
      break;
    }
    case EStatType::kString:
      archive->ReadString(&mValue);
      archive->ReadString(&mScratchValue);
      break;
    default:
      gpg::HandleAssertFailure("Reached the supposably unreachable.", 360, "c:\\work\\rts\\main\\code\\src\\core\\Stats.cpp");
      break;
    }

    archive->ReadString(&mName);
    archive->Read(sEPulseMode, const_cast<std::int32_t*>(&mUseRealtimeSlot), gpg::RRef{});
    DeserializeList(archive);
  }

  /**
   * Address: 0x0041AEE0 (FUN_0041AEE0, Moho::StatItem::MemberSerialize)
   */
  void StatItem::MemberSerialize(gpg::WriteArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    boost::mutex::scoped_lock lock(mLock);

    static gpg::RType* sEStatType = nullptr;
    static gpg::RType* sEPulseMode = nullptr;
    if (!sEStatType) {
      sEStatType = gpg::LookupRType(typeid(EStatType));
    }
    if (!sEPulseMode) {
      sEPulseMode = gpg::LookupRType(typeid(EPulseMode));
    }

    archive->Write(sEStatType, &mType, gpg::RRef{});
    switch (mType) {
    case EStatType::kNone:
      break;
    case EStatType::kFloat:
      archive->WriteFloat(AsFloatBits(mPrimaryValueBits));
      archive->WriteFloat(AsFloatBits(mRealtimeValueBits));
      break;
    case EStatType::kInt:
      archive->WriteInt(mPrimaryValueBits);
      archive->WriteInt(mRealtimeValueBits);
      break;
    case EStatType::kString:
      archive->WriteString(&mValue);
      archive->WriteString(&mScratchValue);
      break;
    default:
      gpg::HandleAssertFailure("Reached the supposably unreachable.", 360, "c:\\work\\rts\\main\\code\\src\\core\\Stats.cpp");
      break;
    }

    archive->WriteString(&mName);
    archive->Write(sEPulseMode, const_cast<std::int32_t*>(&mUseRealtimeSlot), gpg::RRef{});
    SerializeList(archive);
  }

  /**
   * Address: 0x00418750 (FUN_00418750, Moho::StatItem::GetString)
   */
  msvc8::string* StatItem::GetString(const bool useRealtimeValue, msvc8::string* outValue)
  {
    if (mType == EStatType::kFloat) {
      *outValue = gpg::STR_Printf("%.2f", AsFloatBits(ReadNumericSlot(this, useRealtimeValue)));
      return outValue;
    }

    if (mType == EStatType::kInt) {
      *outValue = gpg::STR_Printf("%i", ReadNumericSlot(this, useRealtimeValue));
      return outValue;
    }

    SetValueCopy(outValue);
    return outValue;
  }

  /**
   * Address: 0x00418890 (FUN_00418890, Moho::StatItem::GetInt)
   */
  int StatItem::GetInt(const bool useRealtimeValue)
  {
    if (mType == EStatType::kFloat) {
      return static_cast<int>(AsFloatBits(ReadNumericSlot(this, useRealtimeValue)));
    }

    if (mType == EStatType::kInt) {
      return ReadNumericSlot(this, useRealtimeValue);
    }

    msvc8::string value;
    SetValueCopy(&value);
    return std::atoi(value.c_str());
  }

  /**
   * Address: 0x00418990 (FUN_00418990, Moho::StatItem::GetFloat)
   */
  float StatItem::GetFloat(const bool useRealtimeValue)
  {
    if (mType == EStatType::kFloat) {
      return AsFloatBits(ReadNumericSlot(this, useRealtimeValue));
    }

    if (mType == EStatType::kInt) {
      return static_cast<float>(ReadNumericSlot(this, useRealtimeValue));
    }

    msvc8::string value;
    SetValueCopy(&value);
    return static_cast<float>(std::atof(value.c_str()));
  }

  /**
   * Address: 0x0040D2D0 (FUN_0040D2D0, Moho::StatItem::Synchronize2)
   */
  void StatItem::SynchronizeAsInt()
  {
    AtomicStoreI32(reinterpret_cast<volatile std::int32_t*>(&mType), static_cast<std::int32_t>(EStatType::kInt));
  }

  /**
   * Address: 0x00415370 (FUN_00415370, Moho::StatItem::Synchronize3)
   */
  void StatItem::SynchronizeAsFloat()
  {
    AtomicStoreI32(reinterpret_cast<volatile std::int32_t*>(&mType), static_cast<std::int32_t>(EStatType::kFloat));
  }

  /**
   * Address: 0x00418BD0 (FUN_00418BD0, Moho::StatItem::ToLua)
   */
  void StatItem::ToLua(LuaPlus::LuaState* /*state*/, LuaPlus::LuaObject* outObject)
  {
    outObject->SetString("Name", mName.c_str());
    if (mType == EStatType::kNone) {
      return;
    }

    const bool useRealtimeValue = (mUseRealtimeSlot == 1);
    switch (mType) {
    case EStatType::kFloat:
      outObject->SetNumber("Value", GetFloat(useRealtimeValue));
      outObject->SetString("Type", "Float");
      break;
    case EStatType::kInt:
      outObject->SetInteger("Value", GetInt(useRealtimeValue));
      outObject->SetString("Type", "Integer");
      break;
    case EStatType::kString: {
      msvc8::string value;
      GetString(useRealtimeValue, &value);
      if (!value.empty()) {
        outObject->SetString("Value", value.c_str());
      }
      outObject->SetString("Type", "String");
      break;
    }
    default:
      break;
    }
  }

  /**
   * Address: 0x004194E0 (FUN_004194E0, sub_4194E0)
   */
  void StatItemSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedStatItemType();
    const gpg::RType::load_func_t loadFunc = mSerLoadFunc ? mSerLoadFunc : &DeserializeStatItem;
    const gpg::RType::save_func_t saveFunc = mSerSaveFunc ? mSerSaveFunc : &SerializeStatItem;
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = loadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = saveFunc;
  }

  /**
   * Address: 0x004192B0 (FUN_004192B0, gpg::PrimitiveSerHelper<Moho::EStatType,int>::Init)
   */
  void EStatTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedEStatTypeType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00419350 (FUN_00419350, gpg::PrimitiveSerHelper<Moho::EPulseMode,int>::Init)
   */
  void EPulseModePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedEPulseModeType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x004184B0 (FUN_004184B0, Moho::StatItemTypeInfo::StatItemTypeInfo)
   */
  StatItemTypeInfo::StatItemTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(StatItem), this);
  }

  /**
   * Address: 0x00418560 (FUN_00418560, sub_418560)
   */
  StatItemTypeInfo::~StatItemTypeInfo() = default;

  /**
   * Address: 0x00418550 (FUN_00418550, sub_418550)
   */
  const char* StatItemTypeInfo::GetName() const
  {
    return "StatItem";
  }

  /**
   * Address: 0x00418510 (FUN_00418510, sub_418510)
   */
  void StatItemTypeInfo::Init()
  {
    size_ = sizeof(StatItem);
    AssignStatItemTypeLifecycleCallbacks(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x004181C0 (FUN_004181C0, Moho::EStatTypeTypeInfo::EStatTypeTypeInfo)
   */
  EStatTypeTypeInfo::EStatTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EStatType), this);
  }

  /**
   * Address: 0x00418250 (FUN_00418250, Moho::EStatTypeTypeInfo::dtr)
   */
  EStatTypeTypeInfo::~EStatTypeTypeInfo() = default;

  /**
   * Address: 0x00418240 (FUN_00418240, Moho::EStatTypeTypeInfo::GetName)
   */
  const char* EStatTypeTypeInfo::GetName() const
  {
    return "EStatType";
  }

  /**
   * Address: 0x00418280 (FUN_00418280, Moho::EStatTypeTypeInfo::AddEnums)
   */
  void EStatTypeTypeInfo::AddEnums()
  {
    mPrefix = "STAT_TYPE_";
    AddEnum(StripPrefix("STAT_TYPE_NONE"), static_cast<std::int32_t>(EStatType::kNone));
    AddEnum(StripPrefix("STAT_TYPE_FLOAT"), static_cast<std::int32_t>(EStatType::kFloat));
    AddEnum(StripPrefix("STAT_TYPE_INT"), static_cast<std::int32_t>(EStatType::kInt));
    AddEnum(StripPrefix("STAT_TYPE_STRING"), static_cast<std::int32_t>(EStatType::kString));
  }

  /**
   * Address: 0x00418220 (FUN_00418220, Moho::EStatTypeTypeInfo::Init)
   */
  void EStatTypeTypeInfo::Init()
  {
    size_ = sizeof(EStatType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00418340 (FUN_00418340, Moho::EPulseModeTypeInfo::EPulseModeTypeInfo)
   */
  EPulseModeTypeInfo::EPulseModeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EPulseMode), this);
  }

  /**
   * Address: 0x004183D0 (FUN_004183D0, Moho::EPulseModeTypeInfo::dtr)
   */
  EPulseModeTypeInfo::~EPulseModeTypeInfo() = default;

  /**
   * Address: 0x004183C0 (FUN_004183C0, Moho::EPulseModeTypeInfo::GetName)
   */
  const char* EPulseModeTypeInfo::GetName() const
  {
    return "EPulseMode";
  }

  /**
   * Address: 0x00418400 (FUN_00418400, Moho::EPulseModeTypeInfo::AddEnums)
   */
  void EPulseModeTypeInfo::AddEnums()
  {
    mPrefix = "STAT_PULSE_";
    AddEnum(StripPrefix("STAT_PULSE_NONE"), static_cast<std::int32_t>(EPulseMode::kNone));
    AddEnum(StripPrefix("STAT_PULSE_TICK"), static_cast<std::int32_t>(EPulseMode::kTick));
    AddEnum(StripPrefix("STAT_PULSE_FRAME"), static_cast<std::int32_t>(EPulseMode::kFrame));
  }

  /**
   * Address: 0x004183A0 (FUN_004183A0, Moho::EPulseModeTypeInfo::Init)
   */
  void EPulseModeTypeInfo::Init()
  {
    size_ = sizeof(EPulseMode);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0041A750 (FUN_0041A750, Moho::StatsRType_StatItem::StatsRType_StatItem)
   */
  StatsRType<StatItem>::StatsRType()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Stats<StatItem>), this);
  }

  /**
   * Address: 0x0041A800 (FUN_0041A800, sub_41A800)
   */
  StatsRType<StatItem>::~StatsRType() = default;

  /**
   * Address: 0x00419550 (FUN_00419550, Moho::StatsRType_StatItem::GetName)
   */
  const char* StatsRType<StatItem>::GetName() const
  {
    static msvc8::string cachedName;
    if (cachedName.empty()) {
      cachedName = gpg::STR_Printf("Stats<%s>", CachedStatItemType()->GetName());
    }
    return cachedName.c_str();
  }

  /**
   * Address: 0x004195F0 (FUN_004195F0, Moho::StatsRType_StatItem::Init)
   */
  void StatsRType<StatItem>::Init()
  {
    size_ = sizeof(Stats<StatItem>);
    version_ = 1;
    serLoadFunc_ = &DeserializeStatsStatItem;
    serSaveFunc_ = &SerializeStatsStatItem;
    serConstructFunc_ = &ConstructStatsStatItem;
    deleteFunc_ = &DeleteStatsStatItem;
  }

  /**
   * Address: 0x00BC3600 (FUN_00BC3600, register_PrimitiveSerHelper_EStatType)
   *
   * What it does:
   * Initializes primitive serializer helper callbacks for `EStatType`.
   */
  void register_PrimitiveSerHelper_EStatType()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gEStatTypePrimitiveSerializer.mHelperNext);
    gEStatTypePrimitiveSerializer.mHelperNext = self;
    gEStatTypePrimitiveSerializer.mHelperPrev = self;
    gEStatTypePrimitiveSerializer.mSerLoadFunc =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeEStatType);
    gEStatTypePrimitiveSerializer.mSerSaveFunc =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeEStatType);
    gEStatTypePrimitiveSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x00BC3660 (FUN_00BC3660, register_PrimitiveSerHelper_EPulseModeTypeInfo)
   *
   * What it does:
   * Initializes primitive serializer helper callbacks for `EPulseMode`.
   */
  void register_PrimitiveSerHelper_EPulseModeTypeInfo()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gEPulseModePrimitiveSerializer.mHelperNext);
    gEPulseModePrimitiveSerializer.mHelperNext = self;
    gEPulseModePrimitiveSerializer.mHelperPrev = self;
    gEPulseModePrimitiveSerializer.mSerLoadFunc =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeEPulseMode);
    gEPulseModePrimitiveSerializer.mSerSaveFunc =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeEPulseMode);
    gEPulseModePrimitiveSerializer.RegisterSerializeFunctions();
  }

  void register_StatItemSerializer()
  {
    gStatItemSerializer.mNext = nullptr;
    gStatItemSerializer.mPrev = nullptr;
    gStatItemSerializer.mSerLoadFunc = &DeserializeStatItem;
    gStatItemSerializer.mSerSaveFunc = &SerializeStatItem;
    gStatItemSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x00BC35E0 (FUN_00BC35E0, register_EStatTypeTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `EStatType`.
   */
  void RegisterEStatTypeTypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gEStatTypeTypeInfo);
  }

  /**
   * Address: 0x00BC3640 (FUN_00BC3640, register_EPulseModeTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `EPulseMode`.
   */
  void RegisterEPulseModeTypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gEPulseModeTypeInfo);
  }

  /**
   * Address: 0x00BC36A0 (FUN_00BC36A0, register_StatItemTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `StatItem`.
   */
  void RegisterStatItemTypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gStatItemTypeInfo);
  }

  /**
   * Address: 0x00BC36C0 (FUN_00BC36C0, register_StatItemSerializer)
   *
   * What it does:
   * Initializes the global StatItem serializer helper and binds load/save
   * callbacks into reflected type metadata.
   */
  void RegisterStatItemSerializerBootstrap()
  {
    register_StatItemSerializer();
  }

  /**
   * Address: 0x00BC3700 (FUN_00BC3700, register_StatsRType_StatItem)
   *
   * What it does:
   * Materializes the global reflection descriptor for `Stats<StatItem>`.
   */
  void RegisterStatsRTypeStatItemBootstrap()
  {
    MaterializeReflectionSingleton(gStatsRTypeStatItem);
  }

  void RegisterStatItemReflectionBootstrapBatch()
  {
    RegisterEStatTypeTypeInfoBootstrap();
    RegisterEPulseModeTypeInfoBootstrap();
    register_PrimitiveSerHelper_EStatType();
    register_PrimitiveSerHelper_EPulseModeTypeInfo();
    RegisterStatItemTypeInfoBootstrap();
    RegisterStatItemSerializerBootstrap();
    RegisterStatsRTypeStatItemBootstrap();
  }

  /**
   * Address: 0x0040C200 (FUN_0040C200, mode-based resolver)
   */
  StatItem* ResolveStatByMode(void* statsRoot, const gpg::StrArg name, const int mode)
  {
    auto* const stats = reinterpret_cast<Stats<StatItem>*>(statsRoot);
    if (!stats) {
      return nullptr;
    }
    return stats->GetItem(name, mode != 0);
  }

  /**
   * Address: 0x00417B60 (FUN_00417B60, float resolver)
   */
  StatItem* ResolveStatFloat(void* statsRoot, const gpg::StrArg name)
  {
    auto* const stats = reinterpret_cast<Stats<StatItem>*>(statsRoot);
    if (!stats) {
      return nullptr;
    }
    return stats->GetFloatItem(name);
  }

  /**
   * Address: 0x00417C50 (FUN_00417C50, string resolver)
   */
  StatItem* ResolveStatString(void* statsRoot, const gpg::StrArg name)
  {
    auto* const stats = reinterpret_cast<Stats<StatItem>*>(statsRoot);
    if (!stats) {
      return nullptr;
    }
    return stats->GetStringItem(name);
  }
} // namespace moho

namespace
{
  struct StatItemSerializerBootstrap
  {
    StatItemSerializerBootstrap()
    {
      moho::RegisterStatItemReflectionBootstrapBatch();
    }
  };

  StatItemSerializerBootstrap gStatItemSerializerBootstrap;
} // namespace


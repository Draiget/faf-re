#include "moho/ai/EAiAttackerEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/EAiAttackerEvent.h"

using namespace moho;

namespace
{
  alignas(EAiAttackerEventTypeInfo) unsigned char gEAiAttackerEventTypeInfoStorage[sizeof(EAiAttackerEventTypeInfo)];
  bool gEAiAttackerEventTypeInfoConstructed = false;

  alignas(EAiAttackerEventPrimitiveSerializer)
    unsigned char gEAiAttackerEventPrimitiveSerializerStorage[sizeof(EAiAttackerEventPrimitiveSerializer)];
  bool gEAiAttackerEventPrimitiveSerializerConstructed = false;

  [[nodiscard]] EAiAttackerEventTypeInfo* AcquireEAiAttackerEventTypeInfo()
  {
    if (!gEAiAttackerEventTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiAttackerEventTypeInfoStorage) EAiAttackerEventTypeInfo();
      gpg::PreRegisterRType(typeid(EAiAttackerEvent), typeInfo);
      gEAiAttackerEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiAttackerEventTypeInfo*>(gEAiAttackerEventTypeInfoStorage);
  }

  [[nodiscard]] EAiAttackerEventPrimitiveSerializer* AcquireEAiAttackerEventPrimitiveSerializer()
  {
    if (!gEAiAttackerEventPrimitiveSerializerConstructed) {
      new (gEAiAttackerEventPrimitiveSerializerStorage) EAiAttackerEventPrimitiveSerializer();
      gEAiAttackerEventPrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EAiAttackerEventPrimitiveSerializer*>(gEAiAttackerEventPrimitiveSerializerStorage);
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
  void UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedEAiAttackerEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EAiAttackerEvent));
    }
    return cached;
  }

  /**
   * Address: 0x00BF8240 (FUN_00BF8240, sub_BF8240)
   *
   * What it does:
   * Tears down recovered static `EAiAttackerEventTypeInfo` storage.
   */
  void cleanup_EAiAttackerEventTypeInfo()
  {
    if (!gEAiAttackerEventTypeInfoConstructed) {
      return;
    }

    AcquireEAiAttackerEventTypeInfo()->~EAiAttackerEventTypeInfo();
    gEAiAttackerEventTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF8250 (FUN_00BF8250, sub_BF8250)
   *
   * What it does:
   * Unlinks recovered primitive serializer helper node and restores self-links.
   */
  void cleanup_EAiAttackerEventPrimitiveSerializer()
  {
    if (!gEAiAttackerEventPrimitiveSerializerConstructed) {
      return;
    }

    EAiAttackerEventPrimitiveSerializer* const serializer = AcquireEAiAttackerEventPrimitiveSerializer();
    UnlinkSerializerNode(*serializer);
    gEAiAttackerEventPrimitiveSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005D5A30 (FUN_005D5A30, scalar deleting thunk)
 */
EAiAttackerEventTypeInfo::~EAiAttackerEventTypeInfo() = default;

/**
 * Address: 0x005D5A20 (FUN_005D5A20)
 *
 * What it does:
 * Returns the reflection type name literal for EAiAttackerEvent.
 */
const char* EAiAttackerEventTypeInfo::GetName() const
{
  return "EAiAttackerEvent";
}

/**
 * Address: 0x005D5A60 (FUN_005D5A60)
 *
 * What it does:
 * Registers EAiAttackerEvent enum option names/values.
 */
void EAiAttackerEventTypeInfo::AddEnums()
{
  mPrefix = "AIATTACKEVENT_";
  AddEnum(
    StripPrefix("AIATTACKEVENT_AcquiredDesiredTarget"),
    static_cast<std::int32_t>(AIATTACKEVENT_AcquiredDesiredTarget)
  );
  AddEnum(StripPrefix("AIATTACKEVENT_OutOfRange"), static_cast<std::int32_t>(AIATTACKEVENT_OutOfRange));
  AddEnum(StripPrefix("AIATTACKEVENT_Success"), static_cast<std::int32_t>(AIATTACKEVENT_Success));
}

/**
 * Address: 0x005D5A00 (FUN_005D5A00)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiAttackerEventTypeInfo::Init()
{
  size_ = sizeof(EAiAttackerEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x005DC390 (FUN_005DC390, sub_5DC390)
 */
void EAiAttackerEventPrimitiveSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  int value = 0;
  archive->ReadInt(&value);
  *reinterpret_cast<EAiAttackerEvent*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EAiAttackerEvent>(value);
}

/**
 * Address: 0x005DC3B0 (FUN_005DC3B0, sub_5DC3B0)
 */
void EAiAttackerEventPrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EAiAttackerEvent*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void EAiAttackerEventPrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEAiAttackerEventType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCE750 (FUN_00BCE750, sub_BCE750)
 *
 * What it does:
 * Registers `EAiAttackerEvent` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_EAiAttackerEventTypeInfo()
{
  (void)AcquireEAiAttackerEventTypeInfo();
  return std::atexit(&cleanup_EAiAttackerEventTypeInfo);
}

/**
 * Address: 0x00BCE770 (FUN_00BCE770, sub_BCE770)
 *
 * What it does:
 * Registers primitive serializer callbacks for `EAiAttackerEvent` and
 * installs process-exit cleanup.
 */
int moho::register_EAiAttackerEventPrimitiveSerializer()
{
  EAiAttackerEventPrimitiveSerializer* const serializer = AcquireEAiAttackerEventPrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EAiAttackerEventPrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EAiAttackerEventPrimitiveSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_EAiAttackerEventPrimitiveSerializer);
}

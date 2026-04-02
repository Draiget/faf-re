#include "moho/ai/EAiNavigatorEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

namespace
{
  alignas(EAiNavigatorEventTypeInfo)
    unsigned char gEAiNavigatorEventTypeInfoStorage[sizeof(EAiNavigatorEventTypeInfo)] = {};
  bool gEAiNavigatorEventTypeInfoConstructed = false;

  alignas(EAiNavigatorEventPrimitiveSerializer)
    unsigned char gEAiNavigatorEventPrimitiveSerializerStorage[sizeof(EAiNavigatorEventPrimitiveSerializer)] = {};
  bool gEAiNavigatorEventPrimitiveSerializerConstructed = false;

  gpg::RType* gEAiNavigatorEventType = nullptr;

  [[nodiscard]] EAiNavigatorEventTypeInfo* AcquireEAiNavigatorEventTypeInfo()
  {
    if (!gEAiNavigatorEventTypeInfoConstructed) {
      new (gEAiNavigatorEventTypeInfoStorage) EAiNavigatorEventTypeInfo();
      gEAiNavigatorEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiNavigatorEventTypeInfo*>(gEAiNavigatorEventTypeInfoStorage);
  }

  [[nodiscard]] EAiNavigatorEventPrimitiveSerializer* AcquireEAiNavigatorEventPrimitiveSerializer()
  {
    if (!gEAiNavigatorEventPrimitiveSerializerConstructed) {
      new (gEAiNavigatorEventPrimitiveSerializerStorage) EAiNavigatorEventPrimitiveSerializer();
      gEAiNavigatorEventPrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EAiNavigatorEventPrimitiveSerializer*>(gEAiNavigatorEventPrimitiveSerializerStorage);
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
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedEAiNavigatorEventType()
  {
    if (!gEAiNavigatorEventType) {
      gEAiNavigatorEventType = gpg::LookupRType(typeid(EAiNavigatorEvent));
    }
    return gEAiNavigatorEventType;
  }

  /**
   * Address: 0x00BF6CD0 (FUN_00BF6CD0, cleanup_EAiNavigatorEventPrimitiveSerializer)
   *
   * What it does:
   * Unlinks the recovered primitive serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_EAiNavigatorEventPrimitiveSerializer()
  {
    if (!gEAiNavigatorEventPrimitiveSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireEAiNavigatorEventPrimitiveSerializer());
  }

  void cleanup_EAiNavigatorEventPrimitiveSerializer_atexit()
  {
    (void)cleanup_EAiNavigatorEventPrimitiveSerializer();
  }

  /**
   * Address: 0x00BF6C70 (FUN_00BF6C70, cleanup_EAiNavigatorEventTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EAiNavigatorEventTypeInfo` storage.
   */
  void cleanup_EAiNavigatorEventTypeInfo()
  {
    if (!gEAiNavigatorEventTypeInfoConstructed) {
      return;
    }

    AcquireEAiNavigatorEventTypeInfo()->~EAiNavigatorEventTypeInfo();
    gEAiNavigatorEventTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
 */
EAiNavigatorEventTypeInfo::~EAiNavigatorEventTypeInfo() = default;

/**
 * Address: 0x005A30A0 (FUN_005A30A0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiNavigatorEvent.
 */
const char* EAiNavigatorEventTypeInfo::GetName() const
{
  return "EAiNavigatorEvent";
}

/**
 * Address: 0x005A30E0 (FUN_005A30E0)
 *
 * What it does:
 * Registers EAiNavigatorEvent enum option names/values.
 */
void EAiNavigatorEventTypeInfo::AddEnums()
{
  mPrefix = "AINAVEVENT_";
  AddEnum(StripPrefix("AINAVEVENT_Failed"), static_cast<std::int32_t>(AINAVEVENT_Failed));
  AddEnum(StripPrefix("AINAVEVENT_Aborted"), static_cast<std::int32_t>(AINAVEVENT_Aborted));
  AddEnum(StripPrefix("AINAVEVENT_Succeeded"), static_cast<std::int32_t>(AINAVEVENT_Succeeded));
}

/**
 * Address: 0x005A3080 (FUN_005A3080)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiNavigatorEventTypeInfo::Init()
{
  size_ = sizeof(EAiNavigatorEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x005A7720 (FUN_005A7720, PrimitiveSerHelper_EAiNavigatorEvent::Deserialize)
 */
void EAiNavigatorEventPrimitiveSerializer::Deserialize(
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
  *reinterpret_cast<EAiNavigatorEvent*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EAiNavigatorEvent>(value);
}

/**
 * Address: 0x005A7740 (FUN_005A7740, PrimitiveSerHelper_EAiNavigatorEvent::Serialize)
 */
void EAiNavigatorEventPrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EAiNavigatorEvent*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void EAiNavigatorEventPrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEAiNavigatorEventType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC640 (FUN_00BCC640, register_EAiNavigatorEventTypeInfo)
 *
 * What it does:
 * Preregisters startup construction for the `EAiNavigatorEvent` enum RTTI
 * descriptor and installs exit-time teardown.
 */
void moho::register_EAiNavigatorEventTypeInfo()
{
  (void)AcquireEAiNavigatorEventTypeInfo();
  (void)std::atexit(&cleanup_EAiNavigatorEventTypeInfo);
}

/**
 * Address: 0x00BCC660 (FUN_00BCC660)
 *
 * What it does:
 * Initializes primitive serializer callbacks for `EAiNavigatorEvent` and
 * installs process-exit helper unlink cleanup.
 */
int moho::register_EAiNavigatorEventPrimitiveSerializer()
{
  EAiNavigatorEventPrimitiveSerializer* const serializer = AcquireEAiNavigatorEventPrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EAiNavigatorEventPrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EAiNavigatorEventPrimitiveSerializer::Serialize;
  return std::atexit(&cleanup_EAiNavigatorEventPrimitiveSerializer_atexit);
}

namespace
{
  struct EAiNavigatorEventTypeInfoBootstrap
  {
    EAiNavigatorEventTypeInfoBootstrap()
    {
      (void)moho::register_EAiNavigatorEventTypeInfo();
      (void)moho::register_EAiNavigatorEventPrimitiveSerializer();
    }
  };

  [[maybe_unused]] EAiNavigatorEventTypeInfoBootstrap gEAiNavigatorEventTypeInfoBootstrap;
} // namespace

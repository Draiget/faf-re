#include "moho/ai/EAiTransportEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"

using namespace moho;

namespace
{
  alignas(EAiTransportEventTypeInfo) unsigned char gEAiTransportEventTypeInfoStorage[sizeof(EAiTransportEventTypeInfo)];
  bool gEAiTransportEventTypeInfoConstructed = false;

  alignas(EAiTransportEventPrimitiveSerializer)
    unsigned char gEAiTransportEventPrimitiveSerializerStorage[sizeof(EAiTransportEventPrimitiveSerializer)];
  bool gEAiTransportEventPrimitiveSerializerConstructed = false;

  [[nodiscard]] EAiTransportEventTypeInfo* AcquireEAiTransportEventTypeInfo()
  {
    if (!gEAiTransportEventTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiTransportEventTypeInfoStorage) EAiTransportEventTypeInfo();
      gpg::PreRegisterRType(typeid(EAiTransportEvent), typeInfo);
      gEAiTransportEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiTransportEventTypeInfo*>(gEAiTransportEventTypeInfoStorage);
  }

  [[nodiscard]] EAiTransportEventPrimitiveSerializer* AcquireEAiTransportEventPrimitiveSerializer()
  {
    if (!gEAiTransportEventPrimitiveSerializerConstructed) {
      new (gEAiTransportEventPrimitiveSerializerStorage) EAiTransportEventPrimitiveSerializer();
      gEAiTransportEventPrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EAiTransportEventPrimitiveSerializer*>(gEAiTransportEventPrimitiveSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedEAiTransportEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EAiTransportEvent));
    }
    return cached;
  }

  void cleanup_EAiTransportEventTypeInfo()
  {
    if (!gEAiTransportEventTypeInfoConstructed) {
      return;
    }

    AcquireEAiTransportEventTypeInfo()->~EAiTransportEventTypeInfo();
    gEAiTransportEventTypeInfoConstructed = false;
  }

  void cleanup_EAiTransportEventPrimitiveSerializer()
  {
    if (!gEAiTransportEventPrimitiveSerializerConstructed) {
      return;
    }

    EAiTransportEventPrimitiveSerializer* const serializer = AcquireEAiTransportEventPrimitiveSerializer();
    UnlinkSerializerNode(*serializer);
    serializer->~EAiTransportEventPrimitiveSerializer();
    gEAiTransportEventPrimitiveSerializerConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E3DA0 (FUN_005E3DA0, scalar deleting thunk)
 */
EAiTransportEventTypeInfo::~EAiTransportEventTypeInfo() = default;

/**
 * Address: 0x005E3D90 (FUN_005E3D90)
 *
 * What it does:
 * Returns the reflection type name literal for EAiTransportEvent.
 */
const char* EAiTransportEventTypeInfo::GetName() const
{
  return "EAiTransportEvent";
}

/**
 * Address: 0x005E3DD0 (FUN_005E3DD0)
 *
 * What it does:
 * Registers EAiTransportEvent enum option names/values.
 */
void EAiTransportEventTypeInfo::AddEnums()
{
  mPrefix = "AITRANSPORTEVENT_";
  AddEnum(StripPrefix("AITRANSPORTEVENT_LoadFailed"), static_cast<std::int32_t>(AITRANSPORTEVENT_LoadFailed));
  AddEnum(StripPrefix("AITRANSPORTEVENT_Load"), static_cast<std::int32_t>(AITRANSPORTEVENT_Load));
  AddEnum(StripPrefix("AITRANSPORTEVENT_Unload"), static_cast<std::int32_t>(AITRANSPORTEVENT_Unload));
}

/**
 * Address: 0x005E3D70 (FUN_005E3D70)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiTransportEventTypeInfo::Init()
{
  size_ = sizeof(EAiTransportEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x005E9DD0 (FUN_005E9DD0, EAiTransportEventPrimitiveSerializer::Deserialize)
 */
void EAiTransportEventPrimitiveSerializer::Deserialize(
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
  *reinterpret_cast<EAiTransportEvent*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EAiTransportEvent>(value);
}

/**
 * Address: 0x005E9DF0 (FUN_005E9DF0, EAiTransportEventPrimitiveSerializer::Serialize)
 */
void EAiTransportEventPrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EAiTransportEvent*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void EAiTransportEventPrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEAiTransportEventType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCED10 (FUN_00BCED10, register_EAiTransportEventTypeInfo)
 *
 * What it does:
 * Registers `EAiTransportEvent` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_EAiTransportEventTypeInfo()
{
  (void)AcquireEAiTransportEventTypeInfo();
  return std::atexit(&cleanup_EAiTransportEventTypeInfo);
}

/**
 * Address: 0x00BCED30 (FUN_00BCED30, register_EAiTransportEventPrimitiveSerializer)
 *
 * What it does:
 * Registers primitive serializer callbacks for `EAiTransportEvent` and
 * installs process-exit cleanup.
 */
int moho::register_EAiTransportEventPrimitiveSerializer()
{
  EAiTransportEventPrimitiveSerializer* const serializer = AcquireEAiTransportEventPrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EAiTransportEventPrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EAiTransportEventPrimitiveSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_EAiTransportEventPrimitiveSerializer);
}

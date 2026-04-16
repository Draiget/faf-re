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

  /**
   * Address: 0x005E8B60 (FUN_005E8B60)
   *
   * What it does:
   * Reinitializes startup helper storage for one primitive-serializer lane of
   * `EAiTransportEvent` and binds enum load/save callbacks.
   */
  [[maybe_unused]] [[nodiscard]] EAiTransportEventPrimitiveSerializer*
  InitializeEAiTransportEventPrimitiveSerializerPrimitiveLane()
  {
    EAiTransportEventPrimitiveSerializer* const serializer = AcquireEAiTransportEventPrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mLoadCallback = &EAiTransportEventPrimitiveSerializer::Deserialize;
    serializer->mSaveCallback = &EAiTransportEventPrimitiveSerializer::Serialize;
    return serializer;
  }

  /**
   * Address: 0x005E9E10 (FUN_005E9E10)
   *
   * What it does:
   * Reinitializes startup helper storage for one save/load-helper lane of
   * `EAiTransportEvent` and binds enum load/save callbacks.
   */
  [[maybe_unused]] [[nodiscard]] EAiTransportEventPrimitiveSerializer*
  InitializeEAiTransportEventPrimitiveSerializerSaveLoadLane()
  {
    EAiTransportEventPrimitiveSerializer* const serializer = AcquireEAiTransportEventPrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mLoadCallback = &EAiTransportEventPrimitiveSerializer::Deserialize;
    serializer->mSaveCallback = &EAiTransportEventPrimitiveSerializer::Serialize;
    return serializer;
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

  [[nodiscard]] gpg::SerHelperBase* UnlinkEAiTransportEventPrimitiveSerializerHelperNode()
  {
    if (!gEAiTransportEventPrimitiveSerializerConstructed) {
      return nullptr;
    }

    EAiTransportEventPrimitiveSerializer* const serializer = AcquireEAiTransportEventPrimitiveSerializer();
    UnlinkSerializerNode(*serializer);
    return SerializerSelfNode(*serializer);
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
    (void)UnlinkEAiTransportEventPrimitiveSerializerHelperNode();
    serializer->~EAiTransportEventPrimitiveSerializer();
    gEAiTransportEventPrimitiveSerializerConstructed = false;
  }

  /**
   * Address: 0x005E3E20 (FUN_005E3E20)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks recovered
   * `EAiTransportEvent` primitive serializer helper links and restores
   * self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_EAiTransportEventPrimitiveSerializerStartupThunkA()
  {
    return UnlinkEAiTransportEventPrimitiveSerializerHelperNode();
  }

  /**
   * Address: 0x005E3E50 (FUN_005E3E50)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same `EAiTransportEvent`
   * primitive serializer helper unlink/reset path.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_EAiTransportEventPrimitiveSerializerStartupThunkB()
  {
    return UnlinkEAiTransportEventPrimitiveSerializerHelperNode();
  }

  struct EAiTransportEventZeroInitRuntimeView
  {
    std::uint32_t lane00 = 0; // +0x00
    std::uint32_t lane04 = 0; // +0x04
    std::uint32_t lane08 = 0; // +0x08
    std::uint32_t lane0C = 0; // +0x0C
    std::uint32_t lane10 = 0; // +0x10
    std::uint32_t lane14 = 0; // +0x14
    std::uint32_t lane18 = 0; // +0x18
    std::uint32_t lane1C = 0; // +0x1C
  };
  static_assert(sizeof(EAiTransportEventZeroInitRuntimeView) == 0x20, "EAiTransportEventZeroInitRuntimeView size must be 0x20");

  /**
   * Address: 0x005E3E80 (FUN_005E3E80)
   *
   * What it does:
   * Zeroes startup runtime lanes used by the `EAiTransportEvent` reflection
   * helper object while preserving the lane at `+0x10`.
   */
  [[maybe_unused]] EAiTransportEventZeroInitRuntimeView*
  zero_EAiTransportEventRuntimeLanes(EAiTransportEventZeroInitRuntimeView* const runtime) noexcept
  {
    if (runtime == nullptr) {
      return nullptr;
    }

    runtime->lane00 = 0;
    runtime->lane04 = 0;
    runtime->lane08 = 0;
    runtime->lane0C = 0;
    runtime->lane14 = 0;
    runtime->lane18 = 0;
    runtime->lane1C = 0;
    return runtime;
  }
} // namespace

/**
 * Address: 0x005E3D10 (FUN_005E3D10, Moho::EAiTransportEventTypeInfo::EAiTransportEventTypeInfo)
 */
EAiTransportEventTypeInfo::EAiTransportEventTypeInfo()
{
  gpg::PreRegisterRType(typeid(EAiTransportEvent), this);
}

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
  (void)InitializeEAiTransportEventPrimitiveSerializerSaveLoadLane();
  return std::atexit(&cleanup_EAiTransportEventPrimitiveSerializer);
}

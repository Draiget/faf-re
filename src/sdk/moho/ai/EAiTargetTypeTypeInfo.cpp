#include "moho/ai/EAiTargetTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/EAiTargetType.h"

using namespace moho;

namespace
{
  alignas(EAiTargetTypeTypeInfo) unsigned char gEAiTargetTypeTypeInfoStorage[sizeof(EAiTargetTypeTypeInfo)];
  bool gEAiTargetTypeTypeInfoConstructed = false;

  alignas(EAiTargetTypePrimitiveSerializer)
    unsigned char gEAiTargetTypePrimitiveSerializerStorage[sizeof(EAiTargetTypePrimitiveSerializer)];
  bool gEAiTargetTypePrimitiveSerializerConstructed = false;

  [[nodiscard]] EAiTargetTypeTypeInfo* AcquireEAiTargetTypeTypeInfo()
  {
    if (!gEAiTargetTypeTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiTargetTypeTypeInfoStorage) EAiTargetTypeTypeInfo();
      gpg::PreRegisterRType(typeid(EAiTargetType), typeInfo);
      gEAiTargetTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiTargetTypeTypeInfo*>(gEAiTargetTypeTypeInfoStorage);
  }

  /**
   * Address: 0x005E2370 (FUN_005E2370, sub_5E2370)
   *
   * What it does:
   * Constructs and preregisters the static `EAiTargetTypeTypeInfo` instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_EAiTargetTypeTypeInfo()
  {
    return AcquireEAiTargetTypeTypeInfo();
  }

  [[nodiscard]] EAiTargetTypePrimitiveSerializer* AcquireEAiTargetTypePrimitiveSerializer()
  {
    if (!gEAiTargetTypePrimitiveSerializerConstructed) {
      new (gEAiTargetTypePrimitiveSerializerStorage) EAiTargetTypePrimitiveSerializer();
      gEAiTargetTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EAiTargetTypePrimitiveSerializer*>(gEAiTargetTypePrimitiveSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedEAiTargetType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EAiTargetType));
    }
    return cached;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkEAiTargetTypePrimitiveSerializerHelperNode()
  {
    if (!gEAiTargetTypePrimitiveSerializerConstructed) {
      return nullptr;
    }

    EAiTargetTypePrimitiveSerializer* const serializer = AcquireEAiTargetTypePrimitiveSerializer();
    UnlinkSerializerNode(*serializer);
    return SerializerSelfNode(*serializer);
  }

  /**
   * Address: 0x00BF8870 (FUN_00BF8870, sub_BF8870)
   *
   * What it does:
   * Tears down recovered static `EAiTargetTypeTypeInfo` storage.
   */
  void cleanup_EAiTargetTypeTypeInfo()
  {
    if (!gEAiTargetTypeTypeInfoConstructed) {
      return;
    }

    AcquireEAiTargetTypeTypeInfo()->~EAiTargetTypeTypeInfo();
    gEAiTargetTypeTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF8880 (FUN_00BF8880, sub_BF8880)
   *
   * What it does:
   * Unlinks the static primitive serializer node from the intrusive list and
   * restores self-links.
   */
  void cleanup_EAiTargetTypePrimitiveSerializer()
  {
    if (!gEAiTargetTypePrimitiveSerializerConstructed) {
      return;
    }

    (void)UnlinkEAiTargetTypePrimitiveSerializerHelperNode();
    gEAiTargetTypePrimitiveSerializerConstructed = false;
  }

  /**
   * Address: 0x005E2480 (FUN_005E2480)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks recovered `EAiTargetType` primitive
   * serializer helper links and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_EAiTargetTypePrimitiveSerializerStartupThunkA()
  {
    return UnlinkEAiTargetTypePrimitiveSerializerHelperNode();
  }

  /**
   * Address: 0x005E24B0 (FUN_005E24B0)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same `EAiTargetType` primitive
   * serializer helper unlink/reset path.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_EAiTargetTypePrimitiveSerializerStartupThunkB()
  {
    return UnlinkEAiTargetTypePrimitiveSerializerHelperNode();
  }
} // namespace

/**
 * Address: 0x005E2400 (FUN_005E2400, scalar deleting thunk)
 */
EAiTargetTypeTypeInfo::~EAiTargetTypeTypeInfo() = default;

/**
 * Address: 0x005E23F0 (FUN_005E23F0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiTargetType.
 */
const char* EAiTargetTypeTypeInfo::GetName() const
{
  return "EAiTargetType";
}

/**
 * Address: 0x005E2430 (FUN_005E2430)
 *
 * What it does:
 * Registers `EAiTargetType` enum option names/values.
 */
void EAiTargetTypeTypeInfo::AddEnums()
{
  mPrefix = "AITARGET_";
  AddEnum(StripPrefix("AITARGET_None"), static_cast<std::int32_t>(EAiTargetType::AITARGET_None));
  AddEnum(StripPrefix("AITARGET_Entity"), static_cast<std::int32_t>(EAiTargetType::AITARGET_Entity));
  AddEnum(StripPrefix("AITARGET_Ground"), static_cast<std::int32_t>(EAiTargetType::AITARGET_Ground));
}

/**
 * Address: 0x005E23D0 (FUN_005E23D0)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiTargetTypeTypeInfo::Init()
{
  size_ = sizeof(EAiTargetType);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x005E35B0 (FUN_005E35B0, sub_5E35B0)
 *
 * What it does:
 * Deserializes one `EAiTargetType` enum value from archive storage.
 */
void EAiTargetTypePrimitiveSerializer::Deserialize(
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
  *reinterpret_cast<EAiTargetType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EAiTargetType>(value);
}

/**
 * Address: 0x005E35D0 (FUN_005E35D0, sub_5E35D0)
 *
 * What it does:
 * Serializes one `EAiTargetType` enum value to archive storage.
 */
void EAiTargetTypePrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EAiTargetType*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void EAiTargetTypePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEAiTargetType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCEBD0 (FUN_00BCEBD0, register_EAiTargetTypeTypeInfo)
 *
 * What it does:
 * Registers `EAiTargetType` enum type-info and installs process-exit cleanup.
 */
int moho::register_EAiTargetTypeTypeInfo()
{
  (void)preregister_EAiTargetTypeTypeInfo();
  return std::atexit(&cleanup_EAiTargetTypeTypeInfo);
}

/**
 * Address: 0x00BCEBF0 (FUN_00BCEBF0, register_EAiTargetTypePrimitiveSerializer)
 *
 * What it does:
 * Registers primitive serializer callbacks for `EAiTargetType` and installs
 * process-exit cleanup.
 */
int moho::register_EAiTargetTypePrimitiveSerializer()
{
  EAiTargetTypePrimitiveSerializer* const serializer = AcquireEAiTargetTypePrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EAiTargetTypePrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EAiTargetTypePrimitiveSerializer::Serialize;
  return std::atexit(&cleanup_EAiTargetTypePrimitiveSerializer);
}

namespace
{
  struct EAiTargetTypeTypeInfoBootstrap
  {
    EAiTargetTypeTypeInfoBootstrap()
    {
      (void)moho::register_EAiTargetTypeTypeInfo();
      (void)moho::register_EAiTargetTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EAiTargetTypeTypeInfoBootstrap gEAiTargetTypeTypeInfoBootstrap;
} // namespace

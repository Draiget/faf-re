#include "moho/ai/EAiPathNavigatorStateTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathNavigator.h"

using namespace moho;

namespace
{
  alignas(EAiPathNavigatorStateTypeInfo)
    unsigned char gEAiPathNavigatorStateTypeInfoStorage[sizeof(EAiPathNavigatorStateTypeInfo)] = {};
  bool gEAiPathNavigatorStateTypeInfoConstructed = false;

  alignas(EAiPathNavigatorStatePrimitiveSerializer)
    unsigned char gEAiPathNavigatorStatePrimitiveSerializerStorage[sizeof(EAiPathNavigatorStatePrimitiveSerializer)] =
      {};
  bool gEAiPathNavigatorStatePrimitiveSerializerConstructed = false;

  gpg::RType* gEAiPathNavigatorStateType = nullptr;

  [[nodiscard]] EAiPathNavigatorStateTypeInfo* AcquireEAiPathNavigatorStateTypeInfo()
  {
    if (!gEAiPathNavigatorStateTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiPathNavigatorStateTypeInfoStorage) EAiPathNavigatorStateTypeInfo();
      gpg::PreRegisterRType(typeid(EAiPathNavigatorState), typeInfo);
      gEAiPathNavigatorStateType = typeInfo;
      gEAiPathNavigatorStateTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiPathNavigatorStateTypeInfo*>(gEAiPathNavigatorStateTypeInfoStorage);
  }

  /**
   * Address: 0x005AD240 (FUN_005AD240)
   *
   * What it does:
   * Constructs and preregisters the static `EAiPathNavigatorStateTypeInfo`
   * instance.
   */
  [[nodiscard]] gpg::REnumType* preregister_EAiPathNavigatorStateTypeInfo()
  {
    return AcquireEAiPathNavigatorStateTypeInfo();
  }

  [[nodiscard]] EAiPathNavigatorStatePrimitiveSerializer* AcquireEAiPathNavigatorStatePrimitiveSerializer()
  {
    if (!gEAiPathNavigatorStatePrimitiveSerializerConstructed) {
      new (gEAiPathNavigatorStatePrimitiveSerializerStorage) EAiPathNavigatorStatePrimitiveSerializer();
      gEAiPathNavigatorStatePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EAiPathNavigatorStatePrimitiveSerializer*>(gEAiPathNavigatorStatePrimitiveSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedEAiPathNavigatorStateType()
  {
    if (!gEAiPathNavigatorStateType) {
      gEAiPathNavigatorStateType = gpg::LookupRType(typeid(EAiPathNavigatorState));
    }

    return gEAiPathNavigatorStateType;
  }

  /**
   * Address: 0x00BF7320 (FUN_00BF7320, cleanup_EAiPathNavigatorStateTypeInfo)
   *
   * What it does:
   * Tears down recovered static `EAiPathNavigatorStateTypeInfo` storage.
   */
  void cleanup_EAiPathNavigatorStateTypeInfo()
  {
    if (!gEAiPathNavigatorStateTypeInfoConstructed) {
      return;
    }

    AcquireEAiPathNavigatorStateTypeInfo()->~EAiPathNavigatorStateTypeInfo();
    gEAiPathNavigatorStateTypeInfoConstructed = false;
    gEAiPathNavigatorStateType = nullptr;
  }

  /**
   * Address: 0x00BF7330 (FUN_00BF7330, cleanup_EAiPathNavigatorStatePrimitiveSerializer)
   *
   * What it does:
   * Unlinks the recovered primitive serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_EAiPathNavigatorStatePrimitiveSerializer()
  {
    if (!gEAiPathNavigatorStatePrimitiveSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireEAiPathNavigatorStatePrimitiveSerializer());
  }

  void cleanup_EAiPathNavigatorStatePrimitiveSerializer_atexit()
  {
    (void)cleanup_EAiPathNavigatorStatePrimitiveSerializer();
  }
} // namespace

/**
 * Address: 0x005AD2D0 (FUN_005AD2D0, scalar deleting thunk)
 */
EAiPathNavigatorStateTypeInfo::~EAiPathNavigatorStateTypeInfo() = default;

/**
 * Address: 0x005AD2C0 (FUN_005AD2C0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiPathNavigatorState.
 */
const char* EAiPathNavigatorStateTypeInfo::GetName() const
{
  return "EAiPathNavigatorState";
}

/**
 * Address: 0x005AD2A0 (FUN_005AD2A0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAiPathNavigatorStateTypeInfo::Init()
{
  size_ = sizeof(EAiPathNavigatorState);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005B0290 (FUN_005B0290, Deserialize_EAiPathNavigatorState)
 *
 * What it does:
 * Deserializes one `EAiPathNavigatorState` enum lane from archive storage.
 */
void EAiPathNavigatorStatePrimitiveSerializer::Deserialize(
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
  *reinterpret_cast<EAiPathNavigatorState*>(static_cast<std::uintptr_t>(objectPtr)) =
    static_cast<EAiPathNavigatorState>(value);
}

/**
 * Address: 0x005B02B0 (FUN_005B02B0, Serialize_EAiPathNavigatorState)
 *
 * What it does:
 * Serializes one `EAiPathNavigatorState` enum lane to archive storage.
 */
void EAiPathNavigatorStatePrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EAiPathNavigatorState*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void EAiPathNavigatorStatePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEAiPathNavigatorStateType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCCFC0 (FUN_00BCCFC0, register_EAiPathNavigatorStateTypeInfo)
 *
 * What it does:
 * Registers `EAiPathNavigatorState` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_EAiPathNavigatorStateTypeInfo()
{
  (void)preregister_EAiPathNavigatorStateTypeInfo();
  return std::atexit(&cleanup_EAiPathNavigatorStateTypeInfo);
}

/**
 * Address: 0x00BCCFE0 (FUN_00BCCFE0, register_EAiPathNavigatorStatePrimitiveSerializer)
 *
 * What it does:
 * Registers primitive serializer callbacks for `EAiPathNavigatorState` and
 * installs process-exit cleanup.
 */
int moho::register_EAiPathNavigatorStatePrimitiveSerializer()
{
  EAiPathNavigatorStatePrimitiveSerializer* const serializer = AcquireEAiPathNavigatorStatePrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EAiPathNavigatorStatePrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EAiPathNavigatorStatePrimitiveSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  return std::atexit(&cleanup_EAiPathNavigatorStatePrimitiveSerializer_atexit);
}

namespace
{
  struct EAiPathNavigatorStateTypeInfoBootstrap
  {
    EAiPathNavigatorStateTypeInfoBootstrap()
    {
      (void)moho::register_EAiPathNavigatorStateTypeInfo();
      (void)moho::register_EAiPathNavigatorStatePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EAiPathNavigatorStateTypeInfoBootstrap gEAiPathNavigatorStateTypeInfoBootstrap;
} // namespace

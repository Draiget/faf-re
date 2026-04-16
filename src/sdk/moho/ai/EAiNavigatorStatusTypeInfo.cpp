#include "moho/ai/EAiNavigatorStatusTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

namespace
{
  alignas(EAiNavigatorStatusTypeInfo)
    unsigned char gEAiNavigatorStatusTypeInfoStorage[sizeof(EAiNavigatorStatusTypeInfo)] = {};
  bool gEAiNavigatorStatusTypeInfoConstructed = false;

  alignas(EAiNavigatorStatusPrimitiveSerializer)
    unsigned char gEAiNavigatorStatusPrimitiveSerializerStorage[sizeof(EAiNavigatorStatusPrimitiveSerializer)] = {};
  bool gEAiNavigatorStatusPrimitiveSerializerConstructed = false;

  gpg::RType* gEAiNavigatorStatusType = nullptr;

  [[nodiscard]] EAiNavigatorStatusTypeInfo* AcquireEAiNavigatorStatusTypeInfo()
  {
    if (!gEAiNavigatorStatusTypeInfoConstructed) {
      new (gEAiNavigatorStatusTypeInfoStorage) EAiNavigatorStatusTypeInfo();
      gEAiNavigatorStatusTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiNavigatorStatusTypeInfo*>(gEAiNavigatorStatusTypeInfoStorage);
  }

  [[nodiscard]] EAiNavigatorStatusPrimitiveSerializer* AcquireEAiNavigatorStatusPrimitiveSerializer()
  {
    if (!gEAiNavigatorStatusPrimitiveSerializerConstructed) {
      new (gEAiNavigatorStatusPrimitiveSerializerStorage) EAiNavigatorStatusPrimitiveSerializer();
      gEAiNavigatorStatusPrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EAiNavigatorStatusPrimitiveSerializer*>(gEAiNavigatorStatusPrimitiveSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedEAiNavigatorStatusType()
  {
    if (!gEAiNavigatorStatusType) {
      gEAiNavigatorStatusType = gpg::LookupRType(typeid(EAiNavigatorStatus));
    }
    return gEAiNavigatorStatusType;
  }

  /**
   * Address: 0x00BF6C90 (FUN_00BF6C90, cleanup_EAiNavigatorStatusPrimitiveSerializer)
   *
   * What it does:
   * Unlinks the recovered primitive serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_EAiNavigatorStatusPrimitiveSerializer()
  {
    if (!gEAiNavigatorStatusPrimitiveSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireEAiNavigatorStatusPrimitiveSerializer());
  }

  /**
   * Address: 0x005A2FC0 (FUN_005A2FC0)
   *
   * What it does:
   * Legacy startup-cleanup thunk lane that forwards to the canonical
   * EAiNavigatorStatus primitive serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_EAiNavigatorStatusPrimitiveSerializerStartupThunkA()
  {
    return cleanup_EAiNavigatorStatusPrimitiveSerializer();
  }

  /**
   * Address: 0x005A2FF0 (FUN_005A2FF0)
   *
   * What it does:
   * Secondary startup-cleanup thunk lane that forwards to the canonical
   * EAiNavigatorStatus primitive serializer helper unlink path.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_EAiNavigatorStatusPrimitiveSerializerStartupThunkB()
  {
    return cleanup_EAiNavigatorStatusPrimitiveSerializer();
  }

  void cleanup_EAiNavigatorStatusPrimitiveSerializer_atexit()
  {
    (void)cleanup_EAiNavigatorStatusPrimitiveSerializer();
  }

  /**
   * Address: 0x00BF6C50 (FUN_00BF6C50, cleanup_EAiNavigatorStatusTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EAiNavigatorStatusTypeInfo` storage.
   */
  void cleanup_EAiNavigatorStatusTypeInfo()
  {
    if (!gEAiNavigatorStatusTypeInfoConstructed) {
      return;
    }

    AcquireEAiNavigatorStatusTypeInfo()->~EAiNavigatorStatusTypeInfo();
    gEAiNavigatorStatusTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
 */
EAiNavigatorStatusTypeInfo::~EAiNavigatorStatusTypeInfo() = default;

/**
 * Address: 0x005A2F30 (FUN_005A2F30)
 *
 * What it does:
 * Returns the reflection type name literal for EAiNavigatorStatus.
 */
const char* EAiNavigatorStatusTypeInfo::GetName() const
{
  return "EAiNavigatorStatus";
}

/**
 * Address: 0x005A2F70 (FUN_005A2F70)
 *
 * What it does:
 * Registers EAiNavigatorStatus enum option names/values.
 */
void EAiNavigatorStatusTypeInfo::AddEnums()
{
  mPrefix = "AINAVSTATUS_";
  AddEnum(StripPrefix("AINAVSTATUS_Idle"), static_cast<std::int32_t>(AINAVSTATUS_Idle));
  AddEnum(StripPrefix("AINAVSTATUS_Thinking"), static_cast<std::int32_t>(AINAVSTATUS_Thinking));
  AddEnum(StripPrefix("AINAVSTATUS_Steering"), static_cast<std::int32_t>(AINAVSTATUS_Steering));
}

/**
 * Address: 0x005A2F10 (FUN_005A2F10)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiNavigatorStatusTypeInfo::Init()
{
  size_ = sizeof(EAiNavigatorStatus);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x005A76B0 (FUN_005A76B0, gpg::PrimitiveSerHelper_EAiNavigatorStatus::Deserialize)
 */
void EAiNavigatorStatusPrimitiveSerializer::Deserialize(
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
  *reinterpret_cast<EAiNavigatorStatus*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EAiNavigatorStatus>(value);
}

/**
 * Address: 0x005A76D0 (FUN_005A76D0, gpg::PrimitiveSerHelper_EAiNavigatorStatus::Serialize)
 */
void EAiNavigatorStatusPrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EAiNavigatorStatus*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void EAiNavigatorStatusPrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEAiNavigatorStatusType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCC5E0 (FUN_00BCC5E0, register_EAiNavigatorStatusTypeInfo)
 *
 * What it does:
 * Preregisters startup construction for the `EAiNavigatorStatus` enum RTTI
 * descriptor and installs exit-time teardown.
 */
void moho::register_EAiNavigatorStatusTypeInfo()
{
  (void)AcquireEAiNavigatorStatusTypeInfo();
  (void)std::atexit(&cleanup_EAiNavigatorStatusTypeInfo);
}

/**
 * Address: 0x00BCC600 (FUN_00BCC600, register_PrimitiveSerHelper_EAiNavigatorStatus)
 *
 * What it does:
 * Initializes primitive serializer callbacks for `EAiNavigatorStatus` and
 * installs process-exit helper unlink cleanup.
 */
int moho::register_EAiNavigatorStatusPrimitiveSerializer()
{
  EAiNavigatorStatusPrimitiveSerializer* const serializer = AcquireEAiNavigatorStatusPrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EAiNavigatorStatusPrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EAiNavigatorStatusPrimitiveSerializer::Serialize;
  return std::atexit(&cleanup_EAiNavigatorStatusPrimitiveSerializer_atexit);
}

namespace
{
  struct EAiNavigatorStatusTypeInfoBootstrap
  {
    EAiNavigatorStatusTypeInfoBootstrap()
    {
      (void)moho::register_EAiNavigatorStatusTypeInfo();
      (void)moho::register_EAiNavigatorStatusPrimitiveSerializer();
    }
  };

  [[maybe_unused]] EAiNavigatorStatusTypeInfoBootstrap gEAiNavigatorStatusTypeInfoBootstrap;
} // namespace

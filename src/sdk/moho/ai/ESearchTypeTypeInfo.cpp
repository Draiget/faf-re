#include "moho/ai/ESearchTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"

using namespace moho;

namespace
{
  alignas(ESearchTypeTypeInfo) unsigned char gESearchTypeTypeInfoStorage[sizeof(ESearchTypeTypeInfo)] = {};
  bool gESearchTypeTypeInfoConstructed = false;

  alignas(ESearchTypePrimitiveSerializer)
    unsigned char gESearchTypePrimitiveSerializerStorage[sizeof(ESearchTypePrimitiveSerializer)] = {};
  bool gESearchTypePrimitiveSerializerConstructed = false;

  gpg::RType* gESearchTypeRuntimeType = nullptr;

  [[nodiscard]] ESearchTypeTypeInfo* AcquireESearchTypeTypeInfo()
  {
    if (!gESearchTypeTypeInfoConstructed) {
      auto* const typeInfo = new (gESearchTypeTypeInfoStorage) ESearchTypeTypeInfo();
      gpg::PreRegisterRType(typeid(ESearchType), typeInfo);
      gESearchTypeRuntimeType = typeInfo;
      gESearchTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<ESearchTypeTypeInfo*>(gESearchTypeTypeInfoStorage);
  }

  [[nodiscard]] ESearchTypePrimitiveSerializer* AcquireESearchTypePrimitiveSerializer()
  {
    if (!gESearchTypePrimitiveSerializerConstructed) {
      new (gESearchTypePrimitiveSerializerStorage) ESearchTypePrimitiveSerializer();
      gESearchTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<ESearchTypePrimitiveSerializer*>(gESearchTypePrimitiveSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedESearchTypeType()
  {
    if (!gESearchTypeRuntimeType) {
      gESearchTypeRuntimeType = gpg::LookupRType(typeid(ESearchType));
    }
    return gESearchTypeRuntimeType;
  }

  /**
   * Address: 0x00BF71A0 (FUN_00BF71A0, cleanup_ESearchTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `ESearchTypeTypeInfo` reflection storage.
   */
  void cleanup_ESearchTypeTypeInfo()
  {
    if (!gESearchTypeTypeInfoConstructed) {
      return;
    }

    AcquireESearchTypeTypeInfo()->~ESearchTypeTypeInfo();
    gESearchTypeTypeInfoConstructed = false;
    gESearchTypeRuntimeType = nullptr;
  }

  /**
   * Address: 0x00BF71B0 (FUN_00BF71B0, cleanup_ESearchTypePrimitiveSerializer)
   *
   * What it does:
   * Unlinks the recovered primitive serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_ESearchTypePrimitiveSerializer()
  {
    if (!gESearchTypePrimitiveSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireESearchTypePrimitiveSerializer());
  }

  void cleanup_ESearchTypePrimitiveSerializer_atexit()
  {
    (void)cleanup_ESearchTypePrimitiveSerializer();
  }
} // namespace

/**
 * Address: 0x005A9E20 (FUN_005A9E20, scalar deleting thunk)
 */
ESearchTypeTypeInfo::~ESearchTypeTypeInfo() = default;

/**
 * Address: 0x005A9E10 (FUN_005A9E10, Moho::ESearchTypeTypeInfo::GetName)
 */
const char* ESearchTypeTypeInfo::GetName() const
{
  return "ESearchType";
}

/**
 * Address: 0x005A9DF0 (FUN_005A9DF0, Moho::ESearchTypeTypeInfo::Init)
 */
void ESearchTypeTypeInfo::Init()
{
  size_ = sizeof(ESearchType);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005AB520 (FUN_005AB520, PrimitiveSerHelper_ESearchType::Deserialize)
 */
void ESearchTypePrimitiveSerializer::Deserialize(
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
  *reinterpret_cast<ESearchType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<ESearchType>(value);
}

/**
 * Address: 0x005AB540 (FUN_005AB540, PrimitiveSerHelper_ESearchType::Serialize)
 */
void ESearchTypePrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const ESearchType*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

/**
 * Address: 0x005AB120 (FUN_005AB120, gpg::PrimitiveSerHelper<Moho::ESearchType,int>::Init)
 */
void ESearchTypePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedESearchTypeType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCCCF0 (FUN_00BCCCF0, register_ESearchTypeTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `ESearchType` and
 * installs process-exit cleanup.
 */
int moho::register_ESearchTypeTypeInfo()
{
  (void)AcquireESearchTypeTypeInfo();
  return std::atexit(&cleanup_ESearchTypeTypeInfo);
}

/**
 * Address: 0x00BCCD10 (FUN_00BCCD10, register_ESearchTypePrimitiveSerializer)
 *
 * What it does:
 * Initializes primitive serializer callbacks for `ESearchType` and installs
 * process-exit helper unlink cleanup.
 */
int moho::register_ESearchTypePrimitiveSerializer()
{
  ESearchTypePrimitiveSerializer* const serializer = AcquireESearchTypePrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &ESearchTypePrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &ESearchTypePrimitiveSerializer::Serialize;
  return std::atexit(&cleanup_ESearchTypePrimitiveSerializer_atexit);
}

namespace
{
  struct ESearchTypeTypeInfoBootstrap
  {
    ESearchTypeTypeInfoBootstrap()
    {
      (void)moho::register_ESearchTypeTypeInfo();
      (void)moho::register_ESearchTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] ESearchTypeTypeInfoBootstrap gESearchTypeTypeInfoBootstrap;
} // namespace

#include "moho/ai/EPathTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
  alignas(EPathTypeTypeInfo) unsigned char gEPathTypeTypeInfoStorage[sizeof(EPathTypeTypeInfo)] = {};
  bool gEPathTypeTypeInfoConstructed = false;

  alignas(EPathTypePrimitiveSerializer)
    unsigned char gEPathTypePrimitiveSerializerStorage[sizeof(EPathTypePrimitiveSerializer)] = {};
  bool gEPathTypePrimitiveSerializerConstructed = false;

  gpg::RType* gEPathTypeType = nullptr;

  [[nodiscard]] EPathTypeTypeInfo* AcquireEPathTypeTypeInfo()
  {
    if (!gEPathTypeTypeInfoConstructed) {
      auto* const typeInfo = new (gEPathTypeTypeInfoStorage) EPathTypeTypeInfo();
      gpg::PreRegisterRType(typeid(EPathType), typeInfo);
      gEPathTypeType = typeInfo;
      gEPathTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<EPathTypeTypeInfo*>(gEPathTypeTypeInfoStorage);
  }

  [[nodiscard]] EPathTypePrimitiveSerializer* AcquireEPathTypePrimitiveSerializer()
  {
    if (!gEPathTypePrimitiveSerializerConstructed) {
      new (gEPathTypePrimitiveSerializerStorage) EPathTypePrimitiveSerializer();
      gEPathTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<EPathTypePrimitiveSerializer*>(gEPathTypePrimitiveSerializerStorage);
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

  [[nodiscard]] gpg::RType* CachedEPathTypeType()
  {
    if (!gEPathTypeType) {
      gEPathTypeType = gpg::LookupRType(typeid(EPathType));
    }
    return gEPathTypeType;
  }

  /**
   * Address: 0x00BF7410 (FUN_00BF7410, cleanup_EPathTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `EPathTypeTypeInfo` reflection storage.
   */
  void cleanup_EPathTypeTypeInfo()
  {
    if (!gEPathTypeTypeInfoConstructed) {
      return;
    }

    AcquireEPathTypeTypeInfo()->~EPathTypeTypeInfo();
    gEPathTypeTypeInfoConstructed = false;
    gEPathTypeType = nullptr;
  }

  /**
   * Address: 0x00BF7420 (FUN_00BF7420, cleanup_EPathTypePrimitiveSerializer)
   *
   * What it does:
   * Unlinks the recovered primitive serializer helper node from the intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_EPathTypePrimitiveSerializer()
  {
    if (!gEPathTypePrimitiveSerializerConstructed) {
      return nullptr;
    }

    return UnlinkSerializerNode(*AcquireEPathTypePrimitiveSerializer());
  }

  /**
   * Address: 0x005B20F0 (FUN_005B20F0)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks the recovered `EPathType` primitive
   * serializer helper node and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_EPathTypePrimitiveSerializerStartupThunkA()
  {
    return cleanup_EPathTypePrimitiveSerializer();
  }

  /**
   * Address: 0x005B2120 (FUN_005B2120)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same `EPathType` primitive
   * serializer helper unlink/reset path.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_EPathTypePrimitiveSerializerStartupThunkB()
  {
    return cleanup_EPathTypePrimitiveSerializer();
  }

  void cleanup_EPathTypePrimitiveSerializer_atexit()
  {
    (void)cleanup_EPathTypePrimitiveSerializer();
  }
} // namespace

/**
 * Address: 0x005B20B0 (FUN_005B20B0, scalar deleting thunk)
 */
EPathTypeTypeInfo::~EPathTypeTypeInfo() = default;

/**
 * Address: 0x005B20A0 (FUN_005B20A0)
 */
const char* EPathTypeTypeInfo::GetName() const
{
  return "EPathType";
}

/**
 * Address: 0x005B2080 (FUN_005B2080)
 */
void EPathTypeTypeInfo::Init()
{
  size_ = sizeof(EPathType);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005B4E90 (FUN_005B4E90)
 */
void EPathTypePrimitiveSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  int value = 0;
  archive->ReadInt(&value);
  *reinterpret_cast<EPathType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EPathType>(value);
}

/**
 * Address: 0x005B4EB0 (FUN_005B4EB0)
 */
void EPathTypePrimitiveSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  if (!archive || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const EPathType*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

/**
 * Address: 0x005B4780 (FUN_005B4780)
 */
void EPathTypePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEPathTypeType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BCD270 (FUN_00BCD270, register_EPathTypeTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `EPathType` and
 * installs process-exit cleanup.
 */
int moho::register_EPathTypeTypeInfo()
{
  (void)AcquireEPathTypeTypeInfo();
  return std::atexit(&cleanup_EPathTypeTypeInfo);
}

/**
 * Address: 0x00BCD290 (FUN_00BCD290, register_EPathTypePrimitiveSerializer)
 *
 * What it does:
 * Initializes primitive serializer callbacks for `EPathType` and installs
 * process-exit helper unlink cleanup.
 */
int moho::register_EPathTypePrimitiveSerializer()
{
  EPathTypePrimitiveSerializer* const serializer = AcquireEPathTypePrimitiveSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EPathTypePrimitiveSerializer::Deserialize;
  serializer->mSaveCallback = &EPathTypePrimitiveSerializer::Serialize;
  return std::atexit(&cleanup_EPathTypePrimitiveSerializer_atexit);
}

namespace
{
  struct EPathTypeTypeInfoBootstrap
  {
    EPathTypeTypeInfoBootstrap()
    {
      (void)moho::register_EPathTypeTypeInfo();
      (void)moho::register_EPathTypePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EPathTypeTypeInfoBootstrap gEPathTypeTypeInfoBootstrap;
} // namespace

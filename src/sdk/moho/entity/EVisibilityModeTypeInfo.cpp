#include "moho/entity/EVisibilityModeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EVisibilityModeTypeInfo) unsigned char gEVisibilityModeTypeInfoStorage[sizeof(moho::EVisibilityModeTypeInfo)]{};
  bool gEVisibilityModeTypeInfoConstructed = false;
  bool gEVisibilityModeTypeInfoPreregistered = false;

  alignas(moho::EVisibilityModePrimitiveSerializer)
    unsigned char gEVisibilityModePrimitiveSerializerStorage[sizeof(moho::EVisibilityModePrimitiveSerializer)]{};
  bool gEVisibilityModePrimitiveSerializerConstructed = false;

  const gpg::REnumType* gEVisibilityModeCachedType = nullptr;

  [[nodiscard]] moho::EVisibilityModeTypeInfo* AcquireEVisibilityModeTypeInfo()
  {
    if (!gEVisibilityModeTypeInfoConstructed) {
      new (gEVisibilityModeTypeInfoStorage) moho::EVisibilityModeTypeInfo();
      gEVisibilityModeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EVisibilityModeTypeInfo*>(gEVisibilityModeTypeInfoStorage);
  }

  [[nodiscard]] moho::EVisibilityModePrimitiveSerializer* AcquireEVisibilityModePrimitiveSerializer()
  {
    if (!gEVisibilityModePrimitiveSerializerConstructed) {
      new (gEVisibilityModePrimitiveSerializerStorage) moho::EVisibilityModePrimitiveSerializer();
      gEVisibilityModePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::EVisibilityModePrimitiveSerializer*>(gEVisibilityModePrimitiveSerializerStorage);
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

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::RType* ResolveEVisibilityModeType()
  {
    if (!gEVisibilityModeCachedType) {
      gpg::RType* const type = gpg::LookupRType(typeid(moho::EVisibilityMode));
      gEVisibilityModeCachedType = (type != nullptr) ? type->IsEnumType() : nullptr;
    }
    return const_cast<gpg::REnumType*>(gEVisibilityModeCachedType);
  }

  /**
   * Address: 0x00BF1F90 (FUN_00BF1F90, cleanup_EVisibilityModeTypeInfo)
   */
  void cleanup_EVisibilityModeTypeInfo()
  {
    if (!gEVisibilityModeTypeInfoConstructed) {
      return;
    }

    AcquireEVisibilityModeTypeInfo()->~EVisibilityModeTypeInfo();
    gEVisibilityModeTypeInfoConstructed = false;
    gEVisibilityModeTypeInfoPreregistered = false;
    gEVisibilityModeCachedType = nullptr;
  }

  /**
   * Address: 0x00BF1FA0 (FUN_00BF1FA0, cleanup_EVisibilityModePrimitiveSerializer)
   */
  void cleanup_EVisibilityModePrimitiveSerializer()
  {
    if (!gEVisibilityModePrimitiveSerializerConstructed) {
      return;
    }

    UnlinkSerializerNode(*AcquireEVisibilityModePrimitiveSerializer());
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00BF1F90 (FUN_00BF1F90, Moho::EVisibilityModeTypeInfo::dtr)
   */
  EVisibilityModeTypeInfo::~EVisibilityModeTypeInfo() = default;

  /**
   * Address: 0x0050A0D0 (FUN_0050A0D0, Moho::EVisibilityModeTypeInfo::GetName)
   */
  const char* EVisibilityModeTypeInfo::GetName() const
  {
    return "EVisibilityMode";
  }

  /**
   * Address: 0x0050A160 (FUN_0050A160, Moho::EVisibilityModeTypeInfo::Init)
   */
  void EVisibilityModeTypeInfo::Init()
  {
    size_ = sizeof(EVisibilityMode);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0050A1C0 (FUN_0050A1C0, Moho::EVisibilityModeTypeInfo::AddEnums)
   */
  void EVisibilityModeTypeInfo::AddEnums()
  {
    mPrefix = "VIZMODE_";
    AddEnum(StripPrefix("VIZMODE_Always"), VIZMODE_Always);
    AddEnum(StripPrefix("VIZMODE_Never"), VIZMODE_Never);
    AddEnum(StripPrefix("VIZMODE_Intel"), VIZMODE_Intel);
  }

  /**
   * Address: 0x0050AA00 (FUN_0050AA00, PrimitiveSerHelper<EVisibilityMode>::Deserialize)
   */
  void EVisibilityModePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EVisibilityMode*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EVisibilityMode>(value);
  }

  /**
   * Address: 0x0050AA20 (FUN_0050AA20, PrimitiveSerHelper<EVisibilityMode>::Serialize)
   */
  void EVisibilityModePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const EVisibilityMode*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0050A770 (FUN_0050A770, gpg::PrimitiveSerHelper<Moho::EVisibilityMode,int>::Init)
   */
  void EVisibilityModePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveEVisibilityModeType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x0050A100 (FUN_0050A100, preregister_EVisibilityModeTypeInfo)
   */
  gpg::REnumType* preregister_EVisibilityModeTypeInfo()
  {
    auto* const typeInfo = AcquireEVisibilityModeTypeInfo();
    if (!gEVisibilityModeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EVisibilityMode), typeInfo);
      gEVisibilityModeTypeInfoPreregistered = true;
    }

    gEVisibilityModeCachedType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BC7AD0 (FUN_00BC7AD0, register_EVisibilityModeTypeInfo)
   */
  int register_EVisibilityModeTypeInfo()
  {
    (void)preregister_EVisibilityModeTypeInfo();
    return std::atexit(&cleanup_EVisibilityModeTypeInfo);
  }

  /**
   * Address: 0x00BC7AF0 (FUN_00BC7AF0, register_EVisibilityModePrimitiveSerializer)
   */
  int register_EVisibilityModePrimitiveSerializer()
  {
    auto* const serializer = AcquireEVisibilityModePrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &EVisibilityModePrimitiveSerializer::Deserialize;
    serializer->mSerialize = &EVisibilityModePrimitiveSerializer::Serialize;
    return std::atexit(&cleanup_EVisibilityModePrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct EVisibilityModeTypeInfoBootstrap
  {
    EVisibilityModeTypeInfoBootstrap()
    {
      (void)moho::register_EVisibilityModeTypeInfo();
      (void)moho::register_EVisibilityModePrimitiveSerializer();
    }
  };

  [[maybe_unused]] EVisibilityModeTypeInfoBootstrap gEVisibilityModeTypeInfoBootstrap;
} // namespace

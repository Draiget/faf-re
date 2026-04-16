#include "moho/entity/ELayerTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::ELayerTypeInfo) unsigned char gELayerTypeInfoStorage[sizeof(moho::ELayerTypeInfo)]{};
  bool gELayerTypeInfoConstructed = false;
  bool gELayerTypeInfoPreregistered = false;

  alignas(moho::ELayerPrimitiveSerializer) unsigned char gELayerPrimitiveSerializerStorage[sizeof(moho::ELayerPrimitiveSerializer)]{};
  bool gELayerPrimitiveSerializerConstructed = false;

  gpg::RType* gELayerCachedType = nullptr;

  [[nodiscard]] moho::ELayerTypeInfo* AcquireELayerTypeInfo()
  {
    if (!gELayerTypeInfoConstructed) {
      new (gELayerTypeInfoStorage) moho::ELayerTypeInfo();
      gELayerTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ELayerTypeInfo*>(gELayerTypeInfoStorage);
  }

  [[nodiscard]] moho::ELayerPrimitiveSerializer* AcquireELayerPrimitiveSerializer()
  {
    if (!gELayerPrimitiveSerializerConstructed) {
      new (gELayerPrimitiveSerializerStorage) moho::ELayerPrimitiveSerializer();
      gELayerPrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<moho::ELayerPrimitiveSerializer*>(gELayerPrimitiveSerializerStorage);
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

  /**
   * Address: 0x0050C660 (FUN_0050C660)
   *
   * What it does:
   * Initializes callback lanes for startup-owned `ELayer` primitive serializer
   * helper storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] moho::ELayerPrimitiveSerializer*
  InitializeELayerPrimitiveSerializerStartupThunkPrimary()
  {
    auto* const serializer = AcquireELayerPrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &moho::ELayerPrimitiveSerializer::Deserialize;
    serializer->mSerialize = &moho::ELayerPrimitiveSerializer::Serialize;
    return serializer;
  }

  /**
   * Address: 0x0050CA60 (FUN_0050CA60)
   *
   * What it does:
   * Secondary startup-init entry for the `ELayer` primitive serializer helper
   * storage that mirrors the primary callback initialization.
   */
  [[maybe_unused]] [[nodiscard]] moho::ELayerPrimitiveSerializer*
  InitializeELayerPrimitiveSerializerStartupThunkSecondary()
  {
    auto* const serializer = AcquireELayerPrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &moho::ELayerPrimitiveSerializer::Deserialize;
    serializer->mSerialize = &moho::ELayerPrimitiveSerializer::Serialize;
    return serializer;
  }

  /**
   * Address: 0x0050CA90 (FUN_0050CA90, resolve_ELayerType)
   */
  [[nodiscard]] gpg::RType* ResolveELayerType()
  {
    if (!gELayerCachedType) {
      gELayerCachedType = gpg::LookupRType(typeid(moho::ELayer));
    }
    return gELayerCachedType;
  }

  /**
   * Address: 0x00BF2070 (FUN_00BF2070, cleanup_ELayerTypeInfo)
   */
  void cleanup_ELayerTypeInfo()
  {
    if (!gELayerTypeInfoConstructed) {
      return;
    }

    AcquireELayerTypeInfo()->~ELayerTypeInfo();
    gELayerTypeInfoConstructed = false;
    gELayerTypeInfoPreregistered = false;
    gELayerCachedType = nullptr;
  }

  /**
   * Address: 0x00BF2080 (FUN_00BF2080, cleanup_ELayerPrimitiveSerializer)
   */
  void cleanup_ELayerPrimitiveSerializer()
  {
    if (!gELayerPrimitiveSerializerConstructed) {
      return;
    }

    UnlinkSerializerNode(*AcquireELayerPrimitiveSerializer());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BF2070 (FUN_00BF2070, Moho::ELayerTypeInfo::dtr)
   */
  ELayerTypeInfo::~ELayerTypeInfo() = default;

  /**
   * Address: 0x0050BA70 (FUN_0050BA70, Moho::ELayerTypeInfo::GetName)
   */
  const char* ELayerTypeInfo::GetName() const
  {
    return "ELayer";
  }

  /**
   * Address: 0x0050BA50 (FUN_0050BA50, Moho::ELayerTypeInfo::Init)
   */
  void ELayerTypeInfo::Init()
  {
    size_ = sizeof(ELayer);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0050BAB0 (FUN_0050BAB0, Moho::ELayerTypeInfo::AddEnums)
   */
  void ELayerTypeInfo::AddEnums()
  {
    mPrefix = "LAYER_";
    AddEnum(StripPrefix("LAYER_None"), LAYER_None);
    AddEnum(StripPrefix("LAYER_Land"), LAYER_Land);
    AddEnum(StripPrefix("LAYER_Seabed"), LAYER_Seabed);
    AddEnum(StripPrefix("LAYER_Sub"), LAYER_Sub);
    AddEnum(StripPrefix("LAYER_Water"), LAYER_Water);
    AddEnum(StripPrefix("LAYER_Air"), LAYER_Air);
    AddEnum(StripPrefix("LAYER_Orbit"), LAYER_Orbit);
    AddEnum(StripPrefix("LAYER_All"), 127);
  }

  /**
   * Address: 0x0050CA20 (FUN_0050CA20, PrimitiveSerHelper<ELayer>::Deserialize)
   */
  void ELayerPrimitiveSerializer::Deserialize(
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
    *reinterpret_cast<ELayer*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<ELayer>(value);
  }

  /**
   * Address: 0x0050CA40 (FUN_0050CA40, PrimitiveSerHelper<ELayer>::Serialize)
   */
  void ELayerPrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const ELayer*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0050C690 (FUN_0050C690, gpg::PrimitiveSerHelper<Moho::ELayer,int>::Init)
   */
  void ELayerPrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveELayerType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x0050B9F0 (FUN_0050B9F0, preregister_ELayerTypeInfo)
   */
  gpg::REnumType* preregister_ELayerTypeInfo()
  {
    auto* const typeInfo = AcquireELayerTypeInfo();
    if (!gELayerTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ELayer), typeInfo);
      gELayerTypeInfoPreregistered = true;
    }

    gELayerCachedType = typeInfo;
    return typeInfo;
  }

  /**
   * Address: 0x00BC7C60 (FUN_00BC7C60, register_ELayerTypeInfo)
   */
  int register_ELayerTypeInfo()
  {
    (void)preregister_ELayerTypeInfo();
    return std::atexit(&cleanup_ELayerTypeInfo);
  }

  /**
   * Address: 0x00BC7C80 (FUN_00BC7C80, register_ELayerPrimitiveSerializer)
   */
  int register_ELayerPrimitiveSerializer()
  {
    (void)InitializeELayerPrimitiveSerializerStartupThunkPrimary();
    return std::atexit(&cleanup_ELayerPrimitiveSerializer);
  }
} // namespace moho

namespace
{
  struct ELayerTypeInfoBootstrap
  {
    ELayerTypeInfoBootstrap()
    {
      (void)moho::register_ELayerTypeInfo();
      (void)moho::register_ELayerPrimitiveSerializer();
    }
  };

  [[maybe_unused]] ELayerTypeInfoBootstrap gELayerTypeInfoBootstrap;
} // namespace

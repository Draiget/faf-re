#include "moho/resource/EResourceTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

namespace
{
  moho::EResourceTypePrimitiveSerializer gEResourceTypePrimitiveSerializer{};

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
   * Address: 0x00547380 (FUN_00547380)
   *
   * What it does:
   * Reinitializes startup helper storage for `EResourceType` primitive
   * serialization and binds enum load/save callbacks.
   */
  [[maybe_unused]] [[nodiscard]] moho::EResourceTypePrimitiveSerializer*
  InitializeEResourceTypePrimitiveSerializerStartupThunk()
  {
    InitializeSerializerNode(gEResourceTypePrimitiveSerializer);
    gEResourceTypePrimitiveSerializer.mDeserialize = &moho::EResourceTypePrimitiveSerializer::Deserialize;
    gEResourceTypePrimitiveSerializer.mSerialize = &moho::EResourceTypePrimitiveSerializer::Serialize;
    return &gEResourceTypePrimitiveSerializer;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00545AE0 (FUN_00545AE0, Moho::EResourceTypeTypeInfo::dtr)
   */
  EResourceTypeTypeInfo::~EResourceTypeTypeInfo() = default;

  /**
   * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
   */
  const char* EResourceTypeTypeInfo::GetName() const
  {
    return "EResourceType";
  }

  /**
   * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
   */
  void EResourceTypeTypeInfo::Init()
  {
    size_ = sizeof(EResourceType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
   */
  void EResourceTypeTypeInfo::AddEnums()
  {
    mPrefix = "RESTYPE_";

    AddEnum(StripPrefix("RESTYPE_None"), static_cast<std::int32_t>(RESTYPE_None));
    AddEnum(StripPrefix("RESTYPE_Mass"), static_cast<std::int32_t>(RESTYPE_Mass));
    AddEnum(StripPrefix("RESTYPE_Hydrocarbon"), static_cast<std::int32_t>(RESTYPE_Hydrocarbon));
    AddEnum(StripPrefix("RESTYPE_Max"), static_cast<std::int32_t>(RESTYPE_Max));
  }

  /**
   * Address: 0x005478E0 (FUN_005478E0, PrimitiveSerHelper<EResourceType>::Deserialize)
   */
  void EResourceTypePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EResourceType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EResourceType>(value);
  }

  /**
   * Address: 0x00547900 (FUN_00547900, PrimitiveSerHelper<EResourceType>::Serialize)
   */
  void EResourceTypePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto value = *reinterpret_cast<const EResourceType*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  void EResourceTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EResourceType));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

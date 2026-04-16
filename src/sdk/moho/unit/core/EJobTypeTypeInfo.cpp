#include "moho/unit/core/EJobTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

namespace moho
{
  /**
   * Address: 0x0055B810 (FUN_0055B810, Moho::EJobTypeTypeInfo::EJobTypeTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EJobType` with the reflection registry.
   */
  EJobTypeTypeInfo::EJobTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EJobType), this);
  }

  /**
   * Address: 0x0055B8A0 (FUN_0055B8A0, Moho::EJobTypeTypeInfo::dtr)
   */
  EJobTypeTypeInfo::~EJobTypeTypeInfo() = default;

  /**
   * Address: 0x0055B890 (FUN_0055B890, Moho::EJobTypeTypeInfo::GetName)
   */
  const char* EJobTypeTypeInfo::GetName() const
  {
    return "EJobType";
  }

  /**
   * Address: 0x0055B870 (FUN_0055B870, Moho::EJobTypeTypeInfo::Init)
   */
  void EJobTypeTypeInfo::Init()
  {
    size_ = sizeof(EJobType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055B8D0 (FUN_0055B8D0, Moho::EJobTypeTypeInfo::AddEnums)
   */
  void EJobTypeTypeInfo::AddEnums()
  {
    mPrefix = "JOB_";

    AddEnum(StripPrefix("JOB_None"), static_cast<std::int32_t>(JOB_None));
    AddEnum(StripPrefix("JOB_Build"), static_cast<std::int32_t>(JOB_Build));
    AddEnum(StripPrefix("JOB_Repair"), static_cast<std::int32_t>(JOB_Repair));
    AddEnum(StripPrefix("JOB_Reclaim"), static_cast<std::int32_t>(JOB_Reclaim));
  }

  /**
   * Address: 0x0055D370 (FUN_0055D370, PrimitiveSerHelper<EJobType>::Deserialize)
   */
  void EJobTypePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EJobType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EJobType>(value);
  }

  /**
   * Address: 0x0055D390 (FUN_0055D390, PrimitiveSerHelper<EJobType>::Serialize)
   */
  void EJobTypePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto value = *reinterpret_cast<const EJobType*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  void EJobTypePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EJobType));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

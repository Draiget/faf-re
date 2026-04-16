#include "moho/ai/EEconResourceTypeInfo.h"

#include <cstdint>
#include <typeinfo>

namespace moho
{
  /**
   * Address: 0x00563980 (FUN_00563980, Moho::EEconResourceTypeInfo::EEconResourceTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EEconResource` with the reflection registry.
   */
  EEconResourceTypeInfo::EEconResourceTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EEconResource), this);
  }

  /**
   * Address: 0x00563A40 (FUN_00563A40, Moho::EEconResourceTypeInfo::dtr)
   */
  EEconResourceTypeInfo::~EEconResourceTypeInfo() = default;

  /**
   * Address: 0x00563A30 (FUN_00563A30, Moho::EEconResourceTypeInfo::GetName)
   */
  const char* EEconResourceTypeInfo::GetName() const
  {
    return "EEconResource";
  }

  /**
   * Address: 0x005639E0 (FUN_005639E0, Moho::EEconResourceTypeInfo::Init)
   */
  void EEconResourceTypeInfo::Init()
  {
    size_ = sizeof(EEconResource);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00563A70 (FUN_00563A70, Moho::EEconResourceTypeInfo::AddEnums)
   */
  void EEconResourceTypeInfo::AddEnums()
  {
    mPrefix = "ECON_";

    AddEnum(StripPrefix("ECON_ENERGY"), static_cast<std::int32_t>(ECON_ENERGY));
    AddEnum(StripPrefix("ECON_MASS"), static_cast<std::int32_t>(ECON_MASS));
  }

  /**
   * Address: 0x00564120 (FUN_00564120, PrimitiveSerHelper<EEconResource>::Deserialize)
   */
  void EEconResourcePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EEconResource*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EEconResource>(value);
  }

  void EEconResourcePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto value = *reinterpret_cast<const EEconResource*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  void EEconResourcePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EEconResource));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

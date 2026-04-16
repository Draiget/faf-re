#include "moho/unit/core/EFireStateTypeInfo.h"

#include <cstdint>
#include <typeinfo>

namespace moho
{
  /**
   * Address: 0x0055B990 (FUN_0055B990, Moho::EFireStateTypeInfo::EFireStateTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EFireState` with the reflection registry.
   */
  EFireStateTypeInfo::EFireStateTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EFireState), this);
  }

  /**
   * Address: 0x0055BA20 (FUN_0055BA20, Moho::EFireStateTypeInfo::dtr)
   */
  EFireStateTypeInfo::~EFireStateTypeInfo() = default;

  /**
   * Address: 0x0055BA10 (FUN_0055BA10, Moho::EFireStateTypeInfo::GetName)
   */
  const char* EFireStateTypeInfo::GetName() const
  {
    return "EFireState";
  }

  /**
   * Address: 0x0055B9F0 (FUN_0055B9F0, Moho::EFireStateTypeInfo::Init)
   */
  void EFireStateTypeInfo::Init()
  {
    size_ = sizeof(EFireState);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0055BA50 (FUN_0055BA50, Moho::EFireStateTypeInfo::AddEnums)
   */
  void EFireStateTypeInfo::AddEnums()
  {
    mPrefix = "FIRESTATE_";

    AddEnum(StripPrefix("FIRESTATE_Mix"), static_cast<std::int32_t>(FIRESTATE_Mix));
    AddEnum(StripPrefix("FIRESTATE_ReturnFire"), static_cast<std::int32_t>(FIRESTATE_ReturnFire));
    AddEnum(StripPrefix("FIRESTATE_HoldFire"), static_cast<std::int32_t>(FIRESTATE_HoldFire));
    AddEnum(StripPrefix("FIRESTATE_HoldGround"), static_cast<std::int32_t>(FIRESTATE_HoldGround));
  }

  /**
   * Address: 0x0055D3E0 (FUN_0055D3E0, PrimitiveSerHelper<EFireState>::Deserialize)
   */
  void EFireStatePrimitiveSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<EFireState*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<EFireState>(value);
  }

  /**
   * Address: 0x0055D400 (FUN_0055D400, PrimitiveSerHelper<EFireState>::Serialize)
   */
  void EFireStatePrimitiveSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    const auto value = *reinterpret_cast<const EFireState*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  void EFireStatePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = gpg::LookupRType(typeid(EFireState));
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

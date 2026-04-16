#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EFireState : std::int32_t
  {
    FIRESTATE_Mix = -1,
    FIRESTATE_ReturnFire = 0,
    FIRESTATE_HoldFire = 1,
    FIRESTATE_HoldGround = 2,
  };

  static_assert(sizeof(EFireState) == 0x4, "EFireState size must be 0x4");

  class EFireStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055B990 (FUN_0055B990, Moho::EFireStateTypeInfo::EFireStateTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EFireState` with the reflection registry.
     */
    EFireStateTypeInfo();

    /**
     * Address: 0x0055BA20 (FUN_0055BA20, Moho::EFireStateTypeInfo::dtr)
     */
    ~EFireStateTypeInfo() override;

    /**
     * Address: 0x0055BA10 (FUN_0055BA10, Moho::EFireStateTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055B9F0 (FUN_0055B9F0, Moho::EFireStateTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055BA50 (FUN_0055BA50, Moho::EFireStateTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  class EFireStatePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0055D3E0 (FUN_0055D3E0, PrimitiveSerHelper<EFireState>::Deserialize)
     *
     * What it does:
     * Deserializes one `EFireState` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055D400 (FUN_0055D400, PrimitiveSerHelper<EFireState>::Serialize)
     *
     * What it does:
     * Serializes one `EFireState` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EFireState`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EFireStatePrimitiveSerializer, mHelperNext) == 0x04,
    "EFireStatePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EFireStatePrimitiveSerializer, mHelperPrev) == 0x08,
    "EFireStatePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EFireStatePrimitiveSerializer, mDeserialize) == 0x0C,
    "EFireStatePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EFireStatePrimitiveSerializer, mSerialize) == 0x10,
    "EFireStatePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EFireStatePrimitiveSerializer) == 0x14, "EFireStatePrimitiveSerializer size must be 0x14");

  static_assert(sizeof(EFireStateTypeInfo) == 0x78, "EFireStateTypeInfo size must be 0x78");
} // namespace moho

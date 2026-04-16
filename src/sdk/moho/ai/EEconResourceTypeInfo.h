#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EEconResource : std::int32_t
  {
    ECON_ENERGY = 0,
    ECON_MASS = 1,
  };

  static_assert(sizeof(EEconResource) == 0x4, "EEconResource size must be 0x4");

  class EEconResourceTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00563980 (FUN_00563980, Moho::EEconResourceTypeInfo::EEconResourceTypeInfo)
     *
     * What it does:
     * Preregisters the enum type descriptor for `EEconResource` with the reflection registry.
     */
    EEconResourceTypeInfo();

    /**
     * Address: 0x00563A40 (FUN_00563A40, Moho::EEconResourceTypeInfo::dtr)
     */
    ~EEconResourceTypeInfo() override;

    /**
     * Address: 0x00563A30 (FUN_00563A30, Moho::EEconResourceTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005639E0 (FUN_005639E0, Moho::EEconResourceTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00563A70 (FUN_00563A70, Moho::EEconResourceTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  class EEconResourcePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x00564120 (FUN_00564120, PrimitiveSerHelper<EEconResource>::Deserialize)
     *
     * What it does:
     * Deserializes one `EEconResource` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Serializes one `EEconResource` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EEconResource`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EEconResourcePrimitiveSerializer, mHelperNext) == 0x04,
    "EEconResourcePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EEconResourcePrimitiveSerializer, mHelperPrev) == 0x08,
    "EEconResourcePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EEconResourcePrimitiveSerializer, mDeserialize) == 0x0C,
    "EEconResourcePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EEconResourcePrimitiveSerializer, mSerialize) == 0x10,
    "EEconResourcePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(EEconResourcePrimitiveSerializer) == 0x14,
    "EEconResourcePrimitiveSerializer size must be 0x14"
  );

  static_assert(sizeof(EEconResourceTypeInfo) == 0x78, "EEconResourceTypeInfo size must be 0x78");
} // namespace moho

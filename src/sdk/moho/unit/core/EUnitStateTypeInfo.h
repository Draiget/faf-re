#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/IUnit.h"

namespace moho
{
  class EUnitStateTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0055BBA0 (FUN_0055BBA0, Moho::EUnitStateTypeInfo::dtr)
     */
    ~EUnitStateTypeInfo() override;

    /**
     * Address: 0x0055BB90 (FUN_0055BB90, Moho::EUnitStateTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055BB70 (FUN_0055BB70, Moho::EUnitStateTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0055BBD0 (FUN_0055BBD0, Moho::EUnitStateTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  class EUnitStatePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x0055D450 (FUN_0055D450, PrimitiveSerHelper<EUnitState>::Deserialize)
     *
     * What it does:
     * Deserializes one `EUnitState` lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055D470 (FUN_0055D470, PrimitiveSerHelper<EUnitState>::Serialize)
     *
     * What it does:
     * Serializes one `EUnitState` lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `EUnitState`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(EUnitStatePrimitiveSerializer, mHelperNext) == 0x04,
    "EUnitStatePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EUnitStatePrimitiveSerializer, mHelperPrev) == 0x08,
    "EUnitStatePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EUnitStatePrimitiveSerializer, mDeserialize) == 0x0C,
    "EUnitStatePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EUnitStatePrimitiveSerializer, mSerialize) == 0x10,
    "EUnitStatePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EUnitStatePrimitiveSerializer) == 0x14, "EUnitStatePrimitiveSerializer size must be 0x14");

  static_assert(sizeof(EUnitState) == 0x04, "EUnitState size must be 0x04");
  static_assert(sizeof(EUnitStateTypeInfo) == 0x78, "EUnitStateTypeInfo size must be 0x78");

  /**
   * Address: 0x0055BB10 (FUN_0055BB10, preregister_EUnitStateTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `EUnitStateTypeInfo` storage and preregisters
   * RTTI ownership for `EUnitState`.
   */
  [[nodiscard]] gpg::REnumType* preregister_EUnitStateTypeInfo();
} // namespace moho

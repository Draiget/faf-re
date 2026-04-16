#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class ESearchTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A9D90 (FUN_005A9D90, Moho::ESearchTypeTypeInfo::ESearchTypeTypeInfo)
     *
     * What it does:
     * Preregisters `ESearchType` enum metadata with the reflection runtime.
     */
    ESearchTypeTypeInfo();

    /**
     * Address: 0x005A9E20 (FUN_005A9E20, scalar deleting thunk)
     */
    ~ESearchTypeTypeInfo() override;

    /**
     * Address: 0x005A9E10 (FUN_005A9E10, Moho::ESearchTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type name literal for `ESearchType`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A9DF0 (FUN_005A9DF0, Moho::ESearchTypeTypeInfo::Init)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(ESearchTypeTypeInfo) == 0x78, "ESearchTypeTypeInfo size must be 0x78");

  class ESearchTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005AB520 (FUN_005AB520, PrimitiveSerHelper_ESearchType::Deserialize)
     *
     * What it does:
     * Deserializes one `ESearchType` enum lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005AB540 (FUN_005AB540, PrimitiveSerHelper_ESearchType::Serialize)
     *
     * What it does:
     * Serializes one `ESearchType` enum lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005AB120 (FUN_005AB120, gpg::PrimitiveSerHelper<Moho::ESearchType,int>::Init)
     *
     * What it does:
     * Binds primitive enum load/save callbacks onto reflected `ESearchType`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(ESearchTypePrimitiveSerializer, mHelperNext) == 0x04,
    "ESearchTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ESearchTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "ESearchTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ESearchTypePrimitiveSerializer, mLoadCallback) == 0x0C,
    "ESearchTypePrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ESearchTypePrimitiveSerializer, mSaveCallback) == 0x10,
    "ESearchTypePrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ESearchTypePrimitiveSerializer) == 0x14, "ESearchTypePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BCCCF0 (FUN_00BCCCF0, register_ESearchTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `ESearchType` and
   * installs process-exit cleanup.
   */
  int register_ESearchTypeTypeInfo();

  /**
   * Address: 0x00BCCD10 (FUN_00BCCD10, register_ESearchTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `ESearchType` and installs
   * process-exit helper unlink cleanup.
   */
  int register_ESearchTypePrimitiveSerializer();
} // namespace moho

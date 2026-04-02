#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  struct SerHelperBase;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1C82C
   * COL:  0x00E7263C
   */
  class EPathTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005B20B0 (FUN_005B20B0, scalar deleting thunk)
     */
    ~EPathTypeTypeInfo() override;

    /**
     * Address: 0x005B20A0 (FUN_005B20A0)
     *
     * What it does:
     * Returns the reflection type name literal for `EPathType`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005B2080 (FUN_005B2080)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  /**
   * VFTABLE: 0x00E1C85C
   * COL:  0x00E725A4
   */
  class EPathTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005B4E90 (FUN_005B4E90)
     *
     * What it does:
     * Deserializes one `EPathType` enum lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B4EB0 (FUN_005B4EB0)
     *
     * What it does:
     * Serializes one `EPathType` enum lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B4780 (FUN_005B4780)
     *
     * What it does:
     * Binds load/save callbacks into reflected `EPathType` metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(sizeof(EPathTypeTypeInfo) == 0x78, "EPathTypeTypeInfo size must be 0x78");
  static_assert(
    offsetof(EPathTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EPathTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EPathTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EPathTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EPathTypePrimitiveSerializer, mLoadCallback) == 0x0C,
    "EPathTypePrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EPathTypePrimitiveSerializer, mSaveCallback) == 0x10,
    "EPathTypePrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(EPathTypePrimitiveSerializer) == 0x14, "EPathTypePrimitiveSerializer size must be 0x14");

  /**
   * Address: 0x00BCD270 (FUN_00BCD270, register_EPathTypeTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI descriptor for `EPathType` and
   * installs process-exit cleanup.
   */
  int register_EPathTypeTypeInfo();

  /**
   * Address: 0x00BCD290 (FUN_00BCD290, register_EPathTypePrimitiveSerializer)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `EPathType` and installs
   * process-exit helper unlink cleanup.
   */
  int register_EPathTypePrimitiveSerializer();
} // namespace moho

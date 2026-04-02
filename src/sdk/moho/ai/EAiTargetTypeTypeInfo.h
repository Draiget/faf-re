#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1ECE4
   * COL:  0x00E763B4
   */
  class EAiTargetTypeTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005E2400 (FUN_005E2400, scalar deleting thunk)
     */
    ~EAiTargetTypeTypeInfo() override;

    /**
     * Address: 0x005E23F0 (FUN_005E23F0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiTargetType.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E23D0 (FUN_005E23D0)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005E2430 (FUN_005E2430)
     *
     * What it does:
     * Registers `EAiTargetType` enum option names/values.
     */
    void AddEnums();
  };

  /**
   * Address: 0x00BCEBF0 (FUN_00BCEBF0, register_EAiTargetTypePrimitiveSerializer)
   *
   * What it does:
   * Binds primitive enum load/save callbacks onto reflected
   * `EAiTargetType`.
   */
  class EAiTargetTypePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005E35B0 (FUN_005E35B0, sub_5E35B0)
     *
     * What it does:
     * Deserializes one `EAiTargetType` enum value from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E35D0 (FUN_005E35D0, sub_5E35D0)
     *
     * What it does:
     * Serializes one `EAiTargetType` enum value to archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds load/save callbacks into `EAiTargetType` reflected metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(EAiTargetTypePrimitiveSerializer, mHelperNext) == 0x04,
    "EAiTargetTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAiTargetTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "EAiTargetTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAiTargetTypePrimitiveSerializer, mLoadCallback) == 0x0C,
    "EAiTargetTypePrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiTargetTypePrimitiveSerializer, mSaveCallback) == 0x10,
    "EAiTargetTypePrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EAiTargetTypePrimitiveSerializer) == 0x14,
    "EAiTargetTypePrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCEBD0 (FUN_00BCEBD0, register_EAiTargetTypeTypeInfo)
   *
   * What it does:
   * Registers `EAiTargetType` enum type-info and installs process-exit
   * cleanup.
   */
  int register_EAiTargetTypeTypeInfo();

  /**
   * Address: 0x00BCEBF0 (FUN_00BCEBF0, register_EAiTargetTypePrimitiveSerializer)
   *
   * What it does:
   * Registers primitive serializer callbacks for `EAiTargetType` and installs
   * process-exit cleanup.
   */
  int register_EAiTargetTypePrimitiveSerializer();

  static_assert(sizeof(EAiTargetTypeTypeInfo) == 0x78, "EAiTargetTypeTypeInfo size must be 0x78");
} // namespace moho

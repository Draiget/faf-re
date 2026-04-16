#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C674
   * COL:  0x00E72584
   */
  class EAiPathNavigatorStateTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005AD2D0 (FUN_005AD2D0, scalar deleting thunk)
     */
    ~EAiPathNavigatorStateTypeInfo() override;

    /**
     * Address: 0x005AD2C0 (FUN_005AD2C0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiPathNavigatorState.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005AD2A0 (FUN_005AD2A0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCCFE0 (FUN_00BCCFE0, register_EAiPathNavigatorStatePrimitiveSerializer)
   *
   * What it does:
   * Binds primitive enum load/save callbacks onto reflected
   * `EAiPathNavigatorState`.
   */
  class EAiPathNavigatorStatePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005B0290 (FUN_005B0290, Deserialize_EAiPathNavigatorState)
     *
     * What it does:
     * Deserializes one `EAiPathNavigatorState` enum lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B02B0 (FUN_005B02B0, Serialize_EAiPathNavigatorState)
     *
     * What it does:
     * Serializes one `EAiPathNavigatorState` enum lane to archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B0050 (FUN_005B0050)
     *
     * What it does:
     * Binds load/save callbacks into `EAiPathNavigatorState` reflected
     * metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(EAiPathNavigatorStatePrimitiveSerializer, mHelperNext) == 0x04,
    "EAiPathNavigatorStatePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAiPathNavigatorStatePrimitiveSerializer, mHelperPrev) == 0x08,
    "EAiPathNavigatorStatePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAiPathNavigatorStatePrimitiveSerializer, mLoadCallback) == 0x0C,
    "EAiPathNavigatorStatePrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiPathNavigatorStatePrimitiveSerializer, mSaveCallback) == 0x10,
    "EAiPathNavigatorStatePrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EAiPathNavigatorStatePrimitiveSerializer) == 0x14,
    "EAiPathNavigatorStatePrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCCFC0 (FUN_00BCCFC0, register_EAiPathNavigatorStateTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `EAiPathNavigatorState` type-info and installs
   * process-exit cleanup.
   */
  int register_EAiPathNavigatorStateTypeInfo();

  /**
   * Address: 0x00BCCFE0 (FUN_00BCCFE0, register_EAiPathNavigatorStatePrimitiveSerializer)
   *
   * What it does:
   * Registers primitive serializer callbacks for `EAiPathNavigatorState` and
   * installs process-exit cleanup.
   */
  int register_EAiPathNavigatorStatePrimitiveSerializer();

  static_assert(sizeof(EAiPathNavigatorStateTypeInfo) == 0x78, "EAiPathNavigatorStateTypeInfo size must be 0x78");
} // namespace moho

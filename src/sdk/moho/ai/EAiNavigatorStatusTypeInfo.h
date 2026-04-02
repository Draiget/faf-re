#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFD4
   * COL:  0x00E71A88
   */
  class EAiNavigatorStatusTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
     */
    ~EAiNavigatorStatusTypeInfo() override;

    /**
     * Address: 0x005A2F30 (FUN_005A2F30)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorStatus.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A2F10 (FUN_005A2F10)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A2F70 (FUN_005A2F70)
     *
     * What it does:
     * Registers EAiNavigatorStatus enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorStatusTypeInfo) == 0x78, "EAiNavigatorStatusTypeInfo size must be 0x78");

  class EAiNavigatorStatusPrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005A76B0 (FUN_005A76B0, gpg::PrimitiveSerHelper_EAiNavigatorStatus::Deserialize)
     *
     * What it does:
     * Deserializes one `EAiNavigatorStatus` enum lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A76D0 (FUN_005A76D0, gpg::PrimitiveSerHelper_EAiNavigatorStatus::Serialize)
     *
     * What it does:
     * Serializes one `EAiNavigatorStatus` enum lane into archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(EAiNavigatorStatusPrimitiveSerializer, mHelperNext) == 0x04,
    "EAiNavigatorStatusPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAiNavigatorStatusPrimitiveSerializer, mHelperPrev) == 0x08,
    "EAiNavigatorStatusPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAiNavigatorStatusPrimitiveSerializer, mLoadCallback) == 0x0C,
    "EAiNavigatorStatusPrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiNavigatorStatusPrimitiveSerializer, mSaveCallback) == 0x10,
    "EAiNavigatorStatusPrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EAiNavigatorStatusPrimitiveSerializer) == 0x14,
    "EAiNavigatorStatusPrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCC5E0 (FUN_00BCC5E0, register_EAiNavigatorStatusTypeInfo)
   *
   * What it does:
   * Preregisters startup construction for the `EAiNavigatorStatus` enum RTTI
   * descriptor and installs exit-time teardown.
   */
  void register_EAiNavigatorStatusTypeInfo();

  /**
   * Address: 0x00BCC600 (FUN_00BCC600, register_PrimitiveSerHelper_EAiNavigatorStatus)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `EAiNavigatorStatus` and
   * installs process-exit helper unlink cleanup.
   */
  int register_EAiNavigatorStatusPrimitiveSerializer();
} // namespace moho

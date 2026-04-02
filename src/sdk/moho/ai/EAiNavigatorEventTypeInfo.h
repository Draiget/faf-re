#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFC8
   * COL:  0x00E71A54
   */
  class EAiNavigatorEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
     */
    ~EAiNavigatorEventTypeInfo() override;

    /**
     * Address: 0x005A30A0 (FUN_005A30A0)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A3080 (FUN_005A3080)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A30E0 (FUN_005A30E0)
     *
     * What it does:
     * Registers EAiNavigatorEvent enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorEventTypeInfo) == 0x78, "EAiNavigatorEventTypeInfo size must be 0x78");

  class EAiNavigatorEventPrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005A7720 (FUN_005A7720, PrimitiveSerHelper_EAiNavigatorEvent::Deserialize)
     *
     * What it does:
     * Deserializes one `EAiNavigatorEvent` enum lane from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A7740 (FUN_005A7740, PrimitiveSerHelper_EAiNavigatorEvent::Serialize)
     *
     * What it does:
     * Serializes one `EAiNavigatorEvent` enum lane into archive storage.
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
    offsetof(EAiNavigatorEventPrimitiveSerializer, mHelperNext) == 0x04,
    "EAiNavigatorEventPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAiNavigatorEventPrimitiveSerializer, mHelperPrev) == 0x08,
    "EAiNavigatorEventPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAiNavigatorEventPrimitiveSerializer, mLoadCallback) == 0x0C,
    "EAiNavigatorEventPrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiNavigatorEventPrimitiveSerializer, mSaveCallback) == 0x10,
    "EAiNavigatorEventPrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EAiNavigatorEventPrimitiveSerializer) == 0x14,
    "EAiNavigatorEventPrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCC640 (FUN_00BCC640, register_EAiNavigatorEventTypeInfo)
   *
   * What it does:
   * Preregisters startup construction for the `EAiNavigatorEvent` enum RTTI
   * descriptor and installs exit-time teardown.
   */
  void register_EAiNavigatorEventTypeInfo();

  /**
   * Address: 0x00BCC660 (FUN_00BCC660)
   *
   * What it does:
   * Initializes primitive serializer callbacks for `EAiNavigatorEvent` and
   * installs process-exit helper unlink cleanup.
   */
  int register_EAiNavigatorEventPrimitiveSerializer();
} // namespace moho

#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E890
   * COL:  0x00E75E94
   */
  class EAiAttackerEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005D59A0 (FUN_005D59A0, Moho::EAiAttackerEventTypeInfo::EAiAttackerEventTypeInfo)
     *
     * What it does:
     * Preregisters `EAiAttackerEvent` enum metadata with the reflection runtime.
     */
    EAiAttackerEventTypeInfo();

    /**
     * Address: 0x005D5A30 (FUN_005D5A30, scalar deleting thunk)
     */
    ~EAiAttackerEventTypeInfo() override;

    /**
     * Address: 0x005D5A20 (FUN_005D5A20)
     *
     * What it does:
     * Returns the reflection type name literal for EAiAttackerEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D5A00 (FUN_005D5A00)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005D5A60 (FUN_005D5A60)
     *
     * What it does:
     * Registers EAiAttackerEvent enum option names/values.
     */
    void AddEnums();
  };

  /**
   * Address: 0x00BCE770 (FUN_00BCE770, register_EAiAttackerEventPrimitiveSerializer)
   *
   * What it does:
   * Binds primitive enum load/save callbacks onto reflected
   * `EAiAttackerEvent`.
   */
  class EAiAttackerEventPrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005DC390 (FUN_005DC390)
     *
     * What it does:
     * Deserializes one `EAiAttackerEvent` enum value from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DC3B0 (FUN_005DC3B0)
     *
     * What it does:
     * Serializes one `EAiAttackerEvent` enum value to archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DC3E0 (FUN_005DC3E0)
     *
     * What it does:
     * Binds load/save callbacks into `EAiAttackerEvent` reflected metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(EAiAttackerEventPrimitiveSerializer, mHelperNext) == 0x04,
    "EAiAttackerEventPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAiAttackerEventPrimitiveSerializer, mHelperPrev) == 0x08,
    "EAiAttackerEventPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAiAttackerEventPrimitiveSerializer, mLoadCallback) == 0x0C,
    "EAiAttackerEventPrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiAttackerEventPrimitiveSerializer, mSaveCallback) == 0x10,
    "EAiAttackerEventPrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EAiAttackerEventPrimitiveSerializer) == 0x14,
    "EAiAttackerEventPrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCE750 (FUN_00BCE750, sub_BCE750)
   *
   * What it does:
   * Registers `EAiAttackerEvent` enum type-info and installs process-exit
   * cleanup.
   */
  int register_EAiAttackerEventTypeInfo();

  /**
   * Address: 0x00BCE770 (FUN_00BCE770, sub_BCE770)
   *
   * What it does:
   * Registers primitive serializer callbacks for `EAiAttackerEvent` and
   * installs process-exit cleanup.
   */
  int register_EAiAttackerEventPrimitiveSerializer();

  static_assert(sizeof(EAiAttackerEventTypeInfo) == 0x78, "EAiAttackerEventTypeInfo size must be 0x78");
} // namespace moho

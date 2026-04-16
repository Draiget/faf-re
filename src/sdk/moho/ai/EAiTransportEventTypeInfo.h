#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F18C
   * COL:  0x00E76CC0
   */
  class EAiTransportEventTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005E3D10 (FUN_005E3D10, Moho::EAiTransportEventTypeInfo::EAiTransportEventTypeInfo)
     *
     * What it does:
     * Preregisters `EAiTransportEvent` enum metadata with the reflection runtime.
     */
    EAiTransportEventTypeInfo();

    /**
     * Address: 0x005E3DA0 (FUN_005E3DA0, scalar deleting thunk)
     */
    ~EAiTransportEventTypeInfo() override;

    /**
     * Address: 0x005E3D90 (FUN_005E3D90)
     *
     * What it does:
     * Returns the reflection type name literal for EAiTransportEvent.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E3D70 (FUN_005E3D70)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005E3DD0 (FUN_005E3DD0)
     *
     * What it does:
     * Registers EAiTransportEvent enum option names/values.
     */
    void AddEnums();
  };

  /**
   * Address: 0x00BCED30 (FUN_00BCED30, register_EAiTransportEventPrimitiveSerializer)
   *
   * What it does:
   * Binds primitive enum load/save callbacks onto reflected
   * `EAiTransportEvent`.
   */
  class EAiTransportEventPrimitiveSerializer
  {
  public:
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(EAiTransportEventPrimitiveSerializer, mHelperNext) == 0x04,
    "EAiTransportEventPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EAiTransportEventPrimitiveSerializer, mHelperPrev) == 0x08,
    "EAiTransportEventPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EAiTransportEventPrimitiveSerializer, mLoadCallback) == 0x0C,
    "EAiTransportEventPrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EAiTransportEventPrimitiveSerializer, mSaveCallback) == 0x10,
    "EAiTransportEventPrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(EAiTransportEventPrimitiveSerializer) == 0x14,
    "EAiTransportEventPrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCED10 (FUN_00BCED10, register_EAiTransportEventTypeInfo)
   *
   * What it does:
   * Registers `EAiTransportEvent` enum type-info and installs process-exit
   * cleanup.
   */
  int register_EAiTransportEventTypeInfo();

  /**
   * Address: 0x00BCED30 (FUN_00BCED30, register_EAiTransportEventPrimitiveSerializer)
   *
   * What it does:
   * Registers primitive serializer callbacks for `EAiTransportEvent` and
   * installs process-exit cleanup.
   */
  int register_EAiTransportEventPrimitiveSerializer();

  static_assert(sizeof(EAiTransportEventTypeInfo) == 0x78, "EAiTransportEventTypeInfo size must be 0x78");
} // namespace moho

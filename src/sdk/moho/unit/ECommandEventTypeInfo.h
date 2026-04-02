#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  /**
   * Address: 0x006E7D60 (FUN_006E7D60, sub_6E7D60)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ECommandEvent`.
   */
  class ECommandEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006E7D60 (FUN_006E7D60, sub_6E7D60)
     *
     * What it does:
     * Constructs and preregisters `ECommandEvent` enum RTTI.
     */
    ECommandEventTypeInfo();

    ~ECommandEventTypeInfo() override;

    /**
     * Address: 0x006E7D60 (FUN_006E7D60, vftable lane)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006E7D60 (FUN_006E7D60, vftable lane)
     */
    void Init() override;
  };

  static_assert(sizeof(ECommandEventTypeInfo) == 0x78, "ECommandEventTypeInfo size must be 0x78");

  class ECommandEventPrimitiveSerializer
  {
  public:
    /**
     * Address: 0x00BD8EF0 (FUN_00BD8EF0, sub_BD8EF0)
     *
     * What it does:
     * Binds enum load/save callbacks onto the reflected `ECommandEvent` type.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(ECommandEventPrimitiveSerializer, mHelperNext) == 0x04,
    "ECommandEventPrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ECommandEventPrimitiveSerializer, mHelperPrev) == 0x08,
    "ECommandEventPrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ECommandEventPrimitiveSerializer, mDeserialize) == 0x0C,
    "ECommandEventPrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ECommandEventPrimitiveSerializer, mSerialize) == 0x10,
    "ECommandEventPrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(ECommandEventPrimitiveSerializer) == 0x14, "ECommandEventPrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BD8ED0 (FUN_00BD8ED0, sub_BD8ED0)
   *
   * What it does:
   * Ensures `ECommandEvent` type-info is registered and schedules teardown.
   */
  int register_ECommandEventTypeInfo();

  /**
   * Address: 0x00BD8EF0 (FUN_00BD8EF0, sub_BD8EF0)
   *
   * What it does:
   * Registers enum primitive load/save helper callbacks for `ECommandEvent`.
   */
  int register_ECommandEventPrimitiveSerializer();
} // namespace moho


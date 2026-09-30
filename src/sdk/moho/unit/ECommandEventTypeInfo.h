#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  /**
   * Address: 0x006E7D60 (FUN_006E7D60, Moho::ECommandEventTypeInfo::ECommandEventTypeInfo)
   *
   * What it does:
   * Owns the reflected enum descriptor for `ECommandEvent`.
   */
  class ECommandEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006E7D60 (FUN_006E7D60, Moho::ECommandEventTypeInfo::ECommandEventTypeInfo)
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


  /**
   * Address: 0x006E7D60 (FUN_006E7D60, sub_6E7D60)
   *
   * What it does:
   * Ensures `ECommandEvent` type-info is constructed and registered.
   */
  void register_ECommandEventTypeInfo();
} // namespace moho

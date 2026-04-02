#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E16360
   * COL: 0x00E6A8F0
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RScmResourceTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00538AB0 (FUN_00538AB0, Moho::RScmResourceTypeInfo::RScmResourceTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RScmResource`.
     */
    RScmResourceTypeInfo();

    /**
     * Address: 0x00538B40 (FUN_00538B40, Moho::RScmResourceTypeInfo::dtr)
     * Slot: 2
     */
    ~RScmResourceTypeInfo() override;

    /**
     * Address: 0x00538B30 (FUN_00538B30, Moho::RScmResourceTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00538B10 (FUN_00538B10, Moho::RScmResourceTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RScmResource`
     * (`binary object size = 0x4C`) and finalizes indices.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC90F0 (FUN_00BC90F0, register_RScmResourceTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RScmResourceTypeInfo`.
   */
  void register_RScmResourceTypeInfo();

  static_assert(sizeof(RScmResourceTypeInfo) == 0x64, "RScmResourceTypeInfo size must be 0x64");
} // namespace moho

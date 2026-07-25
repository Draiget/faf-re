#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E35B2C (??_7NavPathTypeInfo@Moho@@6B@)
   *
   * Reflection type descriptor for the packed grid-cell path payload
   * `moho::SNavPath` (binary RTTI `??_R0?AUNavPath@Moho@@@8`).
   */
  class NavPathTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00763050 (FUN_00763050, sub_763050 construct-and-preregister worker)
     * Ctor body ICF-folded with 0x00401460 (Moho::BVIntSetTypeInfo::BVIntSetTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the NavPath reflection descriptor.
     */
    NavPathTypeInfo();

    /**
     * Address: 0x007630E0 (FUN_007630E0, scalar deleting dtor lane)
     * Slot: 2
     */
    ~NavPathTypeInfo() override;

    /**
     * Address: 0x007630D0 (FUN_007630D0, Moho::NavPathTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007630B0 (FUN_007630B0, Moho::NavPathTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets reflected NavPath size metadata and finalizes the descriptor.
     */
    void Init() override;
  };

  static_assert(sizeof(NavPathTypeInfo) == 0x64, "NavPathTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDC670 (FUN_00BDC670, register_NavPathTypeInfo)
   *
   * What it does:
   * Materializes startup `NavPathTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_NavPathTypeInfo();
} // namespace moho

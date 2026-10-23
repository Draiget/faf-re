#pragma once

#include "moho/debug/RDebugOverlayClass.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E238BC
   * COL: 0x00E7DBCC
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugWeaponsTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x00652DC0 (FUN_00652DC0, Moho::RDebugWeaponsTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugWeaponsTypeInfo() override;

    /**
     * Address: 0x00652DB0 (FUN_00652DB0, Moho::RDebugWeaponsTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugWeapons`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00652D60 (FUN_00652D60, Moho::RDebugWeaponsTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugWeapons`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x006536A0 (FUN_006536A0, Moho::RDebugWeaponsTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00653710 (FUN_00653710, Moho::RDebugWeaponsTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006536F0 (FUN_006536F0, Moho::RDebugWeaponsTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00653750 (FUN_00653750, Moho::RDebugWeaponsTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00653960 (FUN_00653960, Moho::RDebugWeapons::AddBase_RDebugOverlay)
     */
    static void AddBase_RDebugOverlay(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugWeaponsTypeInfo) == 0xA8, "RDebugWeaponsTypeInfo size must be 0xA8");
} // namespace moho

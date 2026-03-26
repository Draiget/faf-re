#pragma once

#include "moho/debug/RDebugOverlayClass.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E23538
   * COL: 0x00E7D850
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugGridTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x0064D150 (FUN_0064D150, Moho::RDebugGridTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugGridTypeInfo() override;

    /**
     * Address: 0x0064D140 (FUN_0064D140, Moho::RDebugGridTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugGrid`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0064D0F0 (FUN_0064D0F0, Moho::RDebugGridTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugGrid`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0064EA70 (FUN_0064EA70, Moho::RDebugGridTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0064EAE0 (FUN_0064EAE0, Moho::RDebugGridTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0064EAC0 (FUN_0064EAC0, Moho::RDebugGridTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0064EB20 (FUN_0064EB20, Moho::RDebugGridTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x0064F030 (FUN_0064F030, Moho::RDebugGridTypeInfo::AddBase_RDebugOverlay)
     */
    static void AddBase_RDebugOverlay(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugGridTypeInfo) == 0xA8, "RDebugGridTypeInfo size must be 0xA8");
} // namespace moho

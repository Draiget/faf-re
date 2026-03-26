#pragma once

#include "moho/debug/RDebugOverlayClass.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2357C
   * COL: 0x00E7D79C
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugRadarTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x0064D9B0 (FUN_0064D9B0, Moho::RDebugRadarTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugRadarTypeInfo() override;

    /**
     * Address: 0x0064D9A0 (FUN_0064D9A0, Moho::RDebugRadarTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugRadar`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0064D950 (FUN_0064D950, Moho::RDebugRadarTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugRadar`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0064EB30 (FUN_0064EB30, Moho::RDebugRadarTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0064EBA0 (FUN_0064EBA0, Moho::RDebugRadarTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0064EB80 (FUN_0064EB80, Moho::RDebugRadarTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0064EBE0 (FUN_0064EBE0, Moho::RDebugRadarTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x0064F3A0 (FUN_0064F3A0, Moho::RDebugRadarTypeInfo::AddBase_RDebugOverlay)
     */
    static void AddBase_RDebugOverlay(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugRadarTypeInfo) == 0xA8, "RDebugRadarTypeInfo size must be 0xA8");
} // namespace moho

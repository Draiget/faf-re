#pragma once

#include "moho/debug/RDebugOverlayClass.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E236C4
   * COL: 0x00E7D9B8
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugNavWaypointsTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x00650860 (FUN_00650860, Moho::RDebugNavWaypointsTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugNavWaypointsTypeInfo() override;

    /**
     * Address: 0x00650850 (FUN_00650850, Moho::RDebugNavWaypointsTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugNavWaypoints`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00650800 (FUN_00650800, Moho::RDebugNavWaypointsTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugNavWaypoints`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00650D50 (FUN_00650D50, Moho::RDebugNavWaypointsTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00650DC0 (FUN_00650DC0, Moho::RDebugNavWaypointsTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00650DA0 (FUN_00650DA0, Moho::RDebugNavWaypointsTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00650E00 (FUN_00650E00, Moho::RDebugNavWaypointsTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x006510B0 (FUN_006510B0, Moho::RDebugNavWaypoints::AddBase_RDebugOverlay)
     */
    static void AddBase_RDebugOverlay(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugNavWaypointsTypeInfo) == 0xA8, "RDebugNavWaypointsTypeInfo size must be 0xA8");
} // namespace moho

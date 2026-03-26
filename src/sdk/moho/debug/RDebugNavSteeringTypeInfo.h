#pragma once

#include "moho/debug/RDebugOverlayClass.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E23708
   * COL: 0x00E7D904
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugNavSteeringTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x00650A60 (FUN_00650A60, Moho::RDebugNavSteeringTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugNavSteeringTypeInfo() override;

    /**
     * Address: 0x00650A50 (FUN_00650A50, Moho::RDebugNavSteeringTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugNavSteering`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00650A00 (FUN_00650A00, Moho::RDebugNavSteeringTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugNavSteering`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00650E10 (FUN_00650E10, Moho::RDebugNavSteeringTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00650E80 (FUN_00650E80, Moho::RDebugNavSteeringTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00650E60 (FUN_00650E60, Moho::RDebugNavSteeringTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00650EC0 (FUN_00650EC0, Moho::RDebugNavSteeringTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00651110 (FUN_00651110, Moho::RDebugNavSteering::AddBase_RDebugOverlay)
     */
    static void AddBase_RDebugOverlay(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugNavSteeringTypeInfo) == 0xA8, "RDebugNavSteeringTypeInfo size must be 0xA8");
} // namespace moho

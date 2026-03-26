#pragma once

#include "moho/debug/RDebugOverlayClass.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E23680
   * COL: 0x00E7DA6C
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugNavPathTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x00650650 (FUN_00650650, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RDebugNavPathTypeInfo() override;

    /**
     * Address: 0x00650640 (FUN_00650640, Moho::RDebugNavPathTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugNavPath`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006505F0 (FUN_006505F0, Moho::RDebugNavPathTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugNavPath`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00650C90 (FUN_00650C90, Moho::RDebugNavPathTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and default-constructs a `RDebugNavPath` reflected object.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00650D00 (FUN_00650D00, Moho::RDebugNavPathTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs a `RDebugNavPath` in caller-provided storage.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00650CE0 (FUN_00650CE0, Moho::RDebugNavPathTypeInfo::Delete)
     *
     * What it does:
     * Invokes deleting-dtor path for `RDebugNavPath`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00650D40 (FUN_00650D40, Moho::RDebugNavPathTypeInfo::Destruct)
     *
     * What it does:
     * Invokes non-deleting destructor path for `RDebugNavPath`.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00651050 (FUN_00651050, Moho::RDebugNavPathTypeInfo::AddBase_RDebugOverlay)
     *
     * What it does:
     * Registers `RDebugOverlay` as reflection base for `RDebugNavPath`.
     */
    static void AddBase_RDebugOverlay(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugNavPathTypeInfo) == 0xA8, "RDebugNavPathTypeInfo size must be 0xA8");
} // namespace moho

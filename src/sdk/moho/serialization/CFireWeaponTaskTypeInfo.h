#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CFireWeaponTask;

  /**
   * Address: 0x00BD8870 (FUN_00BD8870, register_CFireWeaponTaskTypeInfo)
   *
   * What it does:
   * Forces `CFireWeaponTaskTypeInfo` construction and schedules cleanup at
   * process exit.
   */
  void register_CFireWeaponTaskTypeInfo();

  /**
   * Address: 0x00BFE6B0 (FUN_00BFE6B0, cleanup_CFireWeaponTaskTypeInfo)
   *
   * What it does:
   * Releases the reflected base/field buffers during process exit.
   */
  void cleanup_CFireWeaponTaskTypeInfo();

  class CFireWeaponTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006D3AF0 (FUN_006D3AF0, Moho::CFireWeaponTaskTypeInfo::CFireWeaponTaskTypeInfo)
     */
    CFireWeaponTaskTypeInfo();

    /**
     * Address: 0x006D3BA0 (FUN_006D3BA0, scalar deleting destructor thunk)
     */
    ~CFireWeaponTaskTypeInfo() override;

    /**
     * Address: 0x006D3B90 (FUN_006D3B90, ?GetName@CFireWeaponTaskTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006D3B50 (FUN_006D3B50, ?Init@CFireWeaponTaskTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;

    /**
     * Address: 0x006DD350 (FUN_006DD350, Moho::CFireWeaponTaskTypeInfo::AddBase_CTask)
     *
     * What it does:
     * Adds `CTask` as the reflected base type for `CFireWeaponTask`.
     */
    static void __stdcall AddBase_CTask(gpg::RType* typeInfo);

    /**
     * Address: 0x006DD000 (FUN_006DD000, Moho::CFireWeaponTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and default-constructs one reflected `CFireWeaponTask`.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006DD090 (FUN_006DD090, Moho::CFireWeaponTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one reflected `CFireWeaponTask` in caller-provided storage.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006DD070 (FUN_006DD070, Moho::CFireWeaponTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one reflected `CFireWeaponTask` allocation.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x006DD100 (FUN_006DD100, Moho::CFireWeaponTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the `CFireWeaponTask` destructor without freeing storage.
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CFireWeaponTaskTypeInfo) == 0x64, "CFireWeaponTaskTypeInfo size must be 0x64");
} // namespace moho

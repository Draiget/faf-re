#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the client-side unit view `moho::UserUnit`.
   */
  class UserUnitTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x008BF2D0 (FUN_008BF2D0, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `UserUnit` RTTI so lookup resolves to this type helper.
     */
    UserUnitTypeInfo();

    /**
     * Address: 0x008BF370 (FUN_008BF370, scalar deleting thunk)
     * Slot: 2
     */
    ~UserUnitTypeInfo() override;

    /**
     * Address: 0x008BF360 (FUN_008BF360)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for UserUnit.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x008BF330 (FUN_008BF330)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for UserUnit, registers the `CScriptObject` reflected
     * base, runs base-init, registers the `IUnit` reflected base, then
     * finalizes the descriptor. The base registrations straddle
     * `RType::Init()` exactly as the retail body does.
     */
    void Init() override;

  private:
    /**
     * Address: 0x008C6030 (FUN_008C6030, Moho::UserUnitTypeInfo::AddBase_CScriptObject)
     *
     * What it does:
     * Resolves (and caches) the `CScriptObject` reflection type, then appends
     * it as a reflected base at the `CScriptObject` sub-object offset.
     */
    void AddBaseCScriptObject();

    /**
     * Address: 0x008C6090 (FUN_008C6090, Moho::UserUnitTypeInfo::AddBase_IUnit)
     *
     * What it does:
     * Resolves (and caches) the `IUnit` reflection type, then appends it as a
     * reflected base at the `IUnit` sub-object offset.
     */
    void AddBaseIUnit();
  };

  static_assert(sizeof(UserUnitTypeInfo) == 0x64, "UserUnitTypeInfo size must be 0x64");

  /**
   * Address: 0x00BE8720 (FUN_00BE8720, register_UserUnitTypeInfo)
   *
   * What it does:
   * Registers the `UserUnit` type-info object and installs process-exit cleanup.
   */
  int register_UserUnitTypeInfo();
} // namespace moho

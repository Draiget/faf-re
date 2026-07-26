#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the AI squad aggregate `moho::CSquad`.
   */
  class CSquadTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00723CC0 (FUN_00723CC0, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `CSquad` RTTI so lookup resolves to this type helper.
     */
    CSquadTypeInfo();

    /**
     * Address: 0x00723D50 (FUN_00723D50, scalar deleting thunk)
     * Slot: 2
     */
    ~CSquadTypeInfo() override;

    /**
     * Address: 0x00723D40 (FUN_00723D40)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for CSquad.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00723D20 (FUN_00723D20)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for CSquad, then performs base-init/finalization.
     */
    void Init() override;
  };

  static_assert(sizeof(CSquadTypeInfo) == 0x64, "CSquadTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDABC0 (FUN_00BDABC0, register_CSquadTypeInfo)
   *
   * What it does:
   * Registers the `CSquad` type-info object and installs process-exit cleanup.
   */
  int register_CSquadTypeInfo();
} // namespace moho

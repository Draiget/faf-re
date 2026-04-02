#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E20C60
   * COL: 0x00E7A024
   */
  class CUnitScriptTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00622DE0 (FUN_00622DE0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CUnitScriptTaskTypeInfo() override;

    /**
     * Address: 0x00622DD0 (FUN_00622DD0, ?GetName@CUnitScriptTaskTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00622D80 (FUN_00622D80, ?Init@CUnitScriptTaskTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CUnitScriptTaskTypeInfo) == 0x64, "CUnitScriptTaskTypeInfo size must be 0x64");

  /**
   * Address: 0x00622D20 (FUN_00622D20)
   *
   * What it does:
   * Constructs/preregisters the static CUnitScriptTask type descriptor.
   */
  [[nodiscard]] gpg::RType* register_CUnitScriptTaskTypeInfo();

  /**
   * Address: 0x00BFA410 (FUN_00BFA410)
   *
   * What it does:
   * Clears preregistered CUnitScriptTask typeinfo base/field vectors for
   * process teardown.
   */
  void cleanup_CUnitScriptTaskTypeInfo();

  /**
   * Address: 0x00BD1960 (FUN_00BD1960)
   *
   * What it does:
   * Registers CUnitScriptTask typeinfo and schedules process-exit cleanup.
   */
  int register_CUnitScriptTaskTypeInfo_AtExit();
} // namespace moho

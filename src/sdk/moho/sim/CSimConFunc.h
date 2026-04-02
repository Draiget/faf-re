#pragma once

#include <cstddef>

#include "moho/sim/CSimConCommand.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1D960
   * COL:     0x00E742EC
   */
  class CSimConFunc : public CSimConCommand
  {
  public:
    using Callback = int(__cdecl*)(
      Sim* sim,
      ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    );

    CSimConFunc() noexcept;
    CSimConFunc(bool requiresCheat, const char* name, Callback handler) noexcept;

    /**
     * Address: 0x007347F0 (FUN_007347F0, sub_7347F0)
     *
     * What it does:
     * Forwards command execution to callback payload stored at +0x0C.
     */
    int Run(
      Sim* sim,
      ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    ) override;

  public:
    Callback mHandler; // +0x0C
  };

  static_assert(sizeof(CSimConFunc) == 0x10, "CSimConFunc size must be 0x10");
  static_assert(offsetof(CSimConFunc, mHandler) == 0x0C, "CSimConFunc::mHandler offset must be 0x0C");
} // namespace moho

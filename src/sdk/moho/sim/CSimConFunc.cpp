#include "moho/sim/CSimConFunc.h"

namespace moho
{
  CSimConFunc::CSimConFunc() noexcept
    : CSimConCommand()
    , mHandler(nullptr)
  {
  }

  /**
   * Address: 0x005BE360 (FUN_005BE360)
   *
   * What it does:
   * Constructs one console-function command entry and binds its callback lane.
   */
  CSimConFunc::CSimConFunc(const bool requiresCheat, const char* const name, Callback const handler) noexcept
    : CSimConCommand(requiresCheat, name)
    , mHandler(handler)
  {
  }

  /**
   * Address: 0x007347F0 (FUN_007347F0, sub_7347F0)
   */
  int CSimConFunc::Run(
    Sim* const sim,
    ParsedCommandArgs* const commandArgs,
    Wm3::Vector3f* const worldPos,
    CArmyImpl* const focusArmy,
    SEntitySetTemplateUnit* const selectedUnits
  )
  {
    if (!mHandler) {
      return 0;
    }

    return mHandler(sim, commandArgs, worldPos, focusArmy, selectedUnits);
  }
} // namespace moho

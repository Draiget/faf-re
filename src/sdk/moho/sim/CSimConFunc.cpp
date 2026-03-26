#include "moho/sim/CSimConFunc.h"

namespace moho
{
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

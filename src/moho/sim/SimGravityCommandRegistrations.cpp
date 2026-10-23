#include "moho/console/CConAlias.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/Sim.h"

namespace moho
{
  /**
   * Address: 0x00BD6090 (FUN_00BD6090, dynamic initializer for `gConAlias_sim_Gravity`)
   * Address: 0x00BFD490 (FUN_00BFD490, dynamic atexit destructor for `gConAlias_sim_Gravity`)
   */
  moho::CConAlias gConAlias_sim_Gravity("sim_Gravity", "Show or change the current gravity.  Units are ogrids/(second^2)", "DoSimCommand sim_Gravity");

  /**
   * Address: 0x00BD60C0 (FUN_00BD60C0, dynamic initializer for `gSimConFunc_sim_Gravity`)
   * Address: 0x00BFD4E0 (FUN_00BFD4E0, dynamic atexit destructor for `gSimConFunc_sim_Gravity`)
   */
  CSimConFunc gSimConFunc_sim_Gravity(false, "sim_Gravity", &Sim::sim_Gravity);

} // namespace moho

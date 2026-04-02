#pragma once

namespace moho
{
  /**
   * Address: 0x00BD6090 (FUN_00BD6090, register_sim_Gravity_ConAliasDef)
   *
   * What it does:
   * Registers the `sim_Gravity` console alias and schedules its startup-owned
   * cleanup thunk.
   */
  void register_sim_Gravity_ConAliasDef();

  /**
   * Address: 0x00BFD490 (FUN_00BFD490, cleanup_sim_Gravity_ConAlias)
   *
   * What it does:
   * Tears down recovered `sim_Gravity` alias startup storage.
   */
  void cleanup_sim_Gravity_ConAlias();

  /**
   * Address: 0x00BD60C0 (FUN_00BD60C0, register_sim_Gravity_SimConFuncDef)
   *
   * What it does:
   * Registers the `sim_Gravity` sim-console callback and schedules its
   * startup-owned cleanup thunk.
   */
  void register_sim_Gravity_SimConFuncDef();

  /**
   * Address: 0x00BFD4E0 (FUN_00BFD4E0, cleanup_sim_Gravity_SimConFunc)
   *
   * What it does:
   * Tears down recovered `sim_Gravity` sim-confunc startup storage.
   */
  void cleanup_sim_Gravity_SimConFunc();
} // namespace moho

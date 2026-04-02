#include "moho/sim/SimGravityCommandRegistrations.h"

#include <cstdlib>
#include <new>

#include "moho/console/CConAlias.h"
#include "moho/sim/CSimConFunc.h"
#include "moho/sim/Sim.h"

namespace
{
  [[nodiscard]] moho::CConAlias& ConAlias_sim_Gravity()
  {
    static moho::CConAlias sAlias;
    return sAlias;
  }

  alignas(moho::CSimConFunc) unsigned char gSimConFunc_sim_GravityStorage[sizeof(moho::CSimConFunc)] = {};
  bool gSimConFunc_sim_GravityConstructed = false;

  [[nodiscard]] moho::CSimConFunc& SimConFunc_sim_Gravity()
  {
    return *reinterpret_cast<moho::CSimConFunc*>(gSimConFunc_sim_GravityStorage);
  }

  [[nodiscard]] moho::CSimConFunc& ConstructSimConFunc_sim_Gravity()
  {
    if (!gSimConFunc_sim_GravityConstructed) {
      new (gSimConFunc_sim_GravityStorage) moho::CSimConFunc(false, "sim_Gravity", &moho::Sim::sim_Gravity);
      gSimConFunc_sim_GravityConstructed = true;
    }

    return SimConFunc_sim_Gravity();
  }

  template <void (*Cleanup)()>
  void RegisterAtexitCleanup() noexcept
  {
    (void)std::atexit(Cleanup);
  }

  struct SimGravityCommandRegistrationsBootstrap
  {
    SimGravityCommandRegistrationsBootstrap()
    {
      moho::register_sim_Gravity_ConAliasDef();
      moho::register_sim_Gravity_SimConFuncDef();
    }
  };

  [[maybe_unused]] SimGravityCommandRegistrationsBootstrap gSimGravityCommandRegistrationsBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFD490 (FUN_00BFD490, cleanup_sim_Gravity_ConAlias)
   *
   * What it does:
   * Clears the `sim_Gravity` alias payload and unregisters the startup-owned
   * console command wrapper.
   */
  void cleanup_sim_Gravity_ConAlias()
  {
    ConAlias_sim_Gravity().ShutdownRecovered();
  }

  /**
   * Address: 0x00BD6090 (FUN_00BD6090, register_sim_Gravity_ConAliasDef)
   *
   * What it does:
   * Registers the `sim_Gravity` console alias and arms its exit cleanup.
   */
  void register_sim_Gravity_ConAliasDef()
  {
    ConAlias_sim_Gravity().InitializeRecovered(
      "Show or change the current gravity.  Units are ogrids/(second^2)",
      "sim_Gravity",
      "DoSimCommand sim_Gravity"
    );
    RegisterAtexitCleanup<&cleanup_sim_Gravity_ConAlias>();
  }

  /**
   * Address: 0x00BFD4E0 (FUN_00BFD4E0, cleanup_sim_Gravity_SimConFunc)
   *
   * What it does:
   * Destroys startup-owned `sim_Gravity` sim-console callback storage.
   */
  void cleanup_sim_Gravity_SimConFunc()
  {
    if (!gSimConFunc_sim_GravityConstructed) {
      return;
    }

    static_cast<CSimConCommand&>(SimConFunc_sim_Gravity()).~CSimConCommand();
    gSimConFunc_sim_GravityConstructed = false;
  }

  /**
   * Address: 0x00BD60C0 (FUN_00BD60C0, register_sim_Gravity_SimConFuncDef)
   *
   * What it does:
   * Registers the `sim_Gravity` sim-console callback and arms its exit cleanup.
   */
  void register_sim_Gravity_SimConFuncDef()
  {
    (void)ConstructSimConFunc_sim_Gravity();
    RegisterAtexitCleanup<&cleanup_sim_Gravity_SimConFunc>();
  }
} // namespace moho

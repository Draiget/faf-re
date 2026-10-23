#pragma once

namespace moho
{
  /**
   * Engine addition, not in the binary: the threads `PlaceCurrentThread` knows how to place.
   */
  enum class EThreadRole
  {
    Main,       // WinMain: rendering, UI, sync apply
    Sim,        // CSimDriver::ThreadCreateSim
    Issue,      // CSimDriver::ThreadRun
    SimWorker,  // CSimWorkerPool
    UserWorker, // CUserWorkerPool
  };

  /**
   * Engine addition: `sys_ThreadPlacement`, a process-local console variable seeded from
   * `/threadplacement N` on the command line (-1 until first use).
   * - 0: the OS decides, as the original did;
   * - 1: ideal-processor hints (`SetThreadIdealProcessorEx`), which the scheduler may still
   *      override when the core is busy;
   * - 2: hard affinity to one logical processor (`SetThreadGroupAffinity`).
   * Each thread is placed when it starts, the main thread at startup. Placement cannot change
   * results: every thread that does sim arithmetic sets its FPU state explicitly.
   */
  extern int sys_ThreadPlacement;

  /**
   * Engine addition: places the calling thread according to `sys_ThreadPlacement`.
   *
   * The plan is made once from `GetLogicalProcessorInformationEx`: the main, sim and issue threads
   * each get a physical core of their own (core 0 is left to the OS) whose SMT siblings nothing
   * else is placed on. Sim workers fill the remaining physical cores from the front and user
   * workers from the back, so the two pools meet only when cores run out; after that the workers
   * use the SMT siblings of their pool's cores. `index` is the worker index within its pool.
   */
  void PlaceCurrentThread(EThreadRole role, unsigned int index = 0);
} // namespace moho

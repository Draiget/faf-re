#pragma once

#include <atomic>

namespace moho
{
  class Sim;

  /**
   * Engine addition: called on the sim's thread at the start of each beat (`Sim::AdvanceBeat`), before anything of the
   * beat runs. The map editor sets it to put height edits made in its view into a running solo play (WPE.40); null in
   * the game, where it is never set (no effect on the sim or its checksums). Atomic: the editor sets and clears it on
   * its own thread while the sim runs, and the sim reads it once per beat.
   */
  using SimBeforeBeatHook = void (*)(Sim& sim);
  extern std::atomic<SimBeforeBeatHook> gSimBeforeBeat;
} // namespace moho

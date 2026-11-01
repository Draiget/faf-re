#pragma once

#include <atomic>

namespace moho
{
  /**
   * Engine addition (replay keyframes), not in the binary.
   *
   * While set, sim serializers save and load the exact runtime state, including the fields retail's
   * save refreshes instead of storing: `CAimManipulator::mProjPhysBlueprint` (retail 0x00633B14
   * rewrites it from the weapon's current projectile blueprint on every save, so a save changes how
   * that weapon aims from then on). A save taken this way leaves the sim as it was, and loading it
   * gives back the same state. Retail-format saves are written and read with it clear.
   *
   * Set on the sim thread right before `Sim::SaveState`, by whoever asks for the keyframe.
   */
  inline std::atomic<bool> gSimExactArchive{false};
} // namespace moho

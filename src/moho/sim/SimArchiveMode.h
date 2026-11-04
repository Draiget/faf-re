#pragma once

#include <atomic>
#include <cstdint>

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
   * Set on the sim thread right before `Sim::SaveState`, by whoever asks for the keyframe; the
   * driver clears it as soon as the save is written.
   */
  inline std::atomic<bool> gSimExactArchive{false};

  /** Counts exact saves, from 1; whoever sets gSimExactArchive to save bumps it first. */
  inline std::atomic<std::uint32_t> gSimExactSaveCount{0u};

  /** Set from the start of a keyframe restore until the driver's opening sync is over. */
  inline std::atomic<bool> gSimKeyframeRestoring{false};
} // namespace moho

#pragma once

// Engine addition, not in the shipped binary: how the GPU-driven render paths
// are switched on.
//
// Each path has a console variable: -1 (auto, the default) turns it on where
// the active backend reports both the features it needs
// (`Device::GetGpuDrivenFeatures`) and its verified bit
// (`Device::GetGpuDrivenVerified`, the paths that backend has passed parity
// on); 1 turns it on wherever the features exist; 0 turns it off. A backend
// without the features always draws through the original path.

#include <cstdint>
#include <string>

namespace moho
{
  /** Whether a path whose console variable holds `setting` runs on the active backend. */
  [[nodiscard]] bool GpuPathEnabled(int setting, std::uint32_t path, std::uint32_t requiredFeatures);

  /** One line: every path's setting and what it resolves to on the active backend. */
  [[nodiscard]] std::string DescribeGpuPaths();

  /**
   * Builds every GPU-driven path's programs and resources now, as each path otherwise does on
   * the first frame that draws it: strategic icons and their classification, projectile icons,
   * selection brackets, world shapes, range rings and the fog of war's vision caster. They need
   * only the device, and building them took some 100 ms of the first frame of play; the session
   * calls this while the loading screen waits for the sim. Returns how many paths are active.
   */
  int REN_PrepareGpuPaths();

  /**
   * `ren_PrepareDuringLoading` (default true): the session prepares the GPU-driven paths and the
   * map's sky dome while the loading screen waits for the sim (REN_PrepareGpuPaths); false leaves
   * them to the first frame of play that draws them, as the original did.
   */
  extern bool ren_PrepareDuringLoading;

  /** The fog of war's GPU vision caster, for REN_PrepareGpuPaths (VisionRenderer.cpp). */
  bool REN_PrepareGpuVisionCaster();
} // namespace moho

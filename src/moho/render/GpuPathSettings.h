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
} // namespace moho

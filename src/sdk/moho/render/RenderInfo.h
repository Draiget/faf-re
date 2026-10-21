#pragma once

// Engine addition, not in the shipped binary: `ren_Info` / `ren_InfoDump`.
//
// One text block about the running renderer: the gal backend, its adapter,
// driver and feature level, video memory and its budget, the swap chains,
// vsync and GPU-driven features (`gpg::gal::Device::GetRuntimeInfo`); the last
// frame's draw statistics and, with FAF_GPU_PROFILE, the render CPU and GPU
// times; the process and engine-heap memory; and the shader cache. User side
// only: it reads the device and the process, never the sim.

#include <string>

namespace moho
{
  /** The `ren_Info` block, one line per '\n'. */
  [[nodiscard]] std::string REN_FormatRuntimeInfo();

  /** Writes the block to the log once, the first time a frame is published. */
  void REN_LogRuntimeInfoOnce();
} // namespace moho

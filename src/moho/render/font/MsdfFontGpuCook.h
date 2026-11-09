#pragma once

#include <string>

#include "moho/render/font/MsdfFontCook.h"

namespace moho
{
  /**
   * FAF addition, not in the shipped binary (issue #309).
   *
   * Works out a font's distance fields with a compute shader instead of on the CPU. Reading the outlines,
   * coloring the edges, packing and the last error correction stay on the CPU, so this replaces only the part
   * where each texel looks at every edge. The results aren't bit-identical to the CPU's: the shader has 32-bit
   * floats and uses the plain per-channel distance, not msdfgen's handling of overlapping contours.
   *
   * The game's fonts and mods' fonts alike: a mod's font reaches this only after its work limits, and the
   * batches below keep every dispatch short.
   */

  /** `ren_GpuFontCook`: -1 where the backend has verified it (NVIDIA adapters for now), 1 wherever it has compute, 0 never. */
  extern int ren_GpuFontCook;
  /** `ren_GpuFontCookCompare`: also cook each font on the CPU, ignore the cache, and log how far apart they are. */
  extern bool ren_GpuFontCookCompare;

  [[nodiscard]] bool MSDF_IsGpuCookAvailable();

  /**
   * Fills every glyph of a prepared plan from the GPU, on the thread that calls `MSDF_TickGpuCook`. Blocks a
   * background thread until that's done. False, with `error` set and the plan as it was, when the GPU can't do
   * it: no program, a lost device, a glyph too large for a batch, or no frames arriving.
   */
  [[nodiscard]] bool MSDF_CookOnGpu(MsdfCookPlan& plan, std::string& error);

  /** Runs one short batch of a waiting cook. Called once a frame; costs one load when there's none. */
  void MSDF_TickGpuCook();

  /** Lets a waiting `MSDF_CookOnGpu` give up, for shutdown. */
  void MSDF_CancelGpuCook();

  /** Logs how two atlases of one font differ, per channel and in the shape they draw. */
  void MSDF_LogAtlasComparison(const char* name, const SMsdfFontAtlas& gpu, const SMsdfFontAtlas& cpu, double gpuMs, double cpuMs);
} // namespace moho

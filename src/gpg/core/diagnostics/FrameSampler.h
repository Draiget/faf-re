#pragma once

namespace gpg::diag
{
  /**
   * Engine addition, debugging aid (off unless `FAF_FRAME_SAMPLER=<ms>` is set): a thread
   * samples the call stack of the thread that calls `FrameSamplerMark` about once a
   * millisecond, and for every frame that took at least `<ms>` logs where that frame's time
   * went: the functions on the most samples (inclusive) and at the top of the stack (self),
   * as `[FRAMESAMPLE]` lines. x64 only; the x86 build logs the leaf function alone.
   */
  void FrameSamplerMark();
} // namespace gpg::diag

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

  /**
   * Engine addition, debugging aid: with `FAF_FRAME_SAMPLER_DUMP=<path>` set as well, every sample
   * taken while this is not 0 is added to a count of whole call stacks for that phase. When the
   * phase changes, the counts are appended to `<path>.<phase>.folded`, one `root;...;leaf count`
   * line per stack (the folded format flame graph tools read). The console variable
   * `dbg_FrameSamplerPhase` sets it, so a test script can tag each camera view.
   */
  inline int dbg_FrameSamplerPhase = 0;
} // namespace gpg::diag

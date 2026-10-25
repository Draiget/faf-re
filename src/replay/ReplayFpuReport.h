#pragma once

#include <string>

// Engine addition, server mode (faf-replay `--fpu-report`, plan WPL.8 / M0.5): the x87 control
// word and MXCSR every other thread of this process runs with. The threads are sampled from
// outside (suspended, their floating-point context read, resumed), so no engine code changes.
// Each thread is sampled many times, since x87 helper code switches precision for short
// stretches; the report lists every value seen per thread with how often, busiest thread first
// (the sim thread and its workers do the most work in a replay run).

namespace faf::replay
{
  /** Samples every thread but the caller's `samples` times, `intervalMs` apart; one text block. */
  [[nodiscard]] std::string ReportThreadFloatingPointState(int samples, int intervalMs);
} // namespace faf::replay

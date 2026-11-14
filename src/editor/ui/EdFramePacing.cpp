#include "editor/ui/EdFramePacing.h"

namespace faf::editor
{
  int PacedFps(
    const PacingState& state
  ) noexcept
  {
    if (state.playing) {
      return 0;
    }
    if (!state.foreground) {
      return state.backgroundFps;
    }
    if (state.loading) {
      return 60;
    }
    if (state.secondsSinceInput >= kIdleAfterSeconds) {
      return state.idleFps;
    }
    return 0;
  }
} // namespace faf::editor

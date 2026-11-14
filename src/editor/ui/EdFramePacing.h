#pragma once

namespace faf::editor
{
  /**
   * The editor's frame pacing (FAF Studio's EdPerfPolicy): what the frame rate is capped at now. Behind other
   * windows: the background cap; in front but untouched for a few seconds: the idle cap; while a map's models load:
   * 60; a play, or input in the last seconds: no cap (vsync paces it).
   */
  struct PacingState
  {
    bool foreground = true;
    bool playing = false;
    bool loading = false;
    double secondsSinceInput = 0.0;
    int backgroundFps = 30; // 0: no cap
    int idleFps = 30;       // 0: no cap
  };

  /** Seconds without input before the idle cap. */
  inline constexpr double kIdleAfterSeconds = 3.0;

  /** Frames per second to cap at; 0 for none. */
  [[nodiscard]] int PacedFps(const PacingState& state) noexcept;
} // namespace faf::editor

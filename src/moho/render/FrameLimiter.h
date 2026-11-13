#pragma once

// FAF addition, not in the shipped binary: the user-facing frame rate limit (docs/RENDERER_BACKENDS.md, "Frame rate
// limit").
//
// The mechanism is the main loop's own: CScApp::Main returns to the message pump with WIN_SetWakeupTimer for the rest
// of the frame when less than the shortest frame time has passed, and sc_FrameTimeCarry gives a late wake-up back to
// the next frame, so the limit holds on average. This module only decides the shortest frame time: sc_FrameTimeClamp (4
// ms, 250 FPS) when no limit is set, 1000 / limit when one is. The pump keeps running while the loop waits, on every
// render API.
namespace moho
{
  // ren_FpsLimit: the level of the Options > Video entry (index into the table in FrameLimiter.cpp; 0 = off, the
  // default).
  extern int ren_FpsLimit;
  // ren_MaxFps: an exact limit in frames per second; when above 0 it wins over ren_FpsLimit. /maxfps N on the command
  // line sets it.
  extern float ren_MaxFps;

  // The limit in effect, frames per second; 0 = none.
  [[nodiscard]] float FrameLimitFps();

  // The main loop's shortest frame in milliseconds: 1000 / FrameLimitFps() when a limit is set (also below
  // sc_FrameTimeClamp, for a limit above 250 FPS), else sc_FrameTimeClamp.
  [[nodiscard]] float FrameLimiterShortestFrameMs();
} // namespace moho

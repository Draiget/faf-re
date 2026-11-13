#pragma once

#include <cstdint>

namespace moho
{
  struct GeomCamera3;
}

// The waterfalls and rapids of a river, as the player sees them (docs/projects/RIVERS.md, "Waterfall rendering" and
// "Particles and foam emitters"): a curtain of beam ribbons from the lip to the foot of every fall, splash and mist
// particles at the foot, spray on steep reaches, and foam sources that feed the wave simulation so the pool below runs
// white. Only the falls and rapids near the camera and in view are served, within budgets (the level of
// `ren_Waterfalls`).
//
// Render only: it reads the map's rivers (`CWaterBodies`) and the game clock, and writes particles, beams and wave
// simulation sources of the renderer. It creates no effect, no entity and no simulation state, and uses its own random
// numbers. A map without rivers (or with `sim_FixRivers` off, where no river exists) emits nothing. Nothing is emitted
// while the game is paused. Off with `FAF_NO_RENDER_ADDITIONS=1`.
namespace moho::water::falls
{
  // 0 off, 1 low, 2 normal (the default), 3 high: the range, the budgets and the density (WaterfallPlan.h `QualityOf`).
  extern int ren_Waterfalls;

  // What the last frame and the last beat did, for the log (`ren_WaterfallLog`) and the tests of the scenarios.
  struct Stats
  {
    std::uint32_t emitters{0};  // falls and rapids the map's rivers have
    std::uint32_t served{0};    // of those, near and in view this frame
    std::uint32_t particles{0}; // added by the last frame
    std::uint32_t live{0};      // alive now by the live count
    std::uint32_t beams{0};     // added by the last beat
    std::uint32_t foam{0};      // wave simulation sources added by the last frame
    std::uint64_t particlesTotal{0};
    std::uint64_t beamsTotal{0};
    std::uint64_t foamTotal{0};
  };

  [[nodiscard]] Stats GetStats();

  // Once per rendered frame of the world view, before the wave simulation steps: particles of the layers and foam
  // sources, by the game clock.
  void OnFrame(const GeomCamera3& camera);

  // Once per beat of the game (the particle renderer clears its beams then): the curtains of the falls in view. A beat
  // in which the game did not advance (a pause) keeps the beams of the last one.
  void OnBeat(const GeomCamera3& camera, bool advanced);
} // namespace moho::water::falls

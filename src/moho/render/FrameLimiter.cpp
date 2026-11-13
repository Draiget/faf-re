#include "moho/render/FrameLimiter.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/RenderFeatures.h"

namespace moho
{
  int ren_FpsLimit = 0;
  float ren_MaxFps = 0.0f;

  namespace
  {
    // The levels of the Options entry, frames per second; index 0 is off.
    constexpr float kLevelFps[] = {0.0f, 30.0f, 60.0f, 90.0f, 120.0f, 144.0f, 165.0f, 200.0f, 240.0f};
    constexpr int kLevelCount = static_cast<int>(sizeof(kLevelFps) / sizeof(kLevelFps[0]));

    TConVar<int> gTConVar_ren_FpsLimit(
      "ren_FpsLimit",
      "Frame rate limit: the level of the Options > Video entry. 0 = off (the default), 1 = 30, 2 = 60, 3 = 90, 4 = "
      "120, 5 = 144, 6 = 165, 7 = 200, "
      "8 = 240 frames per second. See ren_MaxFps for an exact value.",
      &ren_FpsLimit
    );

    TConVar<float> gTConVar_ren_MaxFps(
      "ren_MaxFps",
      "Frame rate limit in frames per second, any value (above 0 it wins over ren_FpsLimit); 0 = use ren_FpsLimit. "
      "Also /maxfps N on the command "
      "line. With vsync on the display's refresh rate paces the frames too: pick a limit that divides it (a quarter, a "
      "half) or switch vsync off.",
      &ren_MaxFps
    );

    // The Options > Video entry (render features registry). Pure CPU pacing, so every API supports it; applies at once.
    const bool gRegisteredFeature = [] {
      using render::Api;
      render::Feature feature;
      feature.key = "fps_limit";
      feature.after = "soft_particles";
      feature.title = "Frame Rate Limit";
      feature.tip = "Caps the frames per second the game draws. A cap saves power, heat and fan noise, and avoids the "
                    "coil whine some graphics cards "
                    "make when they run at several hundred frames per second. With vsync on, a limit that divides the "
                    "screen's refresh rate (a half or "
                    "a quarter) keeps the frames evenly spaced. Off allows up to 250 frames per second (console "
                    "variable sc_FrameTimeClamp). Render only, never affects the game. Takes effect at once.";
      feature.console = "ren_FpsLimit";
      feature.states = {
        {"Off (250 fps)", "off"},
        {"30 fps", "fps30"},
        {"60 fps", "fps60"},
        {"90 fps", "fps90"},
        {"120 fps", "fps120"},
        {"144 fps", "fps144"},
        {"165 fps", "fps165"},
        {"200 fps", "fps200"},
        {"240 fps", "fps240"}
      };
      feature.defaultLevel = 0;
      feature.needsRestart = false;
      feature.apis[static_cast<int>(Api::D3D10)].reason = "the Direct3D 10 renderer does not start";
      feature.apis[static_cast<int>(Api::D3D11)].supported = true;
      feature.apis[static_cast<int>(Api::D3D12)].supported = true;
      feature.apis[static_cast<int>(Api::Vulkan)].supported = true;
      feature.apply = [](const int level) {
        ren_FpsLimit = level;
      };
      render::RegisterFeature(feature);
      return true;
    }();

    void ApplyCommandLine()
    {
      static bool applied = false;
      if (applied) {
        return;
      }
      applied = true;
      fa::vector<fa::string> args;
      if (!CFG_GetArgOption("/maxfps", 1U, &args) || args.empty()) {
        return;
      }
      char* end = nullptr;
      const double value = std::strtod(args[0].c_str(), &end);
      if (end == args[0].c_str() || !std::isfinite(value) || value < 0.0) {
        gpg::Warnf(
          "/maxfps %s is not a number of frames per second; the frame rate limit stays as it was", args[0].c_str()
        );
        return;
      }
      ren_MaxFps = static_cast<float>(value);
    }
  } // namespace

  float FrameLimitFps()
  {
    ApplyCommandLine();
    if (ren_MaxFps > 0.0f && std::isfinite(ren_MaxFps)) {
      return std::min(ren_MaxFps, 10000.0f);
    }
    const int level = std::clamp(ren_FpsLimit, 0, kLevelCount - 1);
    return kLevelFps[level];
  }

  float FrameLimiterShortestFrameMs()
  {
    const float fps = FrameLimitFps();
    return fps > 0.0f ? 1000.0f / fps : sc_FrameTimeClamp;
  }
} // namespace moho

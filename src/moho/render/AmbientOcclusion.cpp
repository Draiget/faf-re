#include "moho/render/AmbientOcclusion.h"

#include <cctype>
#include <cmath>
#include <string>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/AmbientOcclusionPass.h"
#include "gpg/gal/Device.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/RenderFeatures.h"
#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  // Standard by default: on Direct3D 12 and Vulkan that is ren_Ao's own kernel, on, as it is without this file.
  // Direct3D 11 starts at Off (the feature's default there) and the player can pick a GTAO level.
  int ren_AmbientOcclusion = 1;
  float ren_AORadius = 1.5f;
  float ren_AOIntensity = 1.0f;
  float ren_AOPower = 1.6f;
  int ren_AOHalfRes = -1;
  float ren_AOPlaneTolerance = 0.35f;
  float ren_AOSmoothReach = 1.5f;
  int ren_AOTapInterp = 1;

  namespace
  {
    TConVar<int> gTConVar_ren_AmbientOcclusion(
      "ren_AmbientOcclusion",
      "Ambient occlusion of the 3D world: 0 off, 1 Standard (ren_Ao's kernel, Direct3D 12 and Vulkan; the default "
      "there), 2 Low, 3 Medium, "
      "4 High (GTAO, also on Direct3D 11). Normally set by the Ambient Occlusion option (Options > Video) or /ao "
      "off|standard|low|medium|high "
      "on the command line (docs/AMBIENT_OCCLUSION.md).",
      &ren_AmbientOcclusion
    );
    TConVar<float> gTConVar_ren_AORadius(
      "ren_AORadius",
      "GTAO ambient occlusion: how far (world units) the search for occluding geometry reaches. Default 1.5.",
      &ren_AORadius
    );
    TConVar<float> gTConVar_ren_AOIntensity(
      "ren_AOIntensity",
      "GTAO ambient occlusion: how strongly the occlusion darkens the picture; 1 is as computed (the default), 0 "
      "nothing.",
      &ren_AOIntensity
    );
    TConVar<float> gTConVar_ren_AOPower(
      "ren_AOPower",
      "GTAO ambient occlusion: contrast of the occlusion; more is darker in the creases and lighter on open ground. "
      "Default 1.6.",
      &ren_AOPower
    );
    TConVar<int> gTConVar_ren_AOHalfRes(
      "ren_AOHalfRes",
      "GTAO ambient occlusion: -1 the level's choice (half resolution at Low and Medium, the default), 0 full "
      "resolution, 1 half resolution.",
      &ren_AOHalfRes
    );

    TConVar<float> gTConVar_ren_AOPlaneTolerance(
      "ren_AOPlaneTolerance",
      "GTAO ambient occlusion: how much the surface may bend (change of its slope) inside the span of the blur's wide "
      "taps before they stop counting: rolling ground and a coarse mesh's facets stay under it, creases, walls' feet "
      "and silhouettes do not. Default 0.35.",
      &ren_AOPlaneTolerance
    );
    TConVar<float> gTConVar_ren_AOSmoothReach(
      "ren_AOSmoothReach",
      "GTAO ambient occlusion: world units the last blur reaches over smooth ground, which averages away the pattern "
      "of a coarse terrain mesh's triangles (two extra draws; 0 turns it off). Default 1.5.",
      &ren_AOSmoothReach
    );
    TConVar<int> gTConVar_ren_AOTapInterp(
      "ren_AOTapInterp",
      "GTAO ambient occlusion: 1 (the default) reads the depth at each search tap's own position, interpolated; 0 "
      "reads the texel it rounds to (the old behaviour, which darkened open ground by up to 4 % at grazing view "
      "angles).",
      &ren_AOTapInterp
    );

    // The Options > Video entry (render features registry). It replaces the On / Off entry of ren_Ao that options.lua
    // had: one option for every occlusion kernel the engine has. The keys of Off and Standard are the values that entry
    // stored (0 and -1), so a profile that holds one of them keeps its meaning. Applied live (the renderer reads the
    // console variable every frame). GTAO needs the scene depth as a texture and the GPU programs (GpuDriven.h):
    // Direct3D 11, 12 and Vulkan. Direct3D 9 draws with the shipped shader model 2 techniques, which write no depth the
    // pass could read; Direct3D 10 does not start.
    const bool gRegisteredFeature = [] {
      using render::Api;
      render::Feature feature;
      feature.key = "ambient_occlusion";
      feature.title = "Ambient Occlusion";
      feature.tip = "Darkens the creases and the places where terrain, buildings and units meet, which gives the scene "
                    "depth. Standard is the "
                    "engine's own ambient occlusion with contact shadows and terrain shadows (Direct3D 12 and Vulkan; "
                    "on Direct3D 11 it "
                    "draws Low); Low, Medium and High are a more accurate method that also works on Direct3D 11, half "
                    "resolution at Low and "
                    "Medium. Render only, never affects the game. Takes effect at once.";
      feature.console = "ren_AmbientOcclusion";
      feature.states = {{"Off", "0"}, {"Standard", "-1"}, {"Low", "low"}, {"Medium", "medium"}, {"High", "high"}};
      feature.defaultLevel = 1;
      feature.needsRestart = false;
      feature.apis[static_cast<int>(Api::D3D9)].reason =
        "the shipped Direct3D 9 techniques write no depth the pass could read";
      feature.apis[static_cast<int>(Api::D3D10)].reason = "the Direct3D 10 renderer does not start";
      feature.apis[static_cast<int>(Api::D3D11)].supported = true;
      feature.apis[static_cast<int>(Api::D3D11)].defaultLevel = 0;
      feature.apis[static_cast<int>(Api::D3D11)].reason =
        "Standard is Low here; the other kernel needs compute and a bound depth read";
      feature.apis[static_cast<int>(Api::D3D12)].supported = true;
      feature.apis[static_cast<int>(Api::Vulkan)].supported = true;
      feature.apply = [](const int level) {
        ren_AmbientOcclusion = level;
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
      if (!CFG_GetArgOption("/ao", 1U, &args) || args.empty()) {
        return;
      }
      std::string value = args[0].c_str();
      for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (value == "off" || value == "0") {
        ren_AmbientOcclusion = 0;
      } else if (value == "standard" || value == "1") {
        ren_AmbientOcclusion = 1;
      } else if (value == "low" || value == "2") {
        ren_AmbientOcclusion = 2;
      } else if (value == "medium" || value == "3") {
        ren_AmbientOcclusion = 3;
      } else if (value == "high" || value == "4") {
        ren_AmbientOcclusion = 4;
      } else {
        gpg::Warnf(
          "/ao %s is not off, standard, low, medium or high; ambient occlusion stays at %d",
          value.c_str(),
          ren_AmbientOcclusion
        );
      }
    }
  } // namespace

  int REN_GetAmbientOcclusionLevel()
  {
    ApplyCommandLine();
    return ren_AmbientOcclusion;
  }

  int REN_GtaoQualityFor(
    const int level,
    const bool legacyAvailable
  )
  {
    if (level >= 2) {
      return level > 4 ? 3 : level - 1;
    }
    return (level == 1 && !legacyAvailable) ? gpg::gal::kAmbientOcclusionLow : gpg::gal::kAmbientOcclusionOff;
  }

  bool REN_ApplyAmbientOcclusion(
    gpg::gal::Device* const device,
    const GeomCamera3& camera,
    const int x,
    const int y,
    const int width,
    const int height,
    const int quality
  )
  {
    if (quality <= 0 || device == nullptr || width <= 0 || height <= 0) {
      return false;
    }
    // A perspective projection puts the view distance in w (m23 = -1 for the engine's right-handed cameras, +1 for a
    // left-handed one; m33 = 0); the cartographic and minimap views are orthographic.
    const auto& projection = camera.projection;
    if (std::fabs(projection.r[2].w) < 0.5f || std::fabs(projection.r[3].w) > 0.5f) {
      static bool sLoggedSkip = false;
      if (!sLoggedSkip) {
        sLoggedSkip = true;
        gpg::Logf(
          "Ambient occlusion skips a view with a non-perspective projection (rows: %.3f %.3f %.3f %.3f / %.3f %.3f "
          "%.3f %.3f / %.3f %.3f %.3f %.3f / %.3f %.3f %.3f %.3f)",
          projection.r[0].x,
          projection.r[0].y,
          projection.r[0].z,
          projection.r[0].w,
          projection.r[1].x,
          projection.r[1].y,
          projection.r[1].z,
          projection.r[1].w,
          projection.r[2].x,
          projection.r[2].y,
          projection.r[2].z,
          projection.r[2].w,
          projection.r[3].x,
          projection.r[3].y,
          projection.r[3].z,
          projection.r[3].w
        );
      }
      return false;
    }
    gpg::gal::AmbientOcclusionParams params;
    params.level = quality > 3 ? 3 : quality;
    params.projectionXScale = projection.r[0].x;
    params.projectionYScale = projection.r[1].y;
    // depth = A + B / distance in front of the camera: A is -m22 when the camera looks down -z (m23 = -1), m22
    // otherwise.
    params.projectionDepthScale = projection.r[2].w < 0.0f ? -projection.r[2].z : projection.r[2].z;
    params.projectionDepthBias = projection.r[3].z;
    params.rectX = static_cast<float>(x);
    params.rectY = static_cast<float>(y);
    params.rectWidth = static_cast<float>(width);
    params.rectHeight = static_cast<float>(height);
    params.radius = ren_AORadius;
    params.intensity = ren_AOIntensity;
    params.power = ren_AOPower;
    params.halfResolution = ren_AOHalfRes;
    params.planeTolerance = ren_AOPlaneTolerance;
    params.smoothReach = ren_AOSmoothReach;
    params.interpolateTaps = ren_AOTapInterp != 0;
    static int sLoggedQuality = -1;
    const bool applied = gpg::gal::AmbientOcclusionPass::Instance().Apply(*device, params);
    if (sLoggedQuality != quality) {
      sLoggedQuality = quality;
      if (applied) {
        gpg::Logf(
          "Ambient occlusion (GTAO) quality %d active (%s resolution, view %dx%d at %d,%d, projection %.3f %.3f %.3f "
          "%.3f)",
          quality,
          gpg::gal::AmbientOcclusionHalfRes(params) ? "half" : "full",
          width,
          height,
          x,
          y,
          params.projectionXScale,
          params.projectionYScale,
          params.projectionDepthScale,
          params.projectionDepthBias
        );
      }
    }
    return applied;
  }
} // namespace moho

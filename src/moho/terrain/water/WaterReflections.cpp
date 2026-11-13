#include "moho/terrain/water/WaterReflections.h"

#include <algorithm>
#include <cmath>

#include <memory>
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderProfiler.h"
#include "gpg/gal/effects/RayTracedShadows.h"
#include "moho/console/CConCommand.h"
#include "moho/render/Shadow.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/d3d/ShaderVar.h"

namespace moho::water
{
  static int ren_WaterSSR = 1;
  static int ren_WaterSSRDebug = 0;
  static int ren_WaterSSRStrength = 100;
  static int ren_WaterSSRDistance = 800;
  static int ren_WaterSSRTilt = 40;
  static int ren_WaterAbsorb = 1;
  static int ren_WaterAbsorbDepth = 10;
  static int ren_WaterCaustics = 50;
  static int ren_WaterUnitShadows = 45;
  static int ren_WaterSheen = 55;
  static int ren_RayWaterDepthTest = 1;

  static TConVar<int> gTConVar_ren_WaterSSR(
    "ren_WaterSSR",
    "Screen-space reflections in the water (terrain, buildings and units show in it): 0 off, 1 (the default) on. A "
    "fixed march of 32 steps "
    "through a copy of the scene depth; Direct3D 11, 12 and Vulkan. Live. docs/WATER_REFLECTIONS.md.",
    &ren_WaterSSR
  );
  static TConVar<int> gTConVar_ren_WaterSSRStrength(
    "ren_WaterSSRStrength",
    "How much of the water reflection the screen-space hits replace, in percent (default 100).",
    &ren_WaterSSRStrength
  );
  static TConVar<int> gTConVar_ren_WaterSSRDistance(
    "ren_WaterSSRDistance",
    "The longest reflected ray the march follows, in world units (default 800).",
    &ren_WaterSSRDistance
  );
  static TConVar<int> gTConVar_ren_WaterSSRTilt(
    "ren_WaterSSRTilt",
    "How much of the wave normal's tilt the ray of the screen-space reflections keeps, in percent (default 40; 100 is "
    "the sharpened per-pixel normal the "
    "sky reflection uses, which makes the reflection of anything dark and detailed, a forest on a far hill, speckle; 0 "
    "a flat mirror).",
    &ren_WaterSSRTilt
  );
  static TConVar<int> gTConVar_ren_WaterAbsorb(
    "ren_WaterAbsorb",
    "Water thickness from the real scene depth instead of the map's baked depth map: 0 off (the shipped look), 1 (the "
    "default) tint and "
    "refraction follow the water the view ray really crosses, objects in front of the water are not refracted into it, "
    "2 also absorbs red "
    "faster than green and blue. Live; Direct3D 11, 12 and Vulkan. docs/WATER_REFLECTIONS.md.",
    &ren_WaterAbsorb
  );
  static TConVar<int> gTConVar_ren_WaterAbsorbDepth(
    "ren_WaterAbsorbDepth",
    "The water thickness, in world units, at which the real-depth tint is 63 percent of the way to the map's deep "
    "colour (default 10; "
    "smaller is murkier).",
    &ren_WaterAbsorbDepth
  );
  static TConVar<int> gTConVar_ren_WaterCaustics(
    "ren_WaterCaustics",
    "Caustics on the sea bed seen through shallow water, in percent (0 off, default 50): the light the wave "
    "simulation's surface focuses, "
    "fading with the water's thickness. Needs ren_WaterAbsorb. Live; Direct3D 11, 12 and Vulkan.",
    &ren_WaterCaustics
  );
  static TConVar<int> gTConVar_ren_WaterSheen(
    "ren_WaterSheen",
    "How far the Fresnel reflection of the water is moved from the shipped look (F0 0.08, the sharpened per-pixel "
    "normal, a grey cast from the "
    "sky) to a physical one (F0 0.03, a smoothed normal so grazing streaks do not light up one by one, the sky "
    "reflection tinted toward the "
    "water's own colour), in percent (0 = shipped, default 55: at 100 the sea loses its surface detail). Live.",
    &ren_WaterSheen
  );
  static TConVar<int> gTConVar_ren_WaterUnitShadows(
    "ren_WaterUnitShadows",
    "How much the sun shadow map (units, buildings, trees) darkens the water it falls on, in percent (0 off, default "
    "45); the sun glint is "
    "cut there as well. Live; Direct3D 11, 12 and Vulkan.",
    &ren_WaterUnitShadows
  );
  static TConVar<int> gTConVar_ren_RayWaterDepthTest(
    "ren_RayWaterDepthTest",
    "ren_RayWaterReflections: 1 (the default) takes the colour of a traced hit from the frame only where the scene "
    "depth there is the hit's own, so something nearer the camera is not mirrored in its place (the sky stays "
    "there); 0 takes it unchecked. Live.",
    &ren_RayWaterDepthTest
  );
  static TConVar<int> gTConVar_ren_WaterSSRDebug(
    "ren_WaterSSRDebug",
    "1: the water shows where the screen-space march found a hit (red) and where it did not (blue); 2: the unit sun "
    "shadow on the water "
    "(white lit, black shade, yellow no shadow map); 3: only the sun glint, 4: only the Fresnel weighted reflection, "
    "5: the Fresnel weight "
    "(red); 6: the caustic factor of the sea bed (grey, 0.5 = none), 7: the height of the wave simulation (red up, "
    "blue down, full scale 0.25 "
    "units), 8: its foam (white), 9: its slope (red x, green z). 0 (the default) normal.",
    &ren_WaterSSRDebug
  );

  namespace
  {
    using namespace gpg::gal;

    struct EffectVars
    {
      ShaderVar depth{};
      ShaderVar params{};
      ShaderVar params2{};
      ShaderVar absorb{};
      ShaderVar shadowMatrix{};
      ShaderVar shadowTexture{};
      ShaderVar shadowParams{};
      EffectVars()
      {
        RegisterShaderVar("waterShadowMatrix", &shadowMatrix, "water2");
        // Named like the terrain's and the meshes' shadow texture: the effect layer reads a texture of that name
        // through the cascade atlas.
        RegisterShaderVar("ShadowTexture", &shadowTexture, "water2");
        RegisterShaderVar("waterShadowParams", &shadowParams, "water2");
        RegisterShaderVar("waterAbsorbParams", &absorb, "water2");
        RegisterShaderVar("waterSceneDepth", &depth, "water2");
        RegisterShaderVar("waterSsrParams", &params, "water2");
        RegisterShaderVar("waterSsrParams2", &params2, "water2");
      }
    };

    struct State
    {
      EffectVars vars;
      Device* device = nullptr;
      std::shared_ptr<DepthStencilTarget> copy;
      std::uint32_t copyWidth = 0U;
      std::uint32_t copyHeight = 0U;
      bool failed = false;
    };

    State& GetState()
    {
      static State* const state =
        new State(); // the effect unlinks its shader vars on its own schedule: never destroyed
      return *state;
    }

    // The shader constants of the sheen and the debug view: they need no scene depth. `depthBound`: the scene depth
    // copy is bound (params2.w), so a traced reflection can be checked against it.
    void BindSheen(
      State& s,
      const bool depthBound = false
    )
    {
      const float absorb[4] = {
        0.0f,
        static_cast<float>(std::max(ren_WaterAbsorbDepth, 1)),
        0.0f,
        0.01f * static_cast<float>(std::clamp(ren_WaterSheen, 0, 100))
      };
      if (s.vars.absorb.Exists()) {
        s.vars.absorb.mEffectVariable->SetVector(absorb);
      }
      if (s.vars.params2.Exists()) {
        const float params2[4] = {
          0.01f * static_cast<float>(ren_WaterSSRStrength),
          static_cast<float>(ren_WaterSSRDebug),
          0.01f * static_cast<float>(std::clamp(ren_WaterSSRTilt, 0, 100)),
          (depthBound && ren_RayWaterDepthTest > 0) ? 1.0f : 0.0f
        };
        s.vars.params2.mEffectVariable->SetVector(params2);
      }
    }

    // The scene depth is not available: the march, the thickness, the caustics and the shadow are off, the sheen stays.
    void BindOff(
      State& s
    )
    {
      const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
      if (s.vars.params.Exists()) {
        s.vars.params.mEffectVariable->SetVector(off);
      }
      if (s.vars.shadowParams.Exists()) {
        s.vars.shadowParams.mEffectVariable->SetVector(off);
      }
      BindSheen(s);
    }

    // Where the water traces its reflections (ren_RayWaterReflections, a ray-tracing device) the marched ones step
    // aside: the traced ones are exact where the march is approximate. The frame's scene must be published.
    bool TracedReflections()
    {
      return gpg::gal::effects::gRayShadows.vectors[8][0] > 0.0f;
    }

    // The traced reflections check their hit against the scene depth, so they need its copy as well.
    bool AnythingOn()
    {
      return ren_WaterSSR > 0 || ren_WaterAbsorb > 0 || ren_WaterCaustics > 0 || ren_WaterUnitShadows > 0 ||
        TracedReflections();
    }

    // The march reads a copy of the depth: the depth buffer itself stays a depth output while the water pass draws into
    // it.
    bool CopyDepth(
      State& s,
      Device& device,
      DepthStencilTarget& source
    )
    {
      DepthStencilTargetContext* const context = source.GetContext();
      if (context == nullptr) {
        return false;
      }
      if (s.device != &device) {
        s.copy.reset();
        s.copyWidth = 0U;
        s.copyHeight = 0U;
        s.failed = false;
        s.device = &device;
      }
      if (s.failed) {
        return false;
      }
      if (s.copy == nullptr || s.copyWidth != context->width_ || s.copyHeight != context->height_) {
        s.copy.reset();
        try {
          s.copy = DepthStencilTarget::Create(
            DepthStencilTargetContext(context->width_, context->height_, context->format_, true)
          );
        } catch (const Error& error) {
          gpg::Warnf("Water reflections: cannot create the depth copy: %s", error.what());
          s.failed = true;
          return false;
        }
        s.copyWidth = context->width_;
        s.copyHeight = context->height_;
      }
      if (s.copy == nullptr || !device.CopyDepthStencil(*s.copy, source)) {
        gpg::Warnf("Water reflections: the backend cannot copy the scene depth; the screen-space reflections stay off");
        s.failed = true;
        return false;
      }
      return true;
    }
  } // namespace

  bool ReflectionPatchWanted(
    const DeviceApi api
  )
  {
    return gpg::gal::UsesD3D10EffectDialect(api);
  }

  void BindWaterReflections(
    Device* const device,
    const GeomCamera3& camera,
    const moho::Shadow* const shadow
  )
  {
    State& s = GetState();
    if (!s.vars.params.Exists() || !s.vars.depth.Exists()) {
      return; // the effect was not patched (another backend, or the source was not recognised)
    }
    const auto& projection = camera.projection;
    const bool perspective = std::fabs(projection.r[2].w) > 0.5f && std::fabs(projection.r[3].w) < 0.5f;
    if (!AnythingOn() || device == nullptr || !perspective) {
      BindOff(s);
      return;
    }
    const RenderProfileScope profile("WaterDepth");
    OutputContext context;
    device->GetContext(&context);
    if (context.depthStencil == nullptr || !CopyDepth(s, *device, *context.depthStencil)) {
      BindOff(s);
      return;
    }
    s.vars.depth.mEffectVariable->SetDepthStencil(s.copy);
    const float steps = (ren_WaterSSR <= 0 || TracedReflections()) ? 0.0f : 32.0f;
    const float params[4] = {
      steps, static_cast<float>(ren_WaterSSRDistance), static_cast<float>(s.copyWidth), static_cast<float>(s.copyHeight)
    };
    s.vars.params.mEffectVariable->SetVector(params);
    BindSheen(s, true);
    if (s.vars.absorb.Exists()) {
      const float absorb[4] = {
        ren_WaterAbsorb <= 0 ? 0.0f : (ren_WaterAbsorb >= 2 ? 2.0f : 1.0f),
        static_cast<float>(std::max(ren_WaterAbsorbDepth, 1)),
        0.005f * static_cast<float>(std::max(ren_WaterCaustics, 0)),
        0.01f * static_cast<float>(std::clamp(ren_WaterSheen, 0, 100))
      };
      s.vars.absorb.mEffectVariable->SetVector(absorb);
    }
    // The sun shadow map of the units (the terrain pass binds the same one, an atlas of cascade tiles when
    // ren_ShadowCascades is on; the water reads it by the whole-view coordinate and the effect layer picks the tile).
    // Off where the shadow pass did not run this frame and while the frame's shadows are traced: the map then holds
    // only alpha meshes and the water would read units as unshadowed.
    if (s.vars.shadowParams.Exists()) {
      std::shared_ptr<CD3DRenderTarget> shadowTexture;
      const bool traced = gpg::gal::effects::gRayShadows.vectors[4][0] > 0.0f;
      if (shadow != nullptr && shadow->mShadowCameraValid && ren_WaterUnitShadows > 0 && !traced) {
        shadowTexture = shadow->GetShadowTexture();
      }
      if (shadowTexture != nullptr && s.vars.shadowMatrix.Exists() && s.vars.shadowTexture.Exists()) {
        s.vars.shadowMatrix.SetMatrix4x4(&shadow->mCamera.viewProjection);
        s.vars.shadowTexture.SetRenderTargetTexture(shadowTexture);
        const auto& vp = shadow->mCamera.viewProjection;
        const float depthAxis = std::sqrt(vp.r[0].z * vp.r[0].z + vp.r[1].z * vp.r[1].z + vp.r[2].z * vp.r[2].z);
        const float worldPerDepth = depthAxis > 1.0e-6f ? 1.0f / depthAxis : 0.0f;
        const float shade[4] = {
          0.01f * static_cast<float>(std::min(ren_WaterUnitShadows, 100)), worldPerDepth, 8.0f, 8.0f
        };
        s.vars.shadowParams.mEffectVariable->SetVector(shade);
      } else {
        const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        s.vars.shadowParams.mEffectVariable->SetVector(off);
      }
    }
  }

  void ReleaseWaterReflections()
  {
    State& s = GetState();
    if (s.vars.depth.mEffectVariable && s.vars.depth.Exists()) {
      s.vars.depth.mEffectVariable->SetDepthStencil(std::shared_ptr<DepthStencilTarget>());
    }
    if (s.vars.shadowTexture.mEffectVariable && s.vars.shadowTexture.Exists()) {
      s.vars.shadowTexture.SetRenderTargetTexture(std::shared_ptr<CD3DRenderTarget>());
    }
    s.copy.reset();
    s.copyWidth = 0U;
    s.copyHeight = 0U;
    s.device = nullptr;
    s.failed = false;
  }
} // namespace moho::water

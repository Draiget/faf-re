#include "moho/render/shadow/ShadowFilter.h"

#include <algorithm>
#include <atomic>

#include "moho/console/CConCommand.h"
#include "moho/render/RayScene.h"
#include "moho/render/RenderFeatures.h"
#include "moho/render/lights/LightFeeds.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/terrain/TerrainShaderVars.h"

namespace moho::shadowfilter
{
  int ren_ShadowFilter = 0;
  static float ren_ShadowFilterBias = 0.5f;
  static float ren_ShadowFilterSlope = 1.0f;
  static float ren_ShadowFilterTerrainBias = 1.0f;

  static TConVar<int> gTConVar_ren_ShadowFilter(
    "ren_ShadowFilter",
    "Shadow filtering (docs/SHADOW_FILTERING.md): 0 Off (the shipped map, 5-tap lookup and blurred caster mask), 1 "
    "Low, 2 Medium, 3 High, 4 Ultra. "
    "A level sets the smallest shadow map size, the number of taps of the rotated-disk lookup, and (High, Ultra) "
    "contact-hardening soft shadows. "
    "Normally set by the Shadow Filtering option (Options, Video); applies at once. Direct3D 11, 12 and Vulkan; yields "
    "to ray-traced shadows.",
    &ren_ShadowFilter
  );

  static TConVar<float> gTConVar_ren_ShadowFilterBias(
    "ren_ShadowFilterBias",
    "Scale of the constant depth bias of the filtered shadow lookup (1 = the shipped bias on meshes, 0.001 on the "
    "ground); default 0.5.",
    &ren_ShadowFilterBias
  );

  static TConVar<float> gTConVar_ren_ShadowFilterSlope(
    "ren_ShadowFilterSlope",
    "Scale of the receiver-plane (slope) bias of the filtered shadow lookup; 0 = none, default 1.",
    &ren_ShadowFilterSlope
  );

  static TConVar<float> gTConVar_ren_ShadowFilterTerrainBias(
    "ren_ShadowFilterTerrainBias",
    "How far, in world units along the light, the terrain in the shadow map is moved from the light before the "
    "filtered lookup compares with it (default 1): the map holds the terrain's mesh seen from the light, which "
    "differs from the shaded surface by a fraction of a triangle on curved ground. A hill still shades what is "
    "behind it.",
    &ren_ShadowFilterTerrainBias
  );

  namespace
  {
    // Direct3D 9 and Direct3D 10 (does not start) are not served; see the feature registration below.
    constexpr LevelParams kLevels[] = {
      {1024, 8, 1.5f, 1.5f, 0.0f},    // Low: the shipped map size, 8 taps
      {2048, 12, 2.0f, 2.0f, 0.0f},   // Medium
      {2048, 16, 1.5f, 6.0f, 0.04f},  // High: contact hardening
      {4096, 24, 2.0f, 10.0f, 0.04f}, // Ultra
    };

    std::atomic<bool> gMeshPatched{false};
    std::atomic<bool> gTerrainPatched{false};
    // Whether the effects in use were built with the patch (the answer EffectPatchWanted gave when the render thread
    // built them).
    std::atomic<bool> gEffectsBuiltFiltered{false};

    float gLightWidth = 0.0f;
    float gLightDepthRange = 0.0f;

    struct FilterVars
    {
      ShaderVar meshFilter{};
      ShaderVar meshFilter2{};
      ShaderVar terrainFilter{};
      ShaderVar terrainFilter2{};
      FilterVars()
      {
        RegisterShaderVar("shadowFilter", &meshFilter, "mesh");
        RegisterShaderVar("shadowFilter2", &meshFilter2, "mesh");
        RegisterShaderVar("ShadowFilter", &terrainFilter, "terrain");
        RegisterShaderVar("ShadowFilter2", &terrainFilter2, "terrain");
      }
    };

    FilterVars& Vars()
    {
      static FilterVars vars;
      return vars;
    }

    // Direct3D 11, 12 and Vulkan: the Direct3D 10 effect dialect, where the tap loop runs on a shader parameter and the
    // level switches live.
    bool UsesDynamicDialect(
      const gpg::gal::DeviceApi api
    )
    {
      return gpg::gal::UsesD3D10EffectDialect(api);
    }

    const bool gRegisteredFeature = [] {
      using render::Api;
      render::Feature feature;
      feature.key = "shadow_filter";
      feature.after = "dynlights_quality"; // Options > Video lists the render features in this order
      feature.title = "Shadow Filtering";
      feature.tip = "Soft, filtered shadows: a larger shadow map, a rotated-disk filter instead of the 5-tap lookup, "
                    "and from High on shadows that soften "
                    "with the distance to the object that casts them. Off keeps the shipped shadows. Render only, "
                    "never affects the game; applies at once. "
                    "Ray-traced shadows, when on, replace it.";
      feature.console = "ren_ShadowFilter";
      feature.states = {
        {"Off (original)", "off"},
        {"Low", "low"},
        {"Medium", "medium"},
        {"High (soft shadows)", "high"},
        {"Ultra (4096 map)", "ultra"}
      };
      feature.defaultLevel = 0;
      feature.needsRestart = false;
      feature.apis[static_cast<int>(Api::D3D9)].reason =
        "the shipped ps_2_a techniques have too few constant registers for the lookup";
      feature.apis[static_cast<int>(Api::D3D10)].reason = "the Direct3D 10 renderer does not start";
      feature.apis[static_cast<int>(Api::D3D11)].supported = true;
      feature.apis[static_cast<int>(Api::D3D12)].supported = true;
      feature.apis[static_cast<int>(Api::Vulkan)].supported = true;
      feature.apply = [](const int level) {
        ren_ShadowFilter = level;
      };
      render::RegisterFeature(feature);
      return true;
    }();
  } // namespace

  const LevelParams& ParamsFor(
    const int level
  )
  {
    return kLevels[std::clamp(level, 1, 4) - 1];
  }

  bool Supported(
    const gpg::gal::DeviceApi api
  )
  {
    return UsesDynamicDialect(api);
  }

  bool TileAware(
    const gpg::gal::DeviceApi api
  )
  {
    return api == gpg::gal::DeviceApi::Direct3D12 || api == gpg::gal::DeviceApi::Vulkan;
  }

  bool EffectPatchWanted(
    const gpg::gal::DeviceApi api
  )
  {
    if (!Supported(api)) {
      return false;
    }
    // Read live: the option (or ren_ShadowFilter) can be switched on in a running game, and lights::ApplyLiveLevel then
    // rebuilds the effects.
    const bool wanted = ren_ShadowFilter > 0 || render::FeatureLevel("shadow_filter", render::ApiFromDevice(api)) > 0;
    if (!lights::OnWarmupThread()) {
      gEffectsBuiltFiltered.store(wanted, std::memory_order_relaxed);
    }
    return wanted;
  }

  void NoteEffectPatched(
    const bool terrain,
    const bool patched
  )
  {
    if (lights::OnWarmupThread()) {
      return;
    }
    (terrain ? gTerrainPatched : gMeshPatched).store(patched, std::memory_order_relaxed);
  }

  bool LiveRebuildWanted()
  {
    return ren_ShadowFilter > 0 && !gEffectsBuiltFiltered.load(std::memory_order_relaxed);
  }

  void NoteRebuilt()
  {
    gEffectsBuiltFiltered.store(
      true, std::memory_order_relaxed
    ); // set first by the caller's rebuild: a failed one must not repeat every frame
  }

  bool Active()
  {
    return ren_ShadowFilter > 0 && gMeshPatched.load(std::memory_order_relaxed) &&
      gTerrainPatched.load(std::memory_order_relaxed) && !RayScene::Instance().Active();
  }

  int WantedMapSize(
    const int userSize,
    const bool atlas
  )
  {
    if (!Active()) {
      return userSize;
    }
    // the level sets the smallest map; the Shadow Resolution slider (ren_ShadowSize) can ask for more
    const int levelSize = ParamsFor(ren_ShadowFilter).mapSize;
    return std::max(userSize, atlas ? std::min(levelSize, kAtlasTileLimit) : levelSize);
  }

  float FootprintTexels()
  {
    return Active() ? ParamsFor(ren_ShadowFilter).maxRadius : 0.0f;
  }

  void SetLightVolume(
    const float width,
    const float depthRange
  )
  {
    gLightWidth = width;
    gLightDepthRange = depthRange;
  }

  void UpdateShaderVars(
    const int textureSize,
    const bool cameraValid
  )
  {
    float filter[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    // the terrain's margin in depth units: world units over the light volume's depth range
    const float terrainMargin =
      gLightDepthRange > 0.0f ? std::max(ren_ShadowFilterTerrainBias, 0.0f) / gLightDepthRange : 0.002f;
    float filter2[4] = {ren_ShadowFilterBias, ren_ShadowFilterSlope, terrainMargin, 0.0f};
    if (Active()) {
      const LevelParams& p = ParamsFor(ren_ShadowFilter);
      filter[0] = static_cast<float>(p.taps);
      filter[1] = p.minRadius;
      filter[2] = p.maxRadius;
      // uv per unit of depth difference: a depth unit spans the light volume's depth range in world units, a uv unit
      // its width
      if (p.penumbraTan > 0.0f && gLightWidth > 0.0f && gLightDepthRange > 0.0f) {
        filter[3] = p.penumbraTan * gLightDepthRange / gLightWidth;
      }
    }
    FilterVars& vars = Vars();
    SetShaderVarMem(vars.meshFilter, 4U, filter);
    SetShaderVarMem(vars.meshFilter2, 4U, filter2);
    SetShaderVarMem(vars.terrainFilter2, 4U, filter2);
    if (!cameraValid) {
      filter[0] =
        0.0f; // the terrain's shipped lookup: the shadow map is cleared to lit, the matrix is from an earlier frame
    }
    SetShaderVarMem(vars.terrainFilter, 4U, filter);
    if (Active()) {
      // the blur passes set the terrain's ShadowSize; with the filter on they do not run
      GetTerrainShaderVars().shadowSize.SetFloat(static_cast<float>(textureSize));
    }
  }
} // namespace moho::shadowfilter

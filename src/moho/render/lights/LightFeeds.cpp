#include "moho/render/lights/LightFeeds.h"
#include "moho/render/RenderFeatures.h"
#include <algorithm>
#include <cstdlib>

#include <atomic>
#include <chrono>
#include <cmath>
#include <string_view>
#include <thread>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DynLightPass.h"
#include "gpg/gal/RenderProfiler.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DDeviceResources.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/lights/LightBinding.h"
#include "moho/render/lights/LightCensus.h"
#include "moho/render/lights/LightDebugView.h"
#include "moho/render/lights/LightField.h"
#include "moho/render/lights/LightTextureCache.h"
#include "moho/render/WRenViewport.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/water/WaterBodySurfaces.h"

namespace moho::lights
{
  int ren_DynLights = model::kOff;
  static int ren_DynLightsLog = 0;
  static int ren_DynLightsGain = 100;
  int ren_DynLightsTest = 0;

  static TConVar<int> gTConVar_ren_DynLights(
    "ren_DynLights",
    "Dynamic lights from explosion flashes, glows, beams, trails and Lua lights: 0 off (the default), 1 only the "
    "biggest, 2 large, 3 most, 4 all. "
    "Render only; the simulation never sees them. Normally set by the Dynamic Lights option (Options, Video; the "
    "effects are patched at start-up when it is not Off) or /dynlights on the command line (docs/DYNAMIC_LIGHTS.md).",
    &ren_DynLights
  );

  static TConVar<int> gTConVar_ren_DynLightsGain(
    "ren_DynLightsGain",
    "How strong the dynamic lights are, in percent of the tuned strength (default 100; 0 to 1000). Scales every light "
    "of the frame: weaker lights show more at 200 or 300. "
    "Needs ren_DynLights.",
    &ren_DynLightsGain
  );

  static TConVar<int> gTConVar_ren_DynLightsTest(
    "ren_DynLightsTest",
    "Test light for the dynamic lights: every N ticks a flash (size 12, 2 seconds) appears on the ground, or over the "
    "water that covers it, in the middle of the view; "
    "0 (the default) adds none. Needs ren_DynLights.",
    &ren_DynLightsTest
  );

  static TConVar<int> gTConVar_ren_DynLightsLog(
    "ren_DynLightsLog",
    "Log the dynamic light pool (offered, stored, gated, active lights) every N rendered frames; 0 (the default) logs "
    "nothing.",
    &ren_DynLightsLog
  );

  namespace
  {
    // Whether the effects in use were built with the light pass (the answer LightsWanted gave when the render thread
    // built them).
    bool gEffectsBuiltLit = false;

    // Direct3D 11 compiles the lit effects with fxc, 20 to 40 s: the compile runs on worker threads while the game goes
    // on (each thread builds one effect into a throw-away object, which leaves the compiled bytecode in the effect
    // cache), and the render thread then swaps the effects in when all are done, which takes the cache hit and a
    // fraction of a second.
    thread_local bool tWarmupThread = false;
    struct WarmupThreads
    {
      std::vector<std::thread> threads;
      ~WarmupThreads()
      {
        for (std::thread& thread : threads) {
          if (thread.joinable()) {
            thread.join();
          }
        }
      }
    } gWarmup; // joined at exit
    std::atomic<int> gWarmupPending{0};
    std::atomic<int> gLitEffects{0}; // bit 0: the mesh effect in use has the light pass, bit 1: the terrain effect
    int gWarmupState = 0;            // 0 not started, 1 running, 2 done (the swap may go on)
    std::chrono::steady_clock::time_point gWarmupStarted;

    // The Options > Video entry of the lights (render features registry): Off / Low .. Ultra are ren_DynLights 0..4.
    // The effects are patched when they load; going from Off to a level rebuilds them once in the running game
    // (ApplyLiveLevel), the levels in between apply live. The effect patch and the light pass run on the Direct3D 11,
    // 12 and Vulkan backends (the Direct3D 10 effect dialect); Direct3D 9 has the first patch's lights in the
    // executable patch (its vs_1_1 / ps_2_0 techniques cannot host a ps_3_0 light loop), Direct3D 10 does not start.
    const bool gRegisteredFeature = [] {
      using render::Api;
      render::Feature feature;
      feature.key = "dynlights_quality";
      feature.title = "Dynamic Lights";
      feature.tip = "Explosions, fire, plasma, beams, trails and glowing buildings light the ground, the water and the "
                    "units around them, with shadows. Render only, never affects the game. "
                    "While it is on, the simpler Explosion and weapon lights option does nothing. "
                    "Turning it on the first time rebuilds the shaders (a fraction of a second on Direct3D 12 and "
                    "Vulkan; Direct3D 11 compiles them in the background for about half a minute first); every change "
                    "after that applies at once.";
      feature.console = "ren_DynLights";
      feature.states = {
        {"Off", "off"},
        {"Low (big explosions)", "low"},
        {"Medium", "medium"},
        {"High", "high"},
        {"Ultra (everything)", "ultra"}
      };
      feature.defaultLevel = 0;
      feature.needsRestart = false;
      feature.apis[static_cast<int>(Api::D3D9)].reason = "Direct3D 9 shaders cannot host the light field";
      feature.apis[static_cast<int>(Api::D3D10)].reason = "the Direct3D 10 renderer does not start";
      feature.apis[static_cast<int>(Api::D3D11)].supported = true;
      feature.apis[static_cast<int>(Api::D3D12)].supported = true;
      feature.apis[static_cast<int>(Api::Vulkan)].supported = true;
      feature.apply = [](const int level) {
        if (level > 0) {
          ren_DynLights = level;
        }
      };
      render::RegisterFeature(feature);
      return true;
    }();

    TConVar<int> gTConVar_ren_DynLightsShadows(
      "ren_DynLightsShadows",
      "Dynamic lights: 1 (the default) lets the buildings and units of the view shade the lights (a soft shadow behind "
      "them), 0 lights through "
      "everything.",
      &ren_DynLightsShadows
    );

    LightCollector gCollector;
    std::vector<Light> gFrameLights;
    LightGridImage gFrameImage;
    bool gGridMissing = false; // this frame's image has no cell table (the field carries the lights), see EnsureGrid
    int gLogCounter = 0;
    int gLastTick = -1; // tick of the last BeginFrame

    // Width and depth of the active map in world units; false when there is no map (front end, loading).
    bool ActiveMapSize(
      float& sizeX,
      float& sizeZ
    )
    {
      CWldSession* const session = WLD_GetActiveSession();
      if (session == nullptr) {
        return false;
      }
      const STIMap* const map = session->GetSTIMap();
      const CHeightField* const field = map != nullptr ? map->GetHeightField() : nullptr;
      if (field == nullptr || field->Width() < 2 || field->Height() < 2) {
        return false;
      }
      sizeX = static_cast<float>(field->Width() - 1);
      sizeZ = static_cast<float>(field->Height() - 1);
      return true;
    }
  } // namespace

  int ren_DynLightsShadows = 1;

  LightCollector& Collector()
  {
    return gCollector;
  }

  void SyncQuality()
  {
    if (gCollector.Quality() != ren_DynLights) {
      gCollector.SetQuality(ren_DynLights);
    }
  }

  void BeginFrame(
    const int tick,
    const float frameAlpha
  )
  {
    TrimTextureCache(); // between frames: no feed holds a texture of the cache now
    // A clock that jumped back is a new game: the lights of the old one must not wake up when the new one reaches their
    // birth tick.
    if (gLastTick >= 0 && tick + 20 < gLastTick) {
      gCollector.Clear();
    }
    gLastTick = tick;
    SyncQuality();
    if (gCollector.Quality() == model::kOff) {
      gpg::gal::gDynLightPassActive.store(false, std::memory_order_relaxed);
      if (!gFrameLights.empty() || gFrameImage.lightCount != 0) {
        gFrameLights.clear();
        gFrameImage.lightCount = 0; // the binding clears the textures once
        LightGridImage cleared;
        float sx = 0.0f, sz = 0.0f;
        if (ActiveMapSize(sx, sz)) {
          BuildLightGrid(gFrameLights, GridLayout::ForMap(sx, sz), cleared);
          gFrameImage = cleared;
          UpdateBinding(gFrameImage);
        }
      }
      return;
    }

    {
      const gpg::gal::RenderProfileScope profile("LightsFeed"); // render profile: the beams and trails of the frame
      FeedBeamsForFrame(tick, frameAlpha);
    }
    {
      const gpg::gal::RenderProfileScope profile("LightsCollect"); // the pool of the frame, strongest first
      gCollector.Update(static_cast<float>(tick) + frameAlpha, kMaxFrameLights, gFrameLights);
    }
    if (ren_DynLightsGain != 100) {
      const float gain = 0.01f * static_cast<float>(std::min(std::max(ren_DynLightsGain, 0), 1000));
      for (Light& l : gFrameLights) {
        l.rgb[0] *= gain;
        l.rgb[1] *= gain;
        l.rgb[2] *= gain;
      }
    }

    float mapX = 0.0f, mapZ = 0.0f;
    gGridMissing = false;
    if (ActiveMapSize(mapX, mapZ)) {
      // The irradiance field (ren_DynLightsMode 1) reads the light data and the casters only; the cell table and lists
      // of the grid, the greater part of the CPU work here and the whole of the grid texture's upload, are for the
      // shaders' grid path. They are made in SetView when the field is not run this frame (see EnsureGrid).
      const bool cells = ren_DynLightsMode != 1 || ren_DynLightsView != 0; // the debug view draws the grid
      gGridMissing = !cells;
      {
        const gpg::gal::RenderProfileScope profile("LightsGrid"); // the light grid and the light data of the frame
        BuildLightGrid(
          gFrameLights,
          GridLayout::ForMap(mapX, mapZ),
          gFrameImage,
          ren_DynLightsShadows != 0 ? &FrameOccluders() : nullptr,
          cells
        );
      }
      const gpg::gal::RenderProfileScope profile("LightsUpload"); // their textures
      UpdateBinding(gFrameImage, cells);
    }
    gpg::gal::gDynLightPassActive.store(gFrameImage.lightCount > 0, std::memory_order_relaxed);
    CensusFrame();

    if (ren_DynLightsLog > 0 && ++gLogCounter >= ren_DynLightsLog) {
      gLogCounter = 0;
      // FAF_DYNLIGHT_DUMP=1 (diagnostics): one line per light of the frame, for tools that group the lights by place
      // (tests/featab)
      static const bool dumpAll = [] {
        const char* const value = std::getenv("FAF_DYNLIGHT_DUMP");
        return value != nullptr && value[0] != '\0' && value[0] != '0';
      }();
      if (dumpAll) {
        for (const Light& l : gFrameLights) {
          gpg::Logf(
            "DYNLIGHT-DUMP %d %.1f %.1f %.1f %.2f %.3f %.3f %.3f %.0f T%d",
            static_cast<int>(l.kind),
            l.pos[0],
            l.pos[1],
            l.pos[2],
            l.radius,
            l.rgb[0],
            l.rgb[1],
            l.rgb[2],
            l.power,
            static_cast<int>(tick)
          );
        }
      }
      for (std::size_t i = 0; i < gFrameLights.size() && i < 4; ++i) {
        const Light& l = gFrameLights[i];
        gpg::Logf(
          "DynLights:   light %u kind=%d pos=(%.1f %.1f %.1f) radius=%.1f rgb=(%.3f %.3f %.3f) power=%.2f",
          static_cast<unsigned>(i),
          static_cast<int>(l.kind),
          l.pos[0],
          l.pos[1],
          l.pos[2],
          l.radius,
          l.rgb[0],
          l.rgb[1],
          l.rgb[2],
          l.power
        );
      }
      {
        // strength by kind: how many lights, their colour x intensity at the centre (mean / strongest) and radius, and
        // the flux (sum of the brightest channel x radius squared), to see which kind dominates a scene
        static const char* const kKindNames[] = {"flash", "glow", "beam", "trail", "mesh", "spot"};
        unsigned count[6] = {};
        double sumPeak[6] = {}, sumRadius[6] = {}, flux[6] = {};
        float maxPeak[6] = {};
        for (const Light& l : gFrameLights) {
          const int k = static_cast<int>(l.kind);
          if (k < 0 || k >= 6) {
            continue;
          }
          const float peak = std::max(l.rgb[0], std::max(l.rgb[1], l.rgb[2]));
          ++count[k];
          sumPeak[k] += peak;
          sumRadius[k] += l.radius;
          flux[k] += static_cast<double>(peak) * l.radius * l.radius;
          maxPeak[k] = std::max(maxPeak[k], peak);
        }
        for (int k = 0; k < 6; ++k) {
          if (count[k] > 0) {
            gpg::Logf(
              "DynLights: kind %s n=%u peak mean %.3f max %.3f radius mean %.1f flux %.0f",
              kKindNames[k],
              count[k],
              sumPeak[k] / count[k],
              maxPeak[k],
              sumRadius[k] / count[k],
              flux[k]
            );
          }
        }
      }
      const Stats& s = gCollector.GetStats();
      gpg::Logf(
        "DynLights: quality=%d stored=%u offered=%u gated=%u invalid=%u full=%u expired=%u | pool=%u active=%u "
        "lights=%u cut=%u | "
        "grid cells=%u overflow=%u occluders=%u/%u | tex uploads=%u fail=%u vars=%u",
        gCollector.Quality(),
        s.stored,
        s.offered,
        s.gated,
        s.invalid,
        s.poolFull,
        s.expired,
        static_cast<unsigned>(gCollector.Stored()),
        s.active,
        static_cast<unsigned>(gFrameLights.size()),
        s.culledByCap,
        gFrameImage.cellsLit,
        gFrameImage.overflow,
        gFrameImage.occluderCount,
        static_cast<unsigned>(FrameOccluders().size()),
        GetBindingStats().uploads,
        GetBindingStats().failures,
        GetBindingStats().boundVariables
      );
    }
  }

  namespace
  {
    // The frame's lights were built without the grid (the field was to carry them): when the field is not valid, the
    // shaders take the grid path, so it is made now, from the same lights, before anything is drawn with it.
    void EnsureGrid()
    {
      if (!gGridMissing || CurrentField().valid) {
        return;
      }
      float mapX = 0.0f, mapZ = 0.0f;
      if (!ActiveMapSize(mapX, mapZ)) {
        return;
      }
      gGridMissing = false;
      {
        const gpg::gal::RenderProfileScope profile("LightsGrid");
        BuildLightGrid(
          gFrameLights,
          GridLayout::ForMap(mapX, mapZ),
          gFrameImage,
          ren_DynLightsShadows != 0 ? &FrameOccluders() : nullptr
        );
      }
      const gpg::gal::RenderProfileScope profile("LightsUpload");
      UpdateBinding(gFrameImage);
    }
  } // namespace

  void SetView(
    GeomCamera3& camera
  )
  {
    if (gCollector.Quality() == model::kOff) {
      return;
    }
    const Wm3::Vec3f& eye = camera.tranform.pos_;
    SetCameraPosition(eye.x, eye.y, eye.z);

    // The irradiance field (docs/LIGHTING_V2.md): lit once for the view; the shaders fall back to the grid when it is
    // off or has no lights. Only the big world view builds it: the minimap and the other small views render too, and
    // each would move the field to its own camera.
    if (camera.viewport.r[3].z * camera.viewport.r[3].w >= 200000.0f) {
      CWldSession* const session = WLD_GetActiveSession();
      const STIMap* const map = session != nullptr ? session->GetSTIMap() : nullptr;
      const CHeightField* const heightField = map != nullptr ? map->GetHeightField() : nullptr;
      FieldTerrain terrain;
      if (heightField != nullptr) {
        terrain.context = heightField;
        terrain.elevation = [](const void* context, const float x, const float z) {
          const auto* const field = static_cast<const CHeightField*>(context);
          const float cx = std::min(std::max(x, 0.0f), static_cast<float>(field->Width() - 1));
          const float cz = std::min(std::max(z, 0.0f), static_cast<float>(field->Height() - 1));
          return field->GetElevation(cx, cz);
        };
        terrain.sample = [](const void* context, const std::int32_t x, const std::int32_t z) {
          return static_cast<const CHeightField*>(context)->GetHeightAt(x, z);
        };
        terrain.width = static_cast<std::uint32_t>(heightField->Width());
        terrain.height = static_cast<std::uint32_t>(heightField->Height());
        terrain.revision = HeightFieldRevision();
        terrain.waterEnabled = map->IsWaterEnabled();
        terrain.waterElevation = map->GetWaterElevation();
        // A map with water bodies has a level per water: the field reads the level of each block (the same blocks the
        // water is drawn from, WaterOfBlock). Without bodies the generation is 0 and the one sea level above stands.
        terrain.waterGeneration = ren_DynLightsWaterLevels != 0 ? WaterBodiesGeneration(*map) : 0U;
        if (terrain.waterGeneration != 0U) {
          terrain.waterContext = map;
          terrain.waterLevel = [](const void* context, const std::int32_t x, const std::int32_t z) {
            return WaterOfBlock(*static_cast<const STIMap*>(context), x, z).level;
          };
        }
        if (const IWldTerrainRes* const terrainRes = REN_GetTerrainRes()) {
          const Wm3::Vector3f sun = terrainRes->GetSunDirection();
          const float length = std::sqrt(sun.x * sun.x + sun.y * sun.y + sun.z * sun.z);
          if (length > 0.0001f) {
            terrain.sunDirection[0] = sun.x / length;
            terrain.sunDirection[1] = sun.y / length;
            terrain.sunDirection[2] = sun.z / length;
            terrain.sunValid = true;
          }
        }
      }
      (void)UpdateField(camera, gFrameImage, terrain);
      BindField(CurrentField());
    }
    EnsureGrid();

    // test light: the point where the ray through the middle of the view meets the ground
    static int sLastTestTick = -1;
    if (ren_DynLightsTest > 0 && gLastTick >= 0 && gLastTick != sLastTestTick && (gLastTick % ren_DynLightsTest) == 0) {
      sLastTestTick = gLastTick;
      CWldSession* const session = WLD_GetActiveSession();
      const STIMap* const map = session != nullptr ? session->GetSTIMap() : nullptr;
      const CHeightField* const field = map != nullptr ? map->GetHeightField() : nullptr;
      if (field != nullptr) {
        const float w = camera.viewport.r[3].z;
        const float h = camera.viewport.r[3].w;
        const GeomLine3 ray = camera.Unproject(Wm3::Vector2f(w * 0.5f, h * 0.5f));
        for (float t = 1.0f; t < 6000.0f; t += 3.0f) {
          const float x = ray.pos.x + ray.dir.x * t;
          const float y = ray.pos.y + ray.dir.y * t;
          const float z = ray.pos.z + ray.dir.z * t;
          const float ground = field->GetElevation(x, z);
          if (y <= ground) {
            Emission e;
            e.kind = Kind::Flash;
            e.pos[0] = x;
            // 6 units over the ground, or over the water that covers it (the level of the block, a map with water
            // bodies has one per water)
            const SWaterOfBlock water =
              WaterOfBlock(*map, static_cast<std::int32_t>(x) & ~1, static_cast<std::int32_t>(z) & ~1);
            e.pos[1] = std::max(ground, water.level) + 6.0f;
            e.pos[2] = z;
            e.birth = static_cast<float>(gLastTick);
            e.life = 20.0f;
            e.size0 = 18.0f;
            e.size1 = 18.0f;
            e.rgb[0] = 1.0f;
            e.rgb[1] = 0.6f;
            e.rgb[2] = 0.25f;
            (void)gCollector.Add(e);
            break;
          }
        }
      }
    }
  }

  const std::vector<Light>& FrameLights()
  {
    return gFrameLights;
  }

  const LightGridImage& FrameImage()
  {
    return gFrameImage;
  }
} // namespace moho::lights

namespace moho::lights
{
  bool LightsWanted(
    const gpg::gal::DeviceApi api
  )
  {
    // Read live: the option (or ren_DynLights) can be switched on in a running game, and ApplyLiveLevel then rebuilds
    // the effects. The answer of the last call is what the effects in use were built with.
    const bool wanted = ren_DynLights > 0 || render::FeatureLevel("dynlights_quality", render::ApiFromDevice(api)) > 0;
    if (!tWarmupThread) {
      gEffectsBuiltLit = wanted;
    }
    return wanted;
  }

  bool Enabled()
  {
    return ren_DynLights > 0 && gLitEffects.load(std::memory_order_relaxed) != 0;
  }

  void NoteEffectPatched(
    const std::string& baseName,
    const bool patched
  )
  {
    if (tWarmupThread) {
      return;
    }
    const int bit = baseName == "mesh" ? 1 : (baseName == "terrain" ? 2 : 0);
    if (bit == 0) {
      return;
    }
    if (patched) {
      gLitEffects.fetch_or(bit, std::memory_order_relaxed);
    } else {
      gLitEffects.fetch_and(~bit, std::memory_order_relaxed);
    }
  }

  bool ApplyLiveLevel()
  {
    if (ren_DynLights <= 0 || gEffectsBuiltLit) {
      return false;
    }
    if (CFG_GetArgOption("/dynlights", 0U, nullptr)) {
      gEffectsBuiltLit = true; // /dynlights builds the effects lit whatever the option says
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
    const render::Feature* const feature = render::FindFeature("dynlights_quality");
    if (
      context == nullptr || feature == nullptr || !gpg::gal::UsesD3D10EffectDialect(context->mDeviceType) ||
      !render::Supported(*feature, render::ApiFromDevice(context->mDeviceType))
    ) {
      gEffectsBuiltLit = true; // nothing to rebuild on this API: do not look again
      return false;
    }
    CD3DDevice* const d3dDevice = D3D_GetDevice();
    ID3DDeviceResources* const resources = d3dDevice != nullptr ? d3dDevice->GetResources() : nullptr;
    if (resources == nullptr) {
      return false;
    }
    auto* const deviceResources = static_cast<CD3DDeviceResources*>(resources);
    if (context->mDeviceType == gpg::gal::DeviceApi::Direct3D11 && gWarmupState < 2) {
      if (gWarmupState == 0) {
        std::vector<std::string> paths;
        for (const char* const name : {"mesh", "terrain", "water2"}) {
          if (CD3DEffect* const effect = deviceResources->FindEffect(name)) {
            paths.emplace_back(effect->mFile.c_str());
          }
        }
        gWarmupStarted = std::chrono::steady_clock::now();
        gWarmupState = 1;
        gWarmupPending = static_cast<int>(paths.size());
        for (const std::string& path : paths) {
          gWarmup.threads.emplace_back([path] {
            tWarmupThread = true;
            try {
              CD3DEffect compiled;
              (void)compiled.InitEffectFromFile(path.c_str());
            } catch (...) {
              gpg::Warnf("DynLights: the background compile of %s failed", path.c_str());
            }
            --gWarmupPending;
          });
        }
        gpg::Logf(
          "DynLights: switched on, compiling the lit effects in the background (%d)", static_cast<int>(paths.size())
        );
        if (paths.empty()) {
          gWarmupState = 2;
        }
      }
      if (gWarmupState == 1) {
        if (gWarmupPending > 0) {
          return false; // the game goes on with the effects it has
        }
        for (std::thread& thread : gWarmup.threads) {
          thread.join();
        }
        gWarmup.threads.clear();
        gWarmupState = 2;
        gpg::Logf(
          "DynLights: the background compile took %.1f s",
          std::chrono::duration<double>(std::chrono::steady_clock::now() - gWarmupStarted).count()
        );
      }
    }
    const auto started = std::chrono::steady_clock::now();
    gEffectsBuiltLit =
      true; // set first: the rebuilds below ask LightsWanted again, and a failed rebuild must not repeat every frame
    int rebuilt = 0;
    for (const char* const name : {"mesh", "terrain", "water2"}) {
      if (deviceResources->ReloadEffectNamed(name)) {
        ++rebuilt;
      } else {
        gpg::Warnf("DynLights: %s could not be rebuilt with the light pass", name);
      }
    }
    gpg::Logf(
      "DynLights: switched on in the running game, %d effects rebuilt in %.0f ms",
      rebuilt,
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count()
    );
    return rebuilt > 0;
  }
} // namespace moho::lights

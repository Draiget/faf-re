#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "gpg/core/utils/Logging.h"
#include "moho/math/QuaternionMath.h"
#include "moho/mesh/Mesh.h"
#include "moho/mesh/MeshBatchKey.h"
#include "moho/render/lights/LightCensus.h"
#include "moho/render/lights/LightFeeds.h"
#include "moho/render/lights/LightMeshEmission.h"
#include "moho/render/lights/LightTextureCache.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/SScmFile.h"
#include "platform/PlatformDefines.h"

// The unit and projectile meshes that glow (docs/DYNAMIC_LIGHTS.md, "Sources of light"): the glow of a mesh is read
// from its albedo and specular maps the way its pixel shader reads them (LightMeshEmission.h), once per mesh LOD; every
// visible instance of a glowing LOD is one light at the centre of the instance's bounding sphere, in the colour of the
// glow (the army colour where the army colour glows).
namespace moho::lights
{
  namespace
  {
    constexpr std::uint64_t kKeyMesh = 5ull << 40;
    constexpr float kHoldTicks = 3.0f;
    constexpr std::size_t kMaxMeshLights = 512; // per frame, the instances on screen are many more

    struct LodGlow
    {
      bool analysed = false;
      MeshGlow glow;
      float intensity = 0.0f;
    };

    std::unordered_map<std::string, LodGlow> gGlow; // keyed by albedo | specular | shader
    std::vector<Occluder> gOccluders;
    constexpr std::size_t kMaxFrameOccluders = 4096;
    constexpr float kBoxGrow =
      1.25f; // the engine's box is tighter than the model (thin parts, turrets, legs): the shadow is of the whole unit

    // The material of a bucket draws into the sun shadow map: the render stage has the depth bit and a depth technique
    // is defined, the gate of MeshRenderer::RenderDepth. Both are cached on the material the first time it is drawn, so
    // a material nobody has drawn yet is no caster.
    std::uint32_t gCasterReasons[5] = {}; // diagnostics: buckets that cast, no render stage yet, no depth bit, depth
                                          // technique not resolved, no depth technique

    bool ReadNames(const RMeshBlueprintLOD& lod, char (&albedo)[260], char (&specular)[260], char (&shader)[64]);

    // Wreckage is a crowd of small low boxes after a fight: it shades nothing worth the room in the cells' caster lists
    // (a full list is cut differently in each cell and draws lit squares).
    bool IsWreckage(
      const MeshLOD& lod
    )
    {
      const RMeshBlueprintLOD* const blueprintLod = lod.lodBlueprintCopy.get();
      const auto value = reinterpret_cast<std::uintptr_t>(blueprintLod);
      if (value < 0x10000u || value == ~static_cast<std::uintptr_t>(0)) {
        return false;
      }
      char albedo[260] = {};
      char specular[260] = {};
      char shader[64] = {};
      if (!ReadNames(*blueprintLod, albedo, specular, shader)) {
        return false;
      }
      for (char* c = shader; *c != 0; ++c) {
        *c = static_cast<char>(std::tolower(static_cast<unsigned char>(*c)));
      }
      return std::strstr(shader, "wreck") != nullptr;
    }

    bool CastsShadows(
      const MeshLOD& lod
    )
    {
      const MeshMaterial& material = lod.mat;
      if (material.mShaderIndex < 0) {
        ++gCasterReasons[1];
        return false;
      }
      if ((material.mShaderIndex & 1) == 0) {
        ++gCasterReasons[2];
        return false;
      }
      if (!material.mDepthTechniqueResolved) {
        ++gCasterReasons[3];
        return false;
      }
      if (material.mDepthTechnique.size() == 0) {
        ++gCasterReasons[4];
        return false;
      }
      ++gCasterReasons[0];
      return true;
    }

    // The oriented box of an instance as an occluder. The box is the engine's (MeshInstance::box, from the mesh
    // resource's own bounds); a box that is not finite, not positive, or far from the instance's sphere is replaced by
    // a box inside the sphere.
    std::uint32_t gInstanceReasons[5] =
      {}; // diagnostics: taken, hidden, dissolved, radius out of range, box replaced by the fallback

    void AddOccluder(
      const MeshInstance& instance
    )
    {
      if (instance.isHidden != 0) {
        ++gInstanceReasons[1];
        return;
      }
      if (instance.dissolve < 0.6f || gOccluders.size() >= kMaxFrameOccluders) {
        ++gInstanceReasons[2];
        return;
      }
      const float radius = instance.sphere.Radius;
      if (
        !std::isfinite(radius) || !(radius > 0.3f) || radius > 40.0f || !std::isfinite(instance.sphere.Center.x) ||
        !std::isfinite(instance.sphere.Center.z)
      ) {
        ++gInstanceReasons[3];
        return;
      }
      ++gInstanceReasons[0];
      Occluder o;
      bool boxOk =
        true; // boundsValid is 0 on every instance seen, and the box (centre, extents, axes) is right all the same
      for (int i = 0; i < 3 && boxOk; ++i) {
        const float extent = instance.box.Extent[i];
        boxOk = std::isfinite(extent) && extent > 0.02f && extent <= radius * 1.5f;
      }
      if (boxOk) {
        const float dx = instance.box.Center[0] - instance.sphere.Center.x;
        const float dy = instance.box.Center[1] - instance.sphere.Center.y;
        const float dz = instance.box.Center[2] - instance.sphere.Center.z;
        boxOk = std::isfinite(dx) && std::isfinite(dy) && std::isfinite(dz) &&
          dx * dx + dy * dy + dz * dz <= radius * radius * 2.25f;
      }
      if (boxOk) {
        for (int i = 0; i < 3; ++i) {
          o.center[i] = instance.box.Center[i];
          for (int k = 0; k < 3; ++k) {
            o.axis[i][k] = instance.box.Axis[i][k] * instance.box.Extent[i] * kBoxGrow;
          }
        }
      } else {
        ++gInstanceReasons[4];
        o.center[0] = instance.sphere.Center.x;
        o.center[1] = instance.sphere.Center.y;
        o.center[2] = instance.sphere.Center.z;
        for (int i = 0; i < 3; ++i) {
          o.axis[i][i] = radius * 0.55f;
        }
      }
      gOccluders.push_back(o);
    }

    // Copies the three names out of a blueprint LOD. Not every LOD the renderer batches has a blueprint behind it (the
    // engine makes some LODs itself, for shields and the like) and such a record can hold anything, so the read is
    // guarded where the platform has structured exception handling: false when it faults. No C++ objects with
    // destructors in this function (structured exception handling).
    bool ReadNames(
      const RMeshBlueprintLOD& lod,
      char (&albedo)[260],
      char (&specular)[260],
      char (&shader)[64]
    )
    {
#if FAFRE_PLATFORM_WINDOWS
      __try {
        std::strncpy(albedo, lod.mAlbedoName.c_str(), sizeof(albedo) - 1);
        std::strncpy(specular, lod.mSpecularName.c_str(), sizeof(specular) - 1);
        std::strncpy(shader, lod.mShaderName.c_str(), sizeof(shader) - 1);
        return true;
      } __except (1 /* EXCEPTION_EXECUTE_HANDLER */) {
        return false;
      }
#else
      // no structured exception handling on this target: the read is not guarded
      std::strncpy(albedo, lod.mAlbedoName.c_str(), sizeof(albedo) - 1);
      std::strncpy(specular, lod.mSpecularName.c_str(), sizeof(specular) - 1);
      std::strncpy(shader, lod.mShaderName.c_str(), sizeof(shader) - 1);
      return true;
#endif
    }

    const LodGlow& GlowOf(
      const RMeshBlueprintLOD& lod
    )
    {
      static const LodGlow kNone{};
      char albedoBuffer[260] = {};
      char specularBuffer[260] = {};
      char shaderBuffer[64] = {};
      if (!ReadNames(lod, albedoBuffer, specularBuffer, shaderBuffer)) {
        return kNone;
      }
      const std::string albedo(albedoBuffer);
      const std::string specular(specularBuffer);
      const std::string shader(shaderBuffer);
      const std::string key = albedo + "|" + specular + "|" + shader;
      LodGlow& entry = gGlow[key];
      if (entry.analysed) {
        return entry;
      }
      if (!TextureBudgetLeft()) {
        return kNone; // not analysed: the next frame asks again
      }
      // The textures are read on a worker thread: while one is pending the mesh has no glow (kNone) and the next frame
      // asks again.
      const TexEntry* albedoTexture = nullptr;
      if (FindTexture(albedo, albedoTexture) == TextureState::Pending) {
        return kNone;
      }
      if (albedoTexture == nullptr) {
        entry.analysed = true;
        return entry;
      }
      const TexEntry* specularTexture = nullptr;
      if (!specular.empty() && FindTexture(specular, specularTexture) == TextureState::Pending) {
        return kNone;
      }
      entry.analysed = true;
      // A unit whose mesh has a shield-named material (the UEF Titan: PhaseShield) is a unit: the shield bubble draws
      // with an effect texture, not with the albedo of a unit. The name alone made the Titan lightless.
      std::string ruleShader = shader;
      {
        std::string lowerShader = shader;
        std::string lowerAlbedo = albedo;
        for (char& c : lowerShader) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        for (char& c : lowerAlbedo) {
          c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (lowerShader.find("shield") != std::string::npos && lowerAlbedo.rfind("/units/", 0) == 0) {
          ruleShader = "Unit";
        }
      }
      const auto analysisStart = std::chrono::steady_clock::now();
      entry.glow = AnalyseMeshGlow(
        albedoTexture->image, specularTexture != nullptr ? &specularTexture->image : nullptr, ruleShader
      );
      NoteTextureWork(
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - analysisStart).count()
      );
      entry.intensity = MeshLightIntensity(entry.glow);
      static int sLogBudget = 150;
      if (sLogBudget > 0) {
        --sLogBudget;
        gpg::Logf(
          "DynLights: mesh LOD shader=%s albedo=%s%s specular=%s%s: glow area=%.3f team=%.2f hue=(%.2f %.2f %.2f) -> "
          "intensity %.3f",
          shader.c_str(),
          albedo.c_str(),
          albedoTexture != nullptr ? "" : " (unreadable)",
          specular.c_str(),
          specular.empty() ? " (none)" : (specularTexture != nullptr ? "" : " (unreadable)"),
          entry.glow.area,
          entry.glow.teamShare,
          entry.glow.hue[0],
          entry.glow.hue[1],
          entry.glow.hue[2],
          entry.intensity
        );
      }
      return entry;
    }
  } // namespace

  void FeedMeshes(
    const float nowTick
  )
  {
    if (gGlow.size() > 4096) {
      gGlow.clear(); // between uses: GlowOf hands out references into the map
    }
    SyncQuality();
    LightCollector& collector = Collector();
    if (collector.Quality() == model::kOff) {
      return;
    }
    MeshRenderer* const renderer = MeshRenderer::GetInstance();
    if (renderer == nullptr) {
      return;
    }

    std::size_t emitted = 0;
    static int sFrame = 0;
    gOccluders.clear();
    for (std::uint32_t& n : gCasterReasons) {
      n = 0;
    }
    for (std::uint32_t& n : gInstanceReasons) {
      n = 0;
    }
    const bool shadows = ren_DynLightsShadows != 0;
    for (const MeshBatchBucket& bucket : renderer->meshes) {
      MeshLOD* const lod = bucket.first.mLod;
      // MeshRenderer::Batch stores Mesh::ComputeLOD's result in the key, and that is -1 (all bits set) for an instance
      // that is too far for every LOD: not a pointer, not drawn.
      const auto lodValue = reinterpret_cast<std::uintptr_t>(lod);
      if (lodValue < 0x10000u || lodValue == ~static_cast<std::uintptr_t>(0)) {
        continue;
      }
      if (shadows && CastsShadows(*lod) && !IsWreckage(*lod)) {
        for (const MeshInstance* const instance : bucket.second) {
          if (instance != nullptr) {
            AddOccluder(*instance);
          }
        }
      }
      // the LOD's blueprint copy can be a marker too (LODs the engine makes itself, shields): only a plausible address
      // is used
      const RMeshBlueprintLOD* const blueprintLod = lod->lodBlueprintCopy.get();
      const auto blueprintValue = reinterpret_cast<std::uintptr_t>(blueprintLod);
      if (blueprintValue < 0x10000u || blueprintValue == ~static_cast<std::uintptr_t>(0)) {
        continue;
      }
      const LodGlow glowCopy = GlowOf(*blueprintLod);
      if (CensusEnabled()) {
        char albedo[260] = {};
        char specular[260] = {};
        char shader[64] = {};
        if (ReadNames(*blueprintLod, albedo, specular, shader)) {
          TextureColour c;
          c.valid = true;
          c.peak = glowCopy.glow.area;
          c.hue[0] = glowCopy.glow.hue[0];
          c.hue[1] = glowCopy.glow.hue[1];
          c.hue[2] = glowCopy.glow.hue[2];
          c.brightness = glowCopy.glow.teamShare;
          const std::string key = std::string("shader=") + shader + " albedo=" + albedo + " spec=" + specular;
          for (std::size_t i = 0; i < bucket.second.size(); ++i) {
            CensusNote("mesh", key, glowCopy.intensity > 0.0f ? "ok:glowing unit" : "no:no glow (area 0)", 0.0f, &c);
          }
        }
      }
      if (glowCopy.intensity <= 0.0f) {
        continue;
      }
      for (const MeshInstance* const instance : bucket.second) {
        if (instance == nullptr || instance->isHidden != 0 || emitted >= kMaxMeshLights) {
          continue;
        }
        const float radius = instance->sphere.Radius;
        if (!std::isfinite(instance->sphere.Center.x) || !std::isfinite(radius)) {
          continue;
        }

        // The colour: the albedo hue of the glowing parts, and the army colour for the share of the glow that is the
        // army colour. The instance colour is the army colour packed as ARGB; -1 (props, projectiles) has no army.
        float rgb[3] = {glowCopy.glow.hue[0], glowCopy.glow.hue[1], glowCopy.glow.hue[2]};
        if (glowCopy.glow.teamShare > 0.0f && instance->color != -1) {
          const auto packed = static_cast<std::uint32_t>(instance->color);
          const float team[3] = {
            static_cast<float>((packed >> 16) & 0xFF) / 255.0f,
            static_cast<float>((packed >> 8) & 0xFF) / 255.0f,
            static_cast<float>(packed & 0xFF) / 255.0f
          };
          const float s = glowCopy.glow.teamShare;
          for (int c = 0; c < 3; ++c) {
            rgb[c] = rgb[c] * (1.0f - s) + team[c] * s;
          }
        }
        const float top = std::max(rgb[0], std::max(rgb[1], rgb[2]));
        if (top > 1.0e-4f) {
          for (float& c : rgb) {
            c /= top;
          }
        }
        ReduceWhite(rgb, 0.5f); // a glow is coloured at its edge and white-hot in its core: the light has the colour

        Emission e;
        e.kind = Kind::Mesh;
        e.pos[0] = instance->sphere.Center.x;
        e.pos[1] = instance->sphere.Center.y;
        e.pos[2] = instance->sphere.Center.z;
        e.rgb[0] = rgb[0];
        e.rgb[1] = rgb[1];
        e.rgb[2] = rgb[2];
        e.radius = MeshLightRadius(radius, glowCopy.glow.effect ? kMaxEffectLightRadius : kMaxUnitLightRadius);
        e.intensity = glowCopy.intensity *
          std::min(
                        1.0f, std::max(0.0f, instance->dissolve)
          ); // MeshInstance::dissolve is 1 for a solid mesh, 0 for one that has dissolved away
        const std::uint64_t key = kKeyMesh | (reinterpret_cast<std::uintptr_t>(instance) & 0xFFFFFFFFFFull);
        if (collector.Track(key, e, nowTick, kHoldTicks)) {
          ++emitted;
        }
      }
    }
    if ((++sFrame % 240) == 1) {
      gpg::Logf(
        "DynLights: %u mesh lights, %u shadow casters this frame; buckets: cast %u, no stage %u, no depth bit %u, "
        "unresolved %u, no technique %u",
        static_cast<unsigned>(emitted),
        static_cast<unsigned>(gOccluders.size()),
        gCasterReasons[0],
        gCasterReasons[1],
        gCasterReasons[2],
        gCasterReasons[3],
        gCasterReasons[4]
      );
      for (std::size_t i = 0; i < gOccluders.size() && i < 3; ++i) {
        const Occluder& o = gOccluders[i];
        gpg::Logf(
          "DynLights:   caster %u centre (%.1f %.1f %.1f) half extents (%.2f %.2f %.2f)",
          static_cast<unsigned>(i),
          o.center[0],
          o.center[1],
          o.center[2],
          std::sqrt(o.axis[0][0] * o.axis[0][0] + o.axis[0][1] * o.axis[0][1] + o.axis[0][2] * o.axis[0][2]),
          std::sqrt(o.axis[1][0] * o.axis[1][0] + o.axis[1][1] * o.axis[1][1] + o.axis[1][2] * o.axis[1][2]),
          std::sqrt(o.axis[2][0] * o.axis[2][0] + o.axis[2][1] * o.axis[2][1] + o.axis[2][2] * o.axis[2][2])
        );
      }
    }
  }

  const std::vector<Occluder>& FrameOccluders()
  {
    return gOccluders;
  }
} // namespace moho::lights

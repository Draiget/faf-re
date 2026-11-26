#include "moho/render/lights/LightMeshEmission.h"

#include <algorithm>
#include <cmath>
#include <string>

namespace moho::lights
{
  namespace
  {
    enum class Rule
    {
      Uef,
      Aeon,
      Cybran,
      Seraphim,
      Glow, // meshes made to glow as a whole: projectile and effect meshes (TMeshGlow, NormalMappedGlow ...)
      Nuke, // the fireball meshes of strategic missile detonations (NukeUEF, NukeEMP, NukeQuantum): procedural fire,
            // the whole mesh is the light
      ShieldImpact, // the flash of a hit on a shield (ShieldImpact, CybranShieldImpact)
      Build, // a unit being built draws with the faction's build shader (AeonBuild, UEFBuildCube, CybranBuildOverlay
             // ...): a glowing scan, in the colour of the faction
      Legacy
    };

    Rule RuleFor(
      const std::string_view shader
    )
    {
      std::string s(shader);
      for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      // effect meshes that are light by themselves, before the shield rule below takes every name with "shield" in it
      if (s.rfind("nuke", 0) == 0) {
        return Rule::Nuke;
      }
      if (s.find("shieldimpact") != std::string::npos) {
        return Rule::ShieldImpact;
      }
      if (s.find("build") != std::string::npos) {
        return Rule::Build;
      }
      // the shield bubble of a unit draws with the unit's own textures (AeonPhaseShield ...): the bubble is not the
      // unit
      if (s.find("shield") != std::string::npos) {
        return Rule::Legacy;
      }
      // a mesh whose shader says it glows
      if (s.find("glow") != std::string::npos) {
        return Rule::Glow;
      }
      // the shader names of the unit techniques (mesh.fx: Unit, Insect, Aeon, AeonCZAR, Seraphim, and the navy and
      // other variants)
      if (s.rfind("aeon", 0) == 0) {
        return Rule::Aeon;
      }
      if (s.rfind("seraphim", 0) == 0) {
        return Rule::Seraphim;
      }
      if (s.rfind("insect", 0) == 0 || s.rfind("cybran", 0) == 0) {
        return Rule::Cybran;
      }
      if (s == "unit" || s.rfind("uef", 0) == 0 || s.rfind("nomads", 0) == 0) {
        return Rule::Uef;
      }
      return Rule::Legacy;
    }

    float Saturate(
      const float v
    )
    {
      return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
    }

    void Texel(
      const Rgba8Image& image,
      const float u,
      const float v,
      float (&rgba)[4]
    )
    {
      const std::uint32_t x =
        std::min(image.width - 1, static_cast<std::uint32_t>(Saturate(u) * static_cast<float>(image.width)));
      const std::uint32_t y =
        std::min(image.height - 1, static_cast<std::uint32_t>(Saturate(v) * static_cast<float>(image.height)));
      const std::uint8_t* p = &image.rgba[(static_cast<std::size_t>(y) * image.width + x) * 4];
      for (int c = 0; c < 4; ++c) {
        rgba[c] = p[c] / 255.0f;
      }
    }

    bool Usable(
      const Rgba8Image& image
    )
    {
      return image.width > 0 && image.height > 0 &&
        image.rgba.size() >= static_cast<std::size_t>(image.width) * image.height * 4;
    }
  } // namespace

  MeshGlow AnalyseMeshGlow(
    const Rgba8Image& albedo,
    const Rgba8Image* const specular,
    const std::string_view shader
  )
  {
    MeshGlow out;
    if (!Usable(albedo)) {
      return out;
    }
    const bool haveSpec = specular != nullptr && Usable(*specular);
    const Rule rule = RuleFor(shader);

    constexpr std::uint32_t kSamples =
      64; // the analysis grid: 64 x 64 texels of the albedo and the specular map, by texture coordinate
    double sumEmission = 0.0;
    double sumTeam = 0.0;
    double sumHue[3] = {0.0, 0.0, 0.0};
    double sumHueWeight = 0.0;
    for (std::uint32_t sy = 0; sy < kSamples; ++sy) {
      for (std::uint32_t sx = 0; sx < kSamples; ++sx) {
        const float u = (static_cast<float>(sx) + 0.5f) / static_cast<float>(kSamples);
        const float v = (static_cast<float>(sy) + 0.5f) / static_cast<float>(kSamples);
        float a[4];
        float s[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        Texel(albedo, u, v, a);
        if (haveSpec) {
          Texel(*specular, u, v, s);
        }

        float emission = 0.0f; // the glow that has the albedo's colour
        float team = 0.0f;     // the glow that has the army colour
        switch (rule) {
        case Rule::Uef:
          emission = s[2] * 0.8f;
          break;
        case Rule::Aeon:
          emission = s[2];
          team = s[3] * 0.5f;
          break;
        case Rule::Cybran:
          emission = std::sqrt(std::max(s[2] - 0.04f, 0.0f));
          break;
        case Rule::Seraphim: {
          emission = Saturate(s[2] - 0.1f);
          team = a[3];
          const float bright = std::max(Saturate(a[0] - 0.4f), std::max(Saturate(a[1] - 0.4f), Saturate(a[2] - 0.4f)));
          emission += bright * 1.5f;
          break;
        }
        case Rule::Glow:
          emission = std::max(a[0], std::max(a[1], a[2])); // the whole surface glows, as bright as its albedo
          break;
        case Rule::Nuke:
          emission = 1.0f; // procedural fire: every texel of the mesh burns, in the colour of its albedo
          break;
        case Rule::ShieldImpact:
          emission = 0.5f;
          break;
        case Rule::Build:
          emission = 0.25f; // the scan effect over the unit, a quarter of a full glow
          break;
        case Rule::Legacy:
          break; // props, wreckage, shields, the map border: their specular.b is not a glow (wreckage noise, a shield
                 // pattern), no light
        }

        sumEmission += emission + team;
        sumTeam += team;
        if (emission > 0.0f) {
          // the colour of the glowing part: the albedo, weighted by how hard it glows
          for (int c = 0; c < 3; ++c) {
            sumHue[c] += static_cast<double>(emission) * a[c];
          }
          sumHueWeight += emission;
        }
      }
    }

    const double count = static_cast<double>(kSamples) * kSamples;
    out.area = static_cast<float>(sumEmission / count);
    out.teamShare = sumEmission > 1.0e-9 ? static_cast<float>(sumTeam / sumEmission) : 0.0f;
    if (sumHueWeight > 1.0e-9) {
      float m = 0.0f;
      for (int c = 0; c < 3; ++c) {
        out.hue[c] = static_cast<float>(sumHue[c] / sumHueWeight);
        m = std::max(m, out.hue[c]);
      }
      if (m > 1.0e-6f) {
        for (float& h : out.hue) {
          h /= m;
        }
      }
    }
    if (rule == Rule::Build) {
      // the build shaders draw the unit's own albedo under the scan: the colour of the glow is the faction's build
      // colour
      std::string name(shader);
      for (char& c : name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      const float aeon[3] = {0.45f, 1.0f, 0.35f};
      const float uef[3] = {0.45f, 0.75f, 1.0f};
      const float cybran[3] = {1.0f, 0.5f, 0.2f};
      const float seraphim[3] = {0.75f, 0.55f, 1.0f};
      const float* colour = name.rfind("aeon", 0) == 0
        ? aeon
        : (name.rfind("cybran", 0) == 0 ? cybran : (name.rfind("seraphim", 0) == 0 ? seraphim : uef));
      for (int c = 0; c < 3; ++c) {
        out.hue[c] = colour[c];
      }
    }
    out.effect = rule == Rule::Nuke || rule == Rule::ShieldImpact || rule == Rule::Build;
    out.nuke = rule == Rule::Nuke;
    out.valid = true;
    return out;
  }

  float MeshLightIntensity(
    const MeshGlow& glow
  )
  {
    // Below this the glow is a few texels (a lamp on a building seen from afar): the light would be too faint to see
    // and costs a light.
    if (!glow.valid || glow.area < kMinMeshGlowArea) {
      return 0.0f;
    }
    // A unit whose whole surface glows at full strength (area 1) gets the largest light; a few glowing windows (area
    // 0.02) a faint one. The square root keeps small glows visible without letting a big glowing body white out its
    // surroundings.
    const float cap = glow.nuke ? kMaxNukeMeshIntensity : kMaxMeshIntensity;
    // (the exponent 0.35, not 0.5: a unit with a few small lamps, area 0.007, made 0.046: at the edge of what is
    // dropped as invisible)
    return std::min(cap, cap * std::pow(std::min(1.0f, glow.area), 0.35f));
  }

  float MeshLightRadius(
    const float sphereRadius,
    const float maxRadius
  )
  {
    if (!std::isfinite(sphereRadius) || sphereRadius <= 0.0f) {
      return 2.0f;
    }
    return std::min(maxRadius, std::max(2.5f, 2.0f * sphereRadius + 2.0f));
  }
} // namespace moho::lights

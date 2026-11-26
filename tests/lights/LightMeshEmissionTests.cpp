// Host test of the unit glow analysis (src/moho/render/lights/LightMeshEmission): the per-faction rules of mesh.fx on
// synthetic textures. Called from main() in LightCollectorTests.cpp.

#include <cmath>
#include <cstdint>
#include <cstdio>

#include "moho/render/lights/LightMeshEmission.h"

namespace
{
  using namespace moho::lights;

  int gMeshFailures = 0;
  int gMeshChecks = 0;

#define MCHECK(cond)                                                                                                   \
  do {                                                                                                                 \
    ++gMeshChecks;                                                                                                     \
    if (!(cond)) {                                                                                                     \
      ++gMeshFailures;                                                                                                 \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  bool Near(
    const float a,
    const float b,
    const float eps = 0.03f
  )
  {
    return std::fabs(a - b) <= eps;
  }

  Rgba8Image Solid(
    const std::uint32_t w,
    const std::uint32_t h,
    const std::uint8_t r,
    const std::uint8_t g,
    const std::uint8_t b,
    const std::uint8_t a
  )
  {
    Rgba8Image img;
    img.width = w;
    img.height = h;
    img.rgba.resize(static_cast<std::size_t>(w) * h * 4);
    for (std::size_t i = 0; i < static_cast<std::size_t>(w) * h; ++i) {
      img.rgba[i * 4 + 0] = r;
      img.rgba[i * 4 + 1] = g;
      img.rgba[i * 4 + 2] = b;
      img.rgba[i * 4 + 3] = a;
    }
    return img;
  }

  void SetTexel(
    Rgba8Image& img,
    const std::uint32_t x,
    const std::uint32_t y,
    const std::uint8_t r,
    const std::uint8_t g,
    const std::uint8_t b,
    const std::uint8_t a
  )
  {
    std::uint8_t* p = &img.rgba[(static_cast<std::size_t>(y) * img.width + x) * 4];
    p[0] = r;
    p[1] = g;
    p[2] = b;
    p[3] = a;
  }

  // for temporaries: AnalyseMeshGlow takes the specular map by pointer
  MeshGlow GlowOf(
    const Rgba8Image& albedo,
    const Rgba8Image& spec,
    const char* shader
  )
  {
    return AnalyseMeshGlow(albedo, &spec, shader);
  }

  void TestUef()
  {
    // an orange albedo, a specular map whose blue channel glows in a quarter of the texture
    Rgba8Image albedo = Solid(8, 8, 255, 128, 0, 255);
    Rgba8Image spec = Solid(8, 8, 0, 0, 0, 0);
    for (std::uint32_t y = 0; y < 4; ++y) {
      for (std::uint32_t x = 0; x < 4; ++x) {
        SetTexel(spec, x, y, 0, 0, 255, 0);
      }
    }
    const MeshGlow g = AnalyseMeshGlow(albedo, &spec, "Unit");
    MCHECK(g.valid);
    MCHECK(Near(g.area, 0.25f * 0.8f)); // a quarter of the texels at spec.b * 0.8
    MCHECK(Near(g.hue[0], 1.0f) && Near(g.hue[1], 0.5f, 0.02f) && Near(g.hue[2], 0.0f));
    MCHECK(g.teamShare == 0.0f);

    // nothing glows when the blue channel is empty; no specular map means no glow for the others
    MCHECK(GlowOf(albedo, Solid(8, 8, 255, 255, 0, 255), "Unit").area == 0.0f);
    MCHECK(AnalyseMeshGlow(albedo, nullptr, "Unit").area == 0.0f);
    MCHECK(MeshLightIntensity(AnalyseMeshGlow(albedo, nullptr, "Unit")) == 0.0f);
  }

  void TestAeonTeamGlow()
  {
    // Aeon: the team mask (specular.a) glows in the army colour at half strength
    const Rgba8Image albedo = Solid(4, 4, 40, 40, 40, 255);
    const Rgba8Image spec = Solid(4, 4, 0, 0, 0, 255);
    const MeshGlow g = AnalyseMeshGlow(albedo, &spec, "Aeon");
    MCHECK(Near(g.area, 0.5f));
    MCHECK(Near(g.teamShare, 1.0f)); // all of it is team colour
    const MeshGlow c = AnalyseMeshGlow(albedo, &spec, "AeonCZAR");
    MCHECK(Near(c.area, 0.5f) && Near(c.teamShare, 1.0f));

    // plus a blue-channel glow: white-ish albedo hue, share split
    Rgba8Image spec2 = Solid(4, 4, 0, 0, 255, 255);
    const MeshGlow m = AnalyseMeshGlow(Solid(4, 4, 200, 255, 220, 255), &spec2, "Aeon");
    MCHECK(Near(m.area, 1.5f) && Near(m.teamShare, 1.0f / 3.0f));
    MCHECK(Near(m.hue[1], 1.0f) && Near(m.hue[0], 200.0f / 255.0f));
  }

  void TestCybran()
  {
    // Cybran: sqrt(max(b - 0.04, 0)): b = 0.04 glows not at all, b = 1 fully
    MCHECK(GlowOf(Solid(2, 2, 255, 80, 0, 255), Solid(2, 2, 0, 0, 10, 0), "Insect").area == 0.0f);
    const MeshGlow g = GlowOf(Solid(2, 2, 255, 80, 0, 255), Solid(2, 2, 0, 0, 255, 0), "Insect");
    MCHECK(Near(g.area, std::sqrt(0.96f)) && Near(g.hue[0], 1.0f) && Near(g.hue[1], 80.0f / 255.0f));
  }

  void TestSeraphim()
  {
    // Seraphim: the team mask is the albedo alpha, bright albedo glows by itself
    const MeshGlow team = GlowOf(Solid(2, 2, 20, 20, 20, 255), Solid(2, 2, 0, 0, 0, 0), "Seraphim");
    MCHECK(Near(team.area, 1.0f) && Near(team.teamShare, 1.0f));
    const MeshGlow bright = AnalyseMeshGlow(Solid(2, 2, 255, 255, 255, 0), nullptr, "Seraphim");
    MCHECK(Near(bright.area, (1.0f - 0.4f) * 1.5f) && bright.teamShare == 0.0f); // the specular map may be missing
  }

  void TestLegacyAndNames()
  {
    const Rgba8Image albedo = Solid(2, 2, 255, 255, 255, 255);
    const Rgba8Image spec = Solid(2, 2, 0, 0, 255, 0);
    // everything that is not a unit shader has no glow: its specular.b is not an emission (wreckage noise, shield
    // pattern)
    MCHECK(AnalyseMeshGlow(albedo, &spec, "NormalMapped").area == 0.0f);
    MCHECK(AnalyseMeshGlow(albedo, &spec, "Wreckage").area == 0.0f);
    MCHECK(AnalyseMeshGlow(albedo, &spec, "PhaseShield").area == 0.0f);
    MCHECK(AnalyseMeshGlow(albedo, &spec, "MapImager").area == 0.0f);
    MCHECK(AnalyseMeshGlow(albedo, &spec, "AeonPhaseShield").area == 0.0f); // the bubble of a shield is not the unit
    // a mesh that glows as a whole: its albedo is the emission
    MCHECK(Near(AnalyseMeshGlow(Solid(2, 2, 255, 100, 0, 255), nullptr, "TMeshGlow").area, 1.0f));
    MCHECK(Near(AnalyseMeshGlow(Solid(2, 2, 255, 100, 0, 255), nullptr, "NormalMappedGlow").hue[1], 100.0f / 255.0f));
    MCHECK(Near(AnalyseMeshGlow(Solid(2, 2, 51, 25, 0, 255), nullptr, "TMeshGlow").area, 0.2f));
    MCHECK(AnalyseMeshGlow(albedo, &spec, "").area == 0.0f);
    MCHECK(AnalyseMeshGlow(albedo, &spec, "NormalMapped").valid);
    // the unit shaders, whatever the case of the name
    MCHECK(Near(AnalyseMeshGlow(albedo, &spec, "UNIT").area, 0.8f));
    MCHECK(Near(AnalyseMeshGlow(albedo, &spec, "UEFNavy").area, 0.8f));
    MCHECK(Near(AnalyseMeshGlow(albedo, &spec, "NomadsUnit").area, 0.8f));
    MCHECK(Near(AnalyseMeshGlow(albedo, &spec, "AeonNavy").area, 1.0f));
  }

  void TestEffectMeshes()
  {
    // the fireball of a strategic missile: the whole mesh burns, in the colour of its albedo, and its light may reach
    // far
    const Rgba8Image fire = Solid(2, 2, 255, 40, 0, 255);
    const MeshGlow nuke = AnalyseMeshGlow(fire, nullptr, "NukeUEF");
    MCHECK(nuke.valid && nuke.effect && nuke.nuke);
    MCHECK(Near(nuke.area, 1.0f));
    MCHECK(Near(nuke.hue[0], 1.0f) && nuke.hue[1] < 0.2f && nuke.hue[2] < 0.05f);
    MCHECK(AnalyseMeshGlow(fire, nullptr, "NukeEMP").nuke);
    MCHECK(AnalyseMeshGlow(fire, nullptr, "NukeQuantum").nuke);
    MCHECK(Near(MeshLightIntensity(nuke), kMaxNukeMeshIntensity));
    MCHECK(MeshLightIntensity(nuke) > kMaxMeshIntensity);
    MCHECK(Near(MeshLightRadius(60.0f, kMaxEffectLightRadius), 122.0f));
    MCHECK(Near(MeshLightRadius(200.0f, kMaxEffectLightRadius), kMaxEffectLightRadius));
    // the flash of a hit on a shield is a light; the shield bubble itself is not
    const MeshGlow impact = AnalyseMeshGlow(Solid(2, 2, 80, 160, 255, 255), nullptr, "ShieldImpact");
    MCHECK(impact.valid && impact.effect && !impact.nuke && Near(impact.area, 0.5f));
    MCHECK(AnalyseMeshGlow(Solid(2, 2, 80, 160, 255, 255), nullptr, "CybranShieldImpact").effect);
    MCHECK(AnalyseMeshGlow(Solid(2, 2, 80, 160, 255, 255), nullptr, "ShieldUEF").area == 0.0f);
    MCHECK(AnalyseMeshGlow(Solid(2, 2, 80, 160, 255, 255), nullptr, "ShieldFill").area == 0.0f);
    // a unit being built: a faint glow in the faction's colour
    const MeshGlow aeonBuild = AnalyseMeshGlow(Solid(2, 2, 90, 90, 90, 255), nullptr, "AeonBuildPuddle");
    MCHECK(
      aeonBuild.effect && Near(aeonBuild.area, 0.25f) && aeonBuild.hue[1] > aeonBuild.hue[0] &&
      aeonBuild.hue[1] > aeonBuild.hue[2]
    );
    MCHECK(AnalyseMeshGlow(Solid(2, 2, 90, 90, 90, 255), nullptr, "CybranBuildOverlay").hue[0] > 0.9f);
    MCHECK(AnalyseMeshGlow(Solid(2, 2, 90, 90, 90, 255), nullptr, "UEFBuildCube").hue[2] > 0.9f);
    MCHECK(AnalyseMeshGlow(Solid(2, 2, 90, 90, 90, 255), nullptr, "SeraphimBuild").hue[2] > 0.9f);
  }

  void TestSizesAndRefusals()
  {
    // the two maps may have different sizes
    Rgba8Image albedo = Solid(16, 16, 255, 0, 0, 255);
    Rgba8Image spec = Solid(4, 4, 0, 0, 0, 0);
    SetTexel(spec, 0, 0, 0, 0, 255, 0); // one texel of four by four: a sixteenth
    MCHECK(Near(AnalyseMeshGlow(albedo, &spec, "Unit").area, 0.8f / 16.0f));

    MCHECK(!AnalyseMeshGlow(Rgba8Image{}, &spec, "Unit").valid);
    Rgba8Image broken = Solid(4, 4, 1, 1, 1, 1);
    broken.rgba.resize(10);
    MCHECK(!AnalyseMeshGlow(broken, &spec, "Unit").valid);
    MCHECK(AnalyseMeshGlow(albedo, &broken, "Unit").area == 0.0f); // an unusable specular map is treated as missing
  }

  void TestIntensityAndRadius()
  {
    MeshGlow none;
    MCHECK(MeshLightIntensity(none) == 0.0f);
    MeshGlow a;
    a.valid = true;
    a.area = 0.02f;
    const float faint = MeshLightIntensity(a);
    a.area = 0.5f;
    const float medium = MeshLightIntensity(a);
    a.area = 5.0f;
    const float hard = MeshLightIntensity(a);
    MCHECK(faint > 0.0f && faint < medium && medium < hard);
    a.area = 0.001f;
    MCHECK(MeshLightIntensity(a) == 0.0f); // below the minimum glow area
    a.area = 0.002f;
    MCHECK(MeshLightIntensity(a) > 0.0f);
    MCHECK(Near(hard, kMaxMeshIntensity, 1.0e-4f)); // never above the cap

    MCHECK(
      Near(MeshLightRadius(0.0f), 2.0f) && Near(MeshLightRadius(-1.0f), 2.0f) &&
      Near(MeshLightRadius(std::nanf("")), 2.0f)
    );
    MCHECK(Near(MeshLightRadius(1.0f), 4.0f) && Near(MeshLightRadius(10.0f), 22.0f));
    MCHECK(Near(MeshLightRadius(1000.0f), 60.0f)); // capped
  }
} // namespace

int RunMeshTests(
  int& checks
)
{
  TestUef();
  TestAeonTeamGlow();
  TestCybran();
  TestSeraphim();
  TestLegacyAndNames();
  TestEffectMeshes();
  TestSizesAndRefusals();
  TestIntensityAndRadius();
  checks += gMeshChecks;
  return gMeshFailures;
}

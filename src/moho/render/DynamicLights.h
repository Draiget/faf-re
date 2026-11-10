#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_DynamicLights`): light from explosions, muzzle flashes, engines, projectiles and beams on
// the ground and the units around them. Forged Alliance's effects glow but light nothing; their particles carry no
// light data, so the lights are gathered from what reaches the renderer each beat (CWorldParticles::AddParticles):
//  - particles drawn additively, and the "TLight" particles the game's scripts create as lights;
//  - the newest end of each additive trail (projectile glows, engine trails);
//  (both in their ramp texture's colour, read once per texture)
//  - additive beams, in their own colour, where they hit and where they start.
// Nearby sources merge into one light per 3-unit cell. Each light is aged on the CPU in game ticks (the particle
// shader's time) and fades out over its source's life. A half-resolution compute pass sums them per pixel from the
// depth of terrain and opaque meshes, and a composite multiplies (1 + light) into the colour, so lit ground keeps
// its own hue. Direct3D 12 and Vulkan only (it reads the bound depth target, as ren_Ao does).

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  struct GeomCamera3;
  struct SParticleBuffer;

  extern int ren_DynamicLights;

  class DynamicLights
  {
  public:
    [[nodiscard]] static DynamicLights& Get();

    /** Gathers the beat's light sources; `tick` is the game tick the beat brings. */
    void AddParticles(const SParticleBuffer& batch, int tick);

    /** `ren_DynamicLights` is on, the renderer is Direct3D 12 or Vulkan with compute, and the programs built. */
    [[nodiscard]] bool IsActive();

    /**
     * Lights the bound colour target over the view at (`x`, `y`), `width` by `height`, from the bound depth. Call it
     * with the world view's viewport set, after the opaque meshes (and ambient occlusion), before effects and water.
     */
    void Render(const GeomCamera3& camera, int x, int y, int width, int height);

    struct Light
    {
      float position[3]{};
      float velocity[3]{}; // world units per tick
      float color[3]{};
      float radius = 0.0f;
      float intensity = 0.0f;
      float birth = 0.0f;    // game tick
      float lifetime = 0.0f; // ticks
    };

  private:
    struct RampColor
    {
      float color[3]{1.0f, 0.62f, 0.32f}; // the colour, brightest channel 1
      float strength = 1.0f;              // how bright and opaque the ramp is, 0..1
    };
    /** The light colour of a particle ramp texture (its alpha-weighted colour over the first part of life), cached. */
    [[nodiscard]] const RampColor& ColorOfRamp(const char* path);

    std::map<std::string, RampColor> mRampColors;

    void AddSource(const float position[3], const float velocity[3], const float color[3], float size, float birth, float lifetime);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompute;
    boost::shared_ptr<gpg::gal::GpuProgram> mComposite;
    boost::shared_ptr<gpg::gal::GpuBuffer> mTerms;
    std::uint32_t mTermCapacity = 0U;
    std::vector<Light> mLights;
    int mLastTick = -1;
  };
} // namespace moho

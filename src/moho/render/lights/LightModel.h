#pragma once

#include <cmath>

// The light model: the one place that decides how big, how strong and how important a light is.
//
// Dynamic lights are INFERRED from what the engine is about to draw (explosion light particles, glow sprites, beams,
// trails, projectile meshes, emissive unit parts): nothing in unit or effect data carries light data. Each feed
// measures the visual (world size, peak brightness, colour) and asks this header for the light's radius, intensity and
// importance class. The constants live here so a modded effect gets the same treatment as a stock one and the quality
// levels of the options menu act on one number.
//
// Pure functions, no engine headers: the host test (tests/lights) compiles this header and LightCollector.cpp on their
// own. Ported from the FA-DynamicLights patch (src/section/LightModel.h); the hue-transfer constants of that file
// belong to the merging stage and are not here yet.
//
// Units: lengths in world units, times in sim ticks (a tick is 0.1 s at game speed 1), intensity unitless (1.0 = a
// fully lit surface at the light's centre).

namespace moho::lights::model
{
  // ------------------------------------------------------------------------------------------------ importance
  // Importance of a light = its POWER, intensity x radius^2 (how much light it puts into the world), taken at its PEAK
  // (before the fade envelope and before any level of detail), so a nuke flash stays "huge" while it fades and a light
  // never changes class while it lives. Calibration against FA's own CreateLightParticle calls (size is the sprite size
  // in world units):
  //     nuke / Seraphim experimental flashes   size 60..300     power 26000 .. 275000     huge
  //     T3 / experimental explosions, jammers  size 10..40      power   700 ..  12000     large
  //     T1/T2 explosions, impacts, beams       size 3..8        power    26 ..    480     normal
  //     muzzle sparks, tracer trails, faint    size < 3         power     0 ..      6     minor
  enum Class
  {
    kMinor = 0,
    kNormal = 1,
    kLarge = 2,
    kHuge = 3,
    kClassCount = 4
  };
  constexpr float kPowerNormal = 4.0f; // it was 9: the build beams (power 7), reclaim rays and the glows of lit units
                                       // fell into Minor and were dropped at High
  constexpr float kPowerLarge = 580.0f;
  constexpr float kPowerHuge =
    11600.0f; // the three limits are the earlier 6 / 400 / 8000 times 1.45, the factor the flash intensity grew by
              // (0.55 to 0.8): the same lights stay in the same class

  // Quality levels (Options > Video > Dynamic Lights, cvar ren_DynLights).
  //   Off     no lights
  //   Low     only the very big ones: nukes and the biggest explosions
  //   Medium  also the smaller big ones (T3 / experimental artillery, large explosions)
  //   High    most lights: everything but tiny sparks and faint glows
  //   Ultra   all of them
  enum Quality
  {
    kOff = 0,
    kLow = 1,
    kMedium = 2,
    kHigh = 3,
    kUltra = 4
  };

  constexpr float Clamp(
    const float v,
    const float lo,
    const float hi
  )
  {
    return v < lo ? lo : (v > hi ? hi : v);
  }

  constexpr float Power(
    const float intensity,
    const float radius
  )
  {
    return intensity * radius * radius;
  }

  constexpr int ClassOfPower(
    const float power
  )
  {
    if (power >= kPowerHuge) {
      return kHuge;
    }
    if (power >= kPowerLarge) {
      return kLarge;
    }
    if (power >= kPowerNormal) {
      return kNormal;
    }
    return kMinor;
  }

  // The lowest importance class a quality level lets through; kClassCount = nothing.
  constexpr int MinClassFor(
    const int quality
  )
  {
    switch (quality) {
    case kLow:
      return kHuge;
    case kMedium:
      return kLarge;
    case kHigh:
      return kNormal;
    case kUltra:
      return kMinor;
    default:
      return kClassCount;
    }
  }

  constexpr bool Admits(
    const int quality,
    const float power
  )
  {
    return ClassOfPower(power) >= MinClassFor(quality);
  }

  // ------------------------------------------------------------------------------------------------ explosion light
  // particles CreateLightParticle(entity, bone, army, size, lifetime, texture, ramp): a flash whose size the effect
  // author chose (nukes 100..300).
  constexpr float kMaxSpriteSize = 1000.0f; // above this a particle is garbage, not a light
  constexpr float kMaxLifeTicks = 600.0f;   // a "light" that lives longer than a minute is not a flash

  // The measured census (docs/DYNAMIC_LIGHTS.md, round 5): with radius 2.6 x size and 0.14 x size the common explosion
  // flash (size ~35) was a radius of 90 at a tenth of the strength, too wide and too faint to light its neighbours. A
  // flash reaches about its own size and a bit, and is as strong as a unit in a fight should be lit by a unit dying
  // next to it; only the very large ones (nukes) are wide.
  constexpr float FlashRadius(
    const float size
  )
  {
    return Clamp(1.4f * size, 3.0f, 420.0f);
  }
  constexpr float FlashIntensity(
    const float size
  )
  {
    return Clamp(0.80f + 0.004f * size, 0.80f, 1.6f);
  }

  // ------------------------------------------------------------------------------------------------ glow sprites
  // (fire, plasma, flares)
  constexpr float GlowRadius(
    const float size
  )
  {
    // a nuke's cloud sprites are tens of units across: they light that far; a muzzle flash (size 0.3..1) still lights
    // its gun and the ground around
    return Clamp(2.4f * size + 2.5f, 5.0f, 40.0f);
  }
  // Per sprite, before the texture and ramp brightness. What a sprite emits follows its area: the energy is
  // proportional to the size (with the radius, which is also proportional to it, the power follows the area). It was
  // 0.05 + 0.12 sqrt(size): a spark of 0.2 got 0.1, which with the flash boost and a hundred sparks per volley made
  // tiny projectiles the brightest things on the map, while a big plasma ball got little.
  inline float GlowEnergy(
    const float size
  )
  {
    return Clamp(0.08f * size, 0.02f, 1.2f);
  }

  // ------------------------------------------------------------------------------------------------ trails and beams
  // Poly trails (projectile streaks) are thin: the Aeon laser bolt has size 0.035.
  constexpr float TrailRadius(
    const float size
  )
  {
    return Clamp(5.0f + 5.0f * size, 5.0f, 12.0f);
  }
  constexpr float TrailIntensity(
    const float size
  ) // of the piece at the head; the pieces behind it are weaker
  {
    return Clamp(0.28f + 0.2f * size, 0.28f, 0.60f);
  }

  // A beam is a long bright line (laser, ion blast, a unit's build or reclaim ray): wider than a trail's thread,
  // brighter than a trail.
  constexpr float BeamRadius(
    const float width
  )
  {
    return Clamp(4.5f + 10.0f * width, 4.5f, 14.0f);
  }
  constexpr float BeamIntensity(
    const float width
  ) // before the beam's own colour brightness and alpha
  {
    return Clamp(1.4f + 0.6f * width, 1.4f, 1.9f);
  }

  // ------------------------------------------------------------------------------------------------ level of detail
  // A very big light is weakened (the same intensity over a ten times larger area is ten times the light), but not
  // below a floor that grows with the radius: a nuke has to stay a nuke.
  constexpr float WeakenFloor(
    const float radius
  )
  {
    return radius >= 300.0f ? 0.70f : (radius >= 100.0f ? 0.65f : 0.60f);
  }
  constexpr float WeakenFactor(
    const float radius
  ) // multiplies the intensity of a light of this radius
  {
    return Clamp(
      40.0f / radius, WeakenFloor(radius), 1.0f
    ); // it started at 20: with the higher soft limits of the light shaders a big light need not be dimmed that much
  }

  // ------------------------------------------------------------------------------------------------ envelope
  // A light fades in over kFadeInSeconds after its birth and out over kFadeOutSeconds after its life ends, so it never
  // pops.
  constexpr float kFadeInSeconds = 0.08f;
  constexpr float kFadeOutSeconds = 0.30f;
  // Big lights (a nuke flash covers the screen) cost a pixel evaluation everywhere: only the strongest few are kept.
  constexpr float kBigLightRadius = 80.0f;
  constexpr int kMaxBigLights = 8;
  constexpr float kMinVisible = 0.02f; // colour x intensity below this adds nothing visible: the light is dropped
} // namespace moho::lights::model

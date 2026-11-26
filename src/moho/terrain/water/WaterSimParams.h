#pragma once

// The numbers of the wave simulation that the game and the headless lab (tools/watersimlab) must share, so that what
// the lab measures is what the game runs. Per step of 1/90 s, on cells of half a unit.
namespace moho::water
{
  // (speed x step / cell)^2: the long waves travel at 2.5 world units a second.
  constexpr float kWaveTerm = 0.0031f;
  // Waves lose this share of their height every step (a quarter of the old 0.003: the viscosity in the shader takes the
  // short waves, so the long front of a splash travels on).
  constexpr float kDamping = 0.0008f;
  // Dispersion: h_tt = c^2 lap(h) - b^2 lap(lap(h)), per step and cell: b^2 step^2 / cell^4 with b = 2.4 u^2/s (found
  // in the lab, tools/watersimlab.py impact: strong enough that a splash runs out into a train of 3-4 crests). Short
  // waves run faster than long ones, so an impulse spreads into a train.
  constexpr float kCapillary = 0.0119f;
  // The share of the foam that is kept every step (a wake lingers for about ten seconds as a thinning trail; the old
  // 0.994 was gone in three and a wake had no foam left to see behind the stern). The share of the velocity spread to
  // the neighbours every step (shader kViscosity): low, so that the short waves of a splash live for a second.
  constexpr float kViscosity = 0.008f;
  constexpr float kFoamKept = 0.9965f;
  // The foam of a hull under way (bow, wash, sides, the arms of the V) is multiplied with this.
  constexpr float kHullFoam = 3.5f;
  // What a body that moves through the water does to it (HullDisplacement.h): a source in a bin of the world of this
  // radius, with the push of the change of volume times kBodyPush, the foam of an entering volume times kBodyBowFoam,
  // of a leaving one times kBodyWashFoam.
  constexpr float kBodyRadius = 0.9f;
  constexpr float kBodyPush = 12.0f;
  constexpr float kBodyBowFoam = 0.25f;
  constexpr float kBodyWashFoam = 0.7f;
} // namespace moho::water

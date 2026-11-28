// Host test of the dynamic light pool (src/moho/render/lights): importance classes, the quality gate, validation,
// envelope, motion, ranking and the pool limits. No engine objects and no GPU: it compiles LightModel.h and
// LightCollector.cpp on their own.
//
// Build: cmake --build --preset clang-x64-release --target faf_light_tests
// Run:   build\clang-x64-release\tests\faf_light_tests.exe   (exit code = failures)

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

#include "moho/render/lights/LightCollector.h"
#include "moho/render/lights/LightModel.h"

namespace
{
  using namespace moho::lights;
  namespace model = moho::lights::model;

  int gFailures = 0;
  int gChecks = 0;

#define CHECK(cond)                                                                                                    \
  do {                                                                                                                 \
    ++gChecks;                                                                                                         \
    if (!(cond)) {                                                                                                     \
      ++gFailures;                                                                                                     \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  bool Near(
    const float a,
    const float b,
    const float eps = 1.0e-3f
  )
  {
    return std::fabs(a - b) <= eps;
  }

  // A CreateLightParticle flash: constant size, no motion.
  Emission Flash(
    const float size,
    const float birth = 0.0f,
    const float life = 10.0f
  )
  {
    Emission e;
    e.kind = Kind::Flash;
    e.birth = birth;
    e.life = life;
    e.size0 = size;
    e.size1 = size;
    return e;
  }

  // sizes taken from the calibration table in LightModel.h
  constexpr float kNukeSize = 300.0f;
  constexpr float kT3Size = 20.0f;
  constexpr float kT2Size = 5.0f;
  constexpr float kSparkSize = 1.0f;

  // ---------------------------------------------------------------------------------------------------- model
  void TestModelClasses()
  {
    static_assert(model::ClassOfPower(0.0f) == model::kMinor);
    static_assert(model::ClassOfPower(model::kPowerNormal) == model::kNormal);
    static_assert(model::ClassOfPower(model::kPowerLarge) == model::kLarge);
    static_assert(model::ClassOfPower(model::kPowerHuge) == model::kHuge);

    const auto power = [](const float size) {
      return model::Power(model::FlashIntensity(size), model::FlashRadius(size));
    };
    CHECK(model::ClassOfPower(power(kNukeSize)) == model::kHuge);
    CHECK(model::ClassOfPower(power(kT3Size)) == model::kLarge);
    CHECK(model::ClassOfPower(power(kT2Size)) == model::kNormal);
    // the smallest flash (radius 3, intensity 0.8, power 7) is Normal since the limit fell from 9 to 4; Minor is what
    // is below that
    CHECK(model::ClassOfPower(power(kSparkSize)) == model::kNormal);
    CHECK(model::ClassOfPower(3.0f) == model::kMinor);

    // each level admits its class and everything above it, nothing below
    for (const float size : {kNukeSize, kT3Size, kT2Size, kSparkSize}) {
      const int cls = model::ClassOfPower(power(size));
      CHECK(model::Admits(model::kOff, power(size)) == false);
      CHECK(model::Admits(model::kLow, power(size)) == (cls >= model::kHuge));
      CHECK(model::Admits(model::kMedium, power(size)) == (cls >= model::kLarge));
      CHECK(model::Admits(model::kHigh, power(size)) == (cls >= model::kNormal));
      CHECK(model::Admits(model::kUltra, power(size)) == true);
    }

    // a nuke keeps its size: radius 420 (the cap), not 60 as in the first patch
    CHECK(Near(model::FlashRadius(kNukeSize), 420.0f));
    CHECK(Near(model::FlashIntensity(kNukeSize), 1.6f));
    CHECK(model::WeakenFactor(520.0f) >= 0.55f);
    CHECK(model::WeakenFactor(2.0f) == 1.0f);
  }

  // ---------------------------------------------------------------------------------------------------- gate and
  // validation
  void TestOffIsFree()
  {
    LightCollector c;
    CHECK(c.Quality() == model::kOff);
    CHECK(!c.Add(Flash(kNukeSize)));
    CHECK(c.Stored() == 0);
    CHECK(c.GetStats().invalid == 0 && c.GetStats().gated == 0); // not even validated
    std::vector<Light> out;
    c.Update(5.0f, 16, out);
    CHECK(out.empty());
  }

  void TestQualityGate()
  {
    const struct
    {
      int quality;
      bool nuke, t3, t2, spark;
    } rows[] = {
      {model::kLow, true, false, false, false},
      {model::kMedium, true, true, false, false},
      {model::kHigh, true, true, true, true},
      {model::kUltra, true, true, true, true},
    };
    for (const auto& r : rows) {
      LightCollector c;
      c.SetQuality(r.quality);
      CHECK(c.Add(Flash(kNukeSize)) == r.nuke);
      CHECK(c.Add(Flash(kT3Size)) == r.t3);
      CHECK(c.Add(Flash(kT2Size)) == r.t2);
      CHECK(c.Add(Flash(kSparkSize)) == r.spark);
      CHECK(c.GetStats().offered == 4);
      CHECK(c.GetStats().gated + c.GetStats().stored == 4);
    }
  }

  void TestLoweringQualityDropsStored()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    c.Add(Flash(kNukeSize));
    c.Add(Flash(kT3Size));
    c.Add(Flash(kT2Size));
    c.Add(Flash(kSparkSize));
    CHECK(c.Stored() == 4);
    c.SetQuality(model::kMedium);
    CHECK(c.Stored() == 2); // nuke and T3 stay
    c.SetQuality(model::kLow);
    CHECK(c.Stored() == 1);
    c.SetQuality(model::kOff);
    CHECK(c.Stored() == 0);
    c.SetQuality(99); // clamped to Ultra
    CHECK(c.Quality() == model::kUltra);
    c.SetQuality(-3);
    CHECK(c.Quality() == model::kOff);
  }

  void TestInvalidEmissionsAreRefused()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    const float nan = std::numeric_limits<float>::quiet_NaN();
    const float inf = std::numeric_limits<float>::infinity();

    Emission e = Flash(kT2Size);
    e.pos[1] = nan;
    CHECK(!c.Add(e));
    e = Flash(kT2Size);
    e.dir[0] = inf;
    CHECK(!c.Add(e));
    e = Flash(kT2Size);
    e.accel[2] = -inf;
    CHECK(!c.Add(e));
    e = Flash(kT2Size);
    e.birth = nan;
    CHECK(!c.Add(e));
    CHECK(!c.Add(Flash(0.0f)));                  // no size
    CHECK(!c.Add(Flash(-4.0f)));                 // negative size
    CHECK(!c.Add(Flash(model::kMaxSpriteSize))); // garbage particle
    CHECK(!c.Add(Flash(kT2Size, 0.0f, 0.0f)));   // no life
    CHECK(!c.Add(Flash(kT2Size, 0.0f, -1.0f)));
    CHECK(!c.Add(Flash(kT2Size, 0.0f, model::kMaxLifeTicks))); // not a flash
    e = Flash(kT2Size);
    e.size1 = nan;
    CHECK(!c.Add(e));
    CHECK(c.GetStats().invalid == 11);
    CHECK(c.Stored() == 0);

    // a size that grows from nothing is fine: the peak counts
    e = Flash(0.0f);
    e.size1 = kT2Size;
    CHECK(c.Add(e));

    // colour is clamped, NaN colour is black (and the light is then invisible, not an error)
    e = Flash(kT2Size);
    e.rgb[0] = 7.0f;
    e.rgb[1] = -1.0f;
    e.rgb[2] = nan;
    CHECK(c.Add(e));
    std::vector<Light> out;
    c.Update(5.0f, 16, out);
    bool sawRed = false;
    for (const Light& l : out) {
      if (l.rgb[1] == 0.0f && l.rgb[2] == 0.0f && l.rgb[0] > 0.0f) {
        sawRed = true;
      }
    }
    CHECK(sawRed);
  }

  // ---------------------------------------------------------------------------------------------------- evaluation
  void TestEnvelope()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    c.SetSecondsPerTick(0.1f); // fade-in 0.8 ticks, fade-out 3 ticks
    CHECK(c.Add(Flash(kT2Size, 100.0f, 10.0f)));
    std::vector<Light> out;

    const float full = model::FlashIntensity(kT2Size) * model::WeakenFactor(model::FlashRadius(kT2Size));
    const auto intensityAt = [&](const float now) {
      c.Update(now, 16, out);
      return out.empty() ? 0.0f : out[0].rgb[0] / 1.0f;
    };
    const float fullR = full * 1.0f; // rgb defaults to white

    CHECK(intensityAt(99.0f) == 0.0f);                       // before birth
    CHECK(Near(intensityAt(100.4f), fullR * 0.5f, 1.0e-3f)); // half way through the fade-in
    CHECK(Near(intensityAt(105.0f), fullR));                 // life
    CHECK(Near(intensityAt(110.0f), fullR));                 // last tick of life
    CHECK(Near(intensityAt(111.5f), fullR * 0.5f, 1.0e-3f)); // half way through the fade-out
    CHECK(intensityAt(113.5f) == 0.0f);                      // faded out
    CHECK(c.Stored() == 0);                                  // and pruned
    CHECK(c.GetStats().expired == 1);
  }

  void TestEnvelopeFollowsGameSpeed()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    c.SetSecondsPerTick(0.05f); // double speed: the fade-out is 6 ticks
    c.Add(Flash(kT2Size, 0.0f, 10.0f));
    std::vector<Light> out;
    c.Update(15.0f, 16, out); // 5 ticks after the end: still alive at double speed (would be gone at 0.1 s per tick)
    CHECK(out.size() == 1);
    c.SetSecondsPerTick(0.0f); // refused: paused or garbage
    c.SetSecondsPerTick(-1.0f);
    c.SetSecondsPerTick(std::numeric_limits<float>::quiet_NaN());
    c.Update(15.5f, 16, out);
    CHECK(out.size() == 1);
  }

  void TestMotionAndSize()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    Emission e = Flash(0.0f, 10.0f, 10.0f);
    e.size0 = 4.0f;
    e.size1 = 8.0f;
    e.pos[0] = 100.0f;
    e.pos[1] = 5.0f;
    e.pos[2] = -20.0f;
    e.dir[0] = 2.0f;
    e.accel[1] = -0.5f;
    c.Add(e);

    std::vector<Light> out;
    c.Update(14.0f, 16, out); // t = 4
    CHECK(out.size() == 1);
    CHECK(Near(out[0].pos[0], 100.0f + 2.0f * 4.0f));
    CHECK(Near(out[0].pos[1], 5.0f + 0.5f * -0.5f * 16.0f));
    CHECK(Near(out[0].pos[2], -20.0f));
    CHECK(Near(out[0].radius, model::FlashRadius(4.0f + 4.0f * 0.4f)));

    c.Update(21.5f, 16, out); // 1.5 ticks past the end: held at size1, half faded
    CHECK(out.size() == 1);
    CHECK(Near(out[0].radius, model::FlashRadius(8.0f)));

    // before birth the light never moves backwards (and is dark anyway)
    LightCollector d;
    d.SetQuality(model::kUltra);
    d.Add(e);
    d.Update(5.0f, 16, out);
    CHECK(out.empty());
  }

  void TestImportanceIsFixedWhileFading()
  {
    // A nuke admitted at Low stays in the pool while it fades; its class comes from the peak, not from the faded
    // intensity.
    LightCollector c;
    c.SetQuality(model::kLow);
    CHECK(c.Add(Flash(kNukeSize, 0.0f, 20.0f)));
    std::vector<Light> out;
    c.Update(22.0f, 16, out); // deep in the fade-out
    CHECK(out.size() == 1);
    CHECK(c.Stored() == 1);
    c.SetQuality(model::kLow); // re-applying the level does not drop it
    CHECK(c.Stored() == 1);
  }

  void TestNukeKeepsItsStrength()
  {
    LightCollector c;
    c.SetQuality(model::kLow);
    c.Add(Flash(kNukeSize, 0.0f, 20.0f));
    std::vector<Light> out;
    c.Update(10.0f, 16, out);
    CHECK(out.size() == 1);
    CHECK(Near(out[0].radius, 420.0f));
    CHECK(out[0].power > model::kPowerHuge);
  }

  void TestInvisibleLightsAreDropped()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    Emission e = Flash(kT2Size);
    e.rgb[0] = e.rgb[1] = e.rgb[2] = 0.0f;
    CHECK(c.Add(e)); // valid, stored ...
    std::vector<Light> out;
    c.Update(5.0f, 16, out);
    CHECK(out.empty()); // ... but it takes no slot
  }

  // ---------------------------------------------------------------------------------------------------- ranking and
  // limits
  void TestRankingAndCap()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    const float sizes[] = {3.0f, 20.0f, 5.0f, 300.0f, 8.0f, 12.0f, 4.0f, 30.0f, 6.0f, 10.0f};
    for (const float s : sizes) {
      c.Add(Flash(s));
    }
    std::vector<Light> out;
    c.Update(5.0f, 3, out);
    CHECK(out.size() == 3);
    CHECK(c.GetStats().active == 10);
    CHECK(c.GetStats().culledByCap == 7);
    CHECK(out[0].power >= out[1].power && out[1].power >= out[2].power);
    CHECK(Near(out[0].radius, 420.0f)); // the nuke
    CHECK(out[0].power > out[1].power);

    c.Update(5.0f, 0, out);
    CHECK(out.empty());
    CHECK(c.GetStats().culledByCap == 10);
  }

  void TestTiesAreStable()
  {
    // equal lights: the earlier birth first, then the order of arrival; the same input gives the same output
    LightCollector a, b;
    a.SetQuality(model::kUltra);
    b.SetQuality(model::kUltra);
    for (int i = 0; i < 40; ++i) {
      Emission e = Flash(kT2Size, 0.0f, 50.0f);
      e.pos[0] = static_cast<float>(i);
      a.Add(e);
      b.Add(e);
    }
    std::vector<Light> oa, ob;
    a.Update(10.0f, 8, oa);
    b.Update(10.0f, 8, ob);
    CHECK(oa.size() == 8 && ob.size() == 8);
    for (std::size_t i = 0; i < oa.size(); ++i) {
      CHECK(oa[i].pos[0] == ob[i].pos[0]);
      CHECK(oa[i].pos[0] == static_cast<float>(i)); // arrival order
    }
  }

  void TestPoolLimit()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    for (std::size_t i = 0; i < LightCollector::kPoolCapacity; ++i) {
      CHECK(c.Add(Flash(kT2Size, 0.0f, 5.0f)));
    }
    CHECK(c.Stored() == LightCollector::kPoolCapacity);
    CHECK(!c.Add(Flash(kT2Size, 0.0f, 5.0f)));
    CHECK(c.GetStats().poolFull == 1);

    // after they expired, an Update frees the pool and new lights fit again
    std::vector<Light> out;
    c.Update(100.0f, 16, out);
    CHECK(c.Stored() == 0);
    CHECK(c.Add(Flash(kT2Size, 100.0f, 5.0f)));

    // a full pool of dead lights is pruned by Add itself (the next Update has not run yet)
    LightCollector d;
    d.SetQuality(model::kUltra);
    d.Update(0.0f, 16, out);
    for (std::size_t i = 0; i < LightCollector::kPoolCapacity; ++i) {
      d.Add(Flash(kT2Size, 0.0f, 5.0f));
    }
    d.Update(1.0f, 16, out); // clock is at 1: nothing expired yet
    CHECK(!d.Add(Flash(kT2Size, 1.0f, 5.0f)));
    d.Update(50.0f, 0, out); // clock moves on and prunes everything
    CHECK(d.Add(Flash(kT2Size, 50.0f, 5.0f)));
  }

  void TestUpdateWithBadClock()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    c.Add(Flash(kT2Size));
    std::vector<Light> out;
    c.Update(std::numeric_limits<float>::quiet_NaN(), 16, out);
    CHECK(out.empty());
    CHECK(c.Stored() == 1); // a NaN clock changes nothing
    c.Update(5.0f, 16, out);
    CHECK(out.size() == 1);
  }

  void TestExplicitStrength()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    Emission e;
    e.kind = Kind::Spot;
    e.pos[0] = 10.0f;
    e.end[0] = 1.0f;
    e.cone = 0.9f;
    e.birth = 0.0f;
    e.life = 50.0f;
    e.radius = 40.0f;
    e.intensity = 0.5f;
    e.rgb[0] = 1.0f;
    e.rgb[1] = 0.0f;
    e.rgb[2] = 0.0f;
    CHECK(c.Add(e)); // no size needed: the author's own radius and intensity
    std::vector<Light> out;
    c.Update(10.0f, 16, out);
    CHECK(out.size() == 1);
    CHECK(Near(out[0].radius, 40.0f));
    CHECK(Near(out[0].rgb[0], 0.5f * model::WeakenFactor(40.0f)));
    CHECK(out[0].rgb[1] == 0.0f && out[0].kind == Kind::Spot && Near(out[0].cone, 0.9f) && Near(out[0].end[0], 1.0f));

    // absurd explicit values are refused
    Emission bad = e;
    bad.radius = 1.0e9f;
    CHECK(!c.Add(bad));
    bad = e;
    bad.intensity = -1.0f;
    CHECK(!c.Add(bad));
    bad = e;
    bad.intensity = std::numeric_limits<float>::quiet_NaN();
    CHECK(!c.Add(bad));
  }

  void TestCapsuleMotion()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    Emission e;
    e.kind = Kind::Beam;
    e.pos[0] = 0.0f;
    e.end[0] = 100.0f;
    e.dir[0] = 2.0f; // the whole beam slides
    e.birth = 0.0f;
    e.life = 20.0f;
    e.size0 = e.size1 = 1.0f;
    CHECK(c.Add(e));
    std::vector<Light> out;
    c.Update(5.0f, 16, out);
    CHECK(out.size() == 1);
    CHECK(Near(out[0].pos[0], 10.0f) && Near(out[0].end[0], 110.0f));
  }

  void TestTrackedLights()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    c.SetSecondsPerTick(0.1f); // fade-in 0.8 ticks, fade-out 3
    Emission e;
    e.kind = Kind::Glow;
    e.radius = 20.0f;
    e.intensity = 1.0f;
    e.pos[0] = 5.0f;
    std::vector<Light> out;

    CHECK(c.Track(7, e, 100.0f, 2.0f));
    CHECK(c.Stored() == 1 && c.GetStats().tracked == 1);
    c.Update(100.0f, 16, out);
    CHECK(out.empty()); // faded in from nothing

    // refreshed every tick: stays, follows the owner, fades in only once
    for (int tick = 101; tick <= 130; ++tick) {
      e.pos[0] = 5.0f + static_cast<float>(tick - 100);
      CHECK(c.Track(7, e, static_cast<float>(tick), 2.0f));
      CHECK(c.Stored() == 1); // the same light, not a new one per tick
    }
    c.Update(130.0f, 16, out);
    CHECK(out.size() == 1);
    CHECK(Near(out[0].pos[0], 35.0f));
    CHECK(Near(out[0].rgb[0], model::WeakenFactor(20.0f))); // full strength, colour (1,1,1)

    // a second owner is a second light; changing colour and radius of the first updates it
    CHECK(c.Track(8, e, 130.0f, 2.0f));
    CHECK(c.Stored() == 2);
    e.radius = 30.0f;
    e.rgb[1] = 0.0f;
    CHECK(c.Track(7, e, 131.0f, 2.0f));
    c.Update(131.0f, 16, out);
    CHECK(out.size() >= 1);
    bool saw = false;
    for (const Light& l : out) {
      saw = saw || (Near(l.radius, 30.0f) && l.rgb[1] == 0.0f);
    }
    CHECK(saw);

    // the owners stop refreshing: the lights live `hold` ticks, then fade out and are pruned
    c.Update(133.5f, 16, out);
    c.Update(135.0f, 16, out);
    c.Update(140.0f, 16, out);
    CHECK(c.Stored() == 0);

    // Untrack ends a light at once (the fade-out still runs)
    CHECK(c.Track(9, e, 200.0f, 50.0f));
    c.Update(210.0f, 16, out);
    CHECK(out.size() == 1);
    c.Untrack(9, 210.0f);
    c.Update(211.5f, 16, out);
    CHECK(out.size() == 1 && out[0].rgb[0] < model::WeakenFactor(30.0f));
    c.Update(215.0f, 16, out);
    CHECK(out.empty() && c.Stored() == 0);
    c.Untrack(9, 216.0f); // already gone: ignored
    c.Untrack(12345, 216.0f);

    // refused: key 0, bad hold, bad clock
    CHECK(!c.Track(0, e, 1.0f, 2.0f));
    CHECK(!c.Track(5, e, 1.0f, 0.0f));
    CHECK(!c.Track(5, e, std::numeric_limits<float>::quiet_NaN(), 2.0f));
  }

  void TestTrackedMotionAtFrameRate()
  {
    // a light refreshed once per tick is drawn every frame: between two refreshes it moves on at the velocity of the
    // last two
    LightCollector c;
    c.SetQuality(model::kUltra);
    Emission e;
    e.kind = Kind::Glow;
    e.radius = 20.0f;
    e.intensity = 1.0f;
    std::vector<Light> out;
    e.pos[0] = 0.0f;
    CHECK(c.Track(1, e, 10.0f, 50.0f));
    e.pos[0] = 2.0f;
    CHECK(c.Track(1, e, 11.0f, 50.0f)); // 2 units per tick
    c.Update(11.0f, 16, out);
    CHECK(out.size() == 1 && Near(out[0].pos[0], 2.0f));
    c.Update(11.5f, 16, out);
    CHECK(out.size() == 1 && Near(out[0].pos[0], 3.0f)); // half a tick on
    c.Update(11.25f, 16, out);
    CHECK(out.size() == 1 && Near(out[0].pos[0], 2.5f));
    c.Update(20.0f, 16, out);
    CHECK(
      out.size() == 1 && Near(out[0].pos[0], 2.0f + 2.0f * LightCollector::kMaxCarryTicks)
    ); // carried at most kMaxCarryTicks

    // a jump (a beam that retargets) is a teleport, not a speed
    e.pos[0] = 500.0f;
    CHECK(c.Track(1, e, 12.0f, 50.0f));
    c.Update(12.5f, 16, out);
    CHECK(out.size() == 1 && Near(out[0].pos[0], 500.0f));

    // the owner may state the velocity: a beam knows its last transform
    Emission b;
    b.kind = Kind::Beam;
    b.radius = 5.0f;
    b.intensity = 1.0f;
    b.pos[0] = 0.0f;
    b.end[0] = 10.0f;
    b.hasVel = true;
    b.vel[0] = 1.0f;
    b.endVel[0] = 4.0f;
    CHECK(c.Track(2, b, 30.0f, 5.0f));
    c.Update(30.5f, 16, out);
    bool saw = false;
    for (const Light& l : out) {
      saw = saw || (l.kind == Kind::Beam && Near(l.pos[0], 0.5f) && Near(l.end[0], 12.0f));
    }
    CHECK(saw);
  }

  void TestGain()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    Emission e;
    e.kind = Kind::Glow;
    e.birth = 0.0f;
    e.life = 50.0f;
    e.size0 = e.size1 = 2.0f;
    e.rgb[0] = e.rgb[1] = e.rgb[2] = 1.0f;
    std::vector<Light> out;
    CHECK(c.Add(e));
    c.Update(20.0f, 16, out);
    CHECK(out.size() == 1);
    const float one = out[0].rgb[0];
    e.gain = 2.0f;
    c.Clear();
    CHECK(c.Add(e));
    c.Update(20.0f, 16, out);
    CHECK(out.size() == 1 && Near(out[0].rgb[0], 2.0f * one));
  }

  void TestManyLightsInPool()
  {
    // 10000 lights are held and ranked; the pool is not what limits them
    LightCollector c;
    c.SetQuality(model::kUltra);
    for (int i = 0; i < 10000; ++i) {
      Emission e = Flash(kT2Size, 0.0f, 50.0f);
      e.pos[0] = static_cast<float>(i);
      CHECK(c.Add(e));
    }
    std::vector<Light> out;
    c.Update(10.0f, 4096, out);
    CHECK(out.size() == 4096);
    CHECK(c.GetStats().active == 10000 && c.GetStats().culledByCap == 10000 - 4096);
  }

  void TestClear()
  {
    LightCollector c;
    c.SetQuality(model::kUltra);
    c.Add(Flash(kT2Size));
    c.Clear();
    CHECK(c.Stored() == 0);
    std::vector<Light> out;
    c.Update(5.0f, 16, out);
    CHECK(out.empty());
  }
} // namespace

int RunGridTests(int& checks);       // LightGridTests.cpp
int RunPatchTests(int& checks);      // LightEffectPatchTests.cpp
int RunTextureTests(int& checks);    // LightTextureTests.cpp
int RunMeshTests(int& checks);       // LightMeshEmissionTests.cpp
int RunWaterLevelTests(int& checks); // LightWaterLevelTests.cpp

int main()
{
  TestModelClasses();
  TestOffIsFree();
  TestQualityGate();
  TestLoweringQualityDropsStored();
  TestInvalidEmissionsAreRefused();
  TestEnvelope();
  TestEnvelopeFollowsGameSpeed();
  TestMotionAndSize();
  TestImportanceIsFixedWhileFading();
  TestNukeKeepsItsStrength();
  TestInvisibleLightsAreDropped();
  TestRankingAndCap();
  TestTiesAreStable();
  TestPoolLimit();
  TestUpdateWithBadClock();
  TestExplicitStrength();
  TestCapsuleMotion();
  TestTrackedLights();
  TestTrackedMotionAtFrameRate();
  TestGain();
  TestManyLightsInPool();
  TestClear();
  gFailures += RunGridTests(gChecks);
  gFailures += RunPatchTests(gChecks);
  gFailures += RunTextureTests(gChecks);
  gFailures += RunMeshTests(gChecks);
  gFailures += RunWaterLevelTests(gChecks);

  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures == 0 ? 0 : 1;
}

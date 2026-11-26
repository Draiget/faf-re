// The pure part of the waterfalls and rapids of a river (src/moho/terrain/water/WaterfallPlan.{h,cpp}): the emitters a
// river gives, the strips of a curtain, the rates, the budget, the frustum test, the game clock and the live count. No
// engine objects, no device.
#include "moho/sim/WaterRivers.h"
#include "moho/terrain/water/WaterfallPlan.h"

#include <gtest/gtest.h>

#include <cmath>
#include <vector>

namespace
{
  using namespace moho::water::falls;
  using moho::SRiverDesc;
  using moho::SRiverFall;
  using moho::SRiverPoint;
  using moho::SRiverSegment;

  // River A of the test map (tools/scenarios/water-rivers): a fall of 7.5 at (130, 76), a steep reach before it and
  // after.
  SRiverDesc RiverA()
  {
    SRiverDesc desc;
    const struct
    {
      float x, z, level, half;
      bool fall;
      float below;
    } points[] = {
      {28.0f, 64.0f, 44.0f, 6.0f, false, 0.0f},
      {64.0f, 52.0f, 43.0f, 6.0f, false, 0.0f},
      {100.0f, 60.0f, 41.5f, 7.0f, false, 0.0f},
      {130.0f, 76.0f, 39.0f, 7.0f, true, 31.5f},
      {162.0f, 86.0f, 30.5f, 8.0f, false, 0.0f},
      {205.0f, 82.0f, 28.0f, 8.0f, false, 0.0f},
    };
    for (const auto& p : points) {
      SRiverPoint point;
      point.x = p.x;
      point.z = p.z;
      point.level = p.level;
      point.halfWidth = p.half;
      point.fall = p.fall;
      point.below = p.below;
      desc.points.push_back(point);
    }
    return desc;
  }

  std::vector<Emitter> EmittersOf(
    const SRiverDesc& desc
  )
  {
    std::vector<SRiverFall> falls;
    const std::vector<SRiverSegment> segments = moho::RiverSegments(desc, &falls);
    return BuildEmitters(falls, segments);
  }

  float Length(
    const float x,
    const float z
  )
  {
    return std::sqrt(x * x + z * z);
  }
} // namespace

TEST(
  WaterfallEmitters,
  a_fall_is_an_emitter_with_the_surface_above_and_below
)
{
  const std::vector<Emitter> emitters = EmittersOf(RiverA());
  int falls = 0;
  for (const Emitter& e : emitters) {
    if (e.kind != Kind::Fall) {
      continue;
    }
    ++falls;
    EXPECT_NEAR(e.x, 130.0f, 0.01f);
    EXPECT_NEAR(e.z, 76.0f, 0.01f);
    EXPECT_NEAR(e.top, 39.0f, 0.001f);
    EXPECT_NEAR(e.bottom, 31.5f, 0.001f);
    EXPECT_NEAR(e.halfWidth, 7.0f, 0.001f);
    EXPECT_NEAR(Length(e.tx, e.tz), 1.0f, 0.01f);
  }
  EXPECT_EQ(falls, 1);
}

TEST(
  WaterfallEmitters,
  rapids_stand_on_steep_reaches_only_and_are_spaced
)
{
  const SRiverDesc desc = RiverA();
  std::vector<SRiverFall> falls;
  const std::vector<SRiverSegment> segments = moho::RiverSegments(desc, &falls);
  const std::vector<Emitter> emitters = BuildEmitters(falls, segments);
  int rapids = 0;
  for (const Emitter& e : emitters) {
    if (e.kind != Kind::Rapid) {
      continue;
    }
    ++rapids;
    EXPECT_GE(e.slope, kRapidMinSlope);
    EXPECT_FLOAT_EQ(e.top, e.bottom);
    // Every rapid lies on a segment whose own drop per length is the emitter's slope.
    bool onSegment = false;
    for (const SRiverSegment& s : segments) {
      const float slope = (s.level0 - s.level1) / s.length;
      const float cross = (e.x - s.x0) * s.tz - (e.z - s.z0) * s.tx;
      const float along = (e.x - s.x0) * s.tx + (e.z - s.z0) * s.tz;
      if (
        std::fabs(cross) < 0.01f && along >= -0.01f && along <= s.length + 0.01f && std::fabs(slope - e.slope) < 1.0e-4f
      ) {
        onSegment = true;
      }
    }
    EXPECT_TRUE(onSegment);
  }
  EXPECT_GT(rapids, 0);
  // Flat reaches (a pool) make none: the slope of every segment that is under the threshold has no emitter on it.
  for (const SRiverSegment& s : segments) {
    const float slope = (s.level0 - s.level1) / s.length;
    if (slope >= kRapidMinSlope) {
      continue;
    }
    for (const Emitter& e : emitters) {
      if (e.kind != Kind::Rapid) {
        continue;
      }
      const float cross = (e.x - s.x0) * s.tz - (e.z - s.z0) * s.tx;
      const float along = (e.x - s.x0) * s.tx + (e.z - s.z0) * s.tz;
      const bool onIt = std::fabs(cross) < 0.01f && along > 0.01f && along < s.length - 0.01f;
      EXPECT_FALSE(onIt && std::fabs(e.slope - slope) < 1.0e-4f);
    }
  }
}

TEST(
  WaterfallEmitters,
  a_flat_river_without_a_fall_has_no_emitters
)
{
  SRiverDesc desc;
  for (int i = 0; i < 3; ++i) {
    SRiverPoint p;
    p.x = 10.0f + 40.0f * static_cast<float>(i);
    p.z = 20.0f;
    p.level = 30.0f;
    p.halfWidth = 4.0f;
    desc.points.push_back(p);
  }
  EXPECT_TRUE(EmittersOf(desc).empty());
}

TEST(
  WaterfallEmitters,
  rapids_are_capped
)
{
  std::vector<SRiverSegment> segments;
  for (int i = 0; i < 400; ++i) {
    SRiverSegment s;
    s.x0 = 0.0f;
    s.z0 = 0.0f;
    s.x1 = 60.0f;
    s.z1 = 0.0f;
    s.level0 = 50.0f;
    s.level1 = 40.0f;
    s.half0 = s.half1 = 3.0f;
    s.length = 60.0f;
    s.tx = 1.0f;
    s.tz = 0.0f;
    segments.push_back(s);
  }
  EXPECT_EQ(BuildEmitters({}, segments).size(), kMaxRapidsPerRiver);
}

namespace
{
  Emitter TestFall()
  {
    Emitter fall;
    fall.kind = Kind::Fall;
    fall.x = 130.0f;
    fall.z = 76.0f;
    fall.tx = 0.8f;
    fall.tz = 0.6f;
    fall.halfWidth = 7.0f;
    fall.top = 39.0f;
    fall.bottom = 31.5f;
    return fall;
  }

  // Distance of a point of a strip past the lip line (downstream) and across the flow, from the middle of the lip.
  float AlongOf(
    const Emitter& fall,
    const Strip& s,
    const int k
  )
  {
    return (s.x[k] - fall.x) * fall.tx + (s.z[k] - fall.z) * fall.tz;
  }
  float AcrossOf(
    const Emitter& fall,
    const Strip& s,
    const int k
  )
  {
    return (s.x[k] - fall.x) * -fall.tz + (s.z[k] - fall.z) * fall.tx;
  }

  Shape PlainShape(
    const int segments = 8
  )
  {
    Shape shape;
    shape.bulge = 0.0f;
    shape.fray = 0.0f;
    shape.segments = segments;
    return shape;
  }
} // namespace

TEST(
  WaterfallCurtain,
  strips_cover_the_lip_across_the_flow
)
{
  const Emitter fall = TestFall();
  std::vector<Strip> strips;
  CurtainStrips(fall, 1.5f, PlainShape(), strips);
  ASSERT_EQ(static_cast<int>(strips.size()), CurtainStripCount(7.0f, 1.5f));
  EXPECT_EQ(strips.size(), 10u);
  float minAcross = 1.0e9f;
  float maxAcross = -1.0e9f;
  for (const Strip& s : strips) {
    ASSERT_EQ(s.points, 9);
    // Plain shape: the first point is on the lip line, at the surface above it, the last at the surface below.
    EXPECT_FLOAT_EQ(s.y[0], 39.0f);
    EXPECT_FLOAT_EQ(s.y[8], 31.5f);
    EXPECT_NEAR(AlongOf(fall, s, 0), 0.0f, 1.0e-3f);
    const float across = AcrossOf(fall, s, 0);
    minAcross = std::min(minAcross, across);
    maxAcross = std::max(maxAcross, across);
    // The foot is downstream of the lip: the water is thrown past it.
    EXPECT_GT(AlongOf(fall, s, 8), 0.2f);
    // Neighbours overlap: the ribbon (twice `width`) is wider than the spacing.
    for (int k = 0; k < s.points; ++k) {
      EXPECT_GT(2.0f * s.width[k], 1.5f);
    }
    EXPECT_GT(s.speed, 5.0f);
  }
  EXPECT_NEAR(minAcross, -maxAcross, 1.0e-3f);
  EXPECT_LE(maxAcross, 7.0f);
  EXPECT_GT(maxAcross, 5.5f);
}

TEST(
  WaterfallCurtain,
  a_strip_follows_a_ballistic_arc_from_the_lip_to_the_foot
)
{
  const Emitter fall = TestFall();
  std::vector<Strip> strips;
  CurtainStrips(fall, 1.5f, PlainShape(8), strips);
  ASSERT_FALSE(strips.empty());
  // The strip in the middle of the channel.
  const Strip& s = strips[strips.size() / 2];
  float previousAlong = -1.0e9f;
  float previousY = 1.0e9f;
  float firstSlope = 0.0f;
  float lastSlope = 0.0f;
  float shortest = 1.0e9f;
  float longest = 0.0f;
  for (int k = 0; k < s.points; ++k) {
    const float along = AlongOf(fall, s, k);
    // Out and down at every point: no wobble in a plain shape.
    EXPECT_GT(along, previousAlong);
    EXPECT_LT(s.y[k], previousY);
    if (k > 0) {
      const float dAlong = along - previousAlong;
      const float dDown = previousY - s.y[k];
      const float length = std::sqrt(dAlong * dAlong + dDown * dDown);
      shortest = std::min(shortest, length);
      longest = std::max(longest, length);
      if (k == 1) {
        firstSlope = dDown / dAlong;
      }
      if (k == s.points - 1) {
        lastSlope = dDown / dAlong;
      }
    }
    previousAlong = along;
    previousY = s.y[k];
  }
  // It leaves the lip nearly horizontally and hits the pool nearly vertically: a parabola, not a slanted line.
  EXPECT_LT(firstSlope, 1.5f);
  EXPECT_GT(lastSlope, 3.0f);
  EXPECT_GT(lastSlope, 3.0f * firstSlope);
  // The pieces are about as long as each other (the points are spread by the length of the arc).
  EXPECT_LT(longest, 1.35f * shortest);
  // The throw is the one of the foot: the foot's offset minus the standing one.
  EXPECT_NEAR(AlongOf(fall, s, 8) - AlongOf(fall, s, 0), FootOffset(fall) - 0.25f, 0.05f);
  // More arc throws further; none drops straight down.
  Emitter far = fall;
  far.arc = 2.0f;
  Emitter none = fall;
  none.arc = 0.0f;
  EXPECT_GT(FootOffset(far), FootOffset(fall));
  EXPECT_GT(FootOffset(fall), FootOffset(none));
  EXPECT_NEAR(FootOffset(none), 0.25f, 1.0e-4f);
  std::vector<Strip> straight;
  CurtainStrips(none, 1.5f, PlainShape(8), straight);
  ASSERT_FALSE(straight.empty());
  for (int k = 0; k < straight[0].points; ++k) {
    EXPECT_NEAR(AlongOf(none, straight[0], k), 0.0f, 1.0e-3f);
  }
}

TEST(
  WaterfallCurtain,
  the_channel_makes_the_middle_thicker_and_the_edges_taper
)
{
  const Emitter fall = TestFall();
  Shape shape;
  shape.fray = 0.0f;
  shape.segments = 8;
  std::vector<Strip> strips;
  CurtainStrips(fall, 1.5f, shape, strips);
  ASSERT_GE(strips.size(), 6u);
  const Strip& edge = strips.front();
  const Strip& middle = strips[strips.size() / 2];
  for (int k = 1; k < middle.points; ++k) {
    EXPECT_GT(middle.width[k], edge.width[k]);
    EXPECT_GT(middle.alpha[k], edge.alpha[k]);
  }
  // The edge strip narrows as it falls, the middle one does not (it spreads over the pool instead).
  EXPECT_LT(edge.width[4], edge.width[0]);
  EXPECT_GT(middle.width[8], middle.width[4]);
  // The lip bows downstream in the middle of the channel: the middle strip starts further out than the edge strip.
  EXPECT_GT(AlongOf(fall, middle, 0), AlongOf(fall, edge, 0) + 0.1f);
  // The sheet gets denser as it falls.
  EXPECT_GT(middle.alpha[8], middle.alpha[0]);
  for (const Strip& s : strips) {
    for (int k = 0; k < s.points; ++k) {
      EXPECT_GE(s.alpha[k], 0.0f);
      EXPECT_LE(s.alpha[k], 1.0f);
      EXPECT_GT(s.width[k], 0.0f);
    }
  }
  // With the cross-section switched off every strip is alike.
  Shape flat = PlainShape();
  std::vector<Strip> even;
  CurtainStrips(fall, 1.5f, flat, even);
  ASSERT_GE(even.size(), 6u);
  EXPECT_FLOAT_EQ(even.front().width[3], even[even.size() / 2].width[3]);
}

TEST(
  WaterfallCurtain,
  fray_makes_strips_differ_and_moves_with_the_game_time_only
)
{
  const Emitter fall = TestFall();
  Shape shape;
  shape.segments = 8;
  std::vector<Strip> a;
  std::vector<Strip> b;
  std::vector<Strip> c;
  CurtainStrips(fall, 1.5f, shape, a);
  CurtainStrips(fall, 1.5f, shape, b);
  shape.time = 3.0f;
  CurtainStrips(fall, 1.5f, shape, c);
  ASSERT_EQ(a.size(), b.size());
  ASSERT_EQ(a.size(), c.size());
  bool timeMoves = false;
  float minSpeed = 1.0e9f;
  float maxSpeed = 0.0f;
  float minThrow = 1.0e9f;
  float maxThrow = -1.0e9f;
  for (std::size_t i = 0; i < a.size(); ++i) {
    // The same inputs give the same strips (no random stream, a hash of the place), a later time moves the undulation.
    for (int k = 0; k < a[i].points; ++k) {
      EXPECT_FLOAT_EQ(a[i].x[k], b[i].x[k]);
      EXPECT_FLOAT_EQ(a[i].z[k], b[i].z[k]);
      timeMoves = timeMoves || std::fabs(a[i].x[k] - c[i].x[k]) > 1.0e-3f;
      // The lip and the heights do not depend on the time.
      EXPECT_FLOAT_EQ(a[i].y[k], c[i].y[k]);
    }
    minSpeed = std::min(minSpeed, a[i].speed);
    maxSpeed = std::max(maxSpeed, a[i].speed);
    const float thrown = AlongOf(fall, a[i], a[i].points - 1);
    minThrow = std::min(minThrow, thrown);
    maxThrow = std::max(maxThrow, thrown);
    // A strip may end a little above the foot, never below it, and stays under the lip.
    EXPECT_GE(a[i].y[a[i].points - 1], 31.5f - 1.0e-4f);
    EXPECT_LT(a[i].y[a[i].points - 1], 39.0f);
    EXPECT_FLOAT_EQ(a[i].y[0], 39.0f);
  }
  EXPECT_TRUE(timeMoves);
  EXPECT_GT(maxSpeed, minSpeed * 1.05f);
  // The strips are not thrown alike (the middle ones further than the banks, and each a little differently).
  EXPECT_GT(maxThrow, minThrow + 0.2f);

  // Fray 0: no variation of speed, and a fall of another place gets another variation.
  Shape calm;
  calm.fray = 0.0f;
  std::vector<Strip> still;
  CurtainStrips(fall, 1.5f, calm, still);
  for (const Strip& s : still) {
    EXPECT_FLOAT_EQ(s.speed, still.front().speed);
  }
  Emitter elsewhere = fall;
  elsewhere.x += 40.0f;
  std::vector<Strip> other;
  Shape shape2;
  CurtainStrips(elsewhere, 1.5f, shape2, other);
  bool differs = false;
  for (std::size_t i = 0; i < a.size() && i < other.size(); ++i) {
    differs = differs || std::fabs(a[i].speed - other[i].speed) > 1.0e-4f;
  }
  EXPECT_TRUE(differs);
}

TEST(
  WaterfallCurtain,
  the_segment_count_is_clamped_and_follows_the_quality
)
{
  const Emitter fall = TestFall();
  for (const int wanted : {-3, 0, 1, 5, 12, 40}) {
    Shape shape;
    shape.segments = wanted;
    std::vector<Strip> strips;
    CurtainStrips(fall, 1.5f, shape, strips);
    ASSERT_FALSE(strips.empty());
    const int expected = std::min(std::max(wanted, 1), kMaxCurtainSegments) + 1;
    for (const Strip& s : strips) {
      EXPECT_EQ(s.points, expected);
    }
  }
  EXPECT_EQ(QualityOf(1).curtainSegments, 5);
  EXPECT_EQ(QualityOf(2).curtainSegments, 8);
  EXPECT_EQ(QualityOf(3).curtainSegments, 10);
  EXPECT_LE(QualityOf(3).curtainSegments, kMaxCurtainSegments);
  // The beams of the budget: strips times pieces, per level.
  EXPECT_LE(QualityOf(3).maxStrips * QualityOf(3).curtainSegments, 4000);
}

TEST(
  WaterfallCurtain,
  the_foot_follows_the_throw
)
{
  Emitter fall = TestFall();
  Rng rng;
  rng.state = 777u;
  const float foot = FootOffset(fall);
  EXPECT_GT(foot, 1.5f);
  for (int i = 0; i < 300; ++i) {
    const ParticleSpec splash = SpawnParticle(Layer::Splash, fall, rng);
    const float along = (splash.x - fall.x) * fall.tx + (splash.z - fall.z) * fall.tz;
    EXPECT_GE(along, foot - 1.0e-3f);
    EXPECT_LE(along, foot + 1.6f + 1.0e-3f);
  }
  std::vector<FoamSource> sources;
  FoamSources(fall, sources);
  ASSERT_FALSE(sources.empty());
  for (const FoamSource& s : sources) {
    const float along = (s.x - fall.x) * fall.tx + (s.z - fall.z) * fall.tz;
    EXPECT_NEAR(along, foot + 1.0f, 1.0e-3f);
  }
}

TEST(
  WaterfallCurtain,
  a_rapid_has_no_curtain_and_counts_are_bounded
)
{
  Emitter rapid;
  rapid.kind = Kind::Rapid;
  rapid.halfWidth = 5.0f;
  std::vector<Strip> strips;
  CurtainStrips(rapid, 1.5f, Shape{}, strips);
  EXPECT_TRUE(strips.empty());
  EXPECT_EQ(CurtainStripCount(0.0f, 1.5f), 0);
  EXPECT_EQ(CurtainStripCount(5.0f, 0.0f), 0);
  EXPECT_EQ(CurtainStripCount(0.3f, 1.5f), 1);
  EXPECT_EQ(CurtainStripCount(500.0f, 1.0f), 64);
}

TEST(
  WaterfallQuality,
  levels_widen_the_range_and_the_budgets
)
{
  const Quality off = QualityOf(0);
  const Quality low = QualityOf(1);
  const Quality normal = QualityOf(2);
  const Quality high = QualityOf(3);
  EXPECT_EQ(off.range, 0.0f);
  EXPECT_EQ(off.maxStrips, 0);
  EXPECT_EQ(off.maxParticles, 0);
  EXPECT_FLOAT_EQ(low.range, 150.0f);
  EXPECT_FLOAT_EQ(normal.range, 250.0f);
  EXPECT_FLOAT_EQ(high.range, 400.0f);
  EXPECT_LT(low.maxParticles, normal.maxParticles);
  EXPECT_LT(normal.maxParticles, high.maxParticles);
  EXPECT_LT(low.maxStrips, normal.maxStrips);
  EXPECT_GT(low.stripSpacing, high.stripSpacing);
  EXPECT_FALSE(low.spray);
  EXPECT_TRUE(normal.spray);
  EXPECT_EQ(QualityOf(-5).level, 0);
  EXPECT_EQ(QualityOf(99).level, 3);
}

TEST(
  WaterfallRates,
  a_bigger_drop_and_a_wider_fall_throw_more
)
{
  Emitter small;
  small.kind = Kind::Fall;
  small.halfWidth = 3.0f;
  small.top = 10.0f;
  small.bottom = 8.0f;
  Emitter wide = small;
  wide.halfWidth = 6.0f;
  Emitter tall = small;
  tall.top = 20.0f;
  EXPECT_GT(RatesOf(wide).splash, RatesOf(small).splash);
  EXPECT_GT(RatesOf(tall).splash, RatesOf(small).splash);
  EXPECT_GT(RatesOf(tall).mist, RatesOf(small).mist);
  EXPECT_FLOAT_EQ(RatesOf(small).spray, 0.0f);

  Emitter rapid;
  rapid.kind = Kind::Rapid;
  rapid.halfWidth = 5.0f;
  rapid.slope = 0.08f;
  EXPECT_GT(RatesOf(rapid).spray, 0.0f);
  EXPECT_FLOAT_EQ(RatesOf(rapid).splash, 0.0f);
  EXPECT_FLOAT_EQ(RatesOf(rapid).mist, 0.0f);
  Emitter steeper = rapid;
  steeper.slope = 0.16f;
  EXPECT_GT(RatesOf(steeper).spray, RatesOf(rapid).spray);
}

TEST(
  WaterfallRates,
  far_water_is_thinner_and_nothing_comes_from_beyond_the_range
)
{
  EXPECT_FLOAT_EQ(DistanceRate(10.0f, 250.0f), 1.0f);
  EXPECT_FLOAT_EQ(DistanceRate(100.0f, 250.0f), 1.0f);
  EXPECT_NEAR(DistanceRate(250.0f, 250.0f), kFarRate, 1.0e-5f);
  EXPECT_GT(DistanceRate(175.0f, 250.0f), kFarRate);
  EXPECT_LT(DistanceRate(175.0f, 250.0f), 1.0f);
  EXPECT_FLOAT_EQ(DistanceRate(251.0f, 250.0f), 0.0f);
  EXPECT_FLOAT_EQ(DistanceRate(10.0f, 0.0f), 0.0f);
}

TEST(
  WaterfallRates,
  the_accumulator_gives_whole_particles_and_keeps_the_rest
)
{
  float carry = 0.0f;
  int total = 0;
  for (int i = 0; i < 60; ++i) {
    total += TakeEmission(10.0f, 1.0f / 60.0f, carry);
  }
  // 10 a second for one second: 10 (within the float error of the last one).
  EXPECT_GE(total, 9);
  EXPECT_LE(total, 10);
  EXPECT_LT(carry, 1.0f);
  // Paused (no time) and a rate of 0 emit nothing and keep the carry.
  float kept = 0.4f;
  EXPECT_EQ(TakeEmission(50.0f, 0.0f, kept), 0);
  EXPECT_FLOAT_EQ(kept, 0.4f);
  EXPECT_EQ(TakeEmission(0.0f, 1.0f, kept), 0);
  // A stall does not flood: at most kMaxBurst at once.
  float stall = 0.0f;
  EXPECT_EQ(TakeEmission(100.0f, 5.0f, stall), kMaxBurst);
}

TEST(
  WaterfallParticles,
  a_splash_springs_from_the_foot_and_the_mist_stays_over_it
)
{
  Emitter fall;
  fall.kind = Kind::Fall;
  fall.x = 50.0f;
  fall.z = 50.0f;
  fall.tx = 1.0f;
  fall.tz = 0.0f;
  fall.halfWidth = 7.0f;
  fall.top = 39.0f;
  fall.bottom = 31.5f;
  Rng rng;
  rng.state = 12345u;
  for (int i = 0; i < 500; ++i) {
    const ParticleSpec splash = SpawnParticle(Layer::Splash, fall, rng);
    EXPECT_GE(splash.x, 50.0f);
    EXPECT_LE(std::fabs(splash.z - 50.0f), 7.0f);
    EXPECT_GT(splash.y, 31.5f);
    EXPECT_LT(splash.y, 31.9f);
    EXPECT_GT(splash.vy, 0.0f);
    EXPECT_LT(splash.ay, 0.0f);
    EXPECT_GE(splash.lifetime, 1.2f);
    EXPECT_LE(splash.lifetime, 2.4f);
    EXPECT_LT(splash.beginSize, splash.endSize);
    // It falls back to the foot before it dies: apex under a few metres for a fall of 7.5.
    const float apex = splash.vy * splash.vy / (-2.0f * splash.ay);
    EXPECT_LT(apex, 5.0f);

    const ParticleSpec mist = SpawnParticle(Layer::Mist, fall, rng);
    EXPECT_GT(mist.y, 31.5f);
    EXPECT_LT(mist.y, 34.0f);
    EXPECT_GE(mist.lifetime, 3.0f);
    EXPECT_GT(mist.endSize, mist.beginSize);
    EXPECT_GT(mist.vx, 0.0f); // drifts downstream
  }
}

TEST(
  WaterfallParticles,
  spray_rises_from_the_surface_of_a_rapid_and_goes_with_the_flow
)
{
  Emitter rapid;
  rapid.kind = Kind::Rapid;
  rapid.x = 100.0f;
  rapid.z = 60.0f;
  rapid.tx = 0.0f;
  rapid.tz = 1.0f;
  rapid.halfWidth = 6.0f;
  rapid.top = rapid.bottom = 41.0f;
  rapid.slope = 0.07f;
  Rng rng;
  rng.state = 99u;
  for (int i = 0; i < 200; ++i) {
    const ParticleSpec p = SpawnParticle(Layer::Spray, rapid, rng);
    EXPECT_GT(p.y, 41.0f);
    EXPECT_GT(p.vz, 0.0f);
    EXPECT_GT(p.vy, 0.0f);
    EXPECT_LE(p.lifetime, 1.5f);
  }
}

TEST(
  WaterfallParticles,
  the_same_seed_gives_the_same_particles
)
{
  Emitter fall;
  fall.kind = Kind::Fall;
  fall.halfWidth = 5.0f;
  fall.top = 10.0f;
  fall.bottom = 4.0f;
  Rng a;
  Rng b;
  a.state = b.state = 777u;
  for (int i = 0; i < 20; ++i) {
    const ParticleSpec pa = SpawnParticle(Layer::Splash, fall, a);
    const ParticleSpec pb = SpawnParticle(Layer::Splash, fall, b);
    EXPECT_EQ(pa.x, pb.x);
    EXPECT_EQ(pa.vy, pb.vy);
    EXPECT_EQ(pa.lifetime, pb.lifetime);
  }
}

TEST(
  WaterfallFoam,
  a_fall_foams_across_its_foot_and_a_rapid_in_one_disc
)
{
  Emitter fall;
  fall.kind = Kind::Fall;
  fall.x = 0.0f;
  fall.z = 0.0f;
  fall.tx = 1.0f;
  fall.tz = 0.0f;
  fall.halfWidth = 7.0f;
  fall.top = 39.0f;
  fall.bottom = 31.5f;
  std::vector<FoamSource> sources;
  FoamSources(fall, sources);
  ASSERT_EQ(sources.size(), 5u); // 14 units of width, one disc every 3
  float minZ = 1.0e9f;
  float maxZ = -1.0e9f;
  for (const FoamSource& s : sources) {
    EXPECT_GT(s.x, 0.0f); // downstream of the lip
    EXPECT_GT(s.radius, 1.5f);
    EXPECT_GT(s.foam, 0.0f);
    minZ = std::min(minZ, s.z);
    maxZ = std::max(maxZ, s.z);
  }
  EXPECT_LT(minZ, -4.0f);
  EXPECT_GT(maxZ, 4.0f);

  Emitter rapid;
  rapid.kind = Kind::Rapid;
  rapid.x = 5.0f;
  rapid.z = 6.0f;
  rapid.halfWidth = 4.0f;
  rapid.slope = 0.07f;
  std::vector<FoamSource> one;
  FoamSources(rapid, one);
  ASSERT_EQ(one.size(), 1u);
  EXPECT_FLOAT_EQ(one[0].x, 5.0f);
  EXPECT_FLOAT_EQ(one[0].z, 6.0f);
  EXPECT_LT(one[0].foam, sources[0].foam); // a rapid foams less than the pool of a fall
}

TEST(
  WaterfallBudget,
  the_nearest_are_served_first_within_the_range_and_the_budget
)
{
  std::vector<Candidate> candidates = {
    {0, 200.0f, 10},
    {1, 30.0f, 10},
    {2, 90.0f, 10},
    {3, 300.0f, 10},
    {4, 60.0f, 10},
  };
  std::vector<Candidate> chosen = SelectWithinBudget(candidates, 250.0f, 100);
  ASSERT_EQ(chosen.size(), 4u); // the one at 300 is out of range
  EXPECT_EQ(chosen[0].index, 1u);
  EXPECT_EQ(chosen[1].index, 4u);
  EXPECT_EQ(chosen[2].index, 2u);
  EXPECT_EQ(chosen[3].index, 0u);

  chosen = SelectWithinBudget(candidates, 250.0f, 25);
  ASSERT_EQ(chosen.size(), 2u); // two fit
  EXPECT_EQ(chosen[0].index, 1u);
  EXPECT_EQ(chosen[1].index, 4u);

  // One that does not fit is skipped and a cheaper one behind it is taken.
  candidates = {{0, 10.0f, 20}, {1, 20.0f, 30}, {2, 30.0f, 5}};
  chosen = SelectWithinBudget(candidates, 100.0f, 30);
  ASSERT_EQ(chosen.size(), 2u);
  EXPECT_EQ(chosen[0].index, 0u);
  EXPECT_EQ(chosen[1].index, 2u);

  EXPECT_TRUE(SelectWithinBudget(candidates, 100.0f, 0).empty());
  EXPECT_TRUE(SelectWithinBudget(candidates, 0.0f, 100).empty());
}

namespace
{
  // A camera at the origin looking down +z with a 90 degree field of view (row vectors, Direct3D depth 0..1, near 1,
  // far 1000): clip = (x, y, z, 1) * M.
  void LookDownZ(
    float (&m)[16]
  )
  {
    const float n = 1.0f;
    const float f = 1000.0f;
    for (float& v : m) {
      v = 0.0f;
    }
    m[0] = 1.0f;              // x -> clip x
    m[5] = 1.0f;              // y -> clip y
    m[10] = f / (f - n);      // z -> clip z
    m[11] = 1.0f;             // z -> clip w
    m[14] = -n * f / (f - n); // clip z offset
  }
} // namespace

TEST(
  WaterfallView,
  the_frustum_keeps_what_is_in_front_and_drops_the_rest
)
{
  float m[16];
  LookDownZ(m);
  const Frustum frustum = FrustumOf(m);
  EXPECT_TRUE(SphereInFrustum(frustum, 0.0f, 0.0f, 50.0f, 1.0f));
  EXPECT_TRUE(SphereInFrustum(frustum, 40.0f, 0.0f, 50.0f, 1.0f));   // 40 of 50: inside the 45 degree half angle
  EXPECT_FALSE(SphereInFrustum(frustum, 80.0f, 0.0f, 50.0f, 1.0f));  // far to the side
  EXPECT_TRUE(SphereInFrustum(frustum, 80.0f, 0.0f, 50.0f, 40.0f));  // a big sphere reaches in
  EXPECT_FALSE(SphereInFrustum(frustum, 0.0f, 0.0f, -50.0f, 1.0f));  // behind
  EXPECT_FALSE(SphereInFrustum(frustum, 0.0f, 80.0f, 50.0f, 1.0f));  // above
  EXPECT_FALSE(SphereInFrustum(frustum, 0.0f, -80.0f, 50.0f, 1.0f)); // below
  EXPECT_TRUE(SphereInFrustum(frustum, 0.0f, 0.0f, -2.0f, 3.0f));    // straddles the near plane
}

TEST(
  WaterfallClock,
  runs_with_the_game_and_stands_when_it_is_paused
)
{
  GameClock clock;
  EXPECT_FLOAT_EQ(clock.Advance(0, 100.0), 0.0f); // the first call has no frame behind it
  // One second of wall time at 60 frames a second, ten ticks a second: the game runs at speed 1.
  double wall = 100.0;
  int tick = 0;
  double total = 0.0;
  for (int frame = 1; frame <= 60; ++frame) {
    wall += 1.0 / 60.0;
    tick = static_cast<int>(std::floor((wall - 100.0) * 10.0));
    total += clock.Advance(tick, wall);
  }
  EXPECT_FALSE(clock.Paused());
  EXPECT_NEAR(total, 1.0, 0.1);
  EXPECT_NEAR(clock.Speed(), 1.0f, 0.15f);

  // No new tick for half a second: paused, nothing passes.
  double pausedTotal = 0.0;
  for (int frame = 1; frame <= 60; ++frame) {
    wall += 1.0 / 60.0;
    pausedTotal += clock.Advance(tick, wall);
  }
  EXPECT_TRUE(clock.Paused());
  // The first third of a second still counts (the game may only have lagged); the rest is 0.
  EXPECT_LT(pausedTotal, 0.4);
  float after = 0.0f;
  for (int frame = 1; frame <= 30; ++frame) {
    wall += 1.0 / 60.0;
    after += clock.Advance(tick, wall);
  }
  EXPECT_FLOAT_EQ(after, 0.0f);

  // And on again.
  tick += 1;
  wall += 1.0 / 60.0;
  EXPECT_GT(clock.Advance(tick, wall), 0.0f);
  EXPECT_FALSE(clock.Paused());
}

TEST(
  WaterfallClock,
  a_stall_of_one_frame_is_not_made_up_for
)
{
  GameClock clock;
  (void)clock.Advance(0, 0.0);
  (void)clock.Advance(1, 0.1);
  EXPECT_LE(clock.Advance(2, 5.0), 0.1f);
}

TEST(
  WaterfallLive,
  the_cap_holds_and_particles_die
)
{
  LiveCounter live;
  int added = 0;
  for (int i = 0; i < 20; ++i) {
    if (live.TryAdd(0.0, 2.0f, 10)) {
      ++added;
    }
  }
  EXPECT_EQ(added, 10);
  EXPECT_EQ(live.Live(1.0), 10);
  EXPECT_FALSE(live.TryAdd(1.0, 2.0f, 10));
  EXPECT_EQ(live.Live(2.5), 0);
  EXPECT_TRUE(live.TryAdd(2.5, 1.0f, 10));
  live.Clear();
  EXPECT_EQ(live.Live(2.5), 0);
  EXPECT_FALSE(live.TryAdd(0.0, 1.0f, 0));
}

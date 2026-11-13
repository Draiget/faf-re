#include "moho/terrain/water/Waterfall.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/console/CConCommand.h"
#include "moho/math/Vector4f.h"
#include "moho/misc/CountedObject.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/ParticleEffectPatch.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/WRenViewport.h"
#include "moho/resource/CParticleTexture.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"
#include "moho/terrain/water/WaterSimulation.h"
#include "moho/terrain/water/WaterfallPlan.h"

namespace moho::water::falls
{
  int ren_Waterfalls = 2;
  static int ren_WaterfallFoam = 100;
  static int ren_WaterfallLog = 0;
  // The shape of the curtain (WaterfallPlan.h `Shape`, `Emitter::arc`).
  static float ren_WaterfallArc = 1.0f;
  static float ren_WaterfallBulge = 1.0f;
  static float ren_WaterfallFray = 1.0f;

  static TConVar<int> gTConVar_ren_Waterfalls(
    "ren_Waterfalls",
    "Waterfalls and rapids of the rivers of a map (water bodies with a River): a curtain of water from the lip to the "
    "foot of a fall, splash and mist at its foot, spray on steep reaches, foam in the pool. Only what is near the "
    "camera and in view is made. 0 off, 1 low, 2 (the default) normal, 3 high (the range and the number of particles "
    "grow with the level). Maps without rivers are not affected. docs/projects/RIVERS.md.",
    &ren_Waterfalls
  );
  static TConVar<int> gTConVar_ren_WaterfallFoam(
    "ren_WaterfallFoam",
    "How much foam the falls and rapids throw into the wave simulation, in percent (default 100, 0 none). Needs "
    "ren_WaterSim and ren_Waterfalls.",
    &ren_WaterfallFoam
  );
  static TConVar<float> gTConVar_ren_WaterfallArc(
    "ren_WaterfallArc",
    "How far the curtain of a fall is thrown past the lip, as a multiple of the ballistic throw: the water leaves the "
    "lip horizontally at the speed of the river and falls under gravity, so the sheet arcs outward and the splash and "
    "foam land where it lands. 1 (default) natural, 0 a straight vertical sheet, up to 3.",
    &ren_WaterfallArc
  );
  static TConVar<float> gTConVar_ren_WaterfallBulge(
    "ren_WaterfallBulge",
    "How much the curtain follows the cross-section of the channel: the lip bows downstream in the middle, the water "
    "is "
    "thicker and denser in the middle than at the banks, the edge strips taper and the sheet narrows a little while "
    "it falls and spreads over the pool. 1 (default), 0 a flat sheet of even strips, up to 3.",
    &ren_WaterfallBulge
  );
  static TConVar<float> gTConVar_ren_WaterfallFray(
    "ren_WaterfallFray",
    "How much the strips of a curtain differ (throw, length, speed) and how much it undulates sideways, so it is not a "
    "rigid plane. 1 (default), 0 identical strips, up to 3.",
    &ren_WaterfallFray
  );
  static TConVar<int> gTConVar_ren_WaterfallLog(
    "ren_WaterfallLog",
    "Diagnostic: every N rendered frames the waterfalls log what they made (falls and rapids served, particles, beams, "
    "foam sources, the clock); 0 (the default) off.",
    &ren_WaterfallLog
  );

  namespace
  {
    // Where the textures are: the shipped particle set for the splash and the mist, our own streak for the curtain.
    constexpr const char* kSplashTexture = "/textures/particles/water_splash_alpha_03.dds";
    constexpr const char* kSprayTexture = "/textures/particles/water_splash_alpha_04.dds";
    constexpr const char* kSplashRamp = "/textures/particles/ramp_water_01.dds";
    constexpr const char* kMistTexture = "/textures/particles/cloud_white_alpha_01.dds";
    constexpr const char* kMistRamp = "/textures/particles/ramp_white_04.dds";
    constexpr const char* kStreakTexture = "/fafengine/textures/particles/waterfall_streak_01.dds";

    // The particle renderer sorts its buckets by this and draws the ones at or above the water surface sort order
    // (efx_ParticleWaterSurface, -101) after the water: ours stand over the water.
    constexpr float kSplashSort = -95.0f;
    constexpr float kMistSort = -94.0f;

    // The curtain: water colour (a little blue, nearly white) from the lip to the foot, the alphas are the plan's.
    // How many repeats of the streak texture to a unit of the beam's length (one repeat every 4 units).
    constexpr float kCurtainRepeat = 0.25f;

    CParticleTexture* Hold(
      const char* const path
    )
    {
      auto* const texture = new CParticleTexture(path);
      static_cast<CountedObject*>(texture)->AddReferenceAtomic();
      return texture;
    }

    struct Textures
    {
      CParticleTexture* splash{nullptr};
      CParticleTexture* splashRamp{nullptr};
      CParticleTexture* spray{nullptr};
      CParticleTexture* mist{nullptr};
      CParticleTexture* mistRamp{nullptr};
      CParticleTexture* streak{nullptr};

      // Made on first use and kept for the life of the process, as the wave generators keep theirs.
      void Ensure()
      {
        if (splash == nullptr) {
          splash = Hold(kSplashTexture);
          splashRamp = Hold(kSplashRamp);
          spray = Hold(kSprayTexture);
          mist = Hold(kMistTexture);
          mistRamp = Hold(kMistRamp);
          streak = Hold(kStreakTexture);
        }
      }
    };

    struct State
    {
      const STIMap* map{nullptr};
      std::uint32_t generation{0};
      std::vector<Emitter> emitters;
      // Per emitter, the part of a particle owed to each layer.
      std::vector<float> carry;
      GameClock clock;
      LiveCounter live;
      Rng rng;
      Textures textures;
      Stats stats;
      std::uint32_t logFrames{0};
      bool seeded{false};
    };

    State& GetState()
    {
      static State state;
      return state;
    }

    // The map the renderer draws: the session's map in a game.
    const STIMap* RenderMap()
    {
      IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
      return terrainRes != nullptr ? terrainRes->mMap : nullptr;
    }

    // Rebuilds the emitters when the map or its water bodies changed; false when the map has no rivers with anything
    // to throw.
    bool Refresh(
      State& s,
      const STIMap* const map
    )
    {
      if (map == nullptr || !map->HasWaterBodies() || !map->mWaterBodies->HasRivers()) {
        if (!s.emitters.empty() || s.map != nullptr) {
          s.emitters.clear();
          s.carry.clear();
          s.live.Clear();
          s.map = nullptr;
          s.generation = 0;
          s.stats.emitters = 0;
        }
        return false;
      }
      const CWaterBodies& bodies = *map->mWaterBodies;
      if (map != s.map || bodies.Generation() != s.generation) {
        s.map = map;
        s.generation = bodies.Generation();
        s.emitters.clear();
        for (std::size_t number = 1u; number <= bodies.BodyCount(); ++number) {
          const CWaterRiver* const river = bodies.River(static_cast<std::uint8_t>(number));
          if (river == nullptr) {
            continue;
          }
          std::vector<Emitter> own = BuildEmitters(river->Falls(), river->Segments());
          s.emitters.insert(s.emitters.end(), own.begin(), own.end());
        }
        s.carry.assign(s.emitters.size() * 3u, 0.0f);
        s.live.Clear();
        s.stats.emitters = static_cast<std::uint32_t>(s.emitters.size());
        std::size_t falls = 0u;
        for (const Emitter& e : s.emitters) {
          falls += e.kind == Kind::Fall ? 1u : 0u;
        }
        gpg::Logf(
          "Waterfalls: %u emitters of the rivers of this map (%u falls, %u rapids)",
          static_cast<unsigned>(s.emitters.size()),
          static_cast<unsigned>(falls),
          static_cast<unsigned>(s.emitters.size() - falls)
        );
      }
      return !s.emitters.empty();
    }

    [[nodiscard]] bool Enabled()
    {
      return ren_Waterfalls > 0 && !ParticleAdditionsDisabled();
    }

    // The shape cvars as the plan wants them (clamped: they are typed by hand).
    [[nodiscard]] float Tuning(
      const float value
    ) noexcept
    {
      return std::min(std::max(value, 0.0f), 3.0f);
    }

    // The arc is a property of the emitter: the splash, the mist and the foam at the foot follow where the curtain
    // lands.
    void ApplyArc(
      State& s
    )
    {
      const float arc = Tuning(ren_WaterfallArc);
      for (Emitter& e : s.emitters) {
        e.arc = arc;
      }
    }

    void ViewProjection(
      const GeomCamera3& camera,
      float (&m)[16]
    ) noexcept
    {
      const gpg::gal::Matrix& vp = camera.viewProjection;
      for (int row = 0; row < 4; ++row) {
        m[row * 4 + 0] = vp.r[row].x;
        m[row * 4 + 1] = vp.r[row].y;
        m[row * 4 + 2] = vp.r[row].z;
        m[row * 4 + 3] = vp.r[row].w;
      }
    }

    // The sphere a fall or a rapid fills: its mist and spray reach a few units beyond its width.
    void Bounds(
      const Emitter& e,
      float& cx,
      float& cy,
      float& cz,
      float& radius
    ) noexcept
    {
      const float drop = std::max(e.top - e.bottom, 0.0f);
      cx = e.x;
      cz = e.z;
      cy = 0.5f * (e.top + e.bottom) + (e.kind == Kind::Fall ? 1.0f : 0.5f);
      radius = std::max(e.halfWidth, 0.5f * drop) + (e.kind == Kind::Fall ? 6.0f : 3.0f);
    }

    float DistanceTo(
      const float cx,
      const float cy,
      const float cz,
      const float x,
      const float y,
      const float z
    ) noexcept
    {
      const float dx = x - cx;
      const float dy = y - cy;
      const float dz = z - cz;
      return std::sqrt(dx * dx + dy * dy + dz * dz);
    }

    // The emitters of `kind` (or both) that are within range and in view, nearest first, within `budget`.
    std::vector<Candidate> Pick(
      const State& s,
      const GeomCamera3& camera,
      const Quality& quality,
      const bool falls,
      const bool rapids,
      const float stripSpacing,
      const int budget
    )
    {
      float m[16];
      ViewProjection(camera, m);
      const Frustum frustum = FrustumOf(m);
      const float camX = camera.inverseView.r[3].x;
      const float camY = camera.inverseView.r[3].y;
      const float camZ = camera.inverseView.r[3].z;
      std::vector<Candidate> candidates;
      for (std::size_t i = 0u; i < s.emitters.size(); ++i) {
        const Emitter& e = s.emitters[i];
        if ((e.kind == Kind::Fall && !falls) || (e.kind == Kind::Rapid && !rapids)) {
          continue;
        }
        float cx;
        float cy;
        float cz;
        float radius;
        Bounds(e, cx, cy, cz, radius);
        const float distance = DistanceTo(camX, camY, camZ, cx, cy, cz);
        if (distance > quality.range + radius || !SphereInFrustum(frustum, cx, cy, cz, radius)) {
          continue;
        }
        Candidate c;
        c.index = i;
        c.distance = distance;
        // A fall costs the strips of its curtain, a rapid one.
        c.cost =
          e.kind == Kind::Fall && stripSpacing > 0.0f ? std::max(CurtainStripCount(e.halfWidth, stripSpacing), 1) : 1;
        candidates.push_back(c);
      }
      return SelectWithinBudget(std::move(candidates), quality.range, budget);
    }

    void SeedOnce(
      State& s
    )
    {
      if (!s.seeded) {
        s.seeded = true;
        // The renderer's own stream, never the simulation's: any seed does.
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        s.rng.state = static_cast<std::uint32_t>(now ^ (now >> 32)) | 1u;
      }
    }

    // One particle of `layer`; false (nothing made) when `maxLive` particles are alive already.
    bool Emit(
      State& s,
      const Layer layer,
      const Emitter& e,
      const SWorldParticle& base,
      const float alpha,
      const float sort,
      const double now,
      const int maxLive
    )
    {
      const ParticleSpec p = SpawnParticle(layer, e, s.rng);
      if (!s.live.TryAdd(now, p.lifetime, maxLive)) {
        return false;
      }
      SWorldParticle particle = base;
      particle.mPos = Wm3::Vector3<float>(p.x, p.y, p.z);
      // The renderer's units are ticks: metres a tick, a tick squared, ticks.
      particle.mDir = Wm3::Vector3<float>(p.vx * kTickSeconds, p.vy * kTickSeconds, p.vz * kTickSeconds);
      particle.mAccel = Wm3::Vector3<float>(0.0f, p.ay * kTickSeconds * kTickSeconds, 0.0f);
      particle.mLifetime = p.lifetime / kTickSeconds;
      particle.mBeginSize = p.beginSize;
      particle.mEndSize = p.endSize;
      particle.mAngle = p.angle;
      particle.mRotationCurve = p.spin * kTickSeconds;
      // Born now, inside the tick the frame is in: the renderer adds the tick it uploads at to this.
      particle.mInterop = alpha;
      particle.mReserved54 = sort;
      sWorldParticles.AddWorldParticle(particle, nullptr);
      return true;
    }

    SWorldParticle Template(
      CParticleTexture* const texture,
      CParticleTexture* const ramp
    )
    {
      SWorldParticle particle;
      particle.mTypeTag = "TRamp";
      (void)AssignCountedParticleTexturePtr(&particle.mTexture, texture);
      (void)AssignCountedParticleTexturePtr(&particle.mRampTexture, ramp);
      particle.mBlendMode = SWorldParticle::BlendMode::Mode0;
      particle.mDragEnabled = false;
      particle.mResistance = 0.0f;
      particle.mFramerate = 1.0f;
      particle.mValue1 = 1.0f;
      particle.mValue3 = 1.0f;
      particle.mTextureSelection = 0.0f;
      particle.mRampSelection = 0.0f;
      return particle;
    }
  } // namespace

  Stats GetStats()
  {
    return GetState().stats;
  }

  namespace
  {
    // The work of one frame; `dt` is the game time since the last one (0 while the game is paused).
    void RunFrame(
      State& s,
      const GeomCamera3& camera,
      const float dt
    )
    {
      s.stats.particles = 0u;
      s.stats.foam = 0u;
      s.stats.served = 0u;
      if (!Enabled() || !Refresh(s, RenderMap())) {
        return;
      }
      ApplyArc(s);
      // The world view only: the other views call the render too.
      if (!(camera.viewport.r[3].z * camera.viewport.r[3].w >= 200000.0f)) {
        return;
      }
      const Quality quality = QualityOf(ren_Waterfalls);
      const std::vector<Candidate> served = Pick(s, camera, quality, true, true, 0.0f, 1 << 20);
      s.stats.served = static_cast<std::uint32_t>(served.size());

      const double now = s.clock.Total();
      const float alpha = std::min(std::max(REN_GetSimDeltaSeconds(), 0.0f), 1.0f);
      const float foamWeight = ren_WaterfallFoam > 0 && ren_WaterSim != 0
        ? SimSourceWeight() * static_cast<float>(std::min(ren_WaterfallFoam, 400)) * 0.01f
        : 0.0f;
      int budget = quality.maxPerFrame;

      if (dt > 0.0f) {
        s.textures.Ensure();
        SeedOnce(s);
      }
      SWorldParticle splash;
      SWorldParticle mist;
      SWorldParticle spray;
      if (dt > 0.0f) {
        splash = Template(s.textures.splash, s.textures.splashRamp);
        mist = Template(s.textures.mist, s.textures.mistRamp);
        spray = Template(s.textures.spray, s.textures.splashRamp);
      }

      std::vector<FoamSource> foam;
      for (const Candidate& c : served) {
        const Emitter& e = s.emitters[c.index];
        if (dt > 0.0f && budget > 0) {
          const Rates rates = RatesOf(e);
          const float scale = quality.rateScale * DistanceRate(c.distance, quality.range);
          float* const carry = &s.carry[c.index * 3u];
          const struct
          {
            Layer layer;
            float rate;
            const SWorldParticle* base;
            float sort;
            bool on;
          } layers[3] = {
            {Layer::Splash, rates.splash, &splash, kSplashSort, quality.splash},
            {Layer::Mist, rates.mist, &mist, kMistSort, true},
            {Layer::Spray, rates.spray, &spray, kSplashSort, quality.spray},
          };
          for (int l = 0; l < 3; ++l) {
            if (!layers[l].on) {
              continue;
            }
            int due = TakeEmission(layers[l].rate * scale, dt, carry[l]);
            while (due-- > 0 && budget > 0) {
              if (!Emit(s, layers[l].layer, e, *layers[l].base, alpha, layers[l].sort, now, quality.maxParticles)) {
                break; // the cap on what is alive
              }
              --budget;
              ++s.stats.particles;
            }
          }
        }
        if (foamWeight > 0.0f) {
          foam.clear();
          FoamSources(e, foam);
          for (const FoamSource& f : foam) {
            SimAddSource(f.x, f.z, f.radius, 0.0f, f.foam * foamWeight, true, 0.0f);
            ++s.stats.foam;
          }
        }
      }
      s.stats.particlesTotal += s.stats.particles;
      s.stats.foamTotal += s.stats.foam;
      s.stats.live = static_cast<std::uint32_t>(s.live.Live(now));
    }
  } // namespace

  void OnFrame(
    const GeomCamera3& camera
  )
  {
    State& s = GetState();
    // The game clock runs on every frame, so that the first frame after a switch-on has a frame behind it.
    const double wall = std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    const float dt = s.clock.Advance(REN_GetGameTick(), wall);
    RunFrame(s, camera, dt);
    if (ren_WaterfallLog > 0 && (++s.logFrames % static_cast<std::uint32_t>(ren_WaterfallLog)) == 0u) {
      gpg::Logf(
        "Waterfalls: %u served of %u, +%u particles (%u alive, %llu in all), %u foam sources, %llu beams in all, clock "
        "dt %.4f s%s, speed %.2f",
        s.stats.served,
        s.stats.emitters,
        s.stats.particles,
        s.stats.live,
        static_cast<unsigned long long>(s.stats.particlesTotal),
        s.stats.foam,
        static_cast<unsigned long long>(s.stats.beamsTotal),
        static_cast<double>(dt),
        s.clock.Paused() ? " (paused)" : "",
        static_cast<double>(s.clock.Speed())
      );
    }
  }

  void OnBeat(
    const GeomCamera3& camera,
    const bool advanced
  )
  {
    if (!advanced) {
      return; // the particle renderer kept the beams of the last beat
    }
    State& s = GetState();
    s.stats.beams = 0u;
    if (!Enabled() || !Refresh(s, RenderMap())) {
      return;
    }
    ApplyArc(s);
    const Quality quality = QualityOf(ren_Waterfalls);
    const std::vector<Candidate> chosen =
      Pick(s, camera, quality, true, false, quality.stripSpacing, quality.maxStrips);
    if (chosen.empty()) {
      return;
    }

    s.textures.Ensure();
    SWorldBeam beam;
    (void)AssignCountedParticleTexturePtr(&beam.mTexture1, s.textures.streak);
    beam.mBlendMode = SWorldBeam::BlendMode::Mode0;
    beam.mFromStart = false;
    beam.mUShift = 0.0f;
    beam.mRepeatRate = kCurtainRepeat;

    Shape shape;
    shape.bulge = Tuning(ren_WaterfallBulge);
    shape.fray = Tuning(ren_WaterfallFray);
    // The game time of the water: it stands while the game is paused, so does the undulation.
    shape.time = static_cast<float>(std::fmod(s.clock.Total(), 1000.0));
    shape.segments = quality.curtainSegments;
    constexpr float kEnd0[3] = {0.72f, 0.86f, 0.96f};
    constexpr float kEnd1[3] = {0.85f, 0.94f, 1.0f};
    std::vector<Strip> strips;
    for (const Candidate& c : chosen) {
      strips.clear();
      CurtainStrips(s.emitters[c.index], quality.stripSpacing, shape, strips);
      for (const Strip& strip : strips) {
        // One straight beam for every piece of the strip's arc; the transforms stay the identity at the origin: start
        // and end are given in world units.
        for (int k = 0; k + 1 < strip.points; ++k) {
          const float dx = strip.x[k + 1] - strip.x[k];
          const float dy = strip.y[k + 1] - strip.y[k];
          const float dz = strip.z[k + 1] - strip.z[k];
          const float length = std::sqrt(dx * dx + dy * dy + dz * dz);
          if (!(length > 0.01f)) {
            continue;
          }
          // A whole number of repeats of the streak texture to a piece, so the streaks of two pieces meet at the joint
          // (the texture coordinate of a beam starts at 0 and ends at its length times the rate).
          const float repeats = std::max(std::floor(length * kCurtainRepeat + 0.5f), 1.0f);
          const float rate = repeats / length;
          const float t0 = static_cast<float>(k) / static_cast<float>(strip.points - 1);
          const float t1 = static_cast<float>(k + 1) / static_cast<float>(strip.points - 1);
          beam.mStart = Wm3::Vector3<float>(strip.x[k], strip.y[k], strip.z[k]);
          beam.mEnd = Wm3::Vector3<float>(strip.x[k + 1], strip.y[k + 1], strip.z[k + 1]);
          beam.mWidth = 0.5f * (strip.width[k] + strip.width[k + 1]);
          beam.mRepeatRate = rate;
          // The shader scrolls the texture by the shift times the time in ticks: the streaks run at the speed of the
          // water, down the strip (the texture coordinate grows from the lip to the foot, so the shift is negative).
          beam.mVShift = -strip.speed * kTickSeconds * rate;
          beam.mStartColor = Vector4f(
            kEnd0[0] + (kEnd1[0] - kEnd0[0]) * t0,
            kEnd0[1] + (kEnd1[1] - kEnd0[1]) * t0,
            kEnd0[2] + (kEnd1[2] - kEnd0[2]) * t0,
            strip.alpha[k]
          );
          beam.mEndColor = Vector4f(
            kEnd0[0] + (kEnd1[0] - kEnd0[0]) * t1,
            kEnd0[1] + (kEnd1[1] - kEnd0[1]) * t1,
            kEnd0[2] + (kEnd1[2] - kEnd0[2]) * t1,
            strip.alpha[k + 1]
          );
          sWorldParticles.AddBeam(beam);
          ++s.stats.beams;
        }
      }
    }
    s.stats.beamsTotal += s.stats.beams;
  }
} // namespace moho::water::falls

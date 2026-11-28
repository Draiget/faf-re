#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldLight.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/particles/SWorldTrail.h"
#include "moho/render/lights/LightCensus.h"
#include "moho/render/lights/LightFeeds.h"
#include "moho/render/lights/LightTexture.h"
#include "moho/render/lights/LightTextureCache.h"
#include "moho/resource/CParticleTexture.h"

// The feeds of the light pool that read the effect records of the sim (docs/DYNAMIC_LIGHTS.md, "Sources of light"):
// what each effect draws is measured, not declared, so a modded effect lights up the same way a stock one does. Colour
// comes from the effect textures (the DDS files are read here, see LightTexture.h): the hue of the texture times the
// ramp at the particle age. Render side only.
namespace moho::lights
{
  namespace
  {
    constexpr float kHoldTicks = 3.0f; // a tracked light fades out this long after its last refresh
    constexpr float kMergeCell = 3.0f; // glow sprites born in the same beat inside one cell of this size, with the same
                                       // texture and similar life, are one light
    constexpr float kGlowPeakMin = 0.20f; // a texture whose brightest alpha x luminance is below this does not glow
                                          // (smoke, dust); the census showed fire at 0.25
    constexpr float kGlowEnergyCap =
      4.0f; // energy of one merged light (a fireball is hundreds of sprites; sprites of one cell add up)
    // A muzzle flash is a small additive sprite that lives a tick or two: the size model gives it a radius of 3 and an
    // energy of about 0.1, which lights nothing (a Cybran point defence fired in the dark with the ground around it
    // unlit). Sprites this short and this big or more are flashes.
    constexpr float kFlashLifeTicks = 5.0f;
    constexpr float kFlashMinSize = 0.25f;
    constexpr float kFlashBoost = 4.0f;
    constexpr float kAlphaHotMinAlpha =
      0.08f; // an alpha-blended sprite whose texture is nearly transparent (noise clouds) is not a flame
    constexpr float kAlphaHotGain =
      0.5f; // an alpha-blended flame lights less than an additive one: it covers what is behind it
    constexpr float kWhiteReduction = 0.9f; // how much of the white of texture x ramp is taken out of the light colour
                                            // (a pale lavender stays a violet, a pink a red)
    constexpr float kRampAlphaExponent =
      0.6f; // the ramp fades the sprite; the light fades less than the sprite (a faint sprite still colours the ground)

    constexpr std::uint64_t kKeyLua = 1ull << 40;
    constexpr std::uint64_t kKeyFollow = 3ull << 40; // beams and trails: followed objects, see Follow()

    std::string PathOf(
      const CountedPtr_CParticleTexture& handle
    )
    {
      return handle.tex != nullptr ? std::string(handle.tex->mTexturePath.c_str()) : std::string();
    }

    // Warm white of a light whose texture cannot be read: the colour the first patch used (255, 215, 160).
    constexpr float kFallbackRgb[3] = {1.0f, 0.843f, 0.627f};

    // Colour of a texture times a colour of the effect (ramp texel, vertex colour), with the white taken out and the
    // brightest channel brought to 1; `brightness` is what the brightest channel was before (0..1).
    void LightChroma(
      const float (&tint)[3],
      const float (&other)[3],
      float (&chroma)[3],
      float& brightness
    )
    {
      for (int c = 0; c < 3; ++c) {
        chroma[c] = std::max(0.0f, tint[c] * other[c]);
      }
      brightness = std::max(chroma[0], std::max(chroma[1], chroma[2]));
      if (!(brightness > 1.0e-4f)) {
        chroma[0] = chroma[1] = chroma[2] = 1.0f;
        brightness = 0.0f;
        return;
      }
      ReduceWhite(chroma, kWhiteReduction);
      const float top = std::max(chroma[0], std::max(chroma[1], chroma[2]));
      for (float& c : chroma) {
        c /= top;
      }
    }

    // Fills the colour of `e` from the texture's tint (its average colour with the white reduced) and, when there is a
    // ramp, its curve over the life at row `rampV`: chroma of tint x ramp colour, brightness of the ramp colour x ramp
    // alpha.
    void FillColour(
      Emission& e,
      const TexEntry* texture,
      const TexEntry* ramp,
      const float rampV,
      bool* hotOut = nullptr
    )
    {
      bool hot = false;
      const float* tintPtr = texture != nullptr ? texture->colour.tint : kFallbackRgb;
      const float tint[3] = {tintPtr[0], tintPtr[1], tintPtr[2]};
      const float white[3] = {1.0f, 1.0f, 1.0f};
      float chroma[3];
      float brightness = 0.0f;
      LightChroma(tint, white, chroma, brightness);
      e.rgb[0] = chroma[0];
      e.rgb[1] = chroma[1];
      e.rgb[2] = chroma[2];
      if (ramp != nullptr) {
        for (int i = 0; i < 4; ++i) {
          float rgba[4];
          SampleRamp(ramp->image, static_cast<float>(i) / 3.0f, rampV, rgba);
          const float rampRgb[3] = {rgba[0], rgba[1], rgba[2]};
          LightChroma(tint, rampRgb, chroma, brightness);
          const float level = brightness * std::pow(std::max(0.0f, rgba[3]), kRampAlphaExponent);
          {
            // a ramp is "hot" when at some age it is bright, coloured (not grey or white: smoke) and not transparent: a
            // flame, a fireball
            const float product[3] = {tint[0] * rgba[0], tint[1] * rgba[1], tint[2] * rgba[2]};
            const float hi = std::max(product[0], std::max(product[1], product[2]));
            const float lo = std::min(product[0], std::min(product[1], product[2]));
            if (hi >= 0.55f && hi > 1.0e-4f && (hi - lo) / hi >= 0.35f && rgba[3] >= 0.25f) {
              hot = true;
            }
          }
          for (int c = 0; c < 3; ++c) {
            e.curve[i][c] = chroma[c] * level;
          }
        }
        e.hasCurve = true;
      }
      if (hotOut != nullptr) {
        *hotOut = hot;
      }
    }

    // Sub-tick emission offset of a particle: the fractional part of mInterop (emission cursor minus tick), as the
    // particle shader uses it.
    float BirthFraction(
      const float interop
    )
    {
      if (!std::isfinite(interop) || std::fabs(interop) >= 1.0e7f) {
        return 0.0f;
      }
      const float frac = interop - std::floor(interop);
      return frac < 0.0f ? 0.0f : (frac > 1.0f ? 1.0f : frac);
    }

    std::uint64_t CellKey(
      const float x,
      const float y,
      const float z,
      const float cell
    )
    {
      const auto q = [cell](const float v) {
        return static_cast<std::int64_t>(std::floor(v / cell)) & 0xFFFFF;
      };
      return static_cast<std::uint64_t>(q(x)) | (static_cast<std::uint64_t>(q(y)) << 20);
    }

    std::uint64_t Mix(
      std::uint64_t h,
      const std::uint64_t v
    )
    {
      h ^= v + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
      return h;
    }

    // Sprites of one beat that are one light: the strongest of them stands for the cell, the others add as energy.
    struct GlowCell
    {
      Emission e;
      float strongest = 0.0f; // energy of the representative
      float energySum = 0.0f; // sum of the energies of all sprites of the cell
      float peakSize = 0.0f;  // peak size of the representative
    };

    // ---- following beams and trails over the ticks
    // A beam or a poly trail has no identity in the record: it is sent anew every tick. To light it without a pop the
    // feed matches each record to the one of the last tick it continues (same texture, the beam's start where it was /
    // the trail's start at the old end) and gives it the same key, so the collector moves one light instead of fading a
    // new one in. The key is a counter, never a position.
    struct TrailPoint
    {
      float tick;
      float p[3];
    };

    struct Followed
    {
      std::uint64_t key = 0;
      float a[3] = {0.0f, 0.0f, 0.0f}; // start of the last record
      float b[3] = {0.0f, 0.0f, 0.0f}; // end of the last record
      std::uint32_t texture = 0;
      int seen = 0;     // beat of the last record
      int claimed = -1; // beat in which a record already took it
      // beams only: the record of the last beat, from which the endpoints are worked out for every frame, and what the
      // light is like
      SWorldBeam beam;
      Emission light;
      // trails only: where the head has been, newest last, so the light can cover the trail behind the head and not
      // just its last segment
      std::vector<TrailPoint> history;
    };
    std::vector<Followed> gFollowedBeams;
    std::vector<Followed> gFollowedTrails;
    std::uint64_t gNextFollowKey = 1;
    constexpr std::size_t kMaxFollowed = 2048;
    constexpr int kFollowForgetBeats = 8;
    constexpr int kTrailPieces = 3;              // a trail's light is this many capsules along its path
    constexpr float kTrailLightShare = 0.7f;     // of the trail's drawn length (ticks) the light covers ...
    constexpr float kTrailLightMaxTicks = 20.0f; // ... but never more than this
    constexpr int kBeamRefreshTicks =
      2; // a beam is sent every tick; its light is refreshed every frame while its record is this young
    constexpr float kBeamHoldTicks = 1.5f; // and fades out this long after the beam stopped

    float Dist2(
      const float (&p)[3],
      const float (&q)[3]
    )
    {
      const float dx = p[0] - q[0], dy = p[1] - q[1], dz = p[2] - q[2];
      return dx * dx + dy * dy + dz * dz;
    }

    // The key of the object this record continues, or a new one. `startAgainstEnd`: compare the new start with the old
    // end (a trail grows from its last point), else with the old start (a beam keeps its muzzle).
    std::uint64_t Follow(
      std::vector<Followed>& list,
      const float (&start)[3],
      const float (&end)[3],
      const std::uint32_t texture,
      const int beat,
      const float maxDistance,
      const bool startAgainstEnd
    )
    {
      Followed* best = nullptr;
      float bestDist2 = maxDistance * maxDistance;
      for (Followed& f : list) {
        if (f.texture != texture || f.claimed == beat) {
          continue;
        }
        const float d2 = Dist2(start, startAgainstEnd ? f.b : f.a);
        if (d2 <= bestDist2) {
          bestDist2 = d2;
          best = &f;
        }
      }
      if (best == nullptr) {
        if (list.size() >= kMaxFollowed) {
          return 0;
        }
        list.push_back(Followed{});
        best = &list.back();
        best->key = gNextFollowKey++;
        best->texture = texture;
      }
      for (int k = 0; k < 3; ++k) {
        best->a[k] = start[k];
        best->b[k] = end[k];
      }
      best->seen = beat;
      best->claimed = beat;
      return best->key;
    }

    // The beam of the last beat that this record continues (same texture, same muzzle), or a new one.
    Followed* FollowBeam(
      std::vector<Followed>& list,
      const float (&start)[3],
      const float (&end)[3],
      const std::uint32_t texture,
      const int beat
    )
    {
      const std::uint64_t key = Follow(list, start, end, texture, beat, 5.0f, false);
      for (Followed& f : list) {
        if (f.key == key) {
          return &f;
        }
      }
      return nullptr;
    }

    void ForgetOld(
      std::vector<Followed>& list,
      const int beat
    )
    {
      list.erase(
        std::remove_if(
          list.begin(),
          list.end(),
          [beat](const Followed& f) {
        return beat - f.seen > kFollowForgetBeats || f.seen > beat + 50;
      }
        ),
        list.end()
      );
    }
  } // namespace

  void FeedParticleBuffer(
    const SParticleBuffer& batch,
    const int beatTick
  )
  {
    SyncQuality();
    LightCollector& collector = Collector();
    if (collector.Quality() == model::kOff) {
      return;
    }
    const float now = static_cast<float>(beatTick);

    // ---- particles: explosion light particles ("TLight"), and glow sprites merged per cell
    std::unordered_map<std::uint64_t, GlowCell> glow;
    for (const SWorldParticle& particle : batch.mParticles) {
      const bool isLight = particle.mTypeTag.view() == std::string_view("TLight");
      const int blend = static_cast<int>(particle.mBlendMode);
      const bool census = CensusEnabled();
      const bool additive = blend == 3 || blend == 4;
      const bool alphaBlend =
        blend == 0; // a flame drawn with alpha blending lights when its ramp is hot, see FillColour
      if (!isLight && !additive && !alphaBlend && !census) {
        continue; // modulate and refraction sprites do not glow
      }
      const float peakSize = std::max(particle.mBeginSize, particle.mEndSize);
      const std::string texturePath = PathOf(particle.mTexture);
      const std::string rampPath = PathOf(particle.mRampTexture);
      std::string censusKey;
      if (census) {
        censusKey = std::string(particle.mTypeTag.view()) + " blend=" + std::to_string(blend) + " tex=" + texturePath +
          " ramp=" + rampPath;
      }
      if (!(peakSize > 0.0f) || !std::isfinite(peakSize)) {
        if (census) {
          CensusNote("particle", censusKey, "no:size zero", 0.0f, nullptr);
        }
        continue;
      }

      // The textures are read on a worker thread the first time one is seen. A light made while one is still pending
      // would have its colour for the whole of its life, so the emitter gives none now; its next beat finds the
      // texture.
      const TexEntry* texture = nullptr;
      const TexEntry* ramp = nullptr;
      bool pending = false;
      if (isLight || additive || alphaBlend || census) {
        pending = FindTexture(texturePath, texture) == TextureState::Pending;
      }
      if (isLight || additive || alphaBlend) {
        pending = FindTexture(rampPath, ramp) == TextureState::Pending || pending;
      }
      if (pending) {
        continue;
      }
      const TextureColour* censusColour = texture != nullptr ? &texture->colour : nullptr;

      if (isLight) {
        Emission e;
        e.kind = Kind::Flash;
        e.pos[0] = particle.mPos.x;
        e.pos[1] = particle.mPos.y;
        e.pos[2] = particle.mPos.z;
        e.dir[0] = particle.mDir.x;
        e.dir[1] = particle.mDir.y;
        e.dir[2] = particle.mDir.z;
        e.accel[0] = particle.mAccel.x;
        e.accel[1] = particle.mAccel.y;
        e.accel[2] = particle.mAccel.z;
        e.birth = now + BirthFraction(particle.mInterop);
        e.life = particle.mLifetime;
        e.size0 = particle.mBeginSize;
        e.size1 = particle.mEndSize;
        FillColour(e, texture, ramp, particle.mRampSelection);
        const bool stored = collector.Add(e);
        if (census) {
          CensusNote(
            "particle",
            censusKey,
            stored ? "ok:flash" : "no:flash refused (quality gate or invalid)",
            peakSize,
            censusColour
          );
        }
        continue;
      }

      if (!additive && !alphaBlend) {
        // modulate (they darken) and refraction sprites do not glow
        if (census) {
          CensusNote("particle", censusKey, "no:blend mode darkens or refracts", peakSize, censusColour);
        }
        continue;
      }

      // a glow sprite: only textures that glow, merged with the others in the same cell
      if (texture == nullptr) {
        if (census) {
          CensusNote("particle", censusKey, "no:texture unreadable", peakSize, nullptr);
        }
        continue;
      }
      if (additive && texture->colour.peak < kGlowPeakMin) {
        if (census) {
          CensusNote("particle", censusKey, "no:texture peak below threshold", peakSize, censusColour);
        }
        continue;
      }
      if (alphaBlend && (ramp == nullptr || texture->colour.alpha < kAlphaHotMinAlpha)) {
        if (census) {
          CensusNote(
            "particle",
            censusKey,
            "no:alpha sprite without a ramp or with a transparent texture",
            peakSize,
            censusColour
          );
        }
        continue;
      }
      // the sprite as a light of its own: it is born with the sprite, moves with it, follows its colour ramp, and dies
      // with it
      Emission e;
      e.kind = Kind::Glow;
      e.pos[0] = particle.mPos.x;
      e.pos[1] = particle.mPos.y;
      e.pos[2] = particle.mPos.z;
      e.dir[0] = particle.mDir.x;
      e.dir[1] = particle.mDir.y;
      e.dir[2] = particle.mDir.z;
      e.accel[0] = particle.mAccel.x;
      e.accel[1] = particle.mAccel.y;
      e.accel[2] = particle.mAccel.z;
      e.birth = now + BirthFraction(particle.mInterop);
      e.life = particle.mLifetime;
      e.size0 = particle.mBeginSize;
      e.size1 = particle.mEndSize;
      bool hotRamp = false;
      FillColour(e, texture, ramp, particle.mRampSelection, &hotRamp);
      if (alphaBlend && !hotRamp) {
        if (census) {
          CensusNote(
            "particle", censusKey, "no:alpha sprite, the ramp is not hot (smoke, dust)", peakSize, censusColour
          );
        }
        continue;
      }
      if (ramp != nullptr) {
        float curvePeak = 0.0f;
        for (const auto& point : e.curve) {
          curvePeak = std::max(curvePeak, std::max(point[0], std::max(point[1], point[2])));
        }
        if (curvePeak < 0.05f) {
          if (census) {
            CensusNote("particle", censusKey, "no:ramp is dark over the whole life", peakSize, censusColour);
          }
          continue;
        }
      }
      // the texture decides how much of the sprite is bright: a spark is a small very bright spot (high peak, low
      // mean), a cloud is bright all over (high mean); a noise cloud with a faint peak gives little
      const float spriteGain = (blend == 4 ? 0.7f : 1.0f) * (alphaBlend ? kAlphaHotGain : 1.0f) *
        model::Clamp(0.15f + 0.5f * texture->colour.peak + 1.5f * texture->colour.brightness, 0.2f, 1.0f);
      const bool muzzleFlash = particle.mLifetime <= kFlashLifeTicks && peakSize >= kFlashMinSize;
      const float energy = model::GlowEnergy(peakSize) * spriteGain * (muzzleFlash ? kFlashBoost : 1.0f);
      if (census) {
        CensusNote(
          "particle", censusKey, alphaBlend ? "ok:hot alpha sprite" : "ok:glow sprite", peakSize, censusColour
        );
      }
      std::uint64_t cellKey = Mix(
        CellKey(particle.mPos.x, particle.mPos.y, particle.mPos.z, kMergeCell), std::hash<std::string>{}(texturePath)
      );
      cellKey = Mix(cellKey, static_cast<std::uint64_t>(static_cast<int>(particle.mLifetime / 6.0f)));
      GlowCell& cell = glow[cellKey];
      if (energy > cell.strongest) {
        cell.e = e;
        cell.strongest = energy;
        cell.peakSize = peakSize;
      }
      cell.energySum += energy;
    }
    for (const auto& item : glow) {
      const GlowCell& c = item.second;
      if (!(c.strongest > 0.0f)) {
        continue;
      }
      Emission e = c.e;
      const float total =
        std::min(kGlowEnergyCap, c.energySum); // the light of sprites in one place adds up (it was the root of the sum
                                               // of squares: a fireball of 100 sprites lit like 10)
      e.gain = total / std::max(1.0e-4f, model::GlowEnergy(c.peakSize));
      (void)collector.Add(e);
    }

    // ---- trails: a segment per tick; one light per cell of the head, refreshed while the trail grows there
    for (const SWorldTrail& trail : batch.mTrails) {
      if (!(trail.mSize > 0.0f) || !std::isfinite(trail.mSize)) {
        continue;
      }
      const std::string texturePath = PathOf(trail.mTexture);
      if (trail.mBlendMode != 3 && trail.mBlendMode != 4) {
        // an alpha or modulate trail is smoke or a contrail: it does not add light
        if (CensusEnabled()) {
          const TexEntry* t = LoadTexture(texturePath);
          CensusNote(
            "trail",
            "blend=" + std::to_string(trail.mBlendMode) + " tex=" + texturePath,
            "no:blend mode is not additive",
            trail.mSize,
            t != nullptr ? &t->colour : nullptr
          );
        }
        continue;
      }
      const TexEntry* texture = nullptr;
      if (FindTexture(texturePath, texture) == TextureState::Pending) {
        continue; // read on the worker: the next beat has it (a light made now would keep a wrong colour)
      }
      const std::string trailKey = "tex=" + texturePath + " ramp=" + PathOf(trail.mRampTexture);
      if (texture == nullptr || texture->colour.peak < 0.2f) {
        // a trail whose texture does not glow (a smoke trail) gives no light
        CensusNote(
          "trail",
          trailKey,
          texture == nullptr ? "no:texture unreadable" : "no:texture peak below threshold",
          trail.mSize,
          texture != nullptr ? &texture->colour : nullptr
        );
        continue;
      }
      CensusNote("trail", trailKey, "ok:trail", trail.mSize, &texture->colour);
      const TexEntry* ramp = nullptr;
      if (FindTexture(PathOf(trail.mRampTexture), ramp) == TextureState::Pending) {
        continue;
      }
      Emission e;
      e.kind = Kind::Trail;
      e.pos[0] = trail.mStartPos.x;
      e.pos[1] = trail.mStartPos.y;
      e.pos[2] = trail.mStartPos.z;
      e.end[0] = trail.mEndPos.x;
      e.end[1] = trail.mEndPos.y;
      e.end[2] = trail.mEndPos.z;
      e.size0 = e.size1 = trail.mSize;
      FillColour(e, texture, nullptr, 0.0f);
      if (ramp != nullptr) {
        // The colour of the bulk of the trail, not its head: a tracer's head is white hot and the rest is red, blue or
        // green. Four samples along the ramp, weighted by how much each one glows (alpha x brightest channel).
        float sum[3] = {0.0f, 0.0f, 0.0f};
        float weights = 0.0f;
        float alphaSum = 0.0f;
        for (int i = 0; i < 4; ++i) {
          float rgba[4];
          SampleRamp(ramp->image, 0.1f + 0.2f * static_cast<float>(i), 0.0f, rgba);
          const float glow = rgba[3] * std::max(rgba[0], std::max(rgba[1], rgba[2]));
          for (int c = 0; c < 3; ++c) {
            sum[c] += rgba[c] * glow;
          }
          weights += glow;
          alphaSum += rgba[3];
        }
        if (weights > 1.0e-4f) {
          const float rampRgb[3] = {sum[0] / weights, sum[1] / weights, sum[2] / weights};
          float chroma[3];
          float brightness = 0.0f;
          LightChroma(texture->colour.tint, rampRgb, chroma, brightness);
          // how strongly the trail shines: the ramp's brightness and alpha, not a floor (a faint trail is a faint
          // light)
          const float level =
            model::Clamp(brightness * std::pow(std::max(0.0f, alphaSum * 0.25f), kRampAlphaExponent), 0.12f, 1.0f);
          for (int c = 0; c < 3; ++c) {
            e.rgb[c] = chroma[c] * level;
          }
        }
      }
      const std::uint64_t id = Follow(
        gFollowedTrails,
        e.pos,
        e.end,
        static_cast<std::uint32_t>(std::hash<std::string>{}(texturePath)),
        beatTick,
        6.0f + 3.0f * trail.mSize,
        true
      );
      if (id == 0) {
        continue;
      }
      Followed* followed = nullptr;
      for (Followed& f : gFollowedTrails) {
        if (f.key == id) {
          followed = &f;
          break;
        }
      }
      if (followed == nullptr) {
        continue;
      }
      // The trail is drawn for `mLifetime` ticks behind its head: its light is a chain of capsules over that stretch of
      // the path, strongest at the head, not one light on the newest segment (which is a round light at the head with
      // nothing behind it).
      followed->history.push_back(TrailPoint{now, {e.end[0], e.end[1], e.end[2]}});
      const float visibleTicks = model::Clamp(trail.mLifetime * kTrailLightShare, 2.0f, kTrailLightMaxTicks);
      while (followed->history.size() > 1 && now - followed->history.front().tick > visibleTicks) {
        followed->history.erase(followed->history.begin());
      }
      if (followed->history.size() > 64) {
        followed->history.erase(followed->history.begin(), followed->history.end() - 64);
      }
      const std::vector<TrailPoint>& path = followed->history;
      const auto pointAt = [&path](const float fraction, float (&out)[3]) {
        // the point of the path that far back along it (0 = head, 1 = oldest point we hold), by index
        const float index = fraction * static_cast<float>(path.size() - 1);
        const std::size_t newest = path.size() - 1;
        const std::size_t i0 = newest - std::min<std::size_t>(newest, static_cast<std::size_t>(std::floor(index)));
        const std::size_t i1 = newest - std::min<std::size_t>(newest, static_cast<std::size_t>(std::ceil(index)));
        const float f = index - std::floor(index);
        for (int k = 0; k < 3; ++k) {
          out[k] = path[i0].p[k] + (path[i1].p[k] - path[i0].p[k]) * f;
        }
      };
      static const float kPieceGain[kTrailPieces] = {1.0f, 0.7f, 0.45f};
      for (int piece = 0; piece < kTrailPieces; ++piece) {
        Emission piece_e = e;
        pointAt(static_cast<float>(piece) / static_cast<float>(kTrailPieces), piece_e.end);
        pointAt(static_cast<float>(piece + 1) / static_cast<float>(kTrailPieces), piece_e.pos);
        piece_e.gain = kPieceGain[piece];
        (void)collector.Track(
          kKeyFollow | (2ull << 38) | (id << 2) | static_cast<std::uint64_t>(piece), piece_e, now, kHoldTicks
        );
      }
    }
    ForgetOld(gFollowedTrails, beatTick);

    // ---- beams: one capsule per beam, followed over the ticks, moved every frame between the refreshes
    for (const SWorldBeam& beam : batch.mBeams) {
      if (!(beam.mWidth > 0.0f) || !std::isfinite(beam.mWidth)) {
        continue;
      }
      const std::string texturePath = PathOf(beam.mTexture1);
      const int beamBlend = static_cast<int>(beam.mBlendMode);
      if (beamBlend != 3 && beamBlend != 4) {
        if (CensusEnabled()) {
          const TexEntry* t = LoadTexture(texturePath);
          CensusNote(
            "beam",
            "blend=" + std::to_string(beamBlend) + " tex=" + texturePath,
            "no:blend mode is not additive",
            beam.mWidth,
            t != nullptr ? &t->colour : nullptr
          );
        }
        continue;
      }
      const TexEntry* texture = nullptr;
      if (FindTexture(texturePath, texture) == TextureState::Pending) {
        continue; // read on the worker: the next frame has it
      }
      CensusNote("beam", "tex=" + texturePath, "ok:beam", beam.mWidth, texture != nullptr ? &texture->colour : nullptr);
      // The record carries the beam in the transforms of its two ends (mStart / mEnd are offsets in their frame): the
      // endpoints of the frame are worked out the way the beam renderer does it, see FeedBeamsForFrame.
      BeamVertexArray corners;
      EmitInterpolatedBeamQuadVertices(beam, 0.0f, corners);
      if (corners.size() < 2) {
        continue;
      }
      Emission e;
      e.kind = Kind::Beam;
      e.pos[0] = corners[0].worldPosition.x;
      e.pos[1] = corners[0].worldPosition.y;
      e.pos[2] = corners[0].worldPosition.z;
      e.end[0] = corners[1].worldPosition.x;
      e.end[1] = corners[1].worldPosition.y;
      e.end[2] = corners[1].worldPosition.z;
      e.size0 = e.size1 = beam.mWidth;
      // the beam is drawn as texture x vertex colour (start colour at one end, end colour at the other): the light has
      // the mean
      const float* tint = texture != nullptr ? texture->colour.tint : kFallbackRgb;
      const float tintCopy[3] = {tint[0], tint[1], tint[2]};
      const float vertex[3] = {
        0.5f * (beam.mStartColor.x + beam.mEndColor.x),
        0.5f * (beam.mStartColor.y + beam.mEndColor.y),
        0.5f * (beam.mStartColor.z + beam.mEndColor.z)
      };
      float chroma[3];
      float brightness = 0.0f;
      LightChroma(tintCopy, vertex, chroma, brightness);
      const float alpha = model::Clamp(0.5f * (beam.mStartColor.w + beam.mEndColor.w), 0.3f, 1.0f);
      for (int c = 0; c < 3; ++c) {
        e.rgb[c] = chroma[c];
      }
      // a beam is a bright thing: its strength comes from the beam model and its own colour, not from the poly-trail
      // model
      e.radius = model::BeamRadius(beam.mWidth);
      e.intensity = model::BeamIntensity(beam.mWidth) *
        model::Clamp(brightness * alpha, 0.55f, 1.0f); // a beam never gives less than just over half the model
      Followed* const followed = FollowBeam(
        gFollowedBeams, e.pos, e.end, static_cast<std::uint32_t>(std::hash<std::string>{}(texturePath)), beatTick
      );
      if (followed != nullptr) {
        followed->beam = beam;
        followed->light = e;
      }
    }
    ForgetOld(gFollowedBeams, beatTick);

    // ---- Lua lights: tracked by their handle
    for (const SWorldLight& light : batch.mLights) {
      if (light.id == 0) {
        continue;
      }
      Emission e;
      e.kind = light.spot != 0 ? Kind::Spot : Kind::Glow;
      e.pos[0] = light.pos[0];
      e.pos[1] = light.pos[1];
      e.pos[2] = light.pos[2];
      e.end[0] = light.dir[0];
      e.end[1] = light.dir[1];
      e.end[2] = light.dir[2];
      e.cone = light.cone;
      e.rgb[0] = light.rgb[0];
      e.rgb[1] = light.rgb[1];
      e.rgb[2] = light.rgb[2];
      e.radius = light.radius;
      e.intensity = light.intensity;
      (void)collector.Track(kKeyLua | light.id, e, now, kHoldTicks);
    }
  }

  void FeedBeamsForFrame(
    const int tick,
    const float frameAlpha
  )
  {
    LightCollector& collector = Collector();
    if (collector.Quality() == model::kOff) {
      return;
    }
    const float nowTick = static_cast<float>(tick) + frameAlpha;
    for (const Followed& f : gFollowedBeams) {
      if (f.key == 0 || tick - f.seen > kBeamRefreshTicks) {
        continue; // the beam stopped: its light is no longer refreshed and fades out
      }
      BeamVertexArray corners;
      EmitInterpolatedBeamQuadVertices(f.beam, frameAlpha, corners);
      if (corners.size() < 2) {
        continue;
      }
      Emission e = f.light;
      e.pos[0] = corners[0].worldPosition.x;
      e.pos[1] = corners[0].worldPosition.y;
      e.pos[2] = corners[0].worldPosition.z;
      e.end[0] = corners[1].worldPosition.x;
      e.end[1] = corners[1].worldPosition.y;
      e.end[2] = corners[1].worldPosition.z;
      (void)collector.Track(kKeyFollow | (1ull << 38) | f.key, e, nowTick, kBeamHoldTicks);
    }
  }
} // namespace moho::lights

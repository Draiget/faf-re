#include "editor/tools/EdHeightBrush.h"

#include "editor/terrain/EdErosion.h"

#include <algorithm>
#include <cmath>
#include <type_traits>
#include <utility>

namespace faf::editor
{
  namespace
  {
    // Raise and Lower at full strength, in game units a second; Noise's amplitude likewise.
    constexpr float kRaiseUnitsPerSecond = 30.0f;
    constexpr float kNoiseUnitsPerSecond = 15.0f;
    // Smooth and Flatten at full strength close this share of the gap each second (capped at all of it).
    constexpr float kBlendPerSecond = 8.0f;
    // Sharpen grows the ground's detail by this share of its difference from the blur each second at full strength:
    // it feeds on its own result, so Smooth's rate would multiply the relief some fifty times a second.
    constexpr float kSharpenPerSecond = 1.5f;
    constexpr float kErodeStepsPerSecond = 60.0f;
    constexpr float kWordsPerUnit = 128.0f;
    constexpr double kTwoPi = 6.283185307179586;
    // N-way turns: copies are written this many samples past the brush's edge, since the heights a copy
    // reads between samples (and their own turned-back samples) reach that far.
    constexpr float kTurnRim = 2.0f;

    [[nodiscard]] bool NeedsSquare(
      const Symmetry symmetry
    )
    {
      return symmetry == Symmetry::DiagonalBack || symmetry == Symmetry::DiagonalForward ||
        symmetry == Symmetry::BothDiagonals || symmetry == Symmetry::QuarterTurns || symmetry == Symmetry::NWay;
    }

    [[nodiscard]] int Turns(
      const int turns
    )
    {
      return std::clamp(turns, 2, kMaxSymmetryCopies);
    }

    /** The copies of a point under `symmetry`, for samples (T int) and for the brush's centre (T float). */
    template <typename T>
    int Copies(
      const Symmetry symmetry,
      const int turns,
      const T w,
      const T h,
      const T x,
      const T z,
      T (&outX)[kMaxSymmetryCopies],
      T (&outZ)[kMaxSymmetryCopies]
    )
    {
      int n = 0;
      const auto add = [&](const T cx, const T cz) {
        outX[n] = cx;
        outZ[n] = cz;
        ++n;
      };
      add(x, z);
      switch (symmetry) {
      case Symmetry::LeftRight:
        add(w - x, z);
        break;
      case Symmetry::TopBottom:
        add(x, h - z);
        break;
      case Symmetry::DiagonalBack:
        add(z, x);
        break;
      case Symmetry::DiagonalForward:
        add(w - z, w - x);
        break;
      case Symmetry::HalfTurn:
        add(w - x, h - z);
        break;
      case Symmetry::BothAxes:
        add(w - x, z);
        add(x, h - z);
        add(w - x, h - z);
        break;
      case Symmetry::BothDiagonals:
        add(z, x);
        add(w - z, w - x);
        add(w - x, w - z);
        break;
      case Symmetry::QuarterTurns:
        add(w - z, x);
        add(w - x, w - z);
        add(z, w - x);
        break;
      case Symmetry::NWay: {
        const double cx = static_cast<double>(w) * 0.5;
        const double cz = static_cast<double>(h) * 0.5;
        const double dx = static_cast<double>(x) - cx;
        const double dz = static_cast<double>(z) - cz;
        const int count = Turns(turns);
        for (int k = 1; k < count; ++k) {
          const double angle = kTwoPi * k / count;
          const double rx = cx + dx * std::cos(angle) - dz * std::sin(angle);
          const double rz = cz + dx * std::sin(angle) + dz * std::cos(angle);
          if constexpr (std::is_integral_v<T>) {
            add(static_cast<T>(std::lround(rx)), static_cast<T>(std::lround(rz)));
          } else {
            add(static_cast<T>(rx), static_cast<T>(rz));
          }
        }
        break;
      }
      default:
        break;
      }
      return n;
    }

    [[nodiscard]] float Weight(
      const float distance,
      const HeightBrush& brush
    )
    {
      const float t = distance / brush.radius;
      if (t >= 1.0f) {
        return 0.0f;
      }
      const float inner = 1.0f - std::clamp(brush.falloff, 0.0f, 1.0f);
      if (t <= inner) {
        return 1.0f;
      }
      const float u = (t - inner) / (1.0f - inner);
      return 1.0f - u * u * (3.0f - 2.0f * u);
    }

    // FAF Studio's smooth value noise (EdBrush.h, terrain.lua): one hashed value in -1..1 per lattice point, blended
    // with a smoothstep between them; a function of the sample and the seed only, so a group's first member gives
    // every member the same change and the dabs of a stroke join into continuous bumps.
    [[nodiscard]] float LatticeNoise(
      const int x,
      const int z,
      const int seed
    )
    {
      const int a = (((x % 4093) + 4093) % 4093 * 1103 + 17) % 4093;
      const int b = (((z % 4091) + 4091) % 4091 * 1999 + 31) % 4091;
      const int c = ((seed % 4079) * 997 + 5) % 4079;
      int n = (a * 4001 + b) % 4093;
      n = (n * n + c) % 4093;
      n = (n * n + a) % 4093;
      n = (n * n + b) % 4093;
      return static_cast<float>(n) / 4093.0f * 2.0f - 1.0f;
    }

    [[nodiscard]] float ValueNoise(
      const int x,
      const int z,
      const float cell,
      const int seed
    )
    {
      const float fx = static_cast<float>(x) / cell;
      const float fz = static_cast<float>(z) / cell;
      const float flx = std::floor(fx);
      const float flz = std::floor(fz);
      float tx = fx - flx;
      float tz = fz - flz;
      tx = tx * tx * (3.0f - 2.0f * tx);
      tz = tz * tz * (3.0f - 2.0f * tz);
      const int ix = static_cast<int>(flx);
      const int iz = static_cast<int>(flz);
      const float top = LatticeNoise(ix, iz, seed) + (LatticeNoise(ix + 1, iz, seed) - LatticeNoise(ix, iz, seed)) * tx;
      const float bottom =
        LatticeNoise(ix, iz + 1, seed) + (LatticeNoise(ix + 1, iz + 1, seed) - LatticeNoise(ix, iz + 1, seed)) * tx;
      return top + (bottom - top) * tz;
    }

    /** Up to four octaves of ValueNoise, each half the cell and `roughness` as strong, kept in -1..1. */
    [[nodiscard]] float SmoothNoise(
      const int x,
      const int z,
      const HeightBrush& brush
    )
    {
      float cell = std::max(1.0f, brush.noiseScale);
      const int octaves = std::clamp(brush.noiseOctaves, 1, 4);
      const float rough = std::clamp(brush.noiseRoughness, 0.0f, 1.0f);
      const int seed = static_cast<int>(brush.noiseSeed % 4079u);
      float total = 0.0f;
      float amp = 1.0f;
      float norm = 0.0f;
      for (int o = 0; o < octaves; ++o) {
        if (o > 0 && cell < 1.0f) {
          break;
        }
        total += ValueNoise(x, z, cell, seed + o * 1013) * amp;
        norm += amp;
        amp *= rough;
        cell *= 0.5f;
      }
      return norm > 0.0f ? total / norm : 0.0f;
    }

    // FAF Studio's procedural brush shapes (brushes.lua), in doubles.
    [[nodiscard]] double ShapeSmooth(
      const double a,
      const double b,
      const double x
    )
    {
      const double t = std::clamp((x - a) / (b - a), 0.0, 1.0);
      return t * t * (3.0 - 2.0 * t);
    }

    [[nodiscard]] double ShapeHash(
      const double ix,
      const double iz
    )
    {
      double n = std::fmod(ix * 374761393.0 + iz * 668265263.0, 2147483647.0);
      n = std::fmod(n * 1103515245.0 + 12345.0, 2147483647.0);
      return std::fmod(n, 65536.0) / 65535.0;
    }

    [[nodiscard]] double ShapeValueNoise(
      const double x,
      const double z
    )
    {
      const double ix = std::floor(x);
      const double iz = std::floor(z);
      double fx = x - ix;
      double fz = z - iz;
      fx = fx * fx * (3.0 - 2.0 * fx);
      fz = fz * fz * (3.0 - 2.0 * fz);
      const double a = ShapeHash(ix, iz);
      const double b = ShapeHash(ix + 1.0, iz);
      const double c = ShapeHash(ix, iz + 1.0);
      const double d = ShapeHash(ix + 1.0, iz + 1.0);
      const double top = a + (b - a) * fx;
      return top + ((c + (d - c) * fx) - top) * fz;
    }

    [[nodiscard]] double ShapeFractal(
      const double x,
      const double z
    )
    {
      return 0.55 * ShapeValueNoise(x * 2.0, z * 2.0) + 0.3 * ShapeValueNoise(x * 4.0 + 7.0, z * 4.0 + 3.0) +
        0.15 * ShapeValueNoise(x * 8.0 + 1.0, z * 8.0 + 11.0);
    }

    /** A fixed value in [-1, 1] per sample, so Noise gives every member of a group the same change. */
    [[maybe_unused]] [[nodiscard]] float SampleNoise(
      const int x,
      const int z
    )
    {
      std::uint32_t v = static_cast<std::uint32_t>(x) * 0x8DA6B343u ^ static_cast<std::uint32_t>(z) * 0xD8163841u;
      v ^= v >> 13;
      v *= 0x5BD1E995u;
      v ^= v >> 15;
      return static_cast<float>(v & 0xFFFFu) / 32767.5f - 1.0f;
    }

    [[nodiscard]] bool Contains(
      const SampleRect& rect,
      const int x,
      const int z
    )
    {
      return x >= rect.x0 && x <= rect.x1 && z >= rect.z0 && z <= rect.z1;
    }

    /** The rectangle each centre's brush covers, clipped to the map; empty ones left out. */
    std::vector<SampleRect> RectsAround(
      const int width,
      const int height,
      const float (&centreX)[kMaxSymmetryCopies],
      const float (&centreZ)[kMaxSymmetryCopies],
      const int centres,
      const float radius
    )
    {
      std::vector<SampleRect> rects;
      for (int i = 0; i < centres; ++i) {
        SampleRect rect{
          std::max(0, static_cast<int>(std::floor(centreX[i] - radius))),
          std::max(0, static_cast<int>(std::floor(centreZ[i] - radius))),
          std::min(width - 1, static_cast<int>(std::ceil(centreX[i] + radius))),
          std::min(height - 1, static_cast<int>(std::ceil(centreZ[i] + radius))),
        };
        if (rect.x0 <= rect.x1 && rect.z0 <= rect.z1) {
          rects.push_back(rect);
        }
      }
      return rects;
    }

    /** A copy of a rectangle of heights plus one sample around it, read as they were before a step. */
    struct Snapshot
    {
      SampleRect area;
      std::vector<std::uint16_t> words;
      /** Smooth and Sharpen: the area blurred (BlurSnapshot); empty for the other modes. */
      std::vector<float> blurred;
      [[nodiscard]] float Blurred(
        const int sx,
        const int sz
      ) const
      {
        const int cx = std::clamp(sx, area.x0, area.x1);
        const int cz = std::clamp(sz, area.z0, area.z1);
        return blurred[static_cast<std::size_t>((cz - area.z0) * (area.x1 - area.x0 + 1) + (cx - area.x0))];
      }
      [[nodiscard]] float At(
        const int sx,
        const int sz
      ) const
      {
        const int cx = std::clamp(sx, area.x0, area.x1);
        const int cz = std::clamp(sz, area.z0, area.z1);
        return words[static_cast<std::size_t>((cz - area.z0) * (area.x1 - area.x0 + 1) + (cx - area.x0))];
      }
    };

    /** A box blur of half width `kr` over a w x h grid, the edge samples repeated (FAF Studio's BoxBlur). */
    void BoxBlur(
      const std::vector<float>& src,
      const int w,
      const int h,
      const int kr,
      std::vector<float>& out
    )
    {
      const float n = static_cast<float>(2 * kr + 1);
      std::vector<float> tmp(src.size());
      out.assign(src.size(), 0.0f);
      const auto at = [w](const int x, const int z) {
        return static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
      };
      for (int z = 0; z < h; ++z) {
        float sum = 0.0f;
        for (int k = -kr; k <= kr; ++k) {
          sum += src[at(std::clamp(k, 0, w - 1), z)];
        }
        for (int x = 0; x < w; ++x) {
          tmp[at(x, z)] = sum / n;
          sum += src[at(std::min(x + kr + 1, w - 1), z)];
          sum -= src[at(std::max(x - kr, 0), z)];
        }
      }
      for (int x = 0; x < w; ++x) {
        float sum = 0.0f;
        for (int k = -kr; k <= kr; ++k) {
          sum += tmp[at(x, std::clamp(k, 0, h - 1))];
        }
        for (int z = 0; z < h; ++z) {
          out[at(x, z)] = sum / n;
          sum += tmp[at(x, std::min(z + kr + 1, h - 1))];
          sum -= tmp[at(x, std::max(z - kr, 0))];
        }
      }
    }

    /**
     * Smooth and Sharpen read the ground blurred twice with a box that widens with strength: 3 x 3 when weak, up to
     * a quarter of the radius (at most 6 samples each way) when strong (FAF Studio's terrain.lua).
     */
    [[nodiscard]] int BlurHalfWidth(
      const HeightBrush& brush
    )
    {
      const float room = std::max(0.0f, std::min(brush.radius * 0.25f, 6.0f) - 1.0f);
      return 1 + static_cast<int>(std::floor(std::clamp(brush.strength, 0.0f, 1.0f) * room + 0.5f));
    }

    std::vector<Snapshot> TakeSnapshots(
      const std::uint16_t* const heights,
      const int width,
      const int height,
      const std::vector<SampleRect>& rects,
      const HeightBrush& brush
    )
    {
      std::vector<Snapshot> snapshots;
      snapshots.reserve(rects.size());
      for (const SampleRect& rect : rects) {
        Snapshot snapshot;
        snapshot.area = {
          std::max(0, rect.x0 - 1),
          std::max(0, rect.z0 - 1),
          std::min(width - 1, rect.x1 + 1),
          std::min(height - 1, rect.z1 + 1)
        };
        for (int sz = snapshot.area.z0; sz <= snapshot.area.z1; ++sz) {
          const std::uint16_t* const row = heights + static_cast<std::size_t>(sz) * static_cast<std::size_t>(width);
          snapshot.words.insert(snapshot.words.end(), row + snapshot.area.x0, row + snapshot.area.x1 + 1);
        }
        if (brush.mode == HeightBrushMode::Smooth || brush.mode == HeightBrushMode::Sharpen) {
          const int w = snapshot.area.x1 - snapshot.area.x0 + 1;
          const int h = snapshot.area.z1 - snapshot.area.z0 + 1;
          const int kr = BlurHalfWidth(brush);
          std::vector<float> src(snapshot.words.begin(), snapshot.words.end());
          std::vector<float> pass;
          BoxBlur(src, w, h, kr, pass);
          BoxBlur(pass, w, h, kr, snapshot.blurred);
        }
        snapshots.push_back(std::move(snapshot));
      }
      return snapshots;
    }

    /** The stamp's value (0..1) at offset (dx, dz) from the brush's centre, over the brush's square; 0 outside. */
    [[nodiscard]] float StampAt(
      const HeightStamp& stamp,
      const float dx,
      const float dz,
      const float radius
    )
    {
      if (stamp.width < 2 || stamp.height < 2 || radius <= 0.0f) {
        return 0.0f;
      }
      const float u = (dx / radius * 0.5f + 0.5f) * static_cast<float>(stamp.width - 1);
      const float v = (dz / radius * 0.5f + 0.5f) * static_cast<float>(stamp.height - 1);
      if (u < 0.0f || v < 0.0f || u > static_cast<float>(stamp.width - 1) || v > static_cast<float>(stamp.height - 1)) {
        return 0.0f;
      }
      const int x0 = std::min(stamp.width - 2, static_cast<int>(u));
      const int z0 = std::min(stamp.height - 2, static_cast<int>(v));
      const float fx = u - static_cast<float>(x0);
      const float fz = v - static_cast<float>(z0);
      const auto at = [&](const int x, const int z) {
        return static_cast<float>(
          stamp.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(stamp.width) + static_cast<std::size_t>(x)]
        );
      };
      const float value = (at(x0, z0) * (1.0f - fx) + at(x0 + 1, z0) * fx) * (1.0f - fz) +
        (at(x0, z0 + 1) * (1.0f - fx) + at(x0 + 1, z0 + 1) * fx) * fz;
      return value / 65535.0f;
    }

    /** Whether the limits let the brush change this sample (read before the step). */
    [[nodiscard]] bool WithinLimits(
      const Snapshot& snapshot,
      const int sx,
      const int sz,
      const HeightBrush& brush
    )
    {
      const float current = snapshot.At(sx, sz);
      if (brush.limitHeight && (current < brush.limitLow || current > brush.limitHigh)) {
        return false;
      }
      if (brush.limitSlope) {
        // Rise over run in game units, from the neighbours on each side (one sample is one unit).
        const float dx = (snapshot.At(sx + 1, sz) - snapshot.At(sx - 1, sz)) * 0.5f / kWordsPerUnit;
        const float dz = (snapshot.At(sx, sz + 1) - snapshot.At(sx, sz - 1)) * 0.5f / kWordsPerUnit;
        if (std::hypot(dx, dz) > brush.limitMaxSlope) {
          return false;
        }
      }
      return true;
    }

    /** The brush's new height for one sample, from the heights before the step; (dx, dz) from its nearest copy's
     * centre. */
    [[nodiscard]] float BrushedHeight(
      const Snapshot& snapshot,
      const int sx,
      const int sz,
      const float weight,
      const HeightBrush& brush,
      const float seconds,
      const float dx,
      const float dz
    )
    {
      const float strength = std::clamp(brush.strength, 0.0f, 1.0f);
      const float blend = std::min(1.0f, strength * kBlendPerSecond * seconds);
      const float current = snapshot.At(sx, sz);
      switch (brush.mode) {
      case HeightBrushMode::Raise:
        return current + weight * strength * kRaiseUnitsPerSecond * kWordsPerUnit * seconds;
      case HeightBrushMode::Lower:
        return current - weight * strength * kRaiseUnitsPerSecond * kWordsPerUnit * seconds;
      case HeightBrushMode::Smooth:
        return current + (snapshot.Blurred(sx, sz) - current) * blend * weight;
      case HeightBrushMode::Sharpen:
        return current -
          (snapshot.Blurred(sx, sz) - current) * std::min(1.0f, strength * kSharpenPerSecond * seconds) * weight;
      case HeightBrushMode::Plateau:
        // To the level in one go where the brush is full at strength 0.5 and more; the falloff shapes the shoulder.
        return current + (brush.flattenTo - current) * std::min(1.0f, 2.0f * strength * weight);
      case HeightBrushMode::Flatten:
        return current + (brush.flattenTo - current) * blend * weight;
      case HeightBrushMode::Noise:
        return current +
          SmoothNoise(sx, sz, brush) * weight * strength * kNoiseUnitsPerSecond * kWordsPerUnit * seconds;
      case HeightBrushMode::SetHeight:
        return current + (brush.setTo - current) * blend * weight;
      case HeightBrushMode::Terrace: {
        const float step = std::max(1.0f, brush.terraceStep);
        return current + (std::round(current / step) * step - current) * blend * weight;
      }
      case HeightBrushMode::Plane:
        if (!brush.planeSet) {
          return current;
        }
        return current +
          (static_cast<float>(brush.planeX * sx + brush.planeZ * sz + brush.planeC) - current) * blend * weight;
      case HeightBrushMode::Stamp:
        if (brush.stamp == nullptr) {
          return current;
        }
        return current + StampAt(*brush.stamp, dx, dz, brush.radius) * brush.stampHeight * strength * weight;
      case HeightBrushMode::Erode: {
        // Each of the 8 neighbours: the part of the difference over the talus slope at its distance, towards it. A
        // sixteenth of each (half of a pair's excess, shared by 8 neighbours) keeps a step from overshooting.
        // Its own rate: up to kErodeStepsPerSecond full steps a second (at most one a call). The other brushes' blend
        // would move a sample under half a word a frame at 60 fps, which rounds back to nothing.
        const float steps = std::min(1.0f, strength * kErodeStepsPerSecond * seconds);
        const float talus = std::max(0.0f, brush.erodeTalus) * kWordsPerUnit;
        float change = 0.0f;
        for (int nz = -1; nz <= 1; ++nz) {
          for (int nx = -1; nx <= 1; ++nx) {
            if (nx == 0 && nz == 0) {
              continue;
            }
            const float distance = nx != 0 && nz != 0 ? 1.41421356f : 1.0f;
            const float diff = snapshot.At(sx + nx, sz + nz) - current;
            const float over = std::abs(diff) - talus * distance;
            if (over > 0.0f) {
              change += diff > 0.0f ? over : -over;
            }
          }
        }
        return current + change * 0.0625f * steps * weight;
      }
      case HeightBrushMode::WaterErode:
      case HeightBrushMode::Rain:
      case HeightBrushMode::Deposit:
        return current; // simulated over the whole area at once (ApplyErosion), not sample by sample
      }
      return current;
    }

    [[nodiscard]] std::uint16_t ToWord(
      const float value
    )
    {
      return static_cast<std::uint16_t>(std::lround(std::clamp(value, 0.0f, 65535.0f)));
    }

    [[nodiscard]] float StrongestWeight(
      const int sx,
      const int sz,
      const float (&centreX)[kMaxSymmetryCopies],
      const float (&centreZ)[kMaxSymmetryCopies],
      const int centres,
      const HeightBrush& brush,
      int* const strongest = nullptr
    )
    {
      float weight = 0.0f;
      float nearest = 0.0f;
      for (int c = 0; c < centres; ++c) {
        const float distance = std::hypot(static_cast<float>(sx) - centreX[c], static_cast<float>(sz) - centreZ[c]);
        const float w = Weight(distance, brush);
        if (strongest != nullptr && (c == 0 || distance < nearest)) {
          nearest = distance;
          *strongest = c;
        }
        weight = std::max(weight, w);
      }
      return weight;
    }

    /** The brush's weight at offset (dx, dz) from its centre in its own frame: its shape, turned, cut at the radius. */
    [[nodiscard]] float ShapeWeight(
      const HeightBrush& brush,
      const float dx,
      const float dz
    )
    {
      const float distance = std::hypot(dx, dz);
      if (brush.shape == BrushShape::Round) {
        return Weight(distance, brush);
      }
      if (distance >= brush.radius) {
        return 0.0f;
      }
      const double angle = static_cast<double>(brush.shapeAngle) * (kTwoPi / 360.0);
      const double c = std::cos(angle);
      const double s = std::sin(angle);
      const double u = (dx * c + dz * s) / brush.radius;
      const double v = (-dx * s + dz * c) / brush.radius;
      if (std::abs(u) > 1.0 || std::abs(v) > 1.0) {
        return 0.0f;
      }
      return std::clamp(BrushShapeAt(brush.shape, static_cast<float>(u), static_cast<float>(v)), 0.0f, 1.0f);
    }

    /** Shapes and stamps aren't round: they are read in the cursor copy's frame (CursorFrameWeight). */
    [[nodiscard]] bool ReadsCursorFrame(
      const HeightBrush& brush
    )
    {
      return brush.shape != BrushShape::Round || brush.mode == HeightBrushMode::Stamp;
    }

    /**
     * A shaped brush's (or a stamp's) weight for a sample's group and the offset it was read at, in the frame of the
     * cursor's copy (centre 0): copy k at a sample reads the cursor's dab at the sample taken back through copy k's
     * symmetry, which is one of the group's members (mirrors and half or quarter turns), or, for N-way turns, the
     * sample's offset from centre k turned back by k turns. The strongest wins, as for the round brush, so a stroke
     * across a mirror line doesn't apply twice, and every copy is the mirror or turned image of the cursor's dab.
     */
    [[nodiscard]] float CursorFrameWeight(
      const int sx,
      const int sz,
      const Symmetry symmetry,
      const int width,
      const int height,
      const float (&centreX)[kMaxSymmetryCopies],
      const float (&centreZ)[kMaxSymmetryCopies],
      const int centres,
      const HeightBrush& brush,
      float& outDx,
      float& outDz
    )
    {
      float best = 0.0f;
      outDx = static_cast<float>(sx) - centreX[0];
      outDz = static_cast<float>(sz) - centreZ[0];
      const auto consider = [&](const float dx, const float dz) {
        const float w = ShapeWeight(brush, dx, dz);
        if (w > best) {
          best = w;
          outDx = dx;
          outDz = dz;
        }
      };
      if (symmetry == Symmetry::NWay) {
        for (int c = 0; c < centres; ++c) {
          const double angle = -kTwoPi * c / centres;
          const double dx = static_cast<double>(sx) - centreX[c];
          const double dz = static_cast<double>(sz) - centreZ[c];
          consider(
            static_cast<float>(dx * std::cos(angle) - dz * std::sin(angle)),
            static_cast<float>(dx * std::sin(angle) + dz * std::cos(angle))
          );
        }
        return best;
      }
      int memberX[kMaxSymmetryCopies];
      int memberZ[kMaxSymmetryCopies];
      const int members = Copies<int>(symmetry, brush.turns, width - 1, height - 1, sx, sz, memberX, memberZ);
      for (int m = 0; m < members; ++m) {
        consider(static_cast<float>(memberX[m]) - centreX[0], static_cast<float>(memberZ[m]) - centreZ[0]);
      }
      return best;
    }

    /** True if the sample is within `reach` of a centre. */
    [[nodiscard]] bool NearACentre(
      const int sx,
      const int sz,
      const float (&centreX)[kMaxSymmetryCopies],
      const float (&centreZ)[kMaxSymmetryCopies],
      const int centres,
      const float reach
    )
    {
      for (int c = 0; c < centres; ++c) {
        if (std::hypot(static_cast<float>(sx) - centreX[c], static_cast<float>(sz) - centreZ[c]) < reach) {
          return true;
        }
      }
      return false;
    }

    /** True if no rectangle before `r` holds the sample (each sample is handled once). */
    [[nodiscard]] bool FirstRectHolding(
      const std::vector<SampleRect>& rects,
      const std::size_t r,
      const int sx,
      const int sz
    )
    {
      for (std::size_t e = 0; e < r; ++e) {
        if (Contains(rects[e], sx, sz)) {
          return false;
        }
      }
      return true;
    }

    /** A small fast generator (SplitMix64) for the droplets: the same seed, the same step. */
    struct DropletRandom
    {
      std::uint64_t state;
      std::uint64_t Next()
      {
        std::uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
      }
      /** 0 to 1. */
      float Unit()
      {
        return static_cast<float>(Next() >> 40) / 16777216.0f;
      }
    };

    constexpr float kDropletsPerSecond = 600.0f;
    constexpr int kDropletSteps = 40;
    constexpr float kDropletInertia = 0.05f;
    constexpr float kDropletCapacity = 4.0f;
    constexpr float kDropletMinCapacity = 0.01f;
    constexpr float kDropletErodeRate = 0.3f;
    constexpr float kDropletDepositRate = 0.3f;
    constexpr float kDropletEvaporate = 0.02f;
    constexpr float kDropletGravity = 4.0f;

    /**
     * Water erode (HeightBrushMode::WaterErode) around the brush's first copy (`rect`, centred on cx, cz): droplets
     * on a float copy of the area, in game units, then each changed sample written, rounded at random but evenly, to
     * every member of its symmetry group.
     */
    void ApplyWater(
      std::uint16_t* const heights,
      const int width,
      const int height,
      const SampleRect& rect,
      const float cx,
      const float cz,
      const Symmetry symmetry,
      const HeightBrush& brush,
      const float seconds
    )
    {
      const int areaW = rect.x1 - rect.x0 + 1;
      const int areaH = rect.z1 - rect.z0 + 1;
      if (areaW < 3 || areaH < 3) {
        return;
      }
      std::vector<float> ground(static_cast<std::size_t>(areaW) * static_cast<std::size_t>(areaH));
      std::vector<std::uint16_t> original(ground.size());
      for (int z = 0; z < areaH; ++z) {
        for (int x = 0; x < areaW; ++x) {
          const std::uint16_t word = heights
            [static_cast<std::size_t>(rect.z0 + z) * static_cast<std::size_t>(width) +
             static_cast<std::size_t>(rect.x0 + x)];
          original[static_cast<std::size_t>(z) * static_cast<std::size_t>(areaW) + static_cast<std::size_t>(x)] = word;
          ground[static_cast<std::size_t>(z) * static_cast<std::size_t>(areaW) + static_cast<std::size_t>(x)] =
            static_cast<float>(word) / kWordsPerUnit;
        }
      }
      const auto cell = [&](const int x, const int z) -> float& {
        return ground[static_cast<std::size_t>(z) * static_cast<std::size_t>(areaW) + static_cast<std::size_t>(x)];
      };
      // Inside the area with a cell to the right and below (bilinear reads and writes), and under the brush.
      const auto usable = [&](const float px, const float pz) {
        return px >= 0.0f && pz >= 0.0f && px < static_cast<float>(areaW - 1) && pz < static_cast<float>(areaH - 1) &&
          Weight(std::hypot(px + static_cast<float>(rect.x0) - cx, pz + static_cast<float>(rect.z0) - cz), brush) >
          0.0f;
      };
      // The height at a point and its gradient, from its cell's four corners.
      const auto sample = [&](const float px, const float pz, float& h, float& gx, float& gz) {
        const int x = static_cast<int>(px);
        const int z = static_cast<int>(pz);
        const float fx = px - static_cast<float>(x);
        const float fz = pz - static_cast<float>(z);
        const float a = cell(x, z), b = cell(x + 1, z), c = cell(x, z + 1), d = cell(x + 1, z + 1);
        gx = (b - a) * (1.0f - fz) + (d - c) * fz;
        gz = (c - a) * (1.0f - fx) + (d - b) * fx;
        h = (a * (1.0f - fx) + b * fx) * (1.0f - fz) + (c * (1.0f - fx) + d * fx) * fz;
      };
      // Ground added (or taken, when negative) at a point, shared between its cell's corners.
      const auto add = [&](const float px, const float pz, const float amount) {
        const int x = static_cast<int>(px);
        const int z = static_cast<int>(pz);
        const float fx = px - static_cast<float>(x);
        const float fz = pz - static_cast<float>(z);
        cell(x, z) += amount * (1.0f - fx) * (1.0f - fz);
        cell(x + 1, z) += amount * fx * (1.0f - fz);
        cell(x, z + 1) += amount * (1.0f - fx) * fz;
        cell(x + 1, z + 1) += amount * fx * fz;
      };

      DropletRandom random{static_cast<std::uint64_t>(brush.seed) * 0x2545F4914F6CDD1DULL + 1};
      const float wanted = std::clamp(brush.strength, 0.0f, 1.0f) * kDropletsPerSecond * seconds;
      const int droplets = static_cast<int>(wanted) + (random.Unit() < wanted - std::floor(wanted) ? 1 : 0);
      for (int d = 0; d < droplets; ++d) {
        const float angle = random.Unit() * 6.2831853f;
        const float reach = brush.radius * std::sqrt(random.Unit());
        float px = cx + std::cos(angle) * reach - static_cast<float>(rect.x0);
        float pz = cz + std::sin(angle) * reach - static_cast<float>(rect.z0);
        if (!usable(px, pz)) {
          continue;
        }
        float dirX = 0.0f, dirZ = 0.0f, speed = 1.0f, water = 1.0f, sediment = 0.0f;
        for (int step = 0; step < kDropletSteps; ++step) {
          float h = 0.0f, gx = 0.0f, gz = 0.0f;
          sample(px, pz, h, gx, gz);
          dirX = dirX * kDropletInertia - gx * (1.0f - kDropletInertia);
          dirZ = dirZ * kDropletInertia - gz * (1.0f - kDropletInertia);
          const float length = std::hypot(dirX, dirZ);
          if (length < 1e-6f) {
            break; // flat: it stays (and leaves what it carries below)
          }
          dirX /= length;
          dirZ /= length;
          const float nx = px + dirX;
          const float nz = pz + dirZ;
          if (!usable(nx, nz)) {
            break;
          }
          float nh = 0.0f, ngx = 0.0f, ngz = 0.0f;
          sample(nx, nz, nh, ngx, ngz);
          const float rise = nh - h;
          const float capacity = std::max(-rise * speed * water * kDropletCapacity, kDropletMinCapacity);
          const float weight =
            Weight(std::hypot(px + static_cast<float>(rect.x0) - cx, pz + static_cast<float>(rect.z0) - cz), brush);
          if (sediment > capacity || rise > 0.0f) {
            // Uphill it fills the dip it leaves (no more than it carries); otherwise it leaves what it can't carry.
            const float drop = rise > 0.0f ? std::min(rise, sediment) : (sediment - capacity) * kDropletDepositRate;
            add(px, pz, drop);
            sediment -= drop;
          } else {
            // It takes ground, no deeper than the drop to its next point, less towards the brush's edge.
            const float take = std::min((capacity - sediment) * kDropletErodeRate, -rise) * weight;
            add(px, pz, -take);
            sediment += take;
          }
          speed = std::sqrt(std::max(0.0f, speed * speed - rise * kDropletGravity));
          water *= 1.0f - kDropletEvaporate;
          px = nx;
          pz = nz;
        }
        add(px, pz, sediment); // what it still carries stays where it stopped
      }

      // Written back: each sample that changed, rounded at random in proportion (so small changes add up, and none is
      // lost on average), to every member of its symmetry group, within the brush's limits.
      const auto originalAt = [&](const int x, const int z) {
        return static_cast<float>(
          original
            [static_cast<std::size_t>(std::clamp(z, 0, areaH - 1)) * static_cast<std::size_t>(areaW) +
             static_cast<std::size_t>(std::clamp(x, 0, areaW - 1))]
        );
      };
      for (int z = 0; z < areaH; ++z) {
        for (int x = 0; x < areaW; ++x) {
          const float value = cell(x, z) * kWordsPerUnit;
          const float lower = std::floor(value);
          const float rounded = random.Unit() < value - lower ? lower + 1.0f : lower;
          const std::uint16_t word = ToWord(rounded);
          if (
            word ==
            original[static_cast<std::size_t>(z) * static_cast<std::size_t>(areaW) + static_cast<std::size_t>(x)]
          ) {
            continue;
          }
          const float before = originalAt(x, z);
          if (brush.limitHeight && (before < brush.limitLow || before > brush.limitHigh)) {
            continue;
          }
          if (brush.limitSlope) {
            const float sx = (originalAt(x + 1, z) - originalAt(x - 1, z)) * 0.5f / kWordsPerUnit;
            const float sz = (originalAt(x, z + 1) - originalAt(x, z - 1)) * 0.5f / kWordsPerUnit;
            if (std::hypot(sx, sz) > brush.limitMaxSlope) {
              continue;
            }
          }
          int memberX[kMaxSymmetryCopies];
          int memberZ[kMaxSymmetryCopies];
          const int members =
            Copies<int>(symmetry, brush.turns, width - 1, height - 1, rect.x0 + x, rect.z0 + z, memberX, memberZ);
          for (int m = 0; m < members; ++m) {
            heights
              [static_cast<std::size_t>(memberZ[m]) * static_cast<std::size_t>(width) +
               static_cast<std::size_t>(memberX[m])] = word;
          }
        }
      }
    }

    namespace erosion = faf::editor::field::erosion;

    // The erosion brushes' settings (FAF Studio's erosionbrush.lua Values). Studio puts down a dab every so often
    // along a stroke; here a step lasts a frame, so a dab's rounds of droplets and its deposit follow the step's time
    // as if 15 dabs a second were put down.
    constexpr double kErosionDabsPerSecond = 15.0;
    constexpr double kErosionRoundsPerDab = 4.0;
    constexpr double kDepositPerDab = 0.5; // game units at the centre

    [[nodiscard]] int ErosionModeOf(
      const HeightBrushMode mode
    )
    {
      return mode == HeightBrushMode::Rain ? 1 : (mode == HeightBrushMode::Deposit ? 2 : 0);
    }

    /** How far from its centre an erosion step can write: the brush, Rain's reach past it, and the window's rim. */
    [[nodiscard]] float ErosionReach(
      const HeightBrush& brush
    )
    {
      const double radius = std::max(1.0, static_cast<double>(brush.radius));
      return static_cast<float>(radius + erosion::BrushDefaultMargin(ErosionModeOf(brush.mode), radius) + 2.0);
    }

    [[nodiscard]] erosion::HydroParams ErosionParams(
      const HeightBrush& brush
    )
    {
      erosion::HydroParams p;
      p.rain = 0.006f;
      p.evaporation = 0.02f;
      p.capacity = 1.0f;
      p.erosion = 0.2f;
      p.deposition = 0.1f;
      p.inertia = 0.3f;
      p.conserve = 0.7f;
      p.thermal = 0.15f;
      p.talus = 0.8f;
      p.vary = 0.5f;
      p.vary_scale = 24.0f;
      p.track = false;
      p.seed = brush.seed;
      return p;
    }
  } // namespace

  const char* BrushShapeName(
    const BrushShape shape
  )
  {
    static const char* const kNames[kBrushShapeCount] = {
      "Round", "Square", "Diamond", "Cone", "Plateau", "Ring", "Ridge", "Mountain", "Rocks", "Bump"
    };
    const int i = static_cast<int>(shape);
    return i >= 0 && i < kBrushShapeCount ? kNames[i] : "Round";
  }

  float BrushShapeAt(
    const BrushShape shape,
    const float uf,
    const float vf
  )
  {
    const double u = uf;
    const double v = vf;
    const double d = std::sqrt(u * u + v * v);
    switch (shape) {
    case BrushShape::Round:
      return d < 1.0 ? 1.0f : 0.0f;
    case BrushShape::Square:
      return static_cast<float>(ShapeSmooth(1.0, 0.85, std::max(std::abs(u), std::abs(v))));
    case BrushShape::Diamond:
      return static_cast<float>(ShapeSmooth(1.0, 0.8, std::abs(u) + std::abs(v)));
    case BrushShape::Cone:
      return static_cast<float>(std::max(0.0, 1.0 - d));
    case BrushShape::Plateau:
      return static_cast<float>(ShapeSmooth(1.0, 0.7, d));
    case BrushShape::Ring:
      return static_cast<float>(ShapeSmooth(0.45, 0.7, d) * ShapeSmooth(1.0, 0.85, d));
    case BrushShape::Ridge:
      return static_cast<float>(ShapeSmooth(1.0, 0.85, std::abs(u)) * ShapeSmooth(0.35, 0.0, std::abs(v)));
    case BrushShape::Mountain:
      return static_cast<float>(std::min(1.0, std::max(0.0, 1.0 - d) * (0.35 + 1.3 * ShapeFractal(u + 3.7, v + 1.9))));
    case BrushShape::Rocks:
      return d >= 1.0
        ? 0.0f
        : static_cast<float>(ShapeSmooth(0.5, 0.62, ShapeValueNoise(u * 3.0 + 11.0, v * 3.0 + 5.0)) * (1.0 - d));
    case BrushShape::Bump:
      return d >= 1.0 ? 0.0f : static_cast<float>(0.5 * (1.0 + std::cos(3.14159265358979 * d)));
    }
    return 0.0f;
  }

  class ErosionStroke
  {
  public:
    erosion::ErodeSession session;
  };

  void ErosionStrokeDelete::operator()(
    ErosionStroke* const stroke
  ) const noexcept
  {
    delete stroke;
  }

  ErosionStrokePtr MakeErosionStroke()
  {
    return ErosionStrokePtr(new ErosionStroke);
  }

  namespace
  {
    /**
     * Rain and Deposit: one dab of the erosion session on the cursor's copy (centred on cx, cz), then
     * every sample it changed written to every member of its symmetry group, and the session told what was written.
     * A change the limits turn down is put back in the session too.
     */
    void ApplyErosion(
      std::uint16_t* const heights,
      const int width,
      const int height,
      const float cx,
      const float cz,
      const Symmetry symmetry,
      const HeightBrush& brush,
      const float seconds,
      ErosionStroke* const stroke
    )
    {
      ErosionStroke own;
      ErosionStroke& state = stroke != nullptr ? *stroke : own;
      if (!state.session.Active()) {
        state.session.Begin(width, height, heights, ErosionParams(brush));
      }
      const double strength = std::clamp(static_cast<double>(brush.strength), 0.0, 1.0);
      const double dabs = static_cast<double>(seconds) * kErosionDabsPerSecond;
      erosion::BrushDab dab;
      dab.cx = cx;
      dab.cz = cz;
      dab.radius = brush.radius;
      dab.falloff = brush.falloff;
      dab.mode = ErosionModeOf(brush.mode);
      dab.iterations = std::clamp(static_cast<int>(std::lround(strength * kErosionRoundsPerDab * dabs)), 1, 60);
      dab.strength = 1.0;
      dab.amount = kDepositPerDab * strength * dabs;
      int x0 = 0;
      int z0 = 0;
      int x1 = 0;
      int z1 = 0;
      std::vector<std::uint16_t> words;
      if (!state.session.Dab(dab, x0, z0, x1, z1, words)) {
        return;
      }
      const int windowW = x1 - x0 + 1;
      const auto at = [&](const int x, const int z) -> std::uint16_t& {
        return heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
      };
      // The heights before this step, for the limits (the window plus a sample around it for the slope).
      const auto before = [&](const int x, const int z) {
        return static_cast<float>(at(std::clamp(x, 0, width - 1), std::clamp(z, 0, height - 1)));
      };
      std::vector<std::uint16_t> original(words.size());
      for (int z = z0; z <= z1; ++z) {
        for (int x = x0; x <= x1; ++x) {
          original
            [static_cast<std::size_t>(z - z0) * static_cast<std::size_t>(windowW) + static_cast<std::size_t>(x - x0)] =
              at(x, z);
        }
      }
      for (int z = z0; z <= z1; ++z) {
        for (int x = x0; x <= x1; ++x) {
          const std::size_t i =
            static_cast<std::size_t>(z - z0) * static_cast<std::size_t>(windowW) + static_cast<std::size_t>(x - x0);
          const std::uint16_t word = words[i];
          if (word == original[i]) {
            continue;
          }
          const float was = static_cast<float>(original[i]);
          bool allowed = !brush.limitHeight || (was >= brush.limitLow && was <= brush.limitHigh);
          if (allowed && brush.limitSlope) {
            const float sx = (before(x + 1, z) - before(x - 1, z)) * 0.5f / kWordsPerUnit;
            const float sz = (before(x, z + 1) - before(x, z - 1)) * 0.5f / kWordsPerUnit;
            allowed = std::hypot(sx, sz) <= brush.limitMaxSlope;
          }
          if (!allowed) {
            state.session.Store(x, z, original[i]);
            continue;
          }
          int memberX[kMaxSymmetryCopies];
          int memberZ[kMaxSymmetryCopies];
          const int members = Copies<int>(symmetry, brush.turns, width - 1, height - 1, x, z, memberX, memberZ);
          for (int m = 0; m < members; ++m) {
            at(memberX[m], memberZ[m]) = word;
            if (memberX[m] != x || memberZ[m] != z) {
              state.session.Store(memberX[m], memberZ[m], word);
            }
          }
        }
      }
    }

    /** N-way turns: see ApplyHeightBrush. */
    void ApplyTurned(
      std::uint16_t* const heights,
      const int width,
      const int height,
      const std::vector<SampleRect>& rects,
      const float (&centreX)[kMaxSymmetryCopies],
      const float (&centreZ)[kMaxSymmetryCopies],
      const int centres,
      const HeightBrush& brush,
      const float seconds
    )
    {
      // The first sector, painted with the brush from the heights before the step.
      const std::vector<Snapshot> snapshots = TakeSnapshots(heights, width, height, rects, brush);
      for (std::size_t r = 0; r < rects.size(); ++r) {
        const SampleRect& rect = rects[r];
        for (int sz = rect.z0; sz <= rect.z1; ++sz) {
          for (int sx = rect.x0; sx <= rect.x1; ++sx) {
            if (TurnSector(width, height, brush.turns, sx, sz) != 0 || !FirstRectHolding(rects, r, sx, sz)) {
              continue;
            }
            int nearest = 0;
            float dx = 0.0f;
            float dz = 0.0f;
            float weight = 0.0f;
            if (ReadsCursorFrame(brush)) {
              weight =
                CursorFrameWeight(sx, sz, Symmetry::NWay, width, height, centreX, centreZ, centres, brush, dx, dz);
            } else {
              weight = StrongestWeight(sx, sz, centreX, centreZ, centres, brush, &nearest);
              dx = static_cast<float>(sx) - centreX[nearest];
              dz = static_cast<float>(sz) - centreZ[nearest];
            }
            if (weight > 0.0f && WithinLimits(snapshots[r], sx, sz, brush)) {
              heights[static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx)] =
                ToWord(BrushedHeight(snapshots[r], sx, sz, weight, brush, seconds, dx, dz));
            }
          }
        }
      }

      // Every other sample the brush covers copies the first sector; TurnedHeight reads only the first
      // sector, which this pass doesn't write.
      for (std::size_t r = 0; r < rects.size(); ++r) {
        const SampleRect& rect = rects[r];
        for (int sz = rect.z0; sz <= rect.z1; ++sz) {
          for (int sx = rect.x0; sx <= rect.x1; ++sx) {
            double value = 0.0;
            if (
              TurnSector(width, height, brush.turns, sx, sz) == 0 || !FirstRectHolding(rects, r, sx, sz) ||
              !NearACentre(sx, sz, centreX, centreZ, centres, brush.radius + kTurnRim) ||
              !TurnedHeight(heights, width, height, brush.turns, sx, sz, value)
            ) {
              continue;
            }
            heights[static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx)] =
              ToWord(static_cast<float>(value));
          }
        }
      }
    }
  } // namespace

  bool PlaneThrough(
    const double (&x)[3],
    const double (&h)[3],
    const double (&z)[3],
    double& planeX,
    double& planeZ,
    double& planeC
  )
  {
    // h = a x + b z + c through the three points: Cramer's rule on the two differences.
    const double x1 = x[1] - x[0];
    const double z1 = z[1] - z[0];
    const double h1 = h[1] - h[0];
    const double x2 = x[2] - x[0];
    const double z2 = z[2] - z[0];
    const double h2 = h[2] - h[0];
    const double determinant = x1 * z2 - x2 * z1;
    if (std::fabs(determinant) < 1e-6) {
      return false;
    }
    planeX = (h1 * z2 - h2 * z1) / determinant;
    planeZ = (x1 * h2 - x2 * h1) / determinant;
    planeC = h[0] - planeX * x[0] - planeZ * z[0];
    return true;
  }

  int TurnSector(
    const int width,
    const int height,
    const int turns,
    const int x,
    const int z
  )
  {
    const int count = Turns(turns);
    double angle = std::atan2(z - (height - 1) * 0.5, x - (width - 1) * 0.5);
    if (angle < 0.0) {
      angle += kTwoPi;
    }
    return std::min(count - 1, static_cast<int>(angle / (kTwoPi / count)));
  }

  bool TurnedHeight(
    const std::uint16_t* const heights,
    const int width,
    const int height,
    const int turns,
    const int x,
    const int z,
    double& value
  )
  {
    const int count = Turns(turns);
    const double cx = (width - 1) * 0.5;
    const double cz = (height - 1) * 0.5;
    // A point turned back by the sector of sample (sx, sz).
    const auto turnBack =
      [&](const int sx, const int sz, const double px, const double pz, double& outX, double& outZ) {
      const double back = -kTwoPi * TurnSector(width, height, count, sx, sz) / count;
      outX = cx + (px - cx) * std::cos(back) - (pz - cz) * std::sin(back);
      outZ = cz + (px - cx) * std::sin(back) + (pz - cz) * std::cos(back);
    };
    double px = 0.0;
    double pz = 0.0;
    turnBack(x, z, x, z, px, pz);
    if (px < 0.0 || pz < 0.0 || px > width - 1 || pz > height - 1) {
      return false;
    }
    const int x0 = std::min(width - 2, static_cast<int>(px));
    const int z0 = std::min(height - 2, static_cast<int>(pz));
    const double fx = px - x0;
    const double fz = pz - z0;
    const auto at = [&](const int ax, const int az) {
      int sx = ax;
      int sz = az;
      if (TurnSector(width, height, count, ax, az) != 0) {
        // Outside the first sector: its own turned-back sample.
        double bx = 0.0;
        double bz = 0.0;
        turnBack(ax, az, ax, az, bx, bz);
        sx = std::clamp(static_cast<int>(std::lround(bx)), 0, width - 1);
        sz = std::clamp(static_cast<int>(std::lround(bz)), 0, height - 1);
      }
      return static_cast<double>(
        heights[static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx)]
      );
    };
    value = (at(x0, z0) * (1.0 - fx) + at(x0 + 1, z0) * fx) * (1.0 - fz) +
      (at(x0, z0 + 1) * (1.0 - fx) + at(x0 + 1, z0 + 1) * fx) * fz;
    return true;
  }

  Symmetry EffectiveSymmetry(
    const Symmetry symmetry,
    const int width,
    const int height
  )
  {
    return NeedsSquare(symmetry) && width != height ? Symmetry::None : symmetry;
  }

  int SymmetricSamples(
    const Symmetry symmetry,
    const int turns,
    const int width,
    const int height,
    const int x,
    const int z,
    int (&outX)[kMaxSymmetryCopies],
    int (&outZ)[kMaxSymmetryCopies]
  )
  {
    return Copies<int>(EffectiveSymmetry(symmetry, width, height), turns, width - 1, height - 1, x, z, outX, outZ);
  }

  int HeightBrushCentres(
    const int width,
    const int height,
    const float x,
    const float z,
    const Symmetry symmetry,
    const int turns,
    float (&outX)[kMaxSymmetryCopies],
    float (&outZ)[kMaxSymmetryCopies]
  )
  {
    return Copies<float>(
      EffectiveSymmetry(symmetry, width, height),
      turns,
      static_cast<float>(width - 1),
      static_cast<float>(height - 1),
      x,
      z,
      outX,
      outZ
    );
  }

  std::vector<SampleRect> HeightBrushRects(
    const int width,
    const int height,
    const float x,
    const float z,
    const HeightBrush& brush
  )
  {
    if (width < 2 || height < 2 || brush.radius <= 0.0f) {
      return {};
    }
    float centreX[kMaxSymmetryCopies];
    float centreZ[kMaxSymmetryCopies];
    const int centres = HeightBrushCentres(width, height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    const bool turned = EffectiveSymmetry(brush.symmetry, width, height) == Symmetry::NWay;
    const float reach = IsErosionMode(brush.mode) ? ErosionReach(brush) : brush.radius;
    return RectsAround(width, height, centreX, centreZ, centres, reach + (turned ? kTurnRim : 0.0f));
  }

  std::vector<SampleRect> ApplyHeightBrush(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const float x,
    const float z,
    const HeightBrush& brush,
    const float seconds,
    ErosionStroke* const stroke
  )
  {
    if (heights == nullptr || width < 2 || height < 2 || brush.radius <= 0.0f || seconds <= 0.0f) {
      return {};
    }
    const Symmetry symmetry = EffectiveSymmetry(brush.symmetry, width, height);

    // The brush's copies and the rectangle each one covers.
    float centreX[kMaxSymmetryCopies];
    float centreZ[kMaxSymmetryCopies];
    const int centres = HeightBrushCentres(width, height, x, z, symmetry, brush.turns, centreX, centreZ);
    const float reach = IsErosionMode(brush.mode) ? ErosionReach(brush) : brush.radius;
    const std::vector<SampleRect> rects =
      RectsAround(width, height, centreX, centreZ, centres, reach + (symmetry == Symmetry::NWay ? kTurnRim : 0.0f));
    // Simulated around the cursor's copy; its changes written to every symmetric copy.
    if (brush.mode == HeightBrushMode::WaterErode) {
      if (!rects.empty()) {
        ApplyWater(heights, width, height, rects.front(), centreX[0], centreZ[0], symmetry, brush, seconds);
      }
      return rects;
    }
    if (IsErosionMode(brush.mode)) {
      if (!rects.empty()) {
        ApplyErosion(heights, width, height, centreX[0], centreZ[0], symmetry, brush, seconds, stroke);
      }
      return rects;
    }
    if (symmetry == Symmetry::NWay) {
      ApplyTurned(heights, width, height, rects, centreX, centreZ, centres, brush, seconds);
      return rects;
    }

    // Smooth reads its neighbours as they were before this step.
    const std::vector<Snapshot> snapshots = TakeSnapshots(heights, width, height, rects, brush);
    for (std::size_t r = 0; r < rects.size(); ++r) {
      const SampleRect& rect = rects[r];
      for (int sz = rect.z0; sz <= rect.z1; ++sz) {
        for (int sx = rect.x0; sx <= rect.x1; ++sx) {
          // Each group once: from its first member, and from the first rectangle that holds it.
          int memberX[kMaxSymmetryCopies];
          int memberZ[kMaxSymmetryCopies];
          const int members = Copies<int>(symmetry, brush.turns, width - 1, height - 1, sx, sz, memberX, memberZ);
          bool first = true;
          for (int m = 1; m < members && first; ++m) {
            first = memberZ[m] > sz || (memberZ[m] == sz && memberX[m] >= sx);
          }
          if (!first || !FirstRectHolding(rects, r, sx, sz)) {
            continue;
          }
          int nearest = 0;
          float dx = 0.0f;
          float dz = 0.0f;
          float weight = 0.0f;
          if (ReadsCursorFrame(brush)) {
            weight = CursorFrameWeight(sx, sz, symmetry, width, height, centreX, centreZ, centres, brush, dx, dz);
          } else {
            weight = StrongestWeight(sx, sz, centreX, centreZ, centres, brush, &nearest);
            dx = static_cast<float>(sx) - centreX[nearest];
            dz = static_cast<float>(sz) - centreZ[nearest];
          }
          if (weight <= 0.0f || !WithinLimits(snapshots[r], sx, sz, brush)) {
            continue;
          }
          const std::uint16_t word = ToWord(BrushedHeight(snapshots[r], sx, sz, weight, brush, seconds, dx, dz));
          for (int m = 0; m < members; ++m) {
            heights
              [static_cast<std::size_t>(memberZ[m]) * static_cast<std::size_t>(width) +
               static_cast<std::size_t>(memberX[m])] = word;
          }
        }
      }
    }
    return rects;
  }
} // namespace faf::editor

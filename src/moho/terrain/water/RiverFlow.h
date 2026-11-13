#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>

// Rivers, render side (docs/projects/RIVERS.md, stages S3 and S4): the pure arithmetic of a river's flow (the speed
// from the height gradient and the depth, the texel the water pixel shader reads, the two phases of the scrolled
// normals) and the source patch of water2.fx that scrolls the normals along it. Render only: nothing here is read by
// the sim. No engine types, so the host tests (tests/water/RiverFlowTests.cpp) compile it as it is; the flow texture of
// a map's rivers and the shader variables are RiverFlowBind.h's.
namespace moho::water
{
  /// The fastest visual speed of a river in world units a second (the B channel of the flow texture spans 0 .. this).
  inline constexpr float kRiverMaxSpeed = 6.0f;
  /// Manning's roughness of a natural channel.
  inline constexpr float kRiverRoughness = 0.04f;
  /// The shallowest water the speed formula takes (a ford is 0.04 deep: its flow is not zero).
  inline constexpr float kRiverMinDepth = 0.05f;
  /// How long one phase of the scrolled normals lasts, in game ticks (ten a second): three seconds.
  inline constexpr float kRiverPhaseTicks = 30.0f;
  /// A river texel's alpha is at least this many of 255, so that "no river" (alpha 0) is its own value and a bilinear
  /// tap at the edge of a river fades out over this range.
  inline constexpr int kRiverTexelAlphaFloor = 16;
  /// The shoreline cut-out of a river block is drawn at its level rounded to this fraction of a unit (the cells are
  /// drawn grouped by level, one draw each).
  inline constexpr float kRiverShoreStep = 0.125f;

  [[nodiscard]] inline float RiverSmoothStep(
    const float a,
    const float b,
    const float x
  ) noexcept
  {
    const float t = std::clamp((x - a) / (b - a), 0.0f, 1.0f);
    return t * t * (3.0f - 2.0f * t);
  }

  /**
   * The visual speed of a river in world units a second: Manning's relation for an open channel,
   * `v = d^(2/3) * sqrt(S) / n` with the slope `S` (drop over run, 0 or more) and the depth `d` (at least
   * `kRiverMinDepth`), times `flowScale`, at most `kRiverMaxSpeed`. 0 for a level or rising reach.
   */
  [[nodiscard]] inline float RiverSpeed(
    const float slope,
    const float depth,
    const float flowScale = 1.0f
  ) noexcept
  {
    if (!(slope > 0.0f) || !(flowScale > 0.0f)) {
      return 0.0f;
    }
    const float d = std::max(depth, kRiverMinDepth);
    const float v = flowScale * std::pow(d, 2.0f / 3.0f) * std::sqrt(slope) / kRiverRoughness;
    return std::min(v, kRiverMaxSpeed);
  }

  /**
   * How much white water a reach carries, 0 to 1: steep reaches (rapids) from a slope of 0.04, and fast water over a
   * shallow bed (riffles, the water over a bump of the bed, a ford): it grows from a speed of one unit a second and a
   * depth of half a unit.
   */
  [[nodiscard]] inline float RiverTurbulence(
    const float slope,
    const float depth,
    const float speed
  ) noexcept
  {
    const float steep = RiverSmoothStep(0.04f, 0.10f, slope);
    const float shallow = (1.0f - RiverSmoothStep(0.05f, 0.5f, depth)) * RiverSmoothStep(1.0f, 2.5f, speed);
    return std::clamp(steep + shallow, 0.0f, 1.0f);
  }

  /// What one 2 x 2 block of the flow texture holds.
  struct SRiverFlowTexel
  {
    /// Whether a river owns the block (alpha 0 in the texture where not).
    bool river = false;
    /// Unit flow direction.
    float dx = 0.0f;
    float dz = 0.0f;
    /// World units a second, 0 .. kRiverMaxSpeed.
    float speed = 0.0f;
    /// 0 .. 1
    float turbulence = 0.0f;
  };

  /**
   * The flow of a river block from the height field of its level: `level_*` are the river's levels a unit before and
   * after the block's middle along x and z (central difference over two units), `fx, fz` the unit direction the
   * centreline runs there (the sim's `FlowAt`), `depth` the water over the bed, `fall` whether the block holds a
   * fall (the water there drops over a step: full speed and white). The direction is the centreline's; where that is
   * unknown (0, 0) it is downhill (against the level's gradient); a block with neither has no flow.
   */
  [[nodiscard]] inline SRiverFlowTexel RiverBlockFlow(
    const float levelXMinus,
    const float levelXPlus,
    const float levelZMinus,
    const float levelZPlus,
    const float fx,
    const float fz,
    const float depth,
    const bool fall,
    const float flowScale = 1.0f
  ) noexcept
  {
    SRiverFlowTexel out;
    out.river = true;
    const float gx = (levelXPlus - levelXMinus) * 0.5f;
    const float gz = (levelZPlus - levelZMinus) * 0.5f;
    float dx = fx;
    float dz = fz;
    float length = std::sqrt(dx * dx + dz * dz);
    if (!(length > 0.0001f)) {
      dx = -gx;
      dz = -gz;
      length = std::sqrt(dx * dx + dz * dz);
    }
    if (length > 0.0001f) {
      out.dx = dx / length;
      out.dz = dz / length;
    }
    // the slope along the flow: how far the surface drops per unit of run
    const float slope = std::max(0.0f, -(gx * out.dx + gz * out.dz));
    if (fall) {
      out.speed = kRiverMaxSpeed;
      out.turbulence = 1.0f;
      return out;
    }
    out.speed = out.dx == 0.0f && out.dz == 0.0f ? 0.0f : RiverSpeed(slope, depth, flowScale);
    out.turbulence = RiverTurbulence(slope, depth, out.speed);
    return out;
  }

  /// A texel as the 32 bits of an A8R8G8B8 texture (the shader reads r, g, b, a): the direction as `0.5 + 0.5 d`,
  /// the speed over `kRiverMaxSpeed`, the turbulence over `kRiverTexelAlphaFloor .. 255`; all 0 without a river.
  [[nodiscard]] inline std::uint32_t PackRiverFlowTexel(
    const SRiverFlowTexel& texel
  ) noexcept
  {
    if (!texel.river) {
      return 0u;
    }
    const auto byte = [](const float v) {
      return static_cast<std::uint32_t>(std::clamp(v, 0.0f, 1.0f) * 255.0f + 0.5f);
    };
    const std::uint32_t r = byte(0.5f + 0.5f * texel.dx);
    const std::uint32_t g = byte(0.5f + 0.5f * texel.dz);
    const std::uint32_t b = byte(texel.speed / kRiverMaxSpeed);
    const std::uint32_t a = static_cast<std::uint32_t>(
      kRiverTexelAlphaFloor +
      static_cast<int>(
        std::clamp(texel.turbulence, 0.0f, 1.0f) * static_cast<float>(255 - kRiverTexelAlphaFloor) + 0.5f
      )
    );
    return (a << 24u) | (r << 16u) | (g << 8u) | b;
  }

  /// The inverse of `PackRiverFlowTexel`, to the byte's precision.
  [[nodiscard]] inline SRiverFlowTexel UnpackRiverFlowTexel(
    const std::uint32_t bits
  ) noexcept
  {
    SRiverFlowTexel out;
    const std::uint32_t a = bits >> 24u;
    if (a == 0u) {
      return out;
    }
    out.river = true;
    out.dx = (static_cast<float>((bits >> 16u) & 0xFFu) / 255.0f - 0.5f) * 2.0f;
    out.dz = (static_cast<float>((bits >> 8u) & 0xFFu) / 255.0f - 0.5f) * 2.0f;
    out.speed = static_cast<float>(bits & 0xFFu) / 255.0f * kRiverMaxSpeed;
    out.turbulence = (static_cast<float>(a) - static_cast<float>(kRiverTexelAlphaFloor)) /
      static_cast<float>(255 - kRiverTexelAlphaFloor);
    return out;
  }

  /// The two phases of the scrolled normals (the pixel shader's own arithmetic): each layer's coordinates are shifted
  /// along the flow by `speed * t * period` for t = `t0` and `t1`, and the two reads are blended by a weight that is 0
  /// at the instant a phase restarts, so nothing pops.
  struct SRiverPhase
  {
    float t0 = 0.0f;
    float t1 = 0.0f;
    /// The weight of phase 0; phase 1 has `1 - w0`.
    float w0 = 0.0f;
  };

  [[nodiscard]] inline SRiverPhase RiverPhase(
    const float timeTicks,
    const float periodTicks = kRiverPhaseTicks
  ) noexcept
  {
    SRiverPhase p;
    const float x = timeTicks / periodTicks;
    p.t0 = x - std::floor(x);
    const float y = p.t0 + 0.5f;
    p.t1 = y - std::floor(y);
    p.w0 = 1.0f - std::fabs(1.0f - 2.0f * p.t0);
    return p;
  }

  /// The levels of the vertices of a block (its four corners, or all nine): `valid[i]` says whether the river has a
  /// value there; a vertex without one takes the mean of those that have, and without any `fallback`. Returns the
  /// number of vertices that had a value.
  template <std::size_t N>
  inline int FillRiverBlockCorners(
    float (&level)[N],
    const bool (&valid)[N],
    const float fallback
  ) noexcept
  {
    float sum = 0.0f;
    int count = 0;
    for (std::size_t i = 0; i < N; ++i) {
      if (valid[i]) {
        sum += level[i];
        ++count;
      }
    }
    const float mean = count > 0 ? sum / static_cast<float>(count) : fallback;
    for (std::size_t i = 0; i < N; ++i) {
      if (!valid[i]) {
        level[i] = mean;
      }
    }
    return count;
  }

  /// The level of a block: the mean of its four corners.
  [[nodiscard]] inline float RiverBlockLevel(
    const float (&level)[4]
  ) noexcept
  {
    return (level[0] + level[1] + level[2] + level[3]) * 0.25f;
  }

  /// A level rounded to `kRiverShoreStep`.
  [[nodiscard]] inline float RiverShoreLevel(
    const float level
  ) noexcept
  {
    return std::floor(level / kRiverShoreStep + 0.5f) * kRiverShoreStep;
  }

  /// The source patch of water2.fx for rivers: the vertex shaders keep the vertex's own height when the mesh being
  /// drawn is a river's (`waterRiverParams.x`), and the pixel shader scrolls the normal layers along the flow texture,
  /// in two phases, and adds the white water of steep and shallow reaches. It anchors on lines of the shipped shader
  /// that the wave simulation patch leaves alone, so it applies to the shipped text and to the simulated one alike, and
  /// it is a no-op at run time while `waterRiverParams` is all zero. Text in, text out; a text that does not carry the
  /// anchors exactly once is left untouched.
  struct RiverPatchResult
  {
    bool patched = false;
    std::string error;
  };
  RiverPatchResult PatchWaterRivers(std::string& source);
} // namespace moho::water

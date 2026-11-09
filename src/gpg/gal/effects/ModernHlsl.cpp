// FAF addition, not in the shipped binary: see ModernHlsl.h.

#include "ModernHlsl.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <tuple>
#include <utility>

#include "EffectText.h"
#include "RayTracedShadows.h"
#include "ShadowCascades.h"
#include "TextureFiltering.h"

namespace gpg::gal::effects
{
  using namespace text;

  ShadowCascadeConstants gShadowCascades{};
  int gTextureAnisotropy = 8;
  std::atomic<bool> gShadowCascadesBlocked{false};
  RayShadowConstants gRayShadows{};
  bool gRayQueryShaders = false;
  int gRayTracedShadows = 1;

  std::string_view RayShadowDeclaration() noexcept
  {
    return "float4 faf_RayShadows[8]; // engine addition (ren_RayTracedShadows), filled by the backend\n";
  }

  bool IsShadowLookupSampler(const SamplerDesc& sampler)
  {
    return Lower(sampler.texture) == "shadowtexture" && Lower(sampler.name).find("blur") == std::string::npos;
  }

  std::string_view ShadowCascadeDeclaration() noexcept
  {
    return "float4 faf_ShadowCascades[9]; // engine addition (ren_ShadowCascades), filled by the backend\n";
  }

  namespace
  {
    static_assert(kShadowCascadeVectors == 9U, "ShadowCascadeDeclaration's array length");

    // Engine addition (ren_ShadowCascades): the lighting shadow samplers' own type; see ShadowCascades.h.
    // The shadow targets have one mip, so every lookup reads level 0 and needs no derivatives: a pixel's
    // neighbours may sit in another tile.
    constexpr const char* kShadowCascadeHelpers = R"hlsl(
// ---- engine addition (ren_ShadowCascades): shadow lookups through the cascade atlas ----
// HLSL converts between structs whose members match one for one, which would make every tex2D on this
// type ambiguous with faf_sampler's. The sampler comes first here and the texture first there, so
// neither converts to the other.
struct faf_shadow_sampler
{
    SamplerState s;
    Texture2D t2;
};
faf_shadow_sampler faf_make_shadow_sampler(Texture2D t2, TextureCube tc, Texture3D t3, SamplerState s)
{
    faf_shadow_sampler r;
    r.s = s;
    r.t2 = t2;
    return r;
}
float2 faf_shadow_uv(float2 uv)
{
    const int count = (int)faf_ShadowCascades[0].x;
    if (count <= 0) return uv;
    [unroll] for (int k = 0; k < 4; ++k) {
        if (k < count) {
            const float4 box = faf_ShadowCascades[1 + 2 * k];
            if (all(uv >= box.xy) && all(uv <= box.zw)) {
                const float4 map = faf_ShadowCascades[2 + 2 * k];
                return uv * map.xy + map.zw;
            }
        }
    }
    return faf_ShadowCascades[0].zw;
}
float4 faf_shadow_read(faf_shadow_sampler s, float2 uv) { return s.t2.SampleLevel(s.s, faf_shadow_uv(uv), 0); }
float4 tex2D(faf_shadow_sampler s, float2 uv) { return faf_shadow_read(s, uv); }
float4 tex2D(faf_shadow_sampler s, float2 uv, float2 dx, float2 dy) { return faf_shadow_read(s, uv); }
float4 tex2Dbias(faf_shadow_sampler s, float4 uv) { return faf_shadow_read(s, uv.xy); }
float4 tex2Dproj(faf_shadow_sampler s, float4 uv) { return faf_shadow_read(s, uv.xy / uv.w); }
float4 tex2Dlod(faf_shadow_sampler s, float4 uv) { return faf_shadow_read(s, uv.xy); }
float4 tex2Dgrad(faf_shadow_sampler s, float2 uv, float2 dx, float2 dy) { return faf_shadow_read(s, uv); }
// ---- end of the cascade lookups ----
)hlsl";

    static_assert(kRayShadowVectors == 8U,"RayShadowDeclaration's array length");

    // Engine addition (ren_RayTracedShadows): the lookups' third argument, the point's whole shadow
    // coordinate (RayTracedShadows.h). A call site whose coordinate has no depth passes a z of -1e30,
    // which the ray code reads as "no point". Its w says which channel the call site reads (the rewrite looks
    // past the call): 1 red (mesh.fx's depth compare), 2 green (terrain.fx's "1 where sun is"), 3 unknown, so
    // the lookup traces only for the reading that is used.
    constexpr const char* kShadowCoordinateHelpers = R"hlsl(
float4 faf_shadow_full(float4 v) { return float4(v.xyz, 3); }
float4 faf_shadow_full(float3 v) { return float4(v.xy, -1e30, 3); }
float4 faf_shadow_full(float2 v) { return float4(v, -1e30, 3); }
float4 faf_shadow_full_r(float4 v) { return float4(v.xyz, 1); }
float4 faf_shadow_full_r(float3 v) { return float4(v.xy, -1e30, 1); }
float4 faf_shadow_full_r(float2 v) { return float4(v, -1e30, 1); }
float4 faf_shadow_full_g(float4 v) { return float4(v.xyz, 2); }
float4 faf_shadow_full_g(float3 v) { return float4(v.xy, -1e30, 2); }
float4 faf_shadow_full_g(float2 v) { return float4(v, -1e30, 2); }
)hlsl";

    // Without rays: the coordinate is ignored.
    constexpr const char* kRayShadowFallback = R"hlsl(
float4 tex2D(faf_shadow_sampler s, float2 uv, float4 full) { return faf_shadow_read(s, uv); }
)hlsl";

    // With rays. A coordinate names a point two ways: as mesh.fx reads it (at z) and as terrain.fx does (at
    // z + 0.01, its own 0.01 shift undone). Both lie on one line towards the sun, so one ray along it answers
    // both: it starts at whichever of the two is further from the sun, and a hit counts for a point only past
    // that point's own distance along the ray plus its bias. The longer test runs first; the short stretch
    // between the two only when it found nothing. Meshes and the ground are traced apart, the ground with a
    // bias that grows with camera distance. mesh.fx's five-tap filter asks for the same point five times, so
    // the answer is kept for the next call.
    constexpr const char* kRayShadowHelpers = R"hlsl(
[[vk::binding(0, 2)]] RaytracingAccelerationStructure faf_RayScene : register(t0, space1);
static float4 faf_ray_key = float4(-1e31, -1e31, -1e31, -1e31);
static float2 faf_ray_lit = float2(1, 1);
float3 faf_ray_point(float2 uv, float z)
{
    const float4 clip = float4(uv.x * 2 - 1, 1 - uv.y * 2, z, 1);
    const float4 p = clip.x * faf_RayShadows[0] + clip.y * faf_RayShadows[1] + clip.z * faf_RayShadows[2] + faf_RayShadows[3];
    return p.xyz / p.w;
}
bool faf_ray_blocked(float3 origin, float3 direction, float tMin, float tMax, uint mask)
{
    if (tMax <= tMin) return false;
    RayDesc ray;
    ray.Origin = origin;
    ray.Direction = direction;
    ray.TMin = tMin;
    ray.TMax = tMax;
    RayQuery<RAY_FLAG_ACCEPT_FIRST_HIT_AND_END_SEARCH | RAY_FLAG_SKIP_PROCEDURAL_PRIMITIVES | RAY_FLAG_FORCE_OPAQUE> query;
    query.TraceRayInline(faf_RayScene, RAY_FLAG_NONE, mask, ray);
    query.Proceed();
    return query.CommittedStatus() == COMMITTED_TRIANGLE_HIT;
}
bool faf_ray_blocked(float3 origin, float3 direction, float tMin, float tMax)
{
    return faf_ray_blocked(origin, direction, tMin, tMax, 0xFF);
}
// One ray against the instances in `mask` answering both readings: x lit past meshT, y lit past terrainT.
float2 faf_ray_pair(float3 start, float3 toSun, float meshT, float terrainT, float tMax, uint mask)
{
    const float nearT = min(meshT, terrainT);
    const float farT = max(meshT, terrainT);
    if (faf_ray_blocked(start, toSun, farT, tMax, mask)) {
        return float2(0, 0);
    }
    if (faf_ray_blocked(start, toSun, nearT, farT, mask)) {
        return (meshT < terrainT) ? float2(0, 1) : float2(1, 0);
    }
    return float2(1, 1);
}
// x: sunlit for a mesh point at full.z; y: sunlit for a terrain point whose z is 0.01 short.
float2 faf_ray_light(float4 full)
{
    if (faf_RayShadows[4].x <= 0 || full.z < -1e29) return float2(1, 1);
    if (all(full == faf_ray_key)) return faf_ray_lit;
    const float2 uv = full.xy;
    const float3 meshPoint = faf_ray_point(uv, full.z);
    const float3 terrainPoint = faf_ray_point(uv, full.z + 0.01);
    const float3 toSun = faf_RayShadows[6].xyz;
    const float ahead = dot(meshPoint - terrainPoint, toSun); // the mesh reading's lead along the ray
    const float3 start = (ahead >= 0) ? terrainPoint : meshPoint;
    const float meshT = max(ahead, 0) + faf_RayShadows[4].y;
    const float terrainT = max(-ahead, 0) + faf_RayShadows[4].z;
    const float tMax = faf_RayShadows[5].w;
    // Meshes (mask 2, RayTracing.h's kRayMaskMesh) with the small biases, so units keep their contact
    // shadows. The ground (mask 1) is drawn coarser with distance than the traced height field, so a ground
    // point can lie under the traced ground: against the ground, its ray leaves further out.
    const float terrainOnTerrainT = terrainT + faf_RayShadows[7].x + faf_RayShadows[4].w * distance(terrainPoint, faf_RayShadows[5].xyz);
    float2 lit;
    if (full.w < 1.5) {
        // Red only (mesh.fx): the mesh reading, from its own point.
        // Against the traced ground with its allowance: it can lie above the drawn ground (a coarse field,
        // tessellation), up into a unit's base.
        const bool shaded = faf_ray_blocked(meshPoint, toSun, faf_RayShadows[4].y, tMax, 2) ||
            faf_ray_blocked(meshPoint, toSun, faf_RayShadows[4].y + faf_RayShadows[7].x, tMax, 1);
        lit = shaded ? float2(0, 1) : float2(1, 1);
    } else if (full.w < 2.5) {
        // Green only (terrain.fx): the terrain reading, from its own point.
        const float groundT = faf_RayShadows[4].z;
        const bool shaded = faf_ray_blocked(terrainPoint, toSun, groundT, tMax, 2) ||
            faf_ray_blocked(terrainPoint, toSun, terrainOnTerrainT - max(-ahead, 0), tMax, 1);
        lit = shaded ? float2(1, 0) : float2(1, 1);
    } else {
        lit = faf_ray_pair(start, toSun, meshT, terrainT, tMax, 2);
        if (any(lit > 0)) {
            lit = min(lit, faf_ray_pair(start, toSun, meshT + faf_RayShadows[7].x, terrainOnTerrainT, tMax, 1));
        }
    }
    // Diagnostics (ren_RayShadowDebug): stripes 20 world units apart across x (1) or z (2) from the
    // rebuilt point, and (3) shade where the rebuilt point lies below the ray scene (a ray straight up hits).
    const float debugMode = faf_RayShadows[6].w;
    if (debugMode > 0.5 && debugMode < 1.5) {
        lit = (frac(terrainPoint.x * 0.05) > 0.5) ? float2(1, 1) : float2(0, 0);
    } else if (debugMode > 1.5 && debugMode < 2.5) {
        lit = (frac(terrainPoint.z * 0.05) > 0.5) ? float2(1, 1) : float2(0, 0);
    } else if (debugMode > 2.5) {
        lit = faf_ray_blocked(terrainPoint + float3(0, 0.02, 0), float3(0, 1, 0), 0.0, 1000.0) ? float2(0, 0) : float2(1, 1);
    }
    faf_ray_key = full;
    faf_ray_lit = lit;
    return lit;
}
float4 tex2D(faf_shadow_sampler s, float2 uv, float4 full)
{
    float4 texel = faf_shadow_read(s, uv);
    const float2 lit = faf_ray_light(full);
    texel.r = (lit.x > 0) ? texel.r : -1e4;
    texel.g *= lit.y;
    return texel;
}
)hlsl";

    /**
     * Engine addition (ren_RayTracedShadows): gives each `tex2D(<shadow sampler>, <coords>.xy ...)` call in
     * `body` a third argument, `faf_shadow_full(<coords>)`, when the call has two arguments and the second
     * starts with a plain name or member chain followed by `.xy`, or is a plain name or member chain alone
     * (not ending in a swizzle). Other calls keep two arguments and read the map alone.
     */
    [[nodiscard]] std::string PassShadowCoordinates(const std::string& body, const std::vector<std::string>& samplers)
    {
      std::string out;
      out.reserve(body.size() + 64U);
      std::size_t index = 0U;
      while (index < body.size()) {
        const std::size_t call = body.find("tex2D", index);
        if (call == std::string::npos) {
          break;
        }
        std::size_t cursor = call + 5U;
        const bool whole = (call == 0U || !IsIdentifierChar(body[call - 1U])) && cursor < body.size() && !IsIdentifierChar(body[cursor]);
        const auto skip = [&] {
          while (cursor < body.size() && std::isspace(static_cast<unsigned char>(body[cursor])) != 0) {
            ++cursor;
          }
        };
        bool rewritten = false;
        if (whole) {
          skip();
          if (cursor < body.size() && body[cursor] == '(') {
            ++cursor;
            skip();
            const std::size_t nameStart = cursor;
            while (cursor < body.size() && IsIdentifierChar(body[cursor])) {
              ++cursor;
            }
            const std::string name = body.substr(nameStart, cursor - nameStart);
            skip();
            if (std::find(samplers.begin(), samplers.end(), name) != samplers.end() && cursor < body.size() && body[cursor] == ',') {
              ++cursor;
              const std::size_t argumentStart = cursor;
              int depth = 0;
              std::size_t end = std::string::npos;
              bool more = false;
              for (std::size_t at = cursor; at < body.size(); ++at) {
                const char c = body[at];
                if (c == '(' || c == '[') {
                  ++depth;
                } else if ((c == ')' || c == ']') && depth > 0) {
                  --depth;
                } else if (c == ')' && depth == 0) {
                  end = at;
                  break;
                } else if (c == ',' && depth == 0) {
                  more = true;
                  break;
                }
              }
              if (end != std::string::npos && !more) {
                std::size_t at = argumentStart;
                while (at < end && std::isspace(static_cast<unsigned char>(body[at])) != 0) {
                  ++at;
                }
                // The member chain's names; the effect layer's token stream spaces them (`inV . mShadow . xy`).
                std::vector<std::string> names;
                while (at < end && IsIdentifierChar(body[at])) {
                  const std::size_t nameAt = at;
                  while (at < end && IsIdentifierChar(body[at])) {
                    ++at;
                  }
                  names.push_back(body.substr(nameAt, at - nameAt));
                  std::size_t next = at;
                  while (next < end && std::isspace(static_cast<unsigned char>(body[next])) != 0) {
                    ++next;
                  }
                  if (next >= end || body[next] != '.') {
                    at = next;
                    break;
                  }
                  ++next;
                  while (next < end && std::isspace(static_cast<unsigned char>(body[next])) != 0) {
                    ++next;
                  }
                  at = next;
                }
                const bool named = !names.empty() && std::isdigit(static_cast<unsigned char>(names.front().front())) == 0;
                const bool plainChain = named && at == end;
                const auto join = [&](const std::size_t count) {
                  std::string chain;
                  for (std::size_t k = 0U; k < count; ++k) {
                    chain += (k == 0U ? "" : ".") + names[k];
                  }
                  return chain;
                };
                // The last member of the chain, when it is a swizzle (only xyzw / rgba letters).
                const bool swizzle = names.size() > 1U && names.back().find_first_not_of("xyzwrgba") == std::string::npos;
                // The channel the call site reads (`tex2D( ... ).g`): the lookup then traces for it alone.
                std::string channel;
                {
                  std::size_t after = end + 1U;
                  while (after < body.size() && std::isspace(static_cast<unsigned char>(body[after])) != 0) {
                    ++after;
                  }
                  if (after < body.size() && body[after] == '.') {
                    ++after;
                    while (after < body.size() && std::isspace(static_cast<unsigned char>(body[after])) != 0) {
                      ++after;
                    }
                    const std::size_t memberAt = after;
                    while (after < body.size() && IsIdentifierChar(body[after])) {
                      ++after;
                    }
                    const std::string member = body.substr(memberAt, after - memberAt);
                    if (member == "r" || member == "x") {
                      channel = "_r";
                    } else if (member == "g" || member == "y") {
                      channel = "_g";
                    }
                  }
                }
                if (named && names.size() > 1U && names.back() == "xy") {
                  // `<coords>.xy`, maybe offset (a filter's taps): the coordinate is the chain before the swizzle.
                  out.append(body, index, end - index);
                  out += ", faf_shadow_full" + channel + "(" + join(names.size() - 1U) + ")";
                  index = end;
                  rewritten = true;
                } else if (plainChain && !swizzle) {
                  // A whole coordinate (terrain.fx's ComputeShadow passes its float4): faf_shadow_full's overloads
                  // trace a float4 and leave a float2 or float3 to the map.
                  out.append(body, index, end - index);
                  out += ", faf_shadow_full" + channel + "(" + join(names.size()) + ")";
                  index = end;
                  rewritten = true;
                }
              }
            }
          }
        }
        if (!rewritten) {
          out.append(body, index, call + 5U - index);
          index = call + 5U;
        }
      }
      out.append(body, index, std::string::npos);
      return out;
    }

    /**
     * Engine addition (ren_ShadowCascades): true when every use of `sampler` in `source`, past its own
     * declaration and outside comments, is the first argument of a tex2D-family call. Those are the
     * calls faf_shadow_sampler answers; anything else (passing it to a function) needs a faf_sampler.
     */
    [[nodiscard]] bool ShadowSamplerOnlyLookedUp(const std::string_view source, const SamplerDesc& sampler)
    {
      static constexpr std::string_view kCalls[] = {"tex2D", "tex2Dbias", "tex2Dproj", "tex2Dlod", "tex2Dgrad"};
      const std::string_view name = sampler.name;
      std::size_t index = 0U;
      while (index < source.size()) {
        if (source.compare(index, 2U, "//") == 0) {
          const std::size_t end = source.find('\n', index);
          index = (end == std::string_view::npos) ? source.size() : end;
          continue;
        }
        if (source.compare(index, 2U, "/*") == 0) {
          const std::size_t end = source.find("*/", index + 2U);
          index = (end == std::string_view::npos) ? source.size() : end + 2U;
          continue;
        }
        if (index >= sampler.begin && index < sampler.end) {
          index = sampler.end;
          continue;
        }
        const bool whole = (index == 0U || !IsIdentifierChar(source[index - 1U])) && source.compare(index, name.size(), name) == 0 &&
          (index + name.size() >= source.size() || !IsIdentifierChar(source[index + name.size()]));
        if (!whole) {
          ++index;
          continue;
        }
        std::size_t before = index;
        const auto skipSpace = [&] {
          while (before > 0U && std::isspace(static_cast<unsigned char>(source[before - 1U])) != 0) {
            --before;
          }
        };
        skipSpace();
        if (before == 0U || source[before - 1U] != '(') {
          return false;
        }
        --before;
        skipSpace();
        std::size_t start = before;
        while (start > 0U && IsIdentifierChar(source[start - 1U])) {
          --start;
        }
        const std::string_view call = source.substr(start, before - start);
        if (std::find(std::begin(kCalls), std::end(kCalls), call) == std::end(kCalls)) {
          return false;
        }
        index += name.size();
      }
      return true;
    }
    // Register numbers of the placeholder views a faf_sampler carries for the
    // dimensions its texture is never sampled in. The compiler removes them
    // with the dead fields; ModernEffect consumers can check none survive.
    constexpr const char* kPrelude = R"hlsl(
// ---- FAF effect layer prelude (generated) ----
struct faf_sampler
{
    Texture2D t2;
    TextureCube tc;
    Texture3D t3;
    SamplerState s;
};
faf_sampler faf_make_sampler(Texture2D t2, TextureCube tc, Texture3D t3, SamplerState s)
{
    faf_sampler r;
    r.t2 = t2;
    r.tc = tc;
    r.t3 = t3;
    r.s = s;
    return r;
}
Texture2D faf_null2D : register(t125);
TextureCube faf_nullCube : register(t126);
Texture3D faf_null3D : register(t127);
// The patch constants of a tessellated pass (engine addition): the factors of the
// edges opposite control points 0, 1 and 2, and of the inside.
struct faf_tess_factors
{
    float edges[3] : SV_TessFactor;
    float inside : SV_InsideTessFactor;
};
#ifndef FAF_TESS_TOPOLOGY
#define FAF_TESS_TOPOLOGY "triangle_cw"
#endif
#if defined(FAF_VERTEX_STAGE) || defined(FAF_HULL_STAGE) || defined(FAF_DOMAIN_STAGE)
// Vertex shaders have no derivatives: Direct3D 9 sampled mip 0 (hull and domain
// shaders have none either).
float4 tex2D(faf_sampler s, float2 uv) { return s.t2.SampleLevel(s.s, uv, 0); }
float4 tex2Dbias(faf_sampler s, float4 uv) { return s.t2.SampleLevel(s.s, uv.xy, 0); }
float4 tex2Dproj(faf_sampler s, float4 uv) { return s.t2.SampleLevel(s.s, uv.xy / uv.w, 0); }
float4 texCUBE(faf_sampler s, float3 uv) { return s.tc.SampleLevel(s.s, uv, 0); }
float4 texCUBEbias(faf_sampler s, float4 uv) { return s.tc.SampleLevel(s.s, uv.xyz, 0); }
float4 texCUBEproj(faf_sampler s, float4 uv) { return s.tc.SampleLevel(s.s, uv.xyz / uv.w, 0); }
float4 tex3D(faf_sampler s, float3 uv) { return s.t3.SampleLevel(s.s, uv, 0); }
float4 tex3Dbias(faf_sampler s, float4 uv) { return s.t3.SampleLevel(s.s, uv.xyz, 0); }
float4 tex3Dproj(faf_sampler s, float4 uv) { return s.t3.SampleLevel(s.s, uv.xyz / uv.w, 0); }
#else
float4 tex2D(faf_sampler s, float2 uv) { return s.t2.Sample(s.s, uv); }
float4 tex2Dbias(faf_sampler s, float4 uv) { return s.t2.SampleBias(s.s, uv.xy, uv.w); }
float4 tex2Dproj(faf_sampler s, float4 uv) { return s.t2.Sample(s.s, uv.xy / uv.w); }
float4 texCUBE(faf_sampler s, float3 uv) { return s.tc.Sample(s.s, uv); }
float4 texCUBEbias(faf_sampler s, float4 uv) { return s.tc.SampleBias(s.s, uv.xyz, uv.w); }
float4 texCUBEproj(faf_sampler s, float4 uv) { return s.tc.Sample(s.s, uv.xyz / uv.w); }
float4 tex3D(faf_sampler s, float3 uv) { return s.t3.Sample(s.s, uv); }
float4 tex3Dbias(faf_sampler s, float4 uv) { return s.t3.SampleBias(s.s, uv.xyz, uv.w); }
float4 tex3Dproj(faf_sampler s, float4 uv) { return s.t3.Sample(s.s, uv.xyz / uv.w); }
#endif
float4 tex2D(faf_sampler s, float2 uv, float2 dx, float2 dy) { return s.t2.SampleGrad(s.s, uv, dx, dy); }
float4 tex2Dgrad(faf_sampler s, float2 uv, float2 dx, float2 dy) { return s.t2.SampleGrad(s.s, uv, dx, dy); }
float4 tex2Dlod(faf_sampler s, float4 uv) { return s.t2.SampleLevel(s.s, uv.xy, uv.w); }
float4 texCUBE(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.tc.SampleGrad(s.s, uv, dx, dy); }
float4 texCUBEgrad(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.tc.SampleGrad(s.s, uv, dx, dy); }
float4 texCUBElod(faf_sampler s, float4 uv) { return s.tc.SampleLevel(s.s, uv.xyz, uv.w); }
float4 tex3D(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.t3.SampleGrad(s.s, uv, dx, dy); }
float4 tex3Dgrad(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.t3.SampleGrad(s.s, uv, dx, dy); }
float4 tex3Dlod(faf_sampler s, float4 uv) { return s.t3.SampleLevel(s.s, uv.xyz, uv.w); }
// ---- end of prelude ----
)hlsl";

    // Direct3D 9 shader math that Shader Model 6 lost. A NaN that reaches
    // blending stores zero, so each of these shows as black pixels:
    // - sqrt and rsqrt compile to rsq, which takes the absolute value of its
    //   operand (normal reconstruction sqrt(1 - dot(xy, xy)));
    // - pow with an integer literal exponent compiles to multiplications,
    //   any other pow to log and exp, and log also takes the absolute value.
    //   That is |x|^y, negated for an odd integer exponent. DXC turns every
    //   exponent but 2 into log/exp of x and returns NaN for a negative x
    //   (FresnelSchlick's pow(1 - dot(h, v), 5) when the dot rounds above 1).
    constexpr const char* kDirect3D9Math = R"hlsl(#define sqrt(x) sqrt(abs(x))
#define rsqrt(x) rsqrt(abs(x))
#define pow(x, y) (pow(abs(x), (y)) * (((x) < 0 && frac((y) * 0.5) == 0.5) ? -1 : 1))
)hlsl";

    // Diagnostics: FAF_GAL_D3D10_MATH=1 keeps Shader Model 4 sqrt/rsqrt.
    [[nodiscard]] bool UseDirect3D9Math() noexcept
    {
      static const bool keepModern = [] {
        const char* const value = std::getenv("FAF_GAL_D3D10_MATH");
        return value != nullptr && value[0] == '1';
      }();
      return !keepModern;
    }

    // Diagnostics: FAF_GAL_NAN_CHECK=1 draws NaN or infinite pixel colours in magenta.
    [[nodiscard]] bool NanCheckRequested() noexcept
    {
      static const bool requested = [] {
        const char* const value = std::getenv("FAF_GAL_NAN_CHECK");
        return value != nullptr && value[0] == '1';
      }();
      return requested;
    }

    constexpr const char* kSamplerTypes[] = {"samplerCUBE", "sampler3D", "sampler2D", "sampler1D", "sampler"};

    [[nodiscard]] const char* ViewSuffix(const TextureDimension dimension) noexcept
    {
      switch (dimension) {
      case TextureDimension::TextureCube:
        return "__faf_cube";
      case TextureDimension::Texture3D:
        return "__faf_3d";
      default:
        return "";
      }
    }

    [[nodiscard]] const char* ViewType(const TextureDimension dimension) noexcept
    {
      switch (dimension) {
      case TextureDimension::TextureCube:
        return "TextureCube";
      case TextureDimension::Texture3D:
        return "Texture3D";
      default:
        return "Texture2D";
      }
    }

    /** The dimensions a sampler can be read in. */
    [[nodiscard]] std::vector<TextureDimension> SamplerDimensions(const SamplerDesc& sampler, const std::string_view source)
    {
      const std::string type = Lower(sampler.declaredType);
      if (type == "samplercube") {
        return {TextureDimension::TextureCube};
      }
      if (type == "sampler3d") {
        return {TextureDimension::Texture3D};
      }
      if (type != "sampler") {
        return {TextureDimension::Texture2D};
      }
      // An untyped `sampler` takes the kind of the lookup that reads it: the
      // primitive batcher reads one sampler as 2D or cube per technique.
      std::vector<TextureDimension> dimensions{TextureDimension::Texture2D};
      if (source.find("texCUBE") != std::string_view::npos) {
        dimensions.push_back(TextureDimension::TextureCube);
      }
      if (source.find("tex3D") != std::string_view::npos) {
        dimensions.push_back(TextureDimension::Texture3D);
      }
      return dimensions;
    }

    [[nodiscard]] std::string ReplaceSamplerTypes(std::string text)
    {
      for (const char* const type : kSamplerTypes) {
        text = ReplaceIdentifier(text, type, "faf_sampler");
      }
      return text;
    }

    /** Strips the annotation block, initializer and semantic of a global declaration. */
    [[nodiscard]] std::string GlobalDeclaration(const Parameter& parameter)
    {
      std::string type = " " + parameter.typeName + " ";
      for (const char* const modifier : {" const ", " uniform ", " shared ", " extern ", " volatile "}) {
        std::size_t position;
        while ((position = type.find(modifier)) != std::string::npos) {
          type.replace(position, std::char_traits<char>::length(modifier), " ");
        }
      }
      std::string declaration = Trim(type) + " " + parameter.name;
      if (parameter.elements != 0U) {
        declaration += "[" + std::to_string(parameter.elements) + "]";
      }
      return declaration + ";";
    }

    [[nodiscard]] std::string LocalCopyType(const Parameter& parameter)
    {
      std::string type = " " + parameter.typeName + " ";
      for (const char* const modifier :
           {" const ", " uniform ", " shared ", " extern ", " volatile ", " row_major ", " column_major "}) {
        std::size_t position;
        while ((position = type.find(modifier)) != std::string::npos) {
          type.replace(position, std::char_traits<char>::length(modifier), " ");
        }
      }
      return Trim(type);
    }

    /** True when `body` writes `name` (assignment, compound assignment, ++/--), through an index or swizzle too. */
    [[nodiscard]] bool AssignsIdentifier(const std::string_view body, const std::string_view name)
    {
      std::size_t index = 0U;
      while ((index = body.find(name, index)) != std::string_view::npos) {
        const std::size_t after = index + name.size();
        const bool whole = (index == 0U || !IsIdentifierChar(body[index - 1U])) && (after >= body.size() || !IsIdentifierChar(body[after]));
        if (!whole) {
          index = after;
          continue;
        }
        std::size_t before = index;
        while (before > 0U && body[before - 1U] == ' ') {
          --before;
        }
        if (before > 0U && body[before - 1U] == '.') {
          index = after;
          continue; // a member of something else
        }
        if (before >= 2U && ((body[before - 1U] == '+' && body[before - 2U] == '+') || (body[before - 1U] == '-' && body[before - 2U] == '-'))) {
          return true;
        }
        std::size_t next = after;
        for (;;) {
          while (next < body.size() && body[next] == ' ') {
            ++next;
          }
          if (next < body.size() && body[next] == '[') {
            const std::size_t close = Matching(body, next);
            next = (close == std::string_view::npos) ? body.size() : close + 1U;
            continue;
          }
          if (next < body.size() && body[next] == '.') {
            ++next;
            while (next < body.size() && body[next] == ' ') {
              ++next;
            }
            while (next < body.size() && IsIdentifierChar(body[next])) {
              ++next;
            }
            continue;
          }
          break;
        }
        if (next < body.size()) {
          const char c = body[next];
          const char c2 = (next + 1U < body.size()) ? body[next + 1U] : '\0';
          if ((c == '=' && c2 != '=') || ((c == '+' || c == '-' || c == '*' || c == '/' || c == '%' || c == '&' || c == '|' || c == '^') && c2 == '=') ||
              (c == '+' && c2 == '+') || (c == '-' && c2 == '-')) {
            return true;
          }
        }
        index = after;
      }
      return false;
    }

    /** True when `body` declares a local named `name` (`float3 name ...`): the global is shadowed. */
    [[nodiscard]] bool DeclaresIdentifier(const std::string_view body, const std::string_view name)
    {
      std::size_t index = 0U;
      while ((index = body.find(name, index)) != std::string_view::npos) {
        const std::size_t after = index + name.size();
        if ((index != 0U && IsIdentifierChar(body[index - 1U])) || (after < body.size() && IsIdentifierChar(body[after]))) {
          index = after;
          continue;
        }
        std::size_t end = index;
        while (end > 0U && body[end - 1U] == ' ') {
          --end;
        }
        std::size_t begin = end;
        while (begin > 0U && IsIdentifierChar(body[begin - 1U])) {
          --begin;
        }
        const std::string_view previous = body.substr(begin, end - begin);
        if (!previous.empty() && previous != "return" && previous != "else" && previous != "case" && previous != "in" &&
            previous != "out" && previous != "inout" && std::isdigit(static_cast<unsigned char>(previous[0])) == 0) {
          return true;
        }
        index = after;
      }
      return false;
    }

    /** A function definition: `[modifiers] ReturnType Name ( params ) [: semantic] { body }`. */
    struct Function
    {
      std::string returnType;
      std::string name;
      std::vector<std::string> parameters; // squeezed, as written
      std::string semantic;                // the return semantic, without ':'
    };

    [[nodiscard]] bool ParseFunctionHead(const std::string& head, Function& function)
    {
      const std::size_t open = head.find('(');
      if (open == std::string::npos) {
        return false;
      }
      const std::size_t close = Matching(head, open);
      if (close == std::string::npos) {
        return false;
      }
      const std::string before = Trim(head.substr(0U, open));
      const std::size_t space = before.rfind(' ');
      if (space == std::string::npos) {
        return false;
      }
      function.name = before.substr(space + 1U);
      function.returnType = Trim(before.substr(0U, space));
      for (const char* const modifier : {"inline ", "static "}) {
        if (function.returnType.rfind(modifier, 0U) == 0U) {
          function.returnType = Trim(function.returnType.substr(std::char_traits<char>::length(modifier)));
        }
      }
      function.parameters.clear();
      const std::string list = head.substr(open + 1U, close - open - 1U);
      if (!Trim(list).empty() && Trim(list) != "void") {
        for (const std::string& parameter : SplitTopLevel(list, ',')) {
          function.parameters.push_back(Trim(parameter));
        }
      }
      const std::string after = Trim(head.substr(close + 1U));
      function.semantic = (!after.empty() && after[0] == ':') ? Trim(after.substr(1U)) : std::string();
      return true;
    }

    struct ParameterParts
    {
      std::string modifiers; // in / out / inout / uniform ...
      std::string type;
      std::string name;
      std::string suffix;    // array dimensions
      std::string semantic;  // without ':'
      bool isUniform = false;
      bool isOut = false;
    };

    [[nodiscard]] ParameterParts SplitParameter(const std::string& parameter)
    {
      ParameterParts parts;
      std::string declaration = parameter;
      const std::size_t equals = declaration.find('=');
      if (equals != std::string::npos) {
        declaration = Trim(declaration.substr(0U, equals));
      }
      const std::size_t colon = declaration.find(':');
      if (colon != std::string::npos) {
        parts.semantic = Trim(declaration.substr(colon + 1U));
        declaration = Trim(declaration.substr(0U, colon));
      }
      const std::size_t bracket = declaration.find('[');
      if (bracket != std::string::npos) {
        parts.suffix = Squeeze(declaration.substr(bracket));
        declaration = Trim(declaration.substr(0U, bracket));
      }
      std::vector<std::string> words;
      for (const std::string& word : SplitTopLevel(Squeeze(declaration), ' ')) {
        if (!word.empty()) {
          words.push_back(word);
        }
      }
      if (words.empty()) {
        return parts;
      }
      parts.name = words.back();
      words.pop_back();
      for (const std::string& word : words) {
        if (word == "uniform") {
          parts.isUniform = true;
        } else if (word == "out" || word == "inout") {
          parts.isOut = true;
          parts.modifiers += word + " ";
        } else if (word == "in" || word == "const" || word == "linear" || word == "centroid" || word == "nointerpolation" ||
                   word == "noperspective" || word == "sample") {
          parts.modifiers += word + " ";
        } else {
          parts.type += (parts.type.empty() ? "" : " ") + word;
        }
      }
      return parts;
    }

    /** "COLOR1" -> ("COLOR", "1"). */
    [[nodiscard]] std::pair<std::string, std::string> SplitSemantic(const std::string& semantic)
    {
      std::size_t digits = semantic.size();
      while (digits > 0U && std::isdigit(static_cast<unsigned char>(semantic[digits - 1U])) != 0) {
        --digits;
      }
      return {Lower(semantic.substr(0U, digits)), semantic.substr(digits)};
    }

    enum class SemanticRole : std::uint8_t
    {
      VertexOutput, // POSITION -> SV_Position
      PixelInput,   // POSITION, VPOS -> SV_Position
      PixelOutput,  // COLORn -> SV_Targetn, DEPTH -> SV_Depth
    };

    [[nodiscard]] std::string ModernSemantic(const std::string& semantic, const SemanticRole role)
    {
      const auto [name, index] = SplitSemantic(semantic);
      switch (role) {
      case SemanticRole::VertexOutput:
        if (name == "position" && (index.empty() || index == "0")) {
          return "SV_Position";
        }
        break;
      case SemanticRole::PixelInput:
        if ((name == "position" && (index.empty() || index == "0")) || name == "vpos") {
          return "SV_Position";
        }
        break;
      case SemanticRole::PixelOutput:
        if (name == "color") {
          return "SV_Target" + (index.empty() ? std::string("0") : index);
        }
        if (name == "depth") {
          return "SV_Depth";
        }
        break;
      }
      return semantic;
    }

    /** Rewrites the member semantics of a struct body for `role`. */
    [[nodiscard]] std::string RewriteStructSemantics(const std::string& body, const SemanticRole role)
    {
      std::string out;
      for (const std::string& member : SplitTopLevel(body, ';')) {
        const std::string trimmed = Trim(member);
        if (trimmed.empty()) {
          continue;
        }
        const std::size_t colon = trimmed.rfind(':');
        if (colon == std::string::npos) {
          out += "    " + trimmed + ";\n";
          continue;
        }
        const std::string semantic = Trim(trimmed.substr(colon + 1U));
        out += "    " + Trim(trimmed.substr(0U, colon)) + " : " + ModernSemantic(semantic, role) + ";\n";
      }
      return out;
    }

    [[nodiscard]] std::uint32_t AlignUp(const std::uint32_t value, const std::uint32_t alignment) noexcept
    {
      return (value + alignment - 1U) / alignment * alignment;
    }
  } // namespace

  const ConstantSlot* ConstantLayout::Find(const std::uint32_t parameter) const noexcept
  {
    for (const ConstantSlot& slot : slots) {
      if (slot.parameter == parameter) {
        return &slot;
      }
    }
    return nullptr;
  }

  namespace
  {
    struct Placement
    {
      std::uint32_t offset = 0;
      std::uint32_t size = 0;
      std::uint32_t elementStride = 0;
    };

    /**
     * Places one value at `offset` by the HLSL constant-buffer rules: a
     * scalar or vector packs into the current 16-byte register when it fits;
     * arrays, matrices and structs start a register, and array elements each
     * start one. Row-major matrices take one register per row.
     */
    [[nodiscard]] Placement PlaceValue(
      const std::uint32_t offset,
      const ParameterClass parameterClass,
      const std::uint32_t rows,
      const std::uint32_t columns,
      const std::uint32_t elements,
      const bool columnMajor,
      const std::uint32_t structBytes
    )
    {
      std::uint32_t registers = 1U;
      std::uint32_t elementBytes = columns * 4U;
      if (parameterClass == ParameterClass::Matrix) {
        registers = columnMajor ? columns : rows;
        elementBytes = (registers - 1U) * 16U + (columnMajor ? rows : columns) * 4U;
      } else if (parameterClass == ParameterClass::Struct) {
        registers = (structBytes + 15U) / 16U;
        elementBytes = structBytes;
      }

      Placement placement;
      if (elements == 0U && registers == 1U && parameterClass != ParameterClass::Struct) {
        placement.offset = ((offset % 16U) + elementBytes > 16U) ? AlignUp(offset, 16U) : offset;
        placement.size = elementBytes;
        placement.elementStride = 16U;
        return placement;
      }
      placement.offset = AlignUp(offset, 16U);
      placement.elementStride = std::max<std::uint32_t>(registers, 1U) * 16U;
      placement.size = (std::max<std::uint32_t>(elements, 1U) - 1U) * placement.elementStride + elementBytes;
      return placement;
    }
  } // namespace

  ConstantLayout ComputeConstantLayout(const EffectDescription& description)
  {
    ConstantLayout layout;
    std::uint32_t offset = 0U;
    for (std::uint32_t index = 0U; index < description.parameters.size(); ++index) {
      const Parameter& parameter = description.parameters[index];
      ConstantSlot slot;
      slot.parameter = index;
      std::uint32_t structBytes = 0U;
      if (parameter.parameterClass == ParameterClass::Struct) {
        const StructType* const structType = description.FindStruct(parameter.typeName.substr(parameter.typeName.rfind(' ') + 1U));
        if (structType == nullptr) {
          continue;
        }
        for (const StructMember& member : structType->members) {
          if (member.parameterClass != ParameterClass::Scalar && member.parameterClass != ParameterClass::Vector &&
              member.parameterClass != ParameterClass::Matrix) {
            structBytes = 0U;
            break; // nothing the shaders read through $Globals
          }
          const Placement placement =
            PlaceValue(structBytes, member.parameterClass, member.rows, member.columns, member.elements, false, 0U);
          slot.members.push_back(ConstantMember{
            placement.offset,
            placement.size,
            placement.elementStride,
            member.rows,
            member.columns,
            std::max<std::uint32_t>(member.elements, 1U),
            member.parameterClass,
            member.scalarType,
          });
          structBytes = placement.offset + placement.size;
        }
        if (structBytes == 0U) {
          continue;
        }
      } else if (parameter.parameterClass != ParameterClass::Scalar && parameter.parameterClass != ParameterClass::Vector &&
                 parameter.parameterClass != ParameterClass::Matrix) {
        continue;
      }
      const Placement placement = PlaceValue(
        offset, parameter.parameterClass, parameter.rows, parameter.columns, parameter.elements, parameter.columnMajor, structBytes
      );
      slot.offset = placement.offset;
      slot.size = placement.size;
      slot.elementStride = placement.elementStride;
      offset = slot.offset + slot.size;
      layout.slots.push_back(std::move(slot));
    }
    layout.size = offset;
    return layout;
  }

  namespace
  {
    /// What GenerateModernHlsl's body needs from the texture views.
    struct TextureViews
    {
      std::vector<std::vector<TextureDimension>> samplerDimensions;
    };

    /// Texture views and sampler registers.
    TextureViews BuildTextureViews(const std::string_view source, EffectDescription& description, ModernEffect& modern)
    {
      TextureViews views;
      std::map<std::string, std::vector<TextureDimension>> textureDimensions;
      std::vector<std::vector<TextureDimension>>& samplerDimensions = views.samplerDimensions;
      for (const SamplerDesc& sampler : description.samplers) {
        samplerDimensions.push_back(SamplerDimensions(sampler, source));
        if (sampler.texture.empty()) {
          continue;
        }
        std::vector<TextureDimension>& dimensions = textureDimensions[sampler.texture];
        for (const TextureDimension dimension : samplerDimensions.back()) {
          if (std::find(dimensions.begin(), dimensions.end(), dimension) == dimensions.end()) {
            dimensions.push_back(dimension);
          }
        }
      }
      for (const Parameter& parameter : description.parameters) {
        if (parameter.parameterClass != ParameterClass::Texture) {
          continue;
        }
        const auto found = textureDimensions.find(parameter.name);
        if (found == textureDimensions.end()) {
          continue; // never sampled
        }
        for (const TextureDimension dimension : found->second) {
          const std::uint32_t slot = static_cast<std::uint32_t>(modern.textures.size());
          modern.textures.push_back(TextureSlot{parameter.name, dimension, slot});
        }
      }
      if (modern.textures.size() > kMaxTextureSlots) {
        modern.notes.push_back("more texture views than the register budget");
      }
      if (description.samplers.size() > kMaxSamplerSlots) {
        modern.notes.push_back("more samplers than the register budget");
      }
      return views;
    }

    /// The functions in the source, by name; the first definition of a name wins.
    std::map<std::string, Function> CollectFunctions(const std::vector<Item>& items)
    {
      std::map<std::string, Function> functions;
      for (const Item& item : items) {
        Function function;
        if (item.braced && item.head.find('(') != std::string::npos && !HasTopLevelAssignment(item.head) &&
            ParseFunctionHead(item.head, function) && functions.find(function.name) == functions.end()) {
          functions[function.name] = function;
        }
      }
      return functions;
    }

    /// The role each struct plays in a stage's signature.
    std::map<std::string, SemanticRole> AssignStructRoles(
      EffectDescription& description, const std::map<std::string, Function>& functions, ModernEffect& modern
    )
    {
      std::map<std::string, SemanticRole> structRoles;
      std::set<std::string> vertexInputStructs;
      const auto isStruct = [&](const std::string& name) { return description.FindStruct(name) != nullptr; };
      // Roles belong to the struct definition, typedef'd names included.
      const auto baseStruct = [&](const std::string& name) {
        const StructType* const found = description.FindStruct(name);
        return (found != nullptr && !found->aliasOf.empty()) ? found->aliasOf : name;
      };
      for (const Technique& technique : description.techniques) {
        for (const Pass& pass : technique.passes) {
          // A domain function's result goes to the rasterizer, as a vertex shader's does.
          // Its control-point parameters are the vertex shader's output struct.
          if (pass.Tessellated()) {
            const auto domain = functions.find(pass.domainShader.function);
            if (domain != functions.end() && isStruct(domain->second.returnType)) {
              structRoles.emplace(baseStruct(domain->second.returnType), SemanticRole::VertexOutput);
            }
          }
          for (const auto& [reference, stage] :
               {std::pair{&pass.vertexShader, ShaderStage::Vertex}, std::pair{&pass.pixelShader, ShaderStage::Pixel}}) {
            const auto found = functions.find(reference->function);
            if (found == functions.end()) {
              continue;
            }
            const Function& function = found->second;
            if (stage == ShaderStage::Vertex) {
              if (isStruct(function.returnType)) {
                structRoles.emplace(baseStruct(function.returnType), SemanticRole::VertexOutput);
              }
              for (const std::string& parameter : function.parameters) {
                const ParameterParts parts = SplitParameter(parameter);
                if (!isStruct(parts.type)) {
                  continue;
                }
                if (parts.isOut) {
                  structRoles.emplace(baseStruct(parts.type), SemanticRole::VertexOutput);
                } else if (!parts.isUniform) {
                  vertexInputStructs.insert(baseStruct(parts.type));
                }
              }
            } else {
              if (isStruct(function.returnType)) {
                structRoles[baseStruct(function.returnType)] = SemanticRole::PixelOutput;
              }
              for (const std::string& parameter : function.parameters) {
                const ParameterParts parts = SplitParameter(parameter);
                if (!isStruct(parts.type)) {
                  continue;
                }
                if (parts.isOut) {
                  structRoles[baseStruct(parts.type)] = SemanticRole::PixelOutput;
                } else if (!parts.isUniform) {
                  structRoles.emplace(baseStruct(parts.type), SemanticRole::PixelInput);
                }
              }
            }
          }
        }
      }
      for (const std::string& name : vertexInputStructs) {
        const auto found = structRoles.find(name);
        if (found != structRoles.end() && found->second != SemanticRole::PixelOutput) {
          modern.notes.push_back("struct " + name + " is both a vertex input and a stage output; semantics left as written");
          structRoles.erase(found);
        }
      }
      return structRoles;
    }
  } // namespace

  ModernEffect GenerateModernHlsl(const std::string_view source, EffectDescription& description)
  {
    ModernEffect modern;
    const std::vector<Item> items = SplitItems(source);

    TextureViews textureViews = BuildTextureViews(source, description, modern);
    std::vector<std::vector<TextureDimension>>& samplerDimensions = textureViews.samplerDimensions;

    // Engine addition (ren_ShadowCascades): the lighting shadow samplers read through the atlas when the
    // effect carries the cascade parameter (EffectProgram adds it) and only ever looks them up.
    bool shadowCascades = false;
    bool rayShadows = false;
    std::vector<std::string> shadowLookupSamplers;
    {
      const bool declared = std::any_of(description.parameters.begin(), description.parameters.end(), [](const Parameter& parameter) {
        return parameter.name == kShadowCascadeParameter && parameter.elements == kShadowCascadeVectors;
      });
      bool lookups = true;
      bool any = false;
      for (const SamplerDesc& sampler : description.samplers) {
        if (IsShadowLookupSampler(sampler)) {
          any = true;
          lookups = lookups && ShadowSamplerOnlyLookedUp(source, sampler);
        }
      }
      shadowCascades = declared && any && lookups;
      if (shadowCascades) {
        for (const SamplerDesc& sampler : description.samplers) {
          if (IsShadowLookupSampler(sampler)) {
            shadowLookupSamplers.push_back(sampler.name);
          }
        }
        // Engine addition (ren_RayTracedShadows): EffectProgram declares faf_RayShadows ahead of the cascades.
        rayShadows = gRayQueryShaders && std::any_of(description.parameters.begin(), description.parameters.end(), [](const Parameter& parameter) {
          return parameter.name == kRayShadowParameter && parameter.elements == kRayShadowVectors;
        });
      }
      if (declared && any && !lookups) {
        gShadowCascadesBlocked.store(true);
        modern.notes.push_back("a shadow sampler is used other than in a tex2D lookup; shadow cascades are off");
      }
    }

    // ---- parameters a function writes -------------------------------------------
    std::map<std::string, const Parameter*> numericParameters;
    for (const Parameter& parameter : description.parameters) {
      if (parameter.parameterClass == ParameterClass::Scalar || parameter.parameterClass == ParameterClass::Vector ||
          parameter.parameterClass == ParameterClass::Matrix) {
        numericParameters[parameter.name] = &parameter;
      }
    }

    const std::map<std::string, Function> functions = CollectFunctions(items);
    std::map<std::string, SemanticRole> structRoles = AssignStructRoles(description, functions, modern);

    // ---- the body ---------------------------------------------------------------
    std::string body;
    body.reserve(source.size() + 4096U);
    body += kPrelude;
    if (UseDirect3D9Math()) {
      body += kDirect3D9Math;
    }
    std::size_t cursor = 0U;
    const auto keepGap = [&](const std::size_t until) {
      // Whitespace between items.
      if (until > cursor) {
        body.append(source.substr(cursor, until - cursor));
      }
    };

    for (const Item& item : items) {
      keepGap(item.begin);
      cursor = item.end;
      const std::string& head = item.head;
      const std::string original(source.substr(item.begin, item.end - item.begin));

      if (item.directive) {
        // A preprocessor line stays a line of its own.
        body += original;
        if (original.empty() || original.back() != '\n') {
          body += '\n';
        }
        continue;
      }

      if (StartsWithWord(head, "technique") || StartsWithWord(head, "technique10") || StartsWithWord(head, "technique11") ||
          StartsWithWord(head, "BlendState") || StartsWithWord(head, "DepthStencilState") || StartsWithWord(head, "RasterizerState") ||
          StartsWithWord(head, "VertexShader") || StartsWithWord(head, "PixelShader") || StartsWithWord(head, "GeometryShader") ||
          StartsWithWord(head, "HullShader") || StartsWithWord(head, "DomainShader") || StartsWithWord(head, "string")) {
        continue; // the effect description carries these
      }

      // Sampler states.
      const auto sampler = std::find_if(description.samplers.begin(), description.samplers.end(), [&](const SamplerDesc& candidate) {
        return candidate.begin == item.begin && candidate.end == item.end;
      });
      if (sampler != description.samplers.end()) {
        const std::size_t index = static_cast<std::size_t>(sampler - description.samplers.begin());
        const auto view = [&](const TextureDimension dimension, const char* const placeholder) -> std::string {
          const auto& dimensions = samplerDimensions[index];
          if (sampler->texture.empty() || std::find(dimensions.begin(), dimensions.end(), dimension) == dimensions.end()) {
            return placeholder;
          }
          return sampler->texture + ViewSuffix(dimension);
        };
        char declaration[256]{};
        std::snprintf(declaration, sizeof(declaration), "SamplerState faf_smp_%s : register(s%u);\n", sampler->name.c_str(),
                      static_cast<unsigned>(index));
        body += declaration;
        const char* const maker = (shadowCascades && IsShadowLookupSampler(*sampler)) ? "faf_make_shadow_sampler(" : "faf_make_sampler(";
        body += "#define " + sampler->name + " " + maker + view(TextureDimension::Texture2D, "faf_null2D") + ", " +
          view(TextureDimension::TextureCube, "faf_nullCube") + ", " + view(TextureDimension::Texture3D, "faf_null3D") +
          ", faf_smp_" + sampler->name + ")\n";
        continue;
      }

      // Parameters.
      const auto parameter = std::find_if(description.parameters.begin(), description.parameters.end(), [&](const Parameter& candidate) {
        return candidate.begin == item.begin && candidate.end == item.end;
      });
      if (parameter != description.parameters.end()) {
        if (parameter->parameterClass == ParameterClass::Texture) {
          for (const TextureSlot& slot : modern.textures) {
            if (slot.parameter == parameter->name) {
              char declaration[256]{};
              std::snprintf(declaration, sizeof(declaration), "%s %s%s : register(t%u);\n", ViewType(slot.dimension),
                            slot.parameter.c_str(), ViewSuffix(slot.dimension), static_cast<unsigned>(slot.slot));
              body += declaration;
            }
          }
        } else if (numericParameters.count(parameter->name) != 0U || parameter->parameterClass == ParameterClass::Struct) {
          body += GlobalDeclaration(*parameter) + "\n";
          if (shadowCascades && parameter->name == kShadowCascadeParameter) {
            body += kShadowCascadeHelpers;
            body += kShadowCoordinateHelpers;
            body += rayShadows ? kRayShadowHelpers : kRayShadowFallback;
          }
        }
        // Anything else (strings, sampler parameters without state) has no shader-side form.
        continue;
      }

      if (!item.braced) {
        // Static globals, typedefs, prototypes.
        body += ReplaceSamplerTypes(original);
        continue;
      }

      if (StartsWithWord(head, "struct")) {
        const std::string name = Trim(head.substr(6U));
        const auto role = structRoles.find(name);
        if (role == structRoles.end()) {
          body += ReplaceSamplerTypes(original);
        } else {
          body += "struct " + name + "\n{\n" + RewriteStructSemantics(ReplaceSamplerTypes(item.body), role->second) + "};";
        }
        continue;
      }

      Function function;
      if (head.find('(') != std::string::npos && !HasTopLevelAssignment(head) && ParseFunctionHead(head, function)) {
        // A function: local copies of the parameters it writes.
        std::string functionBody = item.body;
        if (description.direct3D9PassStates && function.name == "AlphaTestD3D10") {
          // The effects' D3D10 stand-in for the alpha test. Direct3D 9 never
          // ran it (#ifdef DIRECT3D10) and tested the pass state instead, which
          // the entry wrappers now emulate; some calls also test another value
          // (water2 passes a float4, so it tests red, not the alpha it returns).
          functionBody = " ";
        }
        std::string copies;
        for (const auto& [name, global] : numericParameters) {
          bool shadowed = false;
          for (const std::string& parameterText : function.parameters) {
            if (SplitParameter(parameterText).name == name) {
              shadowed = true;
            }
          }
          if (shadowed || DeclaresIdentifier(functionBody, name) || !AssignsIdentifier(functionBody, name)) {
            continue;
          }
          functionBody = ReplaceIdentifier(functionBody, name, "faf_local_" + name);
          std::string type = LocalCopyType(*global);
          copies += " " + type + " faf_local_" + name + (global->elements != 0U ? "[" + std::to_string(global->elements) + "]" : "") +
            " = " + name + ";";
        }
        const std::size_t open = original.find('{', original.find(')'));
        if (shadowCascades) {
          functionBody = PassShadowCoordinates(functionBody, shadowLookupSamplers);
        }
        body += ReplaceSamplerTypes(original.substr(0U, open)) + "{" + copies + ReplaceSamplerTypes(functionBody) + "}";
        continue;
      }

      // Initializer lists and anything else braced at top level.
      body += ReplaceSamplerTypes(original);
    }
    keepGap(source.size());

    // ---- entry points -------------------------------------------------------------
    std::map<std::tuple<ShaderStage, std::string, std::string>, std::string> entryNames;
    std::string wrappers;
    for (Technique& technique : description.techniques) {
      for (Pass& pass : technique.passes) {
        const bool tessellated = pass.Tessellated();
        const bool namedTessellation = !pass.hullShader.function.empty() || !pass.domainShader.function.empty();
        for (const auto& [reference, stage] :
             {std::pair{&pass.vertexShader, ShaderStage::Vertex}, std::pair{&pass.pixelShader, ShaderStage::Pixel},
              std::pair{&pass.hullShader, ShaderStage::Hull}, std::pair{&pass.domainShader, ShaderStage::Domain}}) {
          if (reference->function.empty()) {
            continue;
          }
          if (stage == ShaderStage::Hull || stage == ShaderStage::Domain) {
            if (!tessellated) {
              modern.notes.push_back("technique " + technique.name + ": a hull shader needs a domain shader and the reverse; ignored");
              reference->function.clear();
              continue;
            }
            const std::string arguments = Squeeze(reference->arguments);
            const auto key = std::make_tuple(stage, reference->function, arguments);
            const auto known = entryNames.find(key);
            if (known != entryNames.end()) {
              reference->entry = known->second;
              continue;
            }
            const auto found = functions.find(reference->function);
            if (found == functions.end()) {
              modern.notes.push_back("technique " + technique.name + ": shader function " + reference->function + " not found");
              reference->function.clear();
              continue;
            }
            const Function& function = found->second;
            const unsigned index = static_cast<unsigned>(modern.entries.size());
            char name[64]{};
            std::snprintf(name, sizeof(name), "faf_entry_%s_%u", stage == ShaderStage::Hull ? "hs" : "ds", index);

            // The call: varying parameters take `varying` in order, uniform ones the
            // pass's arguments or their defaults. The control-point type is the type of
            // the first (hull) or second (domain) varying parameter.
            std::vector<std::string> uniformArguments;
            if (!arguments.empty()) {
              for (const std::string& argument : SplitTopLevel(arguments, ',')) {
                uniformArguments.push_back(Trim(argument));
              }
            }
            const std::vector<std::string> varying = (stage == ShaderStage::Hull)
              ? std::vector<std::string>{"faf_patch[0]", "faf_patch[1]", "faf_patch[2]"}
              : std::vector<std::string>{"faf_weights", "faf_patch[0]", "faf_patch[1]", "faf_patch[2]"};
            std::string callArguments;
            std::string pointType;
            std::size_t nextVarying = 0U;
            std::size_t nextUniform = 0U;
            for (const std::string& parameterText : function.parameters) {
              const ParameterParts parts = SplitParameter(parameterText);
              if (!callArguments.empty()) {
                callArguments += ", ";
              }
              if (parts.isUniform) {
                if (nextUniform < uniformArguments.size()) {
                  callArguments += uniformArguments[nextUniform++];
                } else {
                  const std::size_t equals = parameterText.find('=');
                  callArguments += (equals != std::string::npos) ? Trim(parameterText.substr(equals + 1U)) : std::string("0");
                }
                continue;
              }
              if (nextVarying == (stage == ShaderStage::Hull ? 0U : 1U)) {
                pointType = parts.type;
              }
              callArguments += (nextVarying < varying.size()) ? varying[nextVarying] : std::string("0");
              ++nextVarying;
            }
            if (nextVarying != varying.size() || pointType.empty()) {
              modern.notes.push_back("technique " + technique.name + ": " + function.name + " needs " +
                                     std::to_string(varying.size()) + " varying parameters");
              reference->function.clear();
              continue;
            }
            const std::string call = function.name + "(" + callArguments + ")";
            const std::string patch = "InputPatch<" + pointType + ", 3> faf_patch";
            if (stage == ShaderStage::Hull) {
              char constants[64]{};
              std::snprintf(constants, sizeof(constants), "faf_hsconst_%u", index);
              wrappers += std::string("faf_tess_factors ") + constants + "(" + patch + ")\n{\n    float4 faf_f = " + call +
                ";\n    faf_tess_factors faf_r;\n    faf_r.edges[0] = faf_f.x;\n    faf_r.edges[1] = faf_f.y;\n"
                "    faf_r.edges[2] = faf_f.z;\n    faf_r.inside = faf_f.w;\n    return faf_r;\n}\n";
              wrappers += std::string("[domain(\"tri\")]\n[partitioning(\"fractional_odd\")]\n[outputtopology(FAF_TESS_TOPOLOGY)]\n"
                                      "[outputcontrolpoints(3)]\n[patchconstantfunc(\"") +
                constants + "\")]\n[maxtessfactor(64.0)]\n" + pointType + " " + name + "(" + patch +
                ", uint faf_id : SV_OutputControlPointID)\n{\n    return faf_patch[faf_id];\n}\n";
            } else {
              wrappers += "[domain(\"tri\")]\n" + function.returnType + " " + name +
                "(faf_tess_factors faf_factors, float3 faf_weights : SV_DomainLocation, const OutputPatch<" + pointType +
                ", 3> faf_patch)\n{\n    return " + call + ";\n}\n";
            }
            modern.entries.push_back(ShaderEntry{stage, function.name, arguments, name});
            entryNames.emplace(key, name);
            reference->entry = name;
            continue;
          }
          const std::string arguments = Squeeze(reference->arguments);
          // The Direct3D 9 alpha test is part of the pixel entry: one per test.
          const std::optional<AlphaTestDesc> alphaTest = (stage == ShaderStage::Pixel) ? pass.alphaTest : std::nullopt;
          const std::string alphaTestKey =
            alphaTest.has_value() ? "|alphatest " + std::to_string(alphaTest->func) + " " + std::to_string(alphaTest->ref) : std::string();
          const auto key = std::make_tuple(stage, reference->function, arguments + alphaTestKey);
          const auto known = entryNames.find(key);
          if (known != entryNames.end()) {
            reference->entry = known->second;
            continue;
          }
          const auto found = functions.find(reference->function);
          if (found == functions.end()) {
            modern.notes.push_back("technique " + technique.name + ": shader function " + reference->function + " not found");
            continue;
          }
          const Function& function = found->second;
          char name[64]{};
          std::snprintf(name, sizeof(name), "faf_entry_%s_%u", stage == ShaderStage::Vertex ? "vs" : "ps",
                        static_cast<unsigned>(modern.entries.size()));

          std::vector<std::string> uniformArguments;
          if (!arguments.empty()) {
            for (const std::string& argument : SplitTopLevel(arguments, ',')) {
              uniformArguments.push_back(Trim(argument));
            }
          }
          std::string parameters;
          std::string callArguments;
          std::size_t nextUniform = 0U;
          std::map<std::string, std::string> inputsBySemantic;
          for (const std::string& parameterText : function.parameters) {
            const ParameterParts parts = SplitParameter(parameterText);
            if (!callArguments.empty()) {
              callArguments += ", ";
            }
            if (parts.isUniform) {
              if (nextUniform < uniformArguments.size()) {
                callArguments += uniformArguments[nextUniform++];
              } else {
                // A uniform parameter the pass leaves out takes its default.
                const std::size_t equals = parameterText.find('=');
                callArguments += (equals != std::string::npos) ? Trim(parameterText.substr(equals + 1U)) : std::string("0");
              }
              continue;
            }
            if (!parts.isOut && !parts.semantic.empty()) {
              // Two inputs on one semantic (mesh.fx reads NORMAL0 as `normal`
              // and NORMAL as `UnusedNormal`): FXC bound both to one
              // register; DXIL refuses the overlap, so the second reads the first.
              const auto [semanticName, semanticIndex] = SplitSemantic(parts.semantic);
              const std::string key = semanticName + (semanticIndex.empty() ? std::string("0") : semanticIndex);
              const auto earlier = inputsBySemantic.find(key);
              if (earlier != inputsBySemantic.end()) {
                callArguments += "(" + parts.type + ")" + earlier->second;
                continue;
              }
              inputsBySemantic.emplace(key, parts.name);
            }
            callArguments += parts.name;
            std::string semantic = parts.semantic;
            if (!semantic.empty()) {
              const SemanticRole role = (stage == ShaderStage::Vertex) ? SemanticRole::VertexOutput
                : parts.isOut                                          ? SemanticRole::PixelOutput
                                                                       : SemanticRole::PixelInput;
              if (stage == ShaderStage::Pixel || parts.isOut) {
                semantic = ModernSemantic(semantic, role);
              }
            }
            if (!parameters.empty()) {
              parameters += ", ";
            }
            parameters += parts.modifiers + ReplaceSamplerTypes(parts.type) + " " + parts.name + parts.suffix +
              (semantic.empty() ? std::string() : " : " + semantic);
          }
          std::string returnSemantic = function.semantic;
          if (!returnSemantic.empty()) {
            returnSemantic =
              ModernSemantic(returnSemantic, stage == ShaderStage::Vertex ? SemanticRole::VertexOutput : SemanticRole::PixelOutput);
          }
          const bool returnsVoid = (function.returnType == "void");
          // The pixel colour the wrapper post-processes: the float4 the
          // function returns, or the first member of its output struct.
          std::string colour;
          if (stage == ShaderStage::Pixel && function.returnType == "float4") {
            colour = "faf_output";
          } else if (stage == ShaderStage::Pixel) {
            for (const StructType& type : description.structs) {
              if (type.name == function.returnType && !type.members.empty() && type.members.front().typeName == "float4") {
                colour = "faf_output." + type.members.front().name;
              }
            }
          }
          std::string post;
          if (!colour.empty() && alphaTest.has_value()) {
            // D3D9 compares the alpha the blender receives, in 8-bit units.
            static constexpr const char* kComparisons[] = {
              "false", "false", "faf_alpha < faf_ref", "faf_alpha == faf_ref", "faf_alpha <= faf_ref",
              "faf_alpha > faf_ref", "faf_alpha != faf_ref", "faf_alpha >= faf_ref", "true",
            };
            post += "    uint faf_alpha = (uint)round(saturate(" + colour + ".a) * 255.0);\n    uint faf_ref = " +
              std::to_string(alphaTest->ref) + "u;\n    if (!(" + kComparisons[alphaTest->func] + ")) discard;\n";
          } else if (alphaTest.has_value()) {
            modern.notes.push_back("technique " + technique.name + ": alpha test on " + function.name + " without a float4 colour");
          }
          if (!colour.empty() && NanCheckRequested()) {
            // Diagnostics: a pixel whose colour is NaN or infinite turns magenta.
            post += "    if (any(isnan(" + colour + ")) || any(isinf(" + colour + "))) " + colour + " = float4(1, 0, 1, 1);\n";
          }
          const std::string signature = function.returnType + " " + name + "(" + parameters + ")" +
            (returnSemantic.empty() ? std::string() : " : " + returnSemantic);
          const std::string call = function.name + "(" + callArguments + ")";
          if (post.empty()) {
            wrappers += signature + "\n{\n    " + (returnsVoid ? "" : "return ") + call + ";\n}\n";
          } else {
            wrappers += signature + "\n{\n    " + function.returnType + " faf_output = " + call + ";\n" + post +
              "    return faf_output;\n}\n";
          }

          modern.entries.push_back(ShaderEntry{stage, function.name, arguments, name});
          entryNames.emplace(key, name);
          reference->entry = name;
        }
        // A hull or domain function that couldn't be wrapped, or one named without the other, leaves the pass
        // with neither, and it says so (ProgramEffect::TechniqueCompiles fails it).
        if (namedTessellation && (pass.hullShader.function.empty() || pass.domainShader.function.empty())) {
          pass.hullShader = ShaderReference{};
          pass.domainShader = ShaderReference{};
          pass.tessellationDropped = true;
        }
      }
    }

    modern.hlsl = std::move(body);
    modern.hlsl += "\n// ---- entry points (generated) ----\n";
    modern.hlsl += wrappers;
    modern.constants = ComputeConstantLayout(description);
    return modern;
  }
} // namespace gpg::gal::effects

#include "moho/render/lights/LightField.h"
#include "gpg/gal/D3D9Utils.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderProfiler.h"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/lights/LightCollector.h"
#include "moho/render/lights/LightFeeds.h"
#include "moho/sim/STIMap.h"

namespace moho::lights
{
  int ren_DynLightsMode = 1;

  static TConVar<int> gTConVar_ren_DynLightsMode(
    "ren_DynLightsMode",
    "How the dynamic lights reach the shaders: 1 (the default) the irradiance field, 0 the light grid (every pixel "
    "loops over the lights of its cell). The field: "
    "a compute pass lights a world-fixed field once, the terrain and mesh shaders sample it. docs/LIGHTING_V2.md.",
    &ren_DynLightsMode
  );

  int ren_DynLightsFieldShadows = 1;
  int ren_DynLightsSunShadows = 1;
  int ren_DynLightsTerrainSunShadow = 0;
  int ren_DynLightsWaterLevels = 1;

  static TConVar<int> gTConVar_ren_DynLightsWaterLevels(
    "ren_DynLightsWaterLevels",
    "A map with water bodies (lakes and pools at their own levels): 1 (the default) the light field and the sun under "
    "water use the water level of each cell; 0 they use the level of the sea only, as on a map without bodies. No "
    "effect on a map without water bodies.",
    &ren_DynLightsWaterLevels
  );

  static TConVar<int> gTConVar_ren_DynLightsSunShadows(
    "ren_DynLightsSunShadows",
    "The terrain's shadow of the sun (ridges shade valleys, units and water) from the irradiance field "
    "(ren_DynLightsMode 1): 1 (the default) on, 0 off.",
    &ren_DynLightsSunShadows
  );

  static TConVar<int> gTConVar_ren_DynLightsTerrainSunShadow(
    "ren_DynLightsTerrainSunShadow",
    "Whether the terrain itself takes the light field's march of the sun over the height field "
    "(ren_DynLightsSunShadows 1): 0 (the default) no, the ground is shaded by the shadow map and its filter only "
    "(the march gives blocky, axis-aligned patches on hill faces); 1 the old look. Units, buildings, props and the "
    "water keep the field's sun shadow either way.",
    &ren_DynLightsTerrainSunShadow
  );

  static TConVar<int> gTConVar_ren_DynLightsFieldShadows(
    "ren_DynLightsFieldShadows",
    "Shadows of the units and buildings in the irradiance field (ren_DynLightsMode 1): 1 (the default) on, 0 off.",
    &ren_DynLightsFieldShadows
  );

  namespace
  {
    using namespace gpg::gal;

    constexpr std::uint32_t kCellsMax = 512;   // cells of the field per side at the top levels (High, Ultra)
    constexpr std::uint32_t kLayers = 5;       // sea bed, then four heights above the surface
    constexpr std::uint32_t kTile = 8;         // cells per side of a thread group
    constexpr std::uint32_t kAtlasFormat = 9U; // gal render target format: RGBA16F (DxgiFormats.cpp)
    constexpr float kCellLadder[] = {0.5f, 1.0f, 2.0f, 4.0f, 8.0f, 16.0f};

    // Cells per side by quality level (ren_DynLights): the field is cells x cells x kLayers cells of 48 bytes, an atlas
    // of 8 bytes a texel and two visibility buffers (105 MB at 512). Low lights big explosions and Medium the common
    // effects, which do not need the finest shadows; High and Ultra keep 512. A multiple of kTile.
    std::uint32_t CellsForLevel(
      const int level
    )
    {
      return level == 1 ? 256U : (level == 2 ? 384U : kCellsMax);
    }

    struct FieldConstants
    {
      float origin[4]; // originX, originZ, cellSize, lightCount
      float dims[4];   // cells, layers, height samples per side, world units per height sample
      float layerH[4];
      float map[4];    // unused, unused, water elevation of the sea, water on (a sea or water bodies)
      float absorb[4]; // light absorbed per world unit of water, per colour channel
      float sun[4];    // unit vector towards the sun, 1 when it is above the horizon
      float misc[4]; // frame seed, occluder count, temporal blend of the visibility (1: history not usable), shadows on
      float hist[4]; // window shift in cells since the previous frame (x, z), 1 when the history is usable
      float water[4]; // water bodies (the variant with FAF_WATER_LEVELS): the word offset of the level table, blocks in
                      // x, blocks in z
    };

    // One source for the three programs: the compute pass, the fullscreen vertex shader and the copy into the atlas.
    constexpr char kSource[] = R"HLSL(
cbuffer FieldConstants : register(b0)
{
    float4 gOrigin;   // originX, originZ, cellSize, lightCount
    float4 gDims;     // cells, layers, height samples in x, height samples in z
    float4 gLayerH;
    float4 gMap;      // unused, unused, water elevation, water on
    float4 gAbsorb;   // absorption per world unit of water, per channel
    float4 gSun;      // towards the sun, 1 when it is up
    float4 gMisc;     // frame seed, caster count, visibility blend, shadows on
    float4 gHist;     // window shift in cells (x, z), history usable
#if FAF_WATER_LEVELS
    float4 gWater;    // water bodies: the word offset of the level table behind the heights, blocks in x, blocks in z
#endif
};

StructuredBuffer<float4> Lights : register(t0);   // three float4 per light, the data layout of LightGrid.h
StructuredBuffer<uint> Heights : register(t1);    // the map's raw uint16 heights, two to a word
StructuredBuffer<float4> Casters : register(t2);  // four float4 per shadow caster: centre, then three axes with 1 / length squared in w
StructuredBuffer<float> VisPrev : register(t3);
RWStructuredBuffer<float4> Field : register(u0);
RWStructuredBuffer<float> VisCur : register(u1);

#define CHUNK 1024
groupshared uint sList[CHUNK];
groupshared uint sCount;

#define SAMPLES 4

uint Hash(uint v)
{
    uint state = v * 747796405u + 2891336453u;
    uint word = ((state >> ((state >> 28u) + 4u)) ^ state) * 277803737u;
    return (word >> 22u) ^ word;
}

float Rand(uint seed)
{
    return (float)(Hash(seed) & 0xFFFFFFu) * (1.0 / 16777216.0);
}

// How much of the light a caster (the ellipsoid in its box) takes from the cell: the length of the ray inside it, soft.
float CasterShadow(float3 p, float3 d, float len, uint ci)
{
    float4 c = Casters[ci * 4];
    float4 a0 = Casters[ci * 4 + 1];
    float4 a1 = Casters[ci * 4 + 2];
    float4 a2 = Casters[ci * 4 + 3];
    float3 rel = p - c.xyz;
    float3 x = float3(dot(rel, a0.xyz) * a0.w, dot(rel, a1.xyz) * a1.w, dot(rel, a2.xyz) * a2.w);
    float3 dd = float3(dot(d, a0.xyz) * a0.w, dot(d, a1.xyz) * a1.w, dot(d, a2.xyz) * a2.w);
    float3 xs = x * 1.25;
    float3 ds = dd * 1.25;
    float3 ls = xs + ds;
    float shadow = 1.0;
    if (dot(xs, xs) > 1.0 && dot(ls, ls) > 1.0)
    {
        float a2s = dot(ds, ds);
        float bs = dot(xs, ds);
        float cs = dot(xs, xs) - 1.0;
        float disc = bs * bs - a2s * cs;
        if (disc > 0.0 && a2s > 0.00000001)
        {
            float root = sqrt(disc);
            float tEnter = max((-bs - root) / a2s, 0.0);
            float tExit = min((-bs + root) / a2s, 1.0);
            if (tExit > tEnter)
            {
                float thick = saturate((tExit - tEnter) * sqrt(a2s));
                thick = thick * thick * (3.0 - 2.0 * thick);
                float behind = saturate(tEnter * len / 10.0);
                shadow = 1.0 - 0.6 * thick * (1.0 - 0.6 * behind);
            }
        }
    }
    return shadow;
}

static const float kLH[5] = {0.5, 0.3, 3.0, 10.0, 30.0};

float HeightAt(uint x, uint z)
{
    uint idx = z * (uint)gDims.z + x;
    uint word = Heights[idx >> 1];
    return (float)((idx & 1u) != 0u ? (word >> 16) : (word & 0xFFFFu)) * 0.0078125;
}

// The terrain at a world position, bilinear in the engine's own samples (one sample per world unit).
float GroundAt(float2 xz)
{
    float2 g = clamp(xz, float2(0.0, 0.0), float2(gDims.z - 1.001, gDims.w - 1.001));
    uint2 i = (uint2)g;
    float2 f = g - (float2)i;
    float h00 = HeightAt(i.x, i.y);
    float h10 = HeightAt(i.x + 1, i.y);
    float h01 = HeightAt(i.x, i.y + 1);
    float h11 = HeightAt(i.x + 1, i.y + 1);
    return lerp(lerp(h00, h10, f.x), lerp(h01, h11, f.x), f.y);
}

// FAF_WATER_LEVELS is defined (to 1, in front of this text) only for a map with water bodies. Without it every line below compiles to what the
// field was before water bodies (the compiler turns the same lines into other instructions once a branch is added, and the last bits of the
// field, and so of the frames, changed).
#if FAF_WATER_LEVELS
// The level of the water over a world position (-10000: none). A map with water bodies has a level per 2 x 2 block (the water map's texel),
// 16 bits each in the words that follow the heights.
float WaterLevelAt(float2 xz)
{
    int2 b = clamp((int2)floor(xz * 0.5), int2(0, 0), int2((int)gWater.y - 1, (int)gWater.z - 1));
    uint index = (uint)b.y * (uint)gWater.y + (uint)b.x;
    uint word = Heights[(uint)gWater.x + (index >> 1)];
    uint raw = (index & 1u) != 0u ? (word >> 16) : (word & 0xFFFFu);
    return raw == 0xFFFFu ? -10000.0 : (float)raw * 0.0078125;
}
#endif

// What the water between the receiver p and the light point q lets through (red goes first); 1 where the segment is above the surface. The
// surface is the line between the level over p and the level over q (the same level on a map without water bodies).
float3 WaterTransmit(float3 p, float3 q)
{
    if (gMap.w < 0.5)
    {
        return float3(1, 1, 1);
    }
#if FAF_WATER_LEVELS
    float dp = p.y - WaterLevelAt(p.xz);
    float dq = q.y - WaterLevelAt(q.xz);
#else
    float dp = p.y - gMap.z;
    float dq = q.y - gMap.z;
#endif
    if (dp >= 0.0 && dq >= 0.0)
    {
        return float3(1, 1, 1);
    }
    float below = 1.0;
    if (dp > 0.0 || dq > 0.0)
    {
        below = dp < 0.0 ? (-dp) / (dq - dp) : (-dq) / (dp - dq);
    }
    return exp(-gAbsorb.xyz * (length(q - p) * below));
}

// How much of the sun reaches p: the terrain between p and the sun, marched along the sun's direction with steps that grow with the distance
// (long shadows of a low sun), and a penumbra that widens with it.
float SunVis(float3 p)
{
    float vis = 1.0;
    [loop] for (int i = 0; i < 40; ++i)
    {
        float u = ((float)i + 0.5) / 40.0;
        float t = 0.3 + 500.0 * u * u;
        float3 q = p + gSun.xyz * t;
        float clearance = q.y - GroundAt(q.xz) - 0.15;
        vis = min(vis, saturate(clearance / (0.3 + 0.012 * t)));
    }
    return vis;
}

// The sun visibility of a cell: from one point while the cells are small; from four points around the centre once a cell is two units or more
// (zoomed out), so the edge of a ridge shadow crosses the cell in steps and the filtered field does not show it as stairs.
float SunVisCell(float3 p)
{
    float cs = gOrigin.z;
    if (cs < 1.9)
    {
        return SunVis(p);
    }
    float o = 0.25 * cs;
    float sum = 0.0;
    [unroll] for (int k = 0; k < 4; ++k)
    {
        float2 d = float2((k & 1) != 0 ? o : -o, (k & 2) != 0 ? o : -o);
        float3 q = float3(p.x + d.x, p.y, p.z + d.y);
        q.y = max(q.y, GroundAt(q.xz) + 0.3);
        sum += SunVis(q);
    }
    return 0.25 * sum;
}

// The ridges between the receiver and a light: the ray is marched over the terrain; the visibility falls off as it passes close to the
// ground, with a penumbra that widens along the ray.
float TerrainVis(float3 p, float3 d, float len)
{
    float vis = 1.0;
    [unroll] for (int i = 0; i < 12; ++i)
    {
        float t = ((float)i + 0.5) / 12.0;
        float3 q = p + d * t;
        float clearance = q.y - GroundAt(q.xz) - 0.25;
        vis = min(vis, saturate(clearance / (0.5 + 0.12 * t * len)));
    }
    return vis;
}

[numthreads(8, 8, 1)]
void FieldCS(uint3 gid : SV_GroupID, uint3 tid : SV_GroupThreadID, uint index : SV_GroupIndex)
{
    uint cells = (uint)gDims.x;
    uint layer = gid.z;
    uint2 cell = gid.xy * 8 + tid.xy;
    float cs = gOrigin.z;
    float2 xz = gOrigin.xy + ((float2)cell + 0.5) * cs;
    float ground = GroundAt(xz);
#if FAF_WATER_LEVELS
    float level = WaterLevelAt(xz);
    float surface = max(ground, level);
#else
    float surface = gMap.w > 0.5 ? max(ground, gMap.z) : ground;
#endif
    float3 p = float3(xz.x, layer == 0 ? ground + kLH[0] : surface + kLH[layer], xz.y);
    float2 tileMin = gOrigin.xy + (float2)(gid.xy * 8) * cs;
    float2 tileMax = tileMin + 8.0 * cs;

    float3 E = float3(0, 0, 0);
    float3 D = float3(0, 0, 0);
    float W = 0.0;
    uint cellId = (layer * cells + cell.y) * cells + cell.x;
    bool shadows = gMisc.w > 0.5;
    // SAMPLES reservoirs: each ends up holding one light, chosen with probability (luminance x attenuation) / sum: the shadow rays go to those
    uint sel[SAMPLES];
    float wsum = 0.0;
    uint seed = Hash(cellId * 2654435761u + (uint)gMisc.x * 40503u);
    [unroll] for (uint j0 = 0; j0 < SAMPLES; ++j0)
    {
        sel[j0] = 0xFFFFFFFFu;
    }
    uint total = (uint)gOrigin.w;
    for (uint basis = 0; basis < total; basis += CHUNK)
    {
        if (index == 0)
        {
            sCount = 0;
        }
        GroupMemoryBarrierWithGroupSync();
        uint last = min(basis + CHUNK, total);
        for (uint i = basis + index; i < last; i += 64)
        {
            // the light's footprint (its segment grown by the radius) against the tile, in the ground plane
            float4 a = Lights[i * 3];
            float4 c = Lights[i * 3 + 2];
            float r = max(abs(a.w), 1.5 * gOrigin.z);   // grown to the cells: see the accumulation below
            float3 e = a.w < 0.0 ? a.xyz : c.xyz;   // a spotlight stores its direction in c: its footprint is the circle around the position
            float2 lo = min(a.xz, e.xz) - r;
            float2 hi = max(a.xz, e.xz) + r;
            if (hi.x >= tileMin.x && hi.y >= tileMin.y && lo.x <= tileMax.x && lo.y <= tileMax.y)
            {
                uint slot;
                InterlockedAdd(sCount, 1, slot);
                sList[slot] = i;
            }
        }
        GroupMemoryBarrierWithGroupSync();
        uint count = sCount;
        for (uint k = 0; k < count; ++k)
        {
            uint li = sList[k];
            float4 a = Lights[li * 3];
            float4 b = Lights[li * 3 + 1];
            float4 c = Lights[li * 3 + 2];
            bool spot = a.w < 0.0;
            float r = max(abs(a.w), 0.001);
            // The cells of the field grow with the zoom (0.5 units close up, 4 to 16 over the whole map): a light smaller than a cell fell between the
            // cell centres and vanished. Its footprint is at least a cell and a half; it keeps the square root of the share of its radius, so a small
            // glow stays a glow when zoomed out (dimmer and wider) instead of going out.
            float rEff = max(r, 1.5 * gOrigin.z);
            float splat = sqrt(r / rEff);
            float3 seg = spot ? float3(0, 0, 0) : c.xyz - a.xyz;
            float t = saturate(dot(p - a.xyz, seg) / max(dot(seg, seg), 0.0001));
            float3 toLight = a.xyz + seg * t - p;
            float atten = saturate(1.0 - dot(toLight, toLight) / (rEff * rEff));
            atten *= 0.35 + 0.65 * atten;
            atten *= splat;
            if (spot)
            {
                float cd = dot(-normalize(toLight), c.xyz);
                atten *= saturate((cd - c.w) / max((1.0 - c.w) * 0.5, 0.0001));
            }
            if (atten > 0.002)
            {
                float3 colour = b.rgb * atten * WaterTransmit(p, a.xyz + seg * t);
                float lum = dot(colour, float3(0.3, 0.59, 0.11));
                float len = length(toLight);
                E += colour;
                D += toLight * (lum / max(len, 0.001));
                W += lum;
                if (shadows && lum > 0.0)
                {
                    wsum += lum;
                    [unroll] for (uint j1 = 0; j1 < SAMPLES; ++j1)
                    {
                        if (Rand(seed + li * 977u + j1 * 7919u) * wsum < lum)
                        {
                            sel[j1] = li;
                        }
                    }
                }
            }
        }
        GroupMemoryBarrierWithGroupSync();
    }

    // Shadows: each reservoir's light is tested against the casters near the tile (in chunks, so no list is cut); the mean transmittance of the
    // samples estimates how much of the light of the cell the casters take (importance sampled: the lights come with probability ~ their light).
    float vis = 1.0;
    if (shadows)
    {
        float3 pToLight[SAMPLES];
        float len[SAMPLES];
        float trans[SAMPLES];
        [unroll] for (uint j2 = 0; j2 < SAMPLES; ++j2)
        {
            trans[j2] = 1.0;
            pToLight[j2] = float3(0, 0, 0);
            len[j2] = 0.0;
            if (sel[j2] != 0xFFFFFFFFu)
            {
                float4 a = Lights[sel[j2] * 3];
                float4 c = Lights[sel[j2] * 3 + 2];
                bool spot = a.w < 0.0;
                float3 seg = spot ? float3(0, 0, 0) : c.xyz - a.xyz;
                float t = saturate(dot(p - a.xyz, seg) / max(dot(seg, seg), 0.0001));
                pToLight[j2] = a.xyz + seg * t - p;
                len[j2] = length(pToLight[j2]);
            }
        }
        uint casters = (uint)gMisc.y;
        for (uint cb = 0; cb < casters; cb += CHUNK)
        {
            if (index == 0)
            {
                sCount = 0;
            }
            GroupMemoryBarrierWithGroupSync();
            uint clast = min(cb + CHUNK, casters);
            for (uint ci = cb + index; ci < clast; ci += 64)
            {
                float4 cc = Casters[ci * 4];
                float4 b0 = Casters[ci * 4 + 1];
                float4 b1 = Casters[ci * 4 + 2];
                float4 b2 = Casters[ci * 4 + 3];
                // the sphere around the box (its three half extents are the axes: lengths are 1 / sqrt(w))
                float reach = max(max(rsqrt(b0.w), rsqrt(b1.w)), rsqrt(b2.w)) * 1.8 + 16.0;
                if (cc.x + reach >= tileMin.x && cc.x - reach <= tileMax.x && cc.z + reach >= tileMin.y && cc.z - reach <= tileMax.y)
                {
                    uint slot;
                    InterlockedAdd(sCount, 1, slot);
                    sList[slot] = ci;
                }
            }
            GroupMemoryBarrierWithGroupSync();
            uint ccount = sCount;
            for (uint k = 0; k < ccount; ++k)
            {
                [unroll] for (uint j3 = 0; j3 < SAMPLES; ++j3)
                {
                    if (len[j3] > 0.05)
                    {
                        trans[j3] *= CasterShadow(p, pToLight[j3], len[j3], sList[k]);
                    }
                }
            }
            GroupMemoryBarrierWithGroupSync();
        }
        [unroll] for (uint j5 = 0; j5 < SAMPLES; ++j5)
        {
            if (len[j5] > 0.05)
            {
                trans[j5] *= TerrainVis(p, pToLight[j5], len[j5]);
            }
        }
        float sum = 0.0;
        float used = 0.0;
        [unroll] for (uint j4 = 0; j4 < SAMPLES; ++j4)
        {
            if (sel[j4] != 0xFFFFFFFFu)
            {
                sum += trans[j4];
                used += 1.0;
            }
        }
        vis = used > 0.0 ? sum / used : 1.0;
        // the shadow, not the light, is averaged over time: the lights of the cell are exact every frame
        float prev = vis;
        int2 old = (int2)cell + (int2)gHist.xy;
        if (gHist.z > 0.5 && old.x >= 0 && old.y >= 0 && old.x < (int)cells && old.y < (int)cells)
        {
            prev = VisPrev[(layer * cells + (uint)old.y) * cells + (uint)old.x];
        }
        vis = lerp(prev, vis, gMisc.z);
    }
    VisCur[cellId] = vis;
    uint at = cellId * 3;
    Field[at] = float4(E * vis, layer == 0 ? ground : (layer == 1 ? surface : 0.0));
    Field[at + 1] = float4(D * vis, W * vis);
    float sunVis = 1.0;
    if (gSun.w > 0.5 && layer < 2)
    {
        sunVis = gSun.w > 2.5 ? 0.0 : (gSun.w > 1.5 ? (((gid.x + gid.y) & 1u) != 0u ? 0.2 : 1.0) : SunVisCell(p)); // 2: checker, 3: no sun anywhere (debug)
    }
#if FAF_WATER_LEVELS
    Field[at + 2] = float4(sunVis, level, 0.0, 0.0);
#else
    Field[at + 2] = float4(sunVis, 0.0, 0.0, 0.0);
#endif
}

StructuredBuffer<float4> FieldIn : register(t0);

float4 FieldVS(uint id : SV_VertexID) : SV_Position
{
    float2 uv = float2((id << 1) & 2, id & 2);
    return float4(uv * 2.0 - 1.0, 0.0, 1.0);
}

float4 FieldCopyPS(float4 position : SV_Position) : SV_Target
{
    uint cells = (uint)gDims.x;
    uint2 p = (uint2)position.xy;
    uint layer = p.x / cells;
    uint cx = p.x - layer * cells;
    uint part = p.y / cells;
    uint cy = p.y - part * cells;
    return FieldIn[((layer * cells + cy) * cells + cx) * 3 + part];
}
)HLSL";

    struct State
    {
      FieldFrame frame;
      FieldStats stats;
      std::shared_ptr<GpuBuffer> lightBuffer;
      std::shared_ptr<GpuBuffer> heightBuffer;
      std::shared_ptr<GpuBuffer> fieldBuffer;
      std::shared_ptr<GpuBuffer> casterBuffer;
      std::shared_ptr<GpuBuffer> visBuffer[2]; // the visibility of the previous frame and of this one
      std::uint32_t cells = 0U; // cells per side of the buffers and the atlas that exist (CellsForLevel of the level)
      std::uint32_t frameIndex = 0U;
      float lastOriginX = 0.0f;
      float lastOriginZ = 0.0f;
      float lastCellSize = 0.0f;
      bool historyValid = false;
      std::shared_ptr<GpuProgram> compute;
      std::shared_ptr<GpuProgram> computeLevels; // the same pass for a map with water bodies, made when one is played
      bool levelsProgramFailed = false;
      std::shared_ptr<GpuProgram> copy;
      Device* device = nullptr;
      bool failed = false;
      bool loggedRefusal = false;
      // what the height buffer holds
      float heightOriginX = 0.0f;
      float heightOriginZ = 0.0f;
      float heightCell = 0.0f;
      std::uint32_t heightAge = 1000U;
      std::uint64_t heightRevision = ~0ULL;
      bool sunActive = false;
      std::uint32_t heightWidth = 0U;
      std::uint32_t heightHeight = 0U;
      // the water bodies' level table behind the heights (empty: one level for the map)
      const void* waterContext = nullptr;
      std::uint32_t waterGeneration = 0U;
      std::uint32_t levelOffset = 0U; // word offset of the table in the height buffer
      std::uint32_t levelBlocksX = 0U;
      std::uint32_t levelBlocksZ = 0U;
      std::vector<std::uint32_t> levelWords;
    };

    State& GetState()
    {
      static State* const state = new State();
      return *state;
    }

    bool EnsureResources(
      State& s,
      Device& device
    )
    {
      if (s.device != &device) {
        s = State();
        s.device = &device;
      }
      if (s.failed) {
        return false;
      }
      // The buffers that depend on the cell count are made at the size of the level in use, when the field first runs,
      // and again when the level changes to one with another count (the history of the visibility goes with them).
      const std::uint32_t kCells = CellsForLevel(ren_DynLights);
      if (s.cells != kCells) {
        if (s.cells != 0U) {
          gpg::Logf("Light field: %u cells a side, was %u: the buffers are made again", kCells, s.cells);
        }
        s.fieldBuffer.reset();
        s.visBuffer[0].reset();
        s.visBuffer[1].reset();
        s.frame.atlas.reset();
        s.historyValid = false;
        s.cells = kCells;
      }
      if (s.compute == nullptr || s.copy == nullptr) {
        GpuProgramDesc desc;
        desc.name = "LightFieldCompute";
        desc.source = kSource;
        desc.sourceBytes = sizeof(kSource) - 1U;
        desc.computeEntry = "FieldCS";
        s.compute = device.CreateGpuProgram(desc);
        GpuProgramDesc draw;
        draw.name = "LightFieldCopy";
        draw.source = kSource;
        draw.sourceBytes = sizeof(kSource) - 1U;
        draw.vertexEntry = "FieldVS";
        draw.pixelEntry = "FieldCopyPS";
        draw.blend = GpuBlend::Opaque;
        draw.sampler = GpuSampler::PointClamp;
        s.copy = device.CreateGpuProgram(draw);
        if (s.compute == nullptr || s.copy == nullptr) {
          gpg::Warnf("Light field disabled: its GPU programs did not compile");
          s.failed = true;
          return false;
        }
      }
      if (s.lightBuffer == nullptr || s.fieldBuffer == nullptr) {
        if (s.lightBuffer == nullptr) {
          GpuBufferDesc lights;
          lights.name = "LightFieldLights";
          lights.stride = 16U;
          lights.capacity = static_cast<std::uint32_t>(kMaxGridLights * kTexelsPerLight);
          s.lightBuffer = device.CreateGpuBuffer(lights);
          GpuBufferDesc casters;
          casters.name = "LightFieldCasters";
          casters.stride = 16U;
          casters.capacity = static_cast<std::uint32_t>(kMaxOccluders * kOccluderTexels);
          s.casterBuffer = device.CreateGpuBuffer(casters);
        }
        GpuBufferDesc field;
        field.name = "LightFieldCells";
        field.stride = 16U;
        field.capacity = kCells * kCells * kLayers * 3U;
        field.shaderWrite = true;
        s.fieldBuffer = device.CreateGpuBuffer(field);
        GpuBufferDesc vis;
        vis.name = "LightFieldVisibility";
        vis.stride = 4U;
        vis.capacity = kCells * kCells * kLayers;
        vis.shaderWrite = true;
        s.visBuffer[0] = device.CreateGpuBuffer(vis);
        s.visBuffer[1] = device.CreateGpuBuffer(vis);
        if (
          s.lightBuffer == nullptr || s.fieldBuffer == nullptr || s.casterBuffer == nullptr ||
          s.visBuffer[0] == nullptr || s.visBuffer[1] == nullptr
        ) {
          gpg::Warnf("Light field disabled: its GPU buffers could not be created");
          s.failed = true;
          return false;
        }
      }
      if (s.frame.atlas == nullptr) {
        const RenderTargetContext context(kCells * kLayers, kCells * 3U, kAtlasFormat);
        s.frame.atlas = device.CreateRenderTarget(&context);
        if (s.frame.atlas == nullptr) {
          gpg::Warnf("Light field disabled: no %ux%u RGBA16F render target", kCells * kLayers, kCells * 3U);
          s.failed = true;
          return false;
        }
        gpg::Logf(
          "Light field: %ux%u RGBA16F atlas, %u cells x %u layers, %zu light slots",
          kCells * kLayers,
          kCells * 3U,
          kCells,
          kLayers,
          kMaxGridLights
        );
      }
      return true;
    }

    // The ground rectangle the view sees: the corners' rays against the terrain (the camera's own centre ray when a
    // corner looks past the horizon).
    bool ViewGround(
      const GeomCamera3& camera,
      const void* terrain,
      const ElevationFunction elevation,
      float (&minXZ)[2],
      float (&maxXZ)[2]
    )
    {
      const float w = camera.viewport.r[3].z;
      const float h = camera.viewport.r[3].w;
      if (!(w > 0.0f && h > 0.0f)) {
        return false;
      }
      const float corners[5][2] = {{0.0f, 0.0f}, {w, 0.0f}, {0.0f, h}, {w, h}, {w * 0.5f, h * 0.5f}};
      bool any = false;
      for (const auto& corner : corners) {
        const GeomLine3 ray = camera.Unproject(Wm3::Vector2f(corner[0], corner[1]));
        float t = 1.0f;
        float lastX = ray.pos.x;
        float lastZ = ray.pos.z;
        bool hit = false;
        for (; t < 6000.0f; t += 6.0f) {
          const float x = ray.pos.x + ray.dir.x * t;
          const float y = ray.pos.y + ray.dir.y * t;
          const float z = ray.pos.z + ray.dir.z * t;
          lastX = x;
          lastZ = z;
          if (y <= elevation(terrain, x, z)) {
            hit = true;
            break;
          }
        }
        if (!hit && !any) {
          continue; // a corner above the horizon contributes the far point of its ray
        }
        if (!any) {
          minXZ[0] = maxXZ[0] = lastX;
          minXZ[1] = maxXZ[1] = lastZ;
          any = true;
        } else {
          minXZ[0] = std::min(minXZ[0], lastX);
          maxXZ[0] = std::max(maxXZ[0], lastX);
          minXZ[1] = std::min(minXZ[1], lastZ);
          maxXZ[1] = std::max(maxXZ[1], lastZ);
        }
      }
      return any;
    }
  } // namespace

  bool UpdateField(
    const GeomCamera3& camera,
    const LightGridImage& image,
    const FieldTerrain& terrain
  )
  {
    State& s = GetState();
    s.frame.params2[0] = 0.0f;
    s.frame.valid = false;
    const bool sunOnly = image.lightCount == 0 && ren_DynLightsSunShadows != 0 &&
      terrain.sunValid; // no light: the field still carries the sun's shadow
    if (
      ren_DynLightsMode != 1 || (image.lightCount == 0 && !sunOnly) || terrain.context == nullptr ||
      terrain.elevation == nullptr || terrain.sample == nullptr || terrain.width < 2U || terrain.height < 2U
    ) {
      s.historyValid = false; // the visibility buffers go stale while the field is not run
      return false;
    }
    Device* const device = Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    const auto refuse = [&](const char* const reason) {
      if (!s.loggedRefusal) {
        s.loggedRefusal = true;
        gpg::Warnf("Light field is not available: %s; the light grid is used", reason);
      }
      return false;
    };
    const std::uint32_t features = device->GetGpuDrivenFeatures();
    if ((features & kGpuFeatureVertexPulling) == 0U || (features & kGpuFeatureCompute) == 0U) {
      return refuse("this render API has no GPU programs with compute");
    }
    if (!EnsureResources(s, *device)) {
      return false;
    }

    const std::uint32_t kCells = s.cells;
    float minXZ[2];
    float maxXZ[2];
    if (!ViewGround(camera, terrain.context, terrain.elevation, minXZ, maxXZ)) {
      return false;
    }
    // The cell size from a ladder (the field does not shimmer when the zoom changes a little); the origin snaps to
    // whole thread groups.
    const float margin = 24.0f;
    const float extent = std::max(maxXZ[0] - minXZ[0], maxXZ[1] - minXZ[1]) + 2.0f * margin;
    float cellSize = kCellLadder[sizeof(kCellLadder) / sizeof(kCellLadder[0]) - 1];
    for (const float candidate : kCellLadder) {
      if (static_cast<float>(kCells - 2U * kTile) * candidate >= extent) {
        cellSize = candidate;
        break;
      }
    }
    const float tileSpan = static_cast<float>(kTile) * cellSize;
    const float centreX = 0.5f * (minXZ[0] + maxXZ[0]);
    const float centreZ = 0.5f * (minXZ[1] + maxXZ[1]);
    const float originX = std::floor((centreX - 0.5f * static_cast<float>(kCells) * cellSize) / tileSpan) * tileSpan;
    const float originZ = std::floor((centreZ - 0.5f * static_cast<float>(kCells) * cellSize) / tileSpan) * tileSpan;

    // The terrain: the map's raw heights go to the GPU once (and again when they change), two samples to a word.
    // A new revision comes with every building that flattens ground; the whole map goes up at most every 90 frames of
    // the field (the sun's ridge shadows do not need the last foundation).
    if (s.heightAge < 1000000U) {
      ++s.heightAge;
    }
    // The pass for a map with water bodies is the same text with FAF_WATER_LEVELS defined in front of it, compiled the
    // first time one is lit; when it does not compile the map is lit at the one level of its sea, as before.
    const auto ensureLevelsProgram = [&]() {
      if (s.computeLevels != nullptr) {
        return true;
      }
      if (s.levelsProgramFailed) {
        return false;
      }
      static const std::string source = std::string("#define FAF_WATER_LEVELS 1\n") + kSource;
      GpuProgramDesc desc;
      desc.name = "LightFieldComputeLevels";
      desc.source = source.c_str();
      desc.sourceBytes = source.size();
      desc.computeEntry = "FieldCS";
      s.computeLevels = device->CreateGpuProgram(desc);
      if (s.computeLevels == nullptr) {
        s.levelsProgramFailed = true;
        gpg::Warnf("Light field: the pass for water bodies did not compile; the sea level is used for all waters");
        return false;
      }
      return true;
    };

    // A map with water bodies: the level of each block goes behind the heights (rebuilt when the bodies change, which
    // is not a revision of the heights).
    const bool levelsWanted = terrain.waterGeneration != 0U && terrain.waterLevel != nullptr &&
      terrain.waterContext != nullptr && WaterBlocksPerSide(terrain.width) > 0U &&
      WaterBlocksPerSide(terrain.height) > 0U;
    const bool levelsChanged = levelsWanted
      ? (terrain.waterContext != s.waterContext || terrain.waterGeneration != s.waterGeneration || s.levelWords.empty())
      : !s.levelWords.empty();
    if (levelsChanged) {
      s.waterContext = levelsWanted ? terrain.waterContext : nullptr;
      s.waterGeneration = levelsWanted ? terrain.waterGeneration : 0U;
      s.levelBlocksX = levelsWanted ? WaterBlocksPerSide(terrain.width) : 0U;
      s.levelBlocksZ = levelsWanted ? WaterBlocksPerSide(terrain.height) : 0U;
      s.levelWords.clear();
      if (levelsWanted) {
        s.levelWords = BuildWaterLevelWords(terrain.waterContext, terrain.waterLevel, s.levelBlocksX, s.levelBlocksZ);
        gpg::Logf(
          "Light field: water bodies generation %u, a level for each of %ux%u blocks",
          terrain.waterGeneration,
          s.levelBlocksX,
          s.levelBlocksZ
        );
      }
      s.heightRevision = ~0ULL; // the table is part of the height buffer: upload it again now
      s.heightAge = 1000U;
    }
    if (
      s.heightBuffer == nullptr || (terrain.revision != s.heightRevision && s.heightAge >= 90U) ||
      terrain.width != s.heightWidth || terrain.height != s.heightHeight
    ) {
      s.heightAge = 0U;
      const std::size_t samples = static_cast<std::size_t>(terrain.width) * terrain.height;
      const std::uint32_t heightWords = static_cast<std::uint32_t>((samples + 1U) / 2U);
      s.levelOffset = heightWords;
      const std::uint32_t words = heightWords + static_cast<std::uint32_t>(s.levelWords.size());
      if (s.heightBuffer == nullptr || s.heightBuffer->Desc().capacity != words) {
        GpuBufferDesc heights;
        heights.name = "LightFieldHeights";
        heights.stride = 4U;
        heights.capacity = words;
        s.heightBuffer = device->CreateGpuBuffer(heights);
        if (s.heightBuffer == nullptr) {
          s.failed = true;
          return refuse("no GPU buffer for the terrain heights");
        }
      }
      std::vector<std::uint32_t> packed(words, 0U);
      std::copy(s.levelWords.begin(), s.levelWords.end(), packed.begin() + heightWords);
      for (std::uint32_t z = 0; z < terrain.height; ++z) {
        for (std::uint32_t x = 0; x < terrain.width; ++x) {
          const std::size_t index = static_cast<std::size_t>(z) * terrain.width + x;
          packed[index >> 1U] |=
            static_cast<std::uint32_t>(
              terrain.sample(terrain.context, static_cast<std::int32_t>(x), static_cast<std::int32_t>(z))
            )
            << ((index & 1U) * 16U);
        }
      }
      device->UpdateGpuBuffer(*s.heightBuffer, 0U, words, packed.data());
      gpg::Logf(
        "Light field: sun direction (%.3f, %.3f, %.3f), %s",
        terrain.sunDirection[0],
        terrain.sunDirection[1],
        terrain.sunDirection[2],
        terrain.sunValid ? "valid" : "not valid"
      );
      s.heightRevision = terrain.revision;
      s.heightWidth = terrain.width;
      s.heightHeight = terrain.height;
      // a check of the unit: the raw sample against the engine's own elevation
      gpg::Logf(
        "Light field: terrain %ux%u samples uploaded; sample (200,200) = %.3f, engine elevation %.3f; water %s at %.2f",
        terrain.width,
        terrain.height,
        static_cast<float>(terrain.sample(terrain.context, 200, 200)) * 0.0078125f,
        terrain.elevation(terrain.context, 200.0f, 200.0f),
        terrain.waterEnabled ? "on" : "off",
        terrain.waterElevation
      );
    }

    const std::uint32_t lightCount =
      std::min<std::uint32_t>(image.lightCount, static_cast<std::uint32_t>(kMaxGridLights));
    if (lightCount > 0U) {
      device->UpdateGpuBuffer(
        *s.lightBuffer, 0U, lightCount * static_cast<std::uint32_t>(kTexelsPerLight), image.data.data()
      );
    }

    // the casters of the frame (the box of each unit and building in view)
    const std::uint32_t casterCount = ren_DynLightsFieldShadows != 0
      ? std::min<std::uint32_t>(image.occluderCount, static_cast<std::uint32_t>(kMaxOccluders))
      : 0U;
    if (casterCount > 0U) {
      device->UpdateGpuBuffer(
        *s.casterBuffer, 0U, casterCount * static_cast<std::uint32_t>(kOccluderTexels), image.occluders.data()
      );
    }
    // the visibility history: the window moves in whole thread groups, so a cell of this frame is a cell of the last
    // frame (shifted)
    const bool sameScale = s.historyValid && cellSize == s.lastCellSize;
    const float shiftX = sameScale ? std::round((originX - s.lastOriginX) / cellSize) : 0.0f;
    const float shiftZ = sameScale ? std::round((originZ - s.lastOriginZ) / cellSize) : 0.0f;
    const bool usable =
      sameScale && std::fabs(shiftX) < static_cast<float>(kCells) && std::fabs(shiftZ) < static_cast<float>(kCells);
    ++s.frameIndex;
    const std::uint32_t cur = s.frameIndex & 1U;

    FieldConstants constants{};
    constants.misc[0] = static_cast<float>(s.frameIndex);
    constants.misc[1] = static_cast<float>(casterCount);
    constants.misc[2] = usable ? 0.25f : 1.0f;
    constants.misc[3] = casterCount > 0U ? 1.0f : 0.0f;
    constants.hist[0] = shiftX;
    constants.hist[1] = shiftZ;
    constants.hist[2] = usable ? 1.0f : 0.0f;
    constants.origin[0] = originX;
    constants.origin[1] = originZ;
    constants.origin[2] = cellSize;
    constants.origin[3] = static_cast<float>(lightCount);
    constants.dims[0] = static_cast<float>(kCells);
    constants.dims[1] = static_cast<float>(kLayers);
    constants.dims[2] = static_cast<float>(terrain.width);
    constants.dims[3] = static_cast<float>(terrain.height);
    const bool levelsOn = !s.levelWords.empty() && ensureLevelsProgram();
    constants.map[2] = terrain.waterElevation;
    constants.map[3] = (terrain.waterEnabled || levelsOn) ? 1.0f : 0.0f;
    constants.water[0] = static_cast<float>(s.levelOffset);
    constants.water[1] = static_cast<float>(s.levelBlocksX);
    constants.water[2] = static_cast<float>(s.levelBlocksZ);
    constants.absorb[0] = 0.25f; // per world unit: red is gone in a few units, blue goes on
    constants.absorb[1] = 0.06f;
    constants.absorb[2] = 0.03f;
    constants.sun[0] = terrain.sunDirection[0];
    constants.sun[1] = terrain.sunDirection[1];
    constants.sun[2] = terrain.sunDirection[2];
    constants.sun[3] = (ren_DynLightsSunShadows != 0 && terrain.sunValid && terrain.sunDirection[1] > 0.02f)
      ? (ren_DynLightsSunShadows >= 2 ? static_cast<float>(ren_DynLightsSunShadows) : 1.0f)
      : 0.0f; // 2: a checker, to see that the sun term reaches the shaders

    OutputContext saved;
    device->GetContext(&saved);
    D3DVIEWPORT9 savedViewport{};
    device->GetViewport(&savedViewport);
    {
      const RenderProfileScope profile("LightField");
      GpuDispatch dispatch;
      dispatch.program = (levelsOn ? s.computeLevels : s.compute).get();
      dispatch.bindings.constants = &constants;
      dispatch.bindings.constantBytes = sizeof(constants);
      dispatch.bindings.readBuffers[0] = s.lightBuffer.get();
      dispatch.bindings.readBuffers[1] = s.heightBuffer.get();
      dispatch.bindings.readBuffers[2] = s.casterBuffer.get();
      dispatch.bindings.readBuffers[3] = s.visBuffer[cur ^ 1U].get();
      dispatch.bindings.writeBuffers[0] = s.fieldBuffer.get();
      dispatch.bindings.writeBuffers[1] = s.visBuffer[cur].get();
      dispatch.groupsX = kCells / kTile;
      dispatch.groupsY = kCells / kTile;
      dispatch.groupsZ = kLayers;
      device->DispatchGpuProgram(dispatch);

      const std::shared_ptr<DepthStencilTarget> noDepth;
      const OutputContext target(s.frame.atlas, noDepth);
      device->ClearTarget(&target);
      D3DVIEWPORT9 viewport{};
      viewport.Width = kCells * kLayers;
      viewport.Height = kCells * 3U;
      viewport.MaxZ = 1.0f;
      device->SetViewport(&viewport);
      GpuDrawCall call;
      call.program = s.copy.get();
      call.bindings.constants = &constants;
      call.bindings.constantBytes = sizeof(constants);
      call.bindings.readBuffers[0] = s.fieldBuffer.get();
      call.vertexCountPerInstance = 3U;
      call.instanceCount = 1U;
      device->DrawGpuProgram(call);
    }
    device->ClearTarget(&saved);
    device->SetViewport(&savedViewport);

    s.lastOriginX = originX;
    s.lastOriginZ = originZ;
    s.lastCellSize = cellSize;
    s.historyValid = true;
    FieldFrame& f = s.frame;
    f.params[0] = originX;
    f.params[1] = originZ;
    f.params[2] = 1.0f / cellSize;
    f.params[3] = static_cast<float>(kCells);
    f.params2[0] = 1.0f;
    f.params2[1] = static_cast<float>(kLayers);
    f.params2[2] = 1.0f / static_cast<float>(kCells * kLayers);
    f.params2[3] = 1.0f / static_cast<float>(kCells * 3U);
    f.water[0] = levelsOn ? 1.0f : 0.0f;
    f.water[1] = (constants.sun[3] > 0.5f && ren_DynLightsTerrainSunShadow != 0) ? 1.0f : 0.0f;
    f.valid = true;
    s.sunActive = constants.sun[3] > 0.5f;
    ++s.stats.frames;
    s.stats.cellSize = cellSize;
    s.stats.cells = kCells;
    s.stats.lights = lightCount;
    return true;
  }

  const FieldFrame& CurrentField()
  {
    return GetState().frame;
  }

  bool SunShadowActive()
  {
    const State& s = GetState();
    return s.frame.valid && s.sunActive;
  }

  bool TerrainSunShadowActive()
  {
    return SunShadowActive() && GetState().frame.water[1] > 0.5f;
  }

  void ReleaseField()
  {
    State& s = GetState();
    s = State();
  }

  const FieldStats& GetFieldStats()
  {
    return GetState().stats;
  }
} // namespace moho::lights

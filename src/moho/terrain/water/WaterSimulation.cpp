#include "moho/terrain/water/WaterSimulation.h"
#include "moho/terrain/water/ShoreField.h"
#include "moho/terrain/water/WaterBodySurfaces.h"
#include "moho/terrain/water/WaterDomains.h"
#include "moho/terrain/water/WaterHull.h"
#include "moho/terrain/water/WaterImpact.h"
#include "moho/terrain/water/WaterShaderCommon.h"
#include "moho/terrain/water/WaterSimParams.h"
#include "moho/terrain/water/WaterSourceGate.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <memory>
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderProfiler.h"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/WRenViewport.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimWaterEvents.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"
#include "moho/sim/WaterBodies.h"
#include "moho/vision/VisionDB.h"

namespace moho::water
{
  int ren_WaterSim = 1;
  static int ren_WaterSimStrength = 100;
  static int ren_WaterGrid = 1;
  static int ren_WaterDisplace = 100;
  static int ren_WaterDomains = 1;
  static int ren_WaterSimTest = 0;
  static int ren_WaterSimLog = 0;
  static int ren_WaterSwell = 100;
  static int ren_WaterSolid = 25;
  static int ren_WaterShoreWave = 100;
  static int ren_WaterMaskDebug = 0;
  static int ren_WaterSeed = 0;
  static int ren_WaterSimWake = 200;
  static int ren_WaterSimFoam = 100;
  static int ren_WaterSimBody = 100;
  static int ren_WaterSimBodyFoam = 100;
  static int ren_WaterSimImpact = 100;
  static int ren_WaterRec = 0;
  static int ren_WaterRecEvery = 6;
  static int ren_WaterSimCapillary = 100;
  static int ren_WaterSimImpactTest = 0;
  static int ren_WaterSimImpactSize = 6;
  static int ren_WaterSimImpactBurst = 1;
  static int ren_WaterSimHullTest = 0;
  static int ren_WaterSimDamping = 100;

  static TConVar<int> gTConVar_ren_WaterSim(
    "ren_WaterSim",
    "Water that moves when units move in it and things hit it (a GPU wave simulation bends the water normals): 1 (the "
    "default) on, 0 the shipped water. "
    "Takes effect at the next map load for the shader patch; docs/WATER_SIMULATION.md.",
    &ren_WaterSim
  );
  static TConVar<int> gTConVar_ren_WaterSimTest(
    "ren_WaterSimTest",
    "Test source of the water simulation: every N rendered frames a ring starts at the water the middle of the view "
    "looks at; 0 (the default) none.",
    &ren_WaterSimTest
  );
  static TConVar<int> gTConVar_ren_WaterSimLog(
    "ren_WaterSimLog",
    "Diagnostic: every N rendered frames the highest and lowest wave height of the simulation is read back and logged "
    "(stalls the GPU); 0 (the default) off.",
    &ren_WaterSimLog
  );
  static TConVar<int> gTConVar_ren_WaterSimBody(
    "ren_WaterSimBody",
    "How strongly bodies push the water, in percent of the physical displacement (default 100, 0 = the old hand-made "
    "wakes of ships).",
    &ren_WaterSimBody
  );
  static TConVar<int> gTConVar_ren_WaterSimBodyFoam(
    "ren_WaterSimBodyFoam",
    "How much foam bodies throw up where they enter and leave the water, in percent (default 100).",
    &ren_WaterSimBodyFoam
  );
  static TConVar<int> gTConVar_ren_WaterSimFoam(
    "ren_WaterSimFoam",
    "How much foam ships throw up, in percent (default 100).",
    &ren_WaterSimFoam
  );
  static TConVar<int> gTConVar_ren_WaterSimWake(
    "ren_WaterSimWake",
    "How strongly ships push the water, in percent of the base wake (default 200).",
    &ren_WaterSimWake
  );
  static TConVar<int> gTConVar_ren_WaterRec(
    "ren_WaterRec",
    "Recorder: write the next N captures of the wave simulation (height, foam, land, hulls, sources around the action) "
    "to the folder of FAF_WATERREC_DIR "
    "(default logs/waterrec); tools/waterrec.py reads them. 0 (the default) off.",
    &ren_WaterRec
  );
  static TConVar<int> gTConVar_ren_WaterSimImpactTest(
    "ren_WaterSimImpactTest",
    "Test impact: every N rendered frames an impact (ren_WaterSimImpactSize: the cube root of the energy, a shell of "
    "100 damage is 4.6, a nuke 20) lands at the "
    "water the middle of the view looks at; ren_WaterSimImpactBurst of them one after the other, 12 frames apart (a "
    "salvo). 0 (the default) none. "
    "Look at it with ren_WaterSSRDebug 7 (height), 8 (foam) and ren_WaterSimLog.",
    &ren_WaterSimImpactTest
  );
  static TConVar<int> gTConVar_ren_WaterSimImpactSize(
    "ren_WaterSimImpactSize",
    "Size of the test impacts of ren_WaterSimImpactTest (default 6).",
    &ren_WaterSimImpactSize
  );
  static TConVar<int> gTConVar_ren_WaterSimImpactBurst(
    "ren_WaterSimImpactBurst",
    "Impacts per trigger of ren_WaterSimImpactTest (default 1).",
    &ren_WaterSimImpactBurst
  );
  static TConVar<int> gTConVar_ren_WaterSimHullTest(
    "ren_WaterSimHullTest",
    "Test hull: 1 and up sends a hull of the size of a destroyer in a circle of 11 units around the water the middle "
    "of the view looks at, at that many "
    "units a second (the wake is the one of a real ship: bow wave, V, wash, foam). 0 (the default) none.",
    &ren_WaterSimHullTest
  );
  static TConVar<int> gTConVar_ren_WaterSimCapillary(
    "ren_WaterSimCapillary",
    "Dispersion of the wave simulation in percent of the tuned value (default 100, 0 off): short waves run faster than "
    "long ones, so a splash spreads into a "
    "rough train instead of one clean ring.",
    &ren_WaterSimCapillary
  );
  static TConVar<int> gTConVar_ren_WaterSimDamping(
    "ren_WaterSimDamping",
    "How fast waves die, in percent of the tuned damping (default 100; 0 none, 200 twice).",
    &ren_WaterSimDamping
  );
  static TConVar<int> gTConVar_ren_WaterRecEvery(
    "ren_WaterRecEvery",
    "Recorder: one capture every N rendered frames (default 6).",
    &ren_WaterRecEvery
  );
  static TConVar<int> gTConVar_ren_WaterSimImpact(
    "ren_WaterSimImpact",
    "How strongly impacts and explosions push the water, in percent of the tuned splash (default 100).",
    &ren_WaterSimImpact
  );
  static TConVar<int> gTConVar_ren_WaterSwell(
    "ren_WaterSwell",
    "The wind sea: height of the constant swell that lifts the water and breaks on the beaches, in percent (default "
    "100, 0 off).",
    &ren_WaterSwell
  );
  static TConVar<int> gTConVar_ren_WaterSeed(
    "ren_WaterSeed",
    "Seed of the ambient sea (the headings, lengths and heights of its waves and where its patches are): 0 (the "
    "default) takes one from the map, so every map has its own sea.",
    &ren_WaterSeed
  );
  static TConVar<int> gTConVar_ren_WaterMaskDebug(
    "ren_WaterMaskDebug",
    "Diagnostic of the water mask (needs ren_WaterGrid): 1 paints the water pixels that the shipped land cut-out mask "
    "discards in magenta, 2 paints every "
    "water pixel that is drawn in green (a gap in the green is where no water pixel is made); 0 (the default) off.",
    &ren_WaterMaskDebug
  );
  static TConVar<int> gTConVar_ren_WaterShoreWave(
    "ren_WaterShoreWave",
    "Waves that roll in over the shallows and break on the beach, as height in percent (default 100, 0 off). Needs "
    "ren_WaterSim.",
    &ren_WaterShoreWave
  );
  static TConVar<int> gTConVar_ren_WaterSolid(
    "ren_WaterSolid",
    "How much of the colour of the water covers the sea bed, at least, in percent: more is a more solid sea, less "
    "see-through (default 25).",
    &ren_WaterSolid
  );
  static TConVar<int> gTConVar_ren_WaterGrid(
    "ren_WaterGrid",
    "Draw the water as a projected grid whose vertices the wave simulation lifts (needs ren_WaterSim): 1 (the default) "
    "on, 0 the flat quad of the shipped game.",
    &ren_WaterGrid
  );
  static TConVar<int> gTConVar_ren_WaterDomains(
    "ren_WaterDomains",
    "On a map with water bodies, simulate each water (the sea, every lake at its own level) in its own domain and draw "
    "each with its own projected grid: 1 (the default) on, 0 the earlier behaviour (one level of simulation, the "
    "water bodies drawn as flat meshes). Takes effect at once.",
    &ren_WaterDomains
  );
  static TConVar<int> gTConVar_ren_WaterDisplace(
    "ren_WaterDisplace",
    "How far the wave simulation lifts the water geometry, in percent of the simulated height (default 100).",
    &ren_WaterDisplace
  );
  static TConVar<int> gTConVar_ren_WaterSimStrength(
    "ren_WaterSimStrength",
    "How strongly the waves bend the water surface, in percent (default 100).",
    &ren_WaterSimStrength
  );

  namespace
  {
    using namespace gpg::gal;

    constexpr std::uint32_t kN = 1024; // cells per side
    constexpr float kCell = 0.5f;      // world units per cell
    constexpr std::uint32_t kTile = 8;
    constexpr std::uint32_t kMaxSources = 4096;
    constexpr float kStepSeconds = 1.0f / 90.0f;
    constexpr int kMaxSteps = 6;
    constexpr std::uint32_t kFormat = 9U; // RGBA16F render target (DxgiFormats.cpp)
    constexpr int kMaxGridLevels = 6;     // projected grids a frame draws for the waters of a map with water bodies

    struct Source
    {
      float x, z, radius, strength; // the push (see SimAddSource)
      float foam, kind, domain, c;  // foam thrown per frame, the shape (0 disc, 1 crater with a rim), the water it was
                                    // made in plus one (0 any: a map without water bodies), unused
    };

    struct HullRecord
    {
      float x, z, hx, hz, speed, halfLength, halfBeam, radius;
    };

    struct SimConstants
    {
      float a[4]; // origin x, z (cells, a multiple of 8), previous origin x, z
      float b[4]; // cell size, cells, source count, step seconds
      float c[4]; // wave speed term, damping per step, centre x, z (world)
      float d[4]; // half extent (world), shore wave height factor, sea seed
      float e[4]; // map height samples x, z, water level in raw height units, 1 when the land mask is on
      float f[4]; // time (s), swell scale, foam kept per step, shore surf
      float g[4]; // blocks x, z of the domain table, 1 when the domains are on, unused
    };

    constexpr char kSource[] = R"HLSL(
cbuffer SimConstants : register(b0)
{
    float4 sA;
    float4 sB;
    float4 sC;
    float4 sD;
    float4 sE;
    float4 sF;   // time (s), swell scale, foam kept per step, shore surf
    float4 sG;   // blocks x, z of the domain table, 1 when the domains are on (a map with water bodies), unused
};

StructuredBuffer<float4> Cur : register(t0);     // height, last height, foam, 1 on land
StructuredBuffer<float4> Src : register(t1);     // two float4 per source: x, z, radius, push; foam, 0, 0, 0
StructuredBuffer<uint> Heights : register(t2);   // the raw uint16 heights of the map, two to a word (the land mask)
StructuredBuffer<float> Shore : register(t3);    // per height sample: the distance to the nearest land sample, world units (the shore waves); then the fetch of the wind; with domains on, then per 2 x 2 block the level (raw units) and the domain of its water
RWStructuredBuffer<float4> Nxt : register(u0);

groupshared uint sList[256];

// the share of the velocity that is spread to the neighbours every step (viscosity: it takes the shortest waves, the ringing of a splash)
static const float kViscosity = 0.10;
groupshared uint sCount;

static const float4 kSwellWave[8] = { float4(0.955, 0.296, 1.047, 0.0477), float4(0.814, 0.581, 1.396, 0.0358), float4(0.989, -0.149, 1.745, 0.0286), float4(0.582, 0.813, 2.094, 0.0239), float4(0.999, 0.050, 2.618, 0.0191), float4(0.697, 0.717, 3.142, 0.0159), float4(0.900, -0.435, 3.927, 0.0127), float4(0.362, 0.932, 4.833, 0.0103) };
static const float kSwellSpeed[8] = { 1.36, 1.68, 1.92, 2.09, 2.49, 2.83, 3.34, 3.87 };   // rad / s: phase speeds of about one unit a second

// the wind sea: eight short travelling waves (direction x, z, wave number, height) with sharp crests (1.273 - 2 |sin(theta / 2)| has a cusp at
// the crest, flat troughs and no mean). It bends the normals and drives the surf; it does not lift the mesh (a coarse grid shows it as facets).
float FafSwellHeight(float2 p, float t)
{
    float h = 0.0;
    [unroll] for (int i = 0; i < 8; ++i)
    {
        float4 w = kSwellWave[i];
        h += w.w * (1.273 - 2.0 * abs(sin(0.5 * (dot(w.xy, p) * w.z - kSwellSpeed[i] * t + (float)i * 1.7))));
    }
    return h;
}

float2 FafSwellSlope(float2 p, float t)
{
    float2 s = float2(0.0, 0.0);
    [unroll] for (int i = 0; i < 8; ++i)
    {
        float4 w = kSwellWave[i];
        float th = 0.5 * (dot(w.xy, p) * w.z - kSwellSpeed[i] * t + (float)i * 1.7);
        s += w.xy * (-w.w * w.z * cos(th) * (sin(th) >= 0.0 ? 1.0 : -1.0));
    }
    return s;
}

// the ground (raw height units) between the four surrounding height samples (they sit on the whole world units; a cell is half a sample)
float GroundRaw(float2 p)
{
    int2 hmax = int2(sE.xy) - 1;
    int2 g0 = (int2)floor(p);
    float2 gf = p - (float2)g0;
    int2 s00 = clamp(g0, int2(0, 0), hmax);
    int2 s11 = clamp(g0 + 1, int2(0, 0), hmax);
    uint i00 = (uint)s00.y * (uint)sE.x + (uint)s00.x;
    uint i10 = (uint)s00.y * (uint)sE.x + (uint)s11.x;
    uint i01 = (uint)s11.y * (uint)sE.x + (uint)s00.x;
    uint i11 = (uint)s11.y * (uint)sE.x + (uint)s11.x;
    float r00 = (float)((Heights[i00 >> 1] >> ((i00 & 1) * 16)) & 0xFFFF);
    float r10 = (float)((Heights[i10 >> 1] >> ((i10 & 1) * 16)) & 0xFFFF);
    float r01 = (float)((Heights[i01 >> 1] >> ((i01 & 1) * 16)) & 0xFFFF);
    float r11 = (float)((Heights[i11 >> 1] >> ((i11 & 1) * 16)) & 0xFFFF);
    return lerp(lerp(r00, r10, gf.x), lerp(r01, r11, gf.x), gf.y);
}

// the distance to the nearest land (world units) between the four surrounding height samples; the field is smooth, the shore waves follow its
// contours (the bilinear depth of the ground is not: its slope has a kink at every sample and crests that follow it zigzag)
float ShoreDist(float2 p)
{
    int2 hmax = int2(sE.xy) - 1;
    int2 g0 = (int2)floor(p);
    float2 gf = p - (float2)g0;
    int2 s00 = clamp(g0, int2(0, 0), hmax);
    int2 s11 = clamp(g0 + 1, int2(0, 0), hmax);
    uint w = (uint)sE.x;
    float d00 = Shore[(uint)s00.y * w + (uint)s00.x];
    float d10 = Shore[(uint)s00.y * w + (uint)s11.x];
    float d01 = Shore[(uint)s11.y * w + (uint)s00.x];
    float d11 = Shore[(uint)s11.y * w + (uint)s11.x];
    return lerp(lerp(d00, d10, gf.x), lerp(d01, d11, gf.x), gf.y);
}

// the fetch of the wind here: how far the water runs upwind before it meets land (the second half of the shore buffer, ShoreField.h); short in a lake, in
// the lee of an island and in a channel, long in the open sea
float ShoreOpen(float2 p)
{
    int2 hmax = int2(sE.xy) - 1;
    int2 g0 = (int2)floor(p);
    float2 gf = p - (float2)g0;
    int2 s00 = clamp(g0, int2(0, 0), hmax);
    int2 s11 = clamp(g0 + 1, int2(0, 0), hmax);
    uint w = (uint)sE.x;
    uint off = w * (uint)sE.y;
    float d00 = Shore[off + (uint)s00.y * w + (uint)s00.x];
    float d10 = Shore[off + (uint)s00.y * w + (uint)s11.x];
    float d01 = Shore[off + (uint)s11.y * w + (uint)s00.x];
    float d11 = Shore[off + (uint)s11.y * w + (uint)s11.x];
    return lerp(lerp(d00, d10, gf.x), lerp(d01, d11, gf.x), gf.y);
}

uint Hash(uint v)
{
    uint state = v * 747796405u + 2891336453u;
    uint word = ((state >> ((state >> 28u) + 4u)) ^ state) * 277803737u;
    return (word >> 22u) ^ word;
}

// FAF_DOMAINS is defined (to 1, in front of this text) only for a map with water bodies. Without it every line below compiles to what the simulation was
// before water bodies: the same instructions, so a map without them is simulated bit for bit as it was.
// A wall of this cell's water: land, or the water of another domain (a lake of another level, whatever lies next to it). The w channel of a water cell
// is its tag: 0 for the sea, minus the number of the body for a lake, 1 for land.
#if FAF_DOMAINS
bool Wall(float4 v, float domW)
{
    return v.w > 0.5 || v.w != domW;
}

float WallF(float4 v, float domW)
{
    return Wall(v, domW) ? 1.0 : 0.0;
}
#else
bool Wall(float4 v, float domW)
{
    return v.w > 0.5;
}

float WallF(float4 v, float domW)
{
    return v.w;
}
#endif

// the height of a cell of the window (wrapped), `fallback` when it is a wall: walls reflect
float HeightAt(int2 c, int n, float fallback, float domW)
{
    float4 v = Cur[(((c.y % n) + n) % n) * n + (((c.x % n) + n) % n)];
    return Wall(v, domW) ? fallback : v.x;
}

[numthreads(8, 8, 1)]
void SimCS(uint3 gid : SV_GroupID, uint3 tid : SV_GroupThreadID, uint index : SV_GroupIndex)
{
    int n = (int)sB.y;
    int2 cell = int2(gid.xy * 8 + tid.xy);
    int2 o = int2(sA.xy);
    int2 op = int2(sA.zw);
    int2 w = o + ((cell - o) % n + n) % n;       // the world cell this texel holds in the window of this frame
    int2 wp = op + ((cell - op) % n + n) % n;    // ... and in the window of the last
    float2 wpos = ((float2)w + 0.5) * sB.x;

    // The domains (a map with water bodies): the water of this cell is the sea, a lake at its own level or a dry polder, from a table of 2 x 2 unit blocks
    // (the texels of the water map, so the cell simulates in the water that is drawn there) behind the shore fields. levelRaw is the level the land test
    // takes, domW the tag this cell's water carries in the w channel (see Wall). Without domains: the one level of the map and the tag 0.
    float levelRaw = sE.z;
    float domW = 0.0;
#if FAF_DOMAINS
    {
        int2 blk = clamp((int2)floor(wpos * 0.5), int2(0, 0), int2(sG.xy) - 1);
        uint blockAt = (uint)blk.y * (uint)sG.x + (uint)blk.x;
        uint tableAt = 2u * (uint)sE.x * (uint)sE.y;
        levelRaw = Shore[tableAt + blockAt];
        float domain = Shore[tableAt + (uint)sG.x * (uint)sG.y + blockAt];
        domW = domain > 0.5 ? -domain : 0.0;
    }
#endif

    int2 tc = int2(gid.xy * 8);
    int2 tw = o + ((tc - o) % n + n) % n;
    float2 tileMin = (float2)tw * sB.x;
    float2 tileMax = tileMin + 8.0 * sB.x;

    float add = 0.0;
    float foamAdd = 0.0;
    uint total = (uint)sB.z;
    for (uint basis = 0; basis < total; basis += 256)
    {
        if (index == 0)
        {
            sCount = 0;
        }
        GroupMemoryBarrierWithGroupSync();
        uint last = min(basis + 256, total);
        for (uint i = basis + index; i < last; i += 64)
        {
            float4 s = Src[i * 2];
            if (s.x + s.z >= tileMin.x && s.x - s.z <= tileMax.x && s.y + s.z >= tileMin.y && s.y - s.z <= tileMax.y)
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
            float4 s = Src[sList[k] * 2];
            float4 s1 = Src[sList[k] * 2 + 1];
            float2 d = wpos - s.xy;
            float f = 1.0 - dot(d, d) / (s.z * s.z);
            // a source acts in the water it was made in only (a shell in the sea does not push the lake next to it): its domain, plus one, is in s1.z (0 for any)
#if FAF_DOMAINS
            if (f > 0.0 && (s1.z < 0.5 || abs(s1.z - 1.0 + domW) < 0.5))
#else
            if (f > 0.0)
#endif
            {
                // kind 0: a disc (the bell f^2); kind 1: a crater with a rim, the bell times (4 f - 3): no volume, so no mound is left to ring
                float shape = s1.y > 0.5 ? f * f * (4.0 * f - 3.0) : f * f;
                add += s.w * sB.w * shape;
                foamAdd += s1.x * (s1.y > 0.5 ? saturate(abs(shape) * 1.6) : f);
            }
        }
        GroupMemoryBarrierWithGroupSync();
    }

    uint idx = (uint)(cell.y * n + cell.x);
    float groundDepth = 1000.0;
    if (sE.w > 0.5)
    {
        // land is a wall: a cell whose ground is above the water holds no wave, so nothing that happens ashore moves the sea and a wave dies at the beach
        // the ground between the four surrounding height samples (a cell is half a sample): the coastline is a smooth line, not a staircase of
        // whole samples
        float raw = GroundRaw(wpos);
        if (raw > levelRaw)
        {
            Nxt[idx] = float4(0.0, 0.0, 0.0, 1.0);
            return;
        }
        groundDepth = (levelRaw - raw) / 128.0;   // how deep the water is here (to the margin above the beach)
    }
    float4 cur = Cur[idx];
    if (w.x != wp.x || w.y != wp.y)
    {
        cur = float4(0.0, 0.0, 0.0, 0.0);   // a cell the window has just moved onto holds what the other side of the window left: start it calm
    }
    float4 L = Cur[cell.y * n + (cell.x + n - 1) % n];
    float4 R = Cur[cell.y * n + (cell.x + 1) % n];
    float4 U = Cur[((cell.y + n - 1) % n) * n + cell.x];
    float4 D = Cur[((cell.y + 1) % n) * n + cell.x];
    // walls reflect: a neighbour that is land or another water counts as the height of this cell
    float hl = Wall(L, domW) ? cur.x : L.x;
    float hr = Wall(R, domW) ? cur.x : R.x;
    float hu = Wall(U, domW) ? cur.x : U.x;
    float hd = Wall(D, domW) ? cur.x : D.x;
    float lap = hl + hr + hu + hd - 4.0 * cur.x;
    // viscosity: the laplacian of the velocity (height minus last height) damps the short waves, the ringing of a splash, and leaves the long ones
    float vel = cur.x - cur.y;
    float vl = Wall(L, domW) ? vel : L.x - L.y;
    float vr = Wall(R, domW) ? vel : R.x - R.y;
    float vu = Wall(U, domW) ? vel : U.x - U.y;
    float vd = Wall(D, domW) ? vel : D.x - D.y;
    float lapv = vl + vr + vu + vd - 4.0 * vel;
    // dispersion: the fourth difference (5 x 5 stencil, land counts as the height of this cell) makes short waves run faster than long ones
    float lap2 = 0.0;
    if (sD.w > 0.0)
    {
        float hLU = HeightAt(cell + int2(-1, -1), n, cur.x, domW);
        float hRU = HeightAt(cell + int2(1, -1), n, cur.x, domW);
        float hLD = HeightAt(cell + int2(-1, 1), n, cur.x, domW);
        float hRD = HeightAt(cell + int2(1, 1), n, cur.x, domW);
        float hLL = HeightAt(cell + int2(-2, 0), n, cur.x, domW);
        float hRR = HeightAt(cell + int2(2, 0), n, cur.x, domW);
        float hUU = HeightAt(cell + int2(0, -2), n, cur.x, domW);
        float hDD = HeightAt(cell + int2(0, 2), n, cur.x, domW);
        lap2 = 20.0 * cur.x - 8.0 * (hl + hr + hu + hd) + 2.0 * (hLU + hRU + hLD + hRD) + (hLL + hRR + hUU + hDD);
    }
    float dmax = max(abs(wpos.x - sC.z), abs(wpos.y - sC.w)) / sD.x;
    float edge = smoothstep(0.8, 1.0, dmax);   // the waves are absorbed at the border of the window
    float hn = (2.0 * cur.x - cur.y + sC.x * lap - sD.w * lap2 + kViscosity * lapv) * sC.y * (1.0 - 0.3 * edge) + add;
    // The sea. A real sea is not one train parallel to the coast and not a few crossing ones: it is a spectrum of many waves of different lengths and
    // headings, short-crested, that come and go. Six independent plane waves (their headings around a wind direction, lengths from 10 to 42 units,
    // deep-water speeds, longer waves taller) are drawn from a seed (sD.z: the map's own unless ren_WaterSeed says otherwise), each one carried by
    // patches of noise that drift with it, so no crest is long and no two seas are alike. Over the last twenty units the sea hands over to the surf: a
    // train that follows the coast (the distance to the shore, a smoothed field of the map computed once, as sqrt of the distance: the crests close up
    // and slow down), wanders along it (a warp of the phase by noise), comes in segments, grows (Green's law) and breaks where it is higher than a
    // quarter of the water under it (the real depth), throwing foam off the crest. The target is a function of the ground and the time only.
    float shoreWaveCrest = 0.0;
    float shoreWaveBreak = 0.0;
    float shoreWaveBand = 0.0;
    float shoreWaveSkew = 0.0;
    float shoreWaveSegment = 0.0;
    float shoreWaveSurf = 0.0;
    float shoreWaveFront = 0.0;
    float shoreDist = 1.0e4;
    // a lake has no fetch for a sea: its waves (the wind sea, the surf and the foam of the beach) are small, and the open sea keeps them
    float calm = 1.0;
    if (sD.y > 0.0)
    {
        shoreDist = ShoreDist(wpos);
        calm = lerp(0.08, 1.0, smoothstep(25.0, 160.0, ShoreOpen(wpos))); // the fetch of the wind (ShoreField.h): a short one, a calm sea
    }
    if (sD.y > 0.0 && shoreDist < 110.0)
    {
        float dist = max(shoreDist, 0.5);
        shoreWaveBand = 1.0 - smoothstep(55.0, 110.0, dist);
        float depth = max(groundDepth, 0.05);
        float wSurf = 1.0 - smoothstep(8.0, 24.0, dist);
        float t = sF.x;
        float seed = sD.z;
        float target = 0.0;

        float windAngle = 6.2832 * FafNoiseCorner(float2(seed, 91.7));
        // the crests are not straight: the position the waves are read at is pushed about by slow noise (a fraction of a wave length)
        float2 wq = wpos + (float2(FafNoise2(wpos * 0.022 + float2(seed, 3.1) + float2(0.013, 0.0) * t), FafNoise2(wpos * 0.022 + float2(seed + 17.3, 8.9) + float2(0.0, 0.011) * t)) - 0.5) * 16.0;
        // three fields of patches, shared by the waves (where the sea is rough and where it is calm; they drift along the wind)
        float2 windDir = float2(cos(windAngle), sin(windAngle));
        float p0 = smoothstep(0.30, 0.75, FafNoise2((wpos - windDir * 1.2 * t) * 0.035 + float2(7.3, 2.9 + seed)));
        float p1 = smoothstep(0.30, 0.75, FafNoise2((wpos - windDir * 0.9 * t) * 0.055 + float2(14.6, 5.8 + seed)));
        float p2 = smoothstep(0.30, 0.75, FafNoise2((wpos - windDir * 1.6 * t) * 0.085 + float2(21.9, 8.7 + seed)));
        [unroll] for (int i = 0; i < 10; ++i)
        {
            float fi = (float)i;
            float heading = windAngle + (FafNoiseCorner(float2(seed + 13.1, fi * 5.3 + 1.0)) - 0.5) * 3.2;
            float u = FafNoiseCorner(float2(seed + 29.9, fi * 7.1 + 2.0));
            float lambda = 8.0 + 52.0 * u * u;                                        // many short waves, a few long ones
            float k = 6.2832 / lambda;
            float omega = sqrt(3.2 * k);                                             // deep-water dispersion, about 3.5 units a second at 24
            float2 dir = float2(cos(heading), sin(heading));
            float th = k * dot(dir, wq) - omega * t + 6.2832 * FafNoiseCorner(float2(seed + 41.3, fi * 3.9 + 3.0));
            float s = 0.5 + 0.5 * saturate((sin(th) + 0.28 * sin(2.0 * th + 1.0)) * 0.9);
            float patch = (i % 3 == 0) ? p0 : ((i % 3 == 1) ? p1 : p2);
            float amp = 0.052 * sD.y * calm * pow(lambda / 24.0, 0.8) * (0.55 + 0.9 * FafNoiseCorner(float2(seed + 53.7, fi * 2.3 + 4.0)));
            target += amp * (0.2 + 0.8 * patch) * (1.6 * pow(s, 2.2) - 0.55);
        }
        target *= 1.0 - 0.9 * wSurf;

        // the surf train: follows the coast, wanders along it, comes in segments
        float warp = (FafNoise2(wpos * 0.04 + float2(1.7, 9.2) + seed) - 0.5) * 6.0 + (FafNoise2(wpos * 0.11 + float2(4.1, 0.3) + float2(0.0, 0.05) * t) - 0.5) * 3.0;
        float theta = 1.1 * t + 3.2 * sqrt(dist) + warp;
        float skew = 0.5 + 0.5 * saturate((sin(theta) + 0.32 * sin(2.0 * theta + 1.2)) * 0.9);
        float segment = smoothstep(0.22, 0.70, FafNoise2(wpos * 0.075 + float2(13.1, 5.7) + float2(0.03, 0.02) * t));
        float group = 0.6 + 0.4 * sin(0.17 * theta + 1.0);
        float rawAmp = 0.22 * sD.y * calm * pow(30.0 / max(dist, 4.0), 0.25) * group * (0.25 + 0.75 * segment);
        float amp = min(rawAmp, 0.42 * depth + 0.02);
        shoreWaveBreak = saturate((rawAmp / depth - 0.12) * 3.0);
        shoreWaveCrest = pow(skew, 5.0) * segment;
        shoreWaveSkew = skew;
        shoreWaveSegment = segment;
        shoreWaveSurf = wSurf;
        shoreWaveFront = saturate(0.5 - 0.9 * sin(theta - 1.2)) * (0.3 + 0.7 * skew);
        target += wSurf * amp * (1.7 * pow(skew, 2.4) - 0.58);
        target = min(target, 0.42 * depth + 0.02);
        hn = lerp(hn, target, 0.25 * shoreWaveBand);
    }
    // a trough never goes deeper than half of the water: in the shallows the lifted grid would dip below the sea bed and show the sand in streaks
    // a height beyond 0.8 is compressed (a salvo on one spot cannot pile the water up into a wall), the hard limits stay
    {
        float ah = abs(hn);
        if (ah > 0.8)
        {
            hn = sign(hn) * (0.8 + 0.7 * tanh((ah - 0.8) / 0.7));
        }
    }
    hn = clamp(hn, -min(1.5, 0.5 * groundDepth), 1.5);

    // foam: spreads a little, fades, is thrown by the sources (noisy: a propeller wash is not a smooth band) and by the surf at the beach
    float fl = Wall(L, domW) ? cur.z : L.z;
    float fr = Wall(R, domW) ? cur.z : R.z;
    float fu = Wall(U, domW) ? cur.z : U.z;
    float fd = Wall(D, domW) ? cur.z : D.z;
    // (the surf of the shore waves fades faster: a trail of a second behind the crest, not a smear that looks as if it stood still)
    float foam = lerp(cur.z, 0.25 * (fl + fr + fu + fd), 0.05) * (sF.z - 0.008 * shoreWaveBand);
    // the grain of the foam a source throws: smooth noise of the place and the time (a hash per cell and step made a mosaic of cells in it)
    float noise = 0.3 + 1.4 * FafGradNoise(FafTurn(wpos) * 1.7 + float2(sF.x * 0.6, 3.7 * sF.x));
    foam += foamAdd * noise;
    float ring2 = max(max(WallF(Cur[cell.y * n + (cell.x + n - 2) % n], domW), WallF(Cur[cell.y * n + (cell.x + 2) % n], domW)),
                      max(WallF(Cur[((cell.y + n - 2) % n) * n + cell.x], domW), WallF(Cur[((cell.y + 2) % n) * n + cell.x], domW)));
    // the beach by depth, not by neighbours on land: a yes / no ring of one cell made the surf a hard band of square blocks. The depth fades the
    // surf out over the shallows (about 0.3 units of water); the neighbours still count for the cells right at the edge.
    float shore = max(max(max(max(WallF(L, domW), WallF(R, domW)), max(WallF(U, domW), WallF(D, domW))), 0.6 * ring2), 1.0 - smoothstep(0.0, 0.12, groundDepth));
    float crest = saturate(FafSwellHeight(wpos, sF.x) * sF.y * 6.0 + 0.1);
    foam += shore * calm * (saturate(abs(hn) * 5.0 - 0.1) * 0.012 + crest * crest * 0.006 * sF.w);
    // (waves make foam only where they are steep: a ship's V is waves, not foam; the foam of a ship is thrown by its own sources)
    foam += saturate((abs(hn) - 0.55) * 5.0) * 0.004;
    // the surface that is thrown about makes foam (a splash, a wake), the one that only heaves does not: by its speed
    foam += saturate((abs(hn - cur.x) - 0.04) * 10.0) * 0.02;
    // the breaking of the shore waves: foam off the crest, and the sheet that runs up the beach behind it
    // The surf: a foam sheet behind every breaking crest (it fades in about a second, so it trails the crest), and the swash on the beach: the foam
    // runs up and down the beach with the waves (the line of the foam is a depth that rises while a crest arrives), in segments along the coast.
    // a wave breaks at its front: the foam is thrown at the leading edge of the crest (the shoreward side, the phase just before the top) and left
    // behind it as the sheet and the streaks that fade in a second
    // (the constant part of both terms follows the fetch like the waves do: a small lake has no surf to throw foam, and the sheet that was left
    // on it every step stood at about a tenth over the whole of a lake that lies inside the surf band of its own shore)
    foam += shoreWaveSurf * shoreWaveCrest * (0.006 * calm + 0.05 * shoreWaveBreak) * (0.5 + 0.5 * noise);
    foam += shoreWaveSurf * shoreWaveFront * (0.004 * calm + 0.30 * shoreWaveBreak) * (0.5 + 0.5 * noise);
    float swashLine = 0.12 + 0.75 * shoreWaveSkew * (0.4 + 0.6 * shoreWaveSegment);
    foam += (1.0 - smoothstep(swashLine - 0.12, swashLine, groundDepth)) * 0.003 * min(sD.y, 1.0) * calm;
    foam = clamp(foam, 0.0, 1.5);
    Nxt[idx] = float4(hn, cur.x, foam, domW);
}

float4 SimVS(uint id : SV_VertexID) : SV_Position
{
    float2 uv = float2((id << 1) & 2, id & 2);
    return float4(uv * 2.0 - 1.0, 0.0, 1.0);
}

// The swell of the open sea: six long waves (wave lengths 58 to 7 units, deep-water speeds, headings around the wind), each carried by patches of noise so
// that no crest runs on for ever and no sea repeats. Height, and its slope in x and z. It is added to what the simulation holds when the result is made:
// the lifted water and the tilt of the surface show it, the simulation (and its foam) never sees it.
static const float kOceanLength[6] = { 58.0, 37.0, 24.0, 16.0, 10.5, 7.0 };
float3 FafOceanSwell(float2 p, float t, float seed)
{
    float windAngle = 6.2832 * FafNoiseCorner(float2(seed, 91.7));
    float3 r = float3(0.0, 0.0, 0.0);
    [unroll] for (int i = 0; i < 6; ++i)
    {
        float fi = (float)i;
        float lambda = kOceanLength[i];
        float heading = windAngle + (FafNoiseCorner(float2(seed + 5.1, fi * 3.7 + 1.0)) - 0.5) * 1.5;
        float2 dir = float2(cos(heading), sin(heading));
        float k = 6.2832 / lambda;
        float omega = sqrt(3.2 * k);
        float th = k * dot(dir, p) - omega * t + 6.2832 * FafNoiseCorner(float2(seed + 9.9, fi * 5.3 + 2.0));
        float patch = 0.45 + 1.0 * FafNoise2(p * 0.02 + float2(fi * 7.3 + t * 0.01, 3.1 + seed));
        float a = 0.020 * lambda * patch;
        float s = sin(th);
        float arg = th + 0.35 * s;
        r.x += a * sin(arg);
        float d = a * cos(arg) * (1.0 + 0.35 * cos(th)) * k;
        r.y += d * dir.x;
        r.z += d * dir.y;
    }
    return r;
}

// slope (x, z), height and foam of the surface, for the water pixel shader
float4 SimCopyPS(float4 position : SV_Position) : SV_Target
{
    int n = (int)sB.y;
    int2 c = int2(position.xy);
    float4 here = Cur[c.y * n + c.x];
    float hl = Cur[c.y * n + (c.x + n - 1) % n].x;
    float hr = Cur[c.y * n + (c.x + 1) % n].x;
    float hu = Cur[((c.y + n - 1) % n) * n + c.x].x;
    float hd = Cur[((c.y + 1) % n) * n + c.x].x;
    float2 slope = float2((hr - hl) * 0.5 / sB.x, (hd - hu) * 0.5 / sB.x);
    float height = here.x;
    if (here.w < 0.5 && sF.y > 0.0)
    {
        int2 o = int2(sA.xy);
        int2 w = o + ((c - o) % n + n) % n;
        float2 wpos = ((float2)w + 0.5) * sB.x;
        float k = sF.y;
        if (sD.y > 0.0)
        {
            // a lake has no fetch for a sea, and the swell hands over to the surf of the simulation at the beach
            k *= lerp(0.08, 1.0, smoothstep(25.0, 160.0, ShoreOpen(wpos))) * smoothstep(12.0, 70.0, ShoreDist(wpos));
        }
        float3 swell = FafOceanSwell(wpos, sF.x, sD.z);
        height += swell.x * k;
        slope += swell.yz * k * 0.35; // (the lifted water shows the height; the tilt of a long swell must not wash the reflection out into big patches)
    }
    return float4(slope, height, here.z);
}
)HLSL";

    // The shader of the simulation: the shared noise of WaterShaderCommon.h, then the source above (the headless lab
    // builds the same text). The variant for a map with water bodies has FAF_DOMAINS defined in front of it; the other
    // is the shader as it was before water bodies, instruction for instruction.
    std::string BuildSimSource(
      const bool domains
    )
    {
      std::string text =
        std::string(domains ? "#define FAF_DOMAINS 1\n" : "") + kWaterNoiseHlsl + kWaterGradientNoiseHlsl + kSource;
      // the viscosity is a number of WaterSimParams.h (shared with the lab): the shader text carries a placeholder
      const std::string key = "static const float kViscosity = 0.10;";
      const std::size_t at = text.find(key);
      if (at != std::string::npos) {
        char number[96];
        std::snprintf(number, sizeof(number), "static const float kViscosity = %.5f;", kViscosity);
        text.replace(at, key.size(), number);
      }
      return text;
    }

    const std::string& SimSource(
      const bool domains = false
    )
    {
      static const std::string plain = BuildSimSource(false);
      static const std::string withDomains = BuildSimSource(true);
      return domains ? withDomains : plain;
    }

    // ---- the water effect: variables, bound by name
    // ------------------------------------------------------------------------------
    struct EffectVars
    {
      ShaderVar texture{};
      ShaderVar params{};
      ShaderVar params2{};
      ShaderVar gridInverse{};
      ShaderVar gridParams{};
      ShaderVar gridParams2{};
      ShaderVar owner{}; // the owner texture of WaterBodySurfaces: which water owns each block
      ShaderVar
        levelParams{}; // x: 1 = the grid draws one water and clips the pixels that are not its own, y: its number
      ShaderVar gridWindow{}; // the part of the screen the grid covers: u0, v0, du, dv
      EffectVars()
      {
        RegisterShaderVar("waterGridInv", &gridInverse, "water2");
        RegisterShaderVar("waterGridParams", &gridParams, "water2");
        RegisterShaderVar("waterGridParams2", &gridParams2, "water2");
        RegisterShaderVar("waterOwner", &owner, "water2");
        RegisterShaderVar("waterLevelParams", &levelParams, "water2");
        RegisterShaderVar("waterGridWindow", &gridWindow, "water2");
        RegisterShaderVar("waterSim", &texture, "water2");
        RegisterShaderVar("waterSimParams", &params, "water2");
        RegisterShaderVar("waterSimParams2", &params2, "water2");
      }
    };

    struct State
    {
      EffectVars vars;
      Device* device = nullptr;
      std::shared_ptr<GpuBuffer> state[2];
      std::shared_ptr<GpuBuffer> sources;
      std::shared_ptr<GpuBuffer> heights;
      std::shared_ptr<GpuBuffer>
        shore; // per height sample: the distance in world units to the nearest land sample (the shore waves run in it)
      std::uint32_t shoreWidth = 0U;
      std::uint32_t shoreHeight = 0U;
      float shoreLevel = 0.0f;
      float shoreWind = -1.0f;            // the heading of the wind the fetch field was made for
      std::uint32_t shoreGeneration = 0U; // the water bodies the shore buffer was made for (0 none)
      const STIMap* shoreMap = nullptr;
      std::uint32_t domainBlocksX = 0U; // the domain table behind the shore fields (0 when the buffer has none)
      std::uint32_t domainBlocksZ = 0U;
      std::uint64_t heightRevision = ~0ull;
      std::uint32_t heightAge = 1000U; // frames since the land mask went up
      std::uint32_t heightWidth = 0U;
      std::uint32_t heightHeight = 0U;
      const CHeightField* field = nullptr;
      std::shared_ptr<GpuProgram> step;
      std::shared_ptr<GpuProgram> stepDomains; // the same step for a map with water bodies, made when one is played
      bool domainProgramFailed = false;
      std::shared_ptr<GpuProgram> copy;
      std::shared_ptr<RenderTarget> texture;
      std::vector<Source> pending;
      std::vector<SSimWaterEvent> events; // what the sim told since the last frame that worked it in (SimWaterEvents.h)
      bool frameServed = false;           // a world view has had this frame's feed and step
      ImpactQueue timed;                  // the parts of impacts that are still being handed over (see SimImpact)
      std::uint32_t statImpacts =
        0U; // diagnostics of the periodic log line: impacts, sources of impacts and sources in all since the last line
      std::uint32_t statSources = 0U;
      ImpactGate gate;
      std::uint32_t impactSeed = 2463534242u;
      bool failed = false;
      bool loggedRefusal = false;
      bool hasHistory = false;
      int originX = 0;
      int originZ = 0;
      float centreX = 0.0f;
      float centreZ = 0.0f;
      std::uint32_t current = 0U;
      float accumulator = 0.0f;
      std::chrono::steady_clock::time_point last{};
      bool haveLast = false;
      float waterElevation =
        0.0f; // the level the simulation is built for: the sea's, or the first wet water body's when the map has no sea
      bool waterEnabled = false; // the sea or at least one water body has water
      bool hasBodies = false;    // the map has water bodies (lakes at their own levels, WaterBodies.h)
      bool domainsOn = false;    // the simulation runs per water: the shore buffer carries the domain table
      int gridPasses = 0;        // the grids drawn for levels in this frame (kMaxGridLevels)
      const STIMap* map =
        nullptr; // the map the renderer draws (REN_GetTerrainRes), also in the editor, where there is no session
      float time = 0.0f;
      int lastTick = -1;                                    // the game tick of the last frame that saw one come
      std::chrono::steady_clock::time_point lastTickWall{}; // when
      bool haveTick = false;
      float gameSpeed = 1.0f;           // game ticks over real time, in units of ten a second (smoothed)
      float sourceWeight = 1.0f;        // game time of the last frame over one step of the simulation
      std::vector<HullRecord> recHulls; // the hulls the feeds saw this frame (recorder)
      std::vector<Source> recSources;   // the sources of this frame (recorder)
      int recFrame = 0;
      int recIndex = 0;
      int lastSteps = 0;
      float lastDt = 0.0f;
    };

    State& GetState()
    {
      static State* const state =
        new State(); // the effect unlinks its shader vars on its own schedule: never destroyed
      return *state;
    }

    // Whether the local player sees this place now: a circle of the vision of the session's focus army (allies
    // included) holds it. An observer (no focus army) sees all. What happens in the fog must not move the sea the
    // player looks at: the waves would tell.
    bool PlayerSees(
      const float x,
      const float z
    )
    {
      CWldSession* const session = WLD_GetActiveSession();
      if (session == nullptr || session->FocusArmy < 0) {
        return true;
      }
      static const Wm3::Vector2f kAxes[2] = {Wm3::Vector2f{1.0f, 0.0f}, Wm3::Vector2f{0.0f, 1.0f}};
      Wm3::Box2f box;
      box.Center.x = x;
      box.Center.y = z;
      box.Axis[0] = kAxes[0];
      box.Axis[1] = kAxes[1];
      box.Extent[0] = 0.5f;
      box.Extent[1] = 0.5f;
      gpg::fastvector_n<Wm3::Circle2f, VisionDB::kVisibleCircleInlineCapacity> circles;
      session->mVisionDb.CollectVisibleCircles(circles, box, std::min(std::max(REN_GetSimDeltaSeconds(), 0.0f), 1.0f));
      for (std::size_t i = 0; i < circles.size(); ++i) {
        const float dx = x - circles[i].Center.x;
        const float dz = z - circles[i].Center.y;
        if (dx * dx + dz * dz <= circles[i].Radius * circles[i].Radius) {
          return true;
        }
      }
      return false;
    }

    // The map the renderer draws: the session's map in a game, the edited map in the editor (there is no session
    // there).
    const STIMap* RenderMap()
    {
      IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
      return terrainRes != nullptr ? terrainRes->mMap : nullptr;
    }

    // The level the simulation is built for and whether there is any water to simulate: the sea; with water bodies and
    // no sea, the first wet body. (A map with bodies has one sea level and one level per body: the simulation window
    // follows the sea. The per-level domains are a later stage, see docs/WATER_SIMULATION.md "Water bodies".)
    bool ActiveMapWater(
      const STIMap* const map,
      float& elevation
    )
    {
      if (map == nullptr) {
        return false;
      }
      if (map->IsWaterEnabled()) {
        elevation = map->GetWaterElevation();
        return true;
      }
      if (map->HasWaterBodies()) {
        const CWaterBodies& bodies = *map->mWaterBodies;
        for (std::size_t number = 1; number <= bodies.BodyCount(); ++number) {
          const float level = bodies.Body(static_cast<std::uint8_t>(number)).elevation;
          if (level != kWaterBodyNoWater) {
            elevation = level;
            return true;
          }
        }
      }
      return false;
    }

    void BindOff(
      State& s
    )
    {
      const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
      if (s.vars.params2.Exists()) {
        s.vars.params2.mEffectVariable->SetVector(off);
      }
      if (s.vars.gridParams.Exists()) {
        s.vars.gridParams.mEffectVariable->SetVector(off);
      }
      if (s.vars.levelParams.Exists()) {
        s.vars.levelParams.mEffectVariable->SetVector(off);
      }
    }

    bool EnsureResources(
      State& s,
      Device& device
    )
    {
      if (s.device != &device) {
        s.state[0].reset();
        s.state[1].reset();
        s.sources.reset();
        s.heights.reset();
        s.shore.reset();
        s.shoreWidth = 0U;
        s.domainBlocksX = 0U;
        s.heightRevision = ~0ull;
        s.step.reset();
        s.stepDomains.reset();
        s.domainProgramFailed = false;
        s.copy.reset();
        s.texture.reset();
        s.failed = false;
        s.hasHistory = false;
        s.device = &device;
      }
      if (s.failed) {
        return false;
      }
      if (s.step == nullptr || s.copy == nullptr) {
        GpuProgramDesc desc;
        desc.name = "WaterSimStep";
        desc.source = SimSource().c_str();
        desc.sourceBytes = SimSource().size();
        desc.computeEntry = "SimCS";
        s.step = device.CreateGpuProgram(desc);
        GpuProgramDesc draw;
        draw.name = "WaterSimCopy";
        draw.source = SimSource().c_str();
        draw.sourceBytes = SimSource().size();
        draw.vertexEntry = "SimVS";
        draw.pixelEntry = "SimCopyPS";
        draw.blend = GpuBlend::Opaque;
        draw.sampler = GpuSampler::PointClamp;
        s.copy = device.CreateGpuProgram(draw);
        if (s.step == nullptr || s.copy == nullptr) {
          gpg::Warnf("Water simulation disabled: its GPU programs did not compile");
          s.failed = true;
          return false;
        }
      }
      if (s.state[0] == nullptr) {
        GpuBufferDesc buffer;
        buffer.name = "WaterSimState";
        buffer.stride = 16U;
        buffer.capacity = kN * kN;
        buffer.shaderWrite = true;
        s.state[0] = device.CreateGpuBuffer(buffer);
        s.state[1] = device.CreateGpuBuffer(buffer);
        GpuBufferDesc sources;
        sources.name = "WaterSimSources";
        sources.stride = 16U;
        sources.capacity = kMaxSources * 2U; // two float4 a source
        s.sources = device.CreateGpuBuffer(sources);
        if (s.state[0] == nullptr || s.state[1] == nullptr || s.sources == nullptr) {
          gpg::Warnf("Water simulation disabled: its GPU buffers could not be created");
          s.failed = true;
          return false;
        }
        const std::vector<float> zeros(static_cast<std::size_t>(kN) * kN * 4U, 0.0f);
        device.UpdateGpuBuffer(*s.state[0], 0U, kN * kN, zeros.data());
        device.UpdateGpuBuffer(*s.state[1], 0U, kN * kN, zeros.data());
        s.hasHistory = false;
      }
      if (s.texture == nullptr) {
        const RenderTargetContext context(kN, kN, kFormat);
        s.texture = device.CreateRenderTarget(&context);
        if (s.texture == nullptr) {
          gpg::Warnf("Water simulation disabled: no %ux%u RGBA16F render target", kN, kN);
          s.failed = true;
          return false;
        }
        gpg::Logf("Water simulation: %ux%u cells of %.1f units, RGBA16F result", kN, kN, kCell);
      }
      return true;
    }

    // The step of a map with water bodies (SimSource(true)), compiled the first time one is played. False when it does
    // not compile: the map is then simulated at its one level, as before water bodies.
    bool EnsureDomainProgram(
      State& s,
      Device& device
    )
    {
      if (s.stepDomains != nullptr) {
        return true;
      }
      if (s.domainProgramFailed) {
        return false;
      }
      GpuProgramDesc desc;
      desc.name = "WaterSimStepDomains";
      desc.source = SimSource(true).c_str();
      desc.sourceBytes = SimSource(true).size();
      desc.computeEntry = "SimCS";
      s.stepDomains = device.CreateGpuProgram(desc);
      if (s.stepDomains == nullptr) {
        s.domainProgramFailed = true;
        gpg::Warnf(
          "Water simulation: the step for water bodies did not compile; the waters are simulated at one level"
        );
        return false;
      }
      return true;
    }
  } // namespace

  // the seed: the player's, else one from the map (its size and sea level), as a number the shader can hash
  float WaterSeedValue(
    const std::uint32_t width,
    const std::uint32_t height,
    const float elevation
  )
  {
    std::uint32_t h = ren_WaterSeed != 0
      ? static_cast<std::uint32_t>(ren_WaterSeed)
      : (width * 2654435761u) ^ (height * 40503u) ^ static_cast<std::uint32_t>(elevation * 128.0f);
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    h *= 0x846ca68bu;
    h ^= h >> 16;
    return 1.0f + static_cast<float>(h % 997u);
  }

  // FafNoiseCorner of WaterShaderCommon.h on the CPU (the same float hash), for the heading of the wind the shader
  // draws from the seed
  static float WaterHashCorner(
    const float ix,
    const float iy
  )
  {
    const auto frac = [](const float v) {
      return v - std::floor(v);
    };
    float p3x = frac(ix * 0.1031f);
    float p3y = frac(iy * 0.1031f);
    float p3z = frac(ix * 0.1031f);
    const float d = p3x * (p3y + 33.33f) + p3y * (p3z + 33.33f) + p3z * (p3x + 33.33f);
    p3x += d;
    p3y += d;
    p3z += d;
    return frac((p3x + p3y) * p3z);
  }

  void SimAddSource(
    const float x,
    const float z,
    const float radius,
    const float strength,
    const float foam,
    const bool shown,
    const float kind
  )
  {
    State& s = GetState();
    if (
      ren_WaterSim == 0 || !(radius > 0.05f) || !std::isfinite(x) || !std::isfinite(z) || !std::isfinite(strength) ||
      s.pending.size() >= kMaxSources
    ) {
      return;
    }
    if (!shown && !PlayerSees(x, z)) {
      if (ren_WaterSimLog > 0) {
        gpg::Logf("WaterSim source in the fog at (%.1f %.1f): dropped", x, z);
      }
      return; // fog: no waves for what the player cannot see
    }
    // only over water: a flash, a glow or a unit ashore (at the height of the sea on a low beach) must not move the
    // sea. The water is the level of the place (a lake has its own, a dry body none): the CPU mirror of the land test
    // of the shader (WaterSourceGate.h)
    if (s.field != nullptr && s.waterEnabled) {
      const bool over = SourceOverWater(x, z, [](const float px, const float pz, float& level) {
        return SimLevelAt(px, pz, level);
      }, [&s](const float px, const float pz) {
        const float cx = std::min(std::max(px, 0.0f), static_cast<float>(s.field->Width() - 1));
        const float cz = std::min(std::max(pz, 0.0f), static_cast<float>(s.field->Height() - 1));
        return s.field->GetElevation(cx, cz);
      });
      if (!over) {
        return;
      }
    }
    ++s.statSources;
    // the water it is made in (the number of the body, plus one): it pushes that water only (SimCS, sameWater)
    float domain = 0.0f;
    if (s.domainsOn && s.map != nullptr) {
      const std::int32_t bx = std::max(static_cast<std::int32_t>(std::floor(x)), 0) & ~1;
      const std::int32_t bz = std::max(static_cast<std::int32_t>(std::floor(z)), 0) & ~1;
      domain = static_cast<float>(WaterOfBlock(*s.map, bx, bz).body) + 1.0f;
    }
    s.pending.push_back(Source{x, z, std::min(radius, 40.0f), strength, foam, kind, domain, 0.0f});
  }

  bool SimIsOwnSide(
    const int armyIndex
  )
  {
    CWldSession* const session = WLD_GetActiveSession();
    if (armyIndex < 0 || session == nullptr || session->FocusArmy < 0) {
      return false;
    }
    const std::size_t index = static_cast<std::size_t>(armyIndex);
    if (index >= session->userArmies.size() || session->userArmies[index] == nullptr) {
      return false;
    }
    return !session->userArmies[index]->IsEnemy(static_cast<std::uint32_t>(session->FocusArmy));
  }

  void BeginWaterFrame()
  {
    GetState().frameServed = false;
  }

  bool ClaimWaterFrame(
    const GeomCamera3& camera
  )
  {
    State& s = GetState();
    // the minimap and the other small views call the render too; only a world view takes the frame
    if (s.frameServed || !(camera.viewport.r[3].z * camera.viewport.r[3].w >= 200000.0f)) {
      return false;
    }
    s.frameServed = true;
    return true;
  }

  void SimImpact(
    const float x,
    const float z,
    const float size,
    const float scale,
    const bool shown
  )
  {
    State& state = GetState();
    const float s = std::max(size, 0.5f);
    if (ren_WaterSimLog > 0) {
      gpg::Logf("WaterSim impact: at (%.1f %.1f), size %.2f, scale %.2f", x, z, s, scale);
    }
    if (ren_WaterSim == 0) {
      return;
    }
    const auto random = [&state]() {
      state.impactSeed = state.impactSeed * 1664525u + 1013904223u;
      return static_cast<float>(state.impactSeed >> 8) * (1.0f / 16777216.0f);
    };
    // an impact on the waves of the last one is weaker and falls a little to the side (a salvo must not build a
    // standing wave)
    ++state.statImpacts;
    const ImpactGate::Result gate = state.gate.Admit(x, z, ImpactRadius(s), state.time, random);
    std::vector<ImpactPart> parts;
    BuildImpact(s, scale, SimImpactScale() * gate.factor, random, parts);
    for (const ImpactPart& part : parts) {
      QueuedPart queued;
      queued.x = x + gate.jitterX + part.dx;
      queued.z = z + gate.jitterZ + part.dz;
      queued.radius = part.radius;
      queued.push = part.push;
      queued.foam = part.foam * gate.factor * 1.4f;
      queued.kind = part.kind;
      queued.delay = part.delay;
      queued.duration = std::max(part.duration, 0.01f);
      queued.remaining = queued.duration;
      queued.shown = shown;
      state.timed.Add(queued);
    }
  }

  void SimUnitDeath(
    const float x,
    const float y,
    const float z,
    const float mass,
    const bool shown
  )
  {
    float elevation = 0.0f;
    if (ren_WaterSimLog > 0) {
      gpg::Logf("WaterSim death: at (%.1f %.1f %.1f), cost %.0f", x, y, z, mass);
    }
    if (!SimLevelAt(x, z, elevation) || y - elevation > 3.0f || !(mass > 0.0f)) {
      return;
    }
    // a hull below the surface (a submarine) is felt less
    // The size follows the square root of the cost, on the scale of a shell's (the cube root of its damage): a hull of
    // cost 300 sinks like a shell of 15 damage, 2,250 like one of 300, a battleship of 10,000 like one of 2,700.
    const float size = 0.14f * std::sqrt(std::max(mass, 20.0f));
    SimImpact(x, z, size, y < elevation - 3.0f ? 0.5f : 1.0f, shown);
  }

  namespace
  {
    // What the simulation told the water since the last frame (SimWaterEvents.h: the sim thread only queues, this is
    // the render thread working the events into the water's own state): a landing, a hull going down.
    void WorkInSimEvents(
      State& s
    )
    {
      for (const SSimWaterEvent& event : s.events) {
        if (event.kind == SSimWaterEvent::Kind::Impact) {
          // the size is the cube root of the damage (a shell of 100: 4.6, a nuke: 20); taken here, not in the sim
          SimImpact(event.x, event.z, std::cbrt(event.value), event.scale, SimIsOwnSide(event.army));
        } else {
          SimUnitDeath(event.x, event.y, event.z, event.value, SimIsOwnSide(event.army));
        }
      }
      s.events.clear();
    }
  } // namespace

  bool SimDiagnostics()
  {
    return ren_WaterSimLog > 0;
  }

  float SimSourceWeight()
  {
    return GetState().sourceWeight;
  }

  float SimTime()
  {
    return GetState().time;
  }

  bool SimRecording()
  {
    return ren_WaterRec > 0;
  }

  void SimRecordHull(
    const float x,
    const float z,
    const float hx,
    const float hz,
    const float speed,
    const float halfLength,
    const float halfBeam,
    const float radius
  )
  {
    if (ren_WaterRec > 0) {
      GetState().recHulls.push_back(HullRecord{x, z, hx, hz, speed, halfLength, halfBeam, radius});
    }
  }

  float SimBodyScale()
  {
    return 0.01f * static_cast<float>(std::max(ren_WaterSimBody, 0));
  }

  float SimBodyFoamScale()
  {
    return 0.01f * static_cast<float>(std::max(ren_WaterSimBodyFoam, 0));
  }

  float SimFoamScale()
  {
    return 0.01f * static_cast<float>(std::max(ren_WaterSimFoam, 0));
  }

  float SimWakeScale()
  {
    return 0.01f * static_cast<float>(std::max(ren_WaterSimWake, 0));
  }

  float SimImpactScale()
  {
    return 0.01f * static_cast<float>(std::max(ren_WaterSimImpact, 0));
  }

  bool SimWaterLevel(
    float& elevation
  )
  {
    State& s = GetState();
    if (ren_WaterSim == 0) {
      return false;
    }
    elevation = s.waterElevation;
    return s.waterEnabled;
  }

  bool SimLevelAt(
    const float x,
    const float z,
    float& level
  )
  {
    State& s = GetState();
    if (ren_WaterSim == 0 || !s.waterEnabled) {
      return false;
    }
    static_assert(kNoWaterLevel == kWaterBodyNoWater, "the gate's no-water level is the map's");
    // no water bodies: the one level, as SimWaterLevel; with them the level the map has at the place (false for a dry
    // body, or no sea outside the bodies)
    return LevelAtPlace(s.map != nullptr && s.hasBodies, s.waterElevation, [&s](const float px, const float pz) {
      return s.map->GetWaterElevationAt(px, pz);
    }, x, z, level);
  }

  namespace
  {
    constexpr std::size_t kMaxSimEvents = 4096U; // what the sim queues between two frames (SimWaterEvents.cpp) at most
  } // namespace

  bool SimWanted()
  {
    return ren_WaterSim != 0;
  }

  void StepWaterSimulation(
    const GeomCamera3& camera
  )
  {
    State& s = GetState();
    float elevation = 0.0f;
    const STIMap* const map = RenderMap();
    s.map = map;
    s.hasBodies = map != nullptr && map->HasWaterBodies();
    s.waterEnabled = ren_WaterSim != 0 && ActiveMapWater(map, elevation);
    s.waterElevation = elevation;
    s.field = map != nullptr ? map->GetHeightField() : nullptr;
    // The sim's events (SimWaterEvents.h) come in while this runs, and only then: off with the simulation or where it
    // is not available (nothing queues), taken here once a frame and worked in below, by a world view.
    EnableSimWaterEvents(ren_WaterSim != 0 && !s.loggedRefusal);
    DrainSimWaterEvents(s.events);
    if (s.events.size() > kMaxSimEvents) {
      s.events.erase(s.events.begin(), s.events.end() - static_cast<std::ptrdiff_t>(kMaxSimEvents));
    }
    if (!s.waterEnabled) {
      s.pending.clear();
      s.events.clear();
      s.timed.Clear();
      s.domainsOn = false;
      BindOff(s);
      return;
    }
    Device* const device = Device::GetInstance();
    if (device == nullptr) {
      return;
    }
    const auto refuse = [&](const char* const reason) {
      if (!s.loggedRefusal) {
        s.loggedRefusal = true;
        gpg::Warnf("Water simulation is not available: %s", reason);
      }
      s.pending.clear();
      s.events.clear();
      s.timed.Clear();
      BindOff(s);
    };
    const std::uint32_t features = device->GetGpuDrivenFeatures();
    if ((features & kGpuFeatureVertexPulling) == 0U || (features & kGpuFeatureCompute) == 0U) {
      refuse("this render API has no GPU programs with compute");
      return;
    }
    if (!EnsureResources(s, *device)) {
      s.pending.clear();
      BindOff(s);
      return;
    }

    // the world view only: the minimap and the other small views call the render too, and each would pull the window to
    // its own camera
    {
      const float viewWidth = camera.viewport.r[3].z;
      const float viewHeight = camera.viewport.r[3].w;
      if (!(viewWidth * viewHeight >= 200000.0f)) {
        return; // keeps the binding of the last frame
      }
    }
    WorkInSimEvents(s);

    // the land mask: the map's raw heights go to the GPU once (and again when they change), two samples to a word
    bool landMask = false;
    if (s.field != nullptr && s.field->Width() >= 2 && s.field->Height() >= 2) {
      const std::uint32_t hw = static_cast<std::uint32_t>(s.field->Width());
      const std::uint32_t hh = static_cast<std::uint32_t>(s.field->Height());
      const std::uint64_t revision = HeightFieldRevision();
      // A new revision comes with every building that flattens ground: the land mask is refreshed at most every 90
      // frames.
      if (s.heightAge < 1000000U) {
        ++s.heightAge;
      }
      if (
        s.heights == nullptr || (s.heightRevision != revision && s.heightAge >= 90U) || s.heightWidth != hw ||
        s.heightHeight != hh
      ) {
        s.heightAge = 0U;
        const std::size_t samples = static_cast<std::size_t>(hw) * hh;
        const std::uint32_t words = static_cast<std::uint32_t>((samples + 1U) / 2U);
        if (s.heights == nullptr || s.heights->Desc().capacity != words) {
          GpuBufferDesc desc;
          desc.name = "WaterSimHeights";
          desc.stride = 4U;
          desc.capacity = words;
          s.heights = device->CreateGpuBuffer(desc);
        }
        if (s.heights != nullptr) {
          std::vector<std::uint32_t> packed(words, 0U);
          for (std::uint32_t z = 0; z < hh; ++z) {
            for (std::uint32_t x = 0; x < hw; ++x) {
              const std::size_t index = static_cast<std::size_t>(z) * hw + x;
              packed[index >> 1U] |= static_cast<std::uint32_t>(
                                       s.field->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z))
                                     )
                << ((index & 1U) * 16U);
            }
          }
          device->UpdateGpuBuffer(*s.heights, 0U, words, packed.data());
          s.heightRevision = revision;
          s.heightWidth = hw;
          s.heightHeight = hh;
          gpg::Logf("Water simulation: land mask of %ux%u height samples uploaded", hw, hh);
        }
      }
      landMask = s.heights != nullptr && s.heightWidth == hw && s.heightHeight == hh;
      // The distance to the shore, once per map: the buildings that flatten ground a little do not move the coast.
      const float shoreLevel = (elevation - kLandMargin) * 128.0f;
      // the heading the shader draws its waves along, from the seed (the same hash): the fetch of the wind is measured
      // against it
      const float windAngle = 6.2832f * WaterHashCorner(WaterSeedValue(hw, hh, elevation), 91.7f);
      // a map with water bodies: the fields are made per water, and the buffer ends with the table of the waters
      // (WaterDomains.h); the generation of the bodies says when they changed
      const bool wantDomains = s.hasBodies && ren_WaterDomains != 0 && map != nullptr && hw >= 3U && hh >= 3U;
      const std::uint32_t generation = wantDomains ? WaterBodiesGeneration(*map) : 0U;
      if (
        landMask &&
        (s.shore == nullptr || s.shoreWidth != hw || s.shoreHeight != hh || s.shoreLevel != shoreLevel ||
         s.shoreWind != windAngle || s.shoreGeneration != generation || s.shoreMap != (wantDomains ? map : nullptr))
      ) {
        const auto rawAt = [&](const std::uint32_t x, const std::uint32_t z) {
          return s.field->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z));
        };
        std::vector<float> dist;
        std::uint32_t blocksX = 0U;
        std::uint32_t blocksZ = 0U;
        if (wantDomains) {
          const DomainTable table = BuildDomainTable(
            (hw - 1U) >> 1U,
            (hh - 1U) >> 1U,
            kWaterBodyNoWater,
            kLandMargin,
            [map](const std::uint32_t bx, const std::uint32_t bz, float& level, std::uint8_t& body) {
            const SWaterOfBlock water =
              WaterOfBlock(*map, static_cast<std::int32_t>(bx * 2U), static_cast<std::int32_t>(bz * 2U));
            level = water.level;
            body = water.body;
          }
          );
          // a river's level is not one number (its surface slopes): its domain is compared with the level of each
          // sample's own block, the table's (docs/projects/RIVERS.md); a flat water is computed as ever
          std::vector<std::uint8_t> sloped;
          if (map->mWaterBodies->HasRivers()) {
            sloped.assign(256U, 0U);
            for (std::size_t body = 1; body <= map->mWaterBodies->BodyCount() && body < sloped.size(); ++body) {
              sloped[body] = map->mWaterBodies->IsRiver(static_cast<std::uint8_t>(body)) ? 1U : 0U;
            }
          }
          dist = ComputeShoreDistanceDomainsSloped(rawAt, [&table](const std::uint32_t x, const std::uint32_t z) {
            return static_cast<std::uint32_t>(table.domain[BlockOfSample(table, x, z)]);
          }, DomainLevels(table), sloped, [&table](const std::uint32_t x, const std::uint32_t z) {
            return table.levelRaw[BlockOfSample(table, x, z)];
          }, hw, hh, windAngle);
          dist.insert(dist.end(), table.levelRaw.begin(), table.levelRaw.end());
          dist.insert(dist.end(), table.domain.begin(), table.domain.end());
          blocksX = table.blocksX;
          blocksZ = table.blocksZ;
        } else {
          dist = ComputeShoreDistance(rawAt, hw, hh, shoreLevel, windAngle);
        }
        const std::uint32_t samples = static_cast<std::uint32_t>(dist.size());
        if (s.shore == nullptr || s.shore->Desc().capacity != samples) {
          GpuBufferDesc desc;
          desc.name = "WaterSimShore";
          desc.stride = 4U;
          desc.capacity = samples;
          s.shore = device->CreateGpuBuffer(desc);
        }
        if (s.shore != nullptr) {
          device->UpdateGpuBuffer(*s.shore, 0U, samples, dist.data());
          s.shoreWidth = hw;
          s.shoreHeight = hh;
          s.shoreLevel = shoreLevel;
          s.shoreWind = windAngle;
          s.shoreGeneration = generation;
          s.shoreMap = wantDomains ? map : nullptr;
          s.domainBlocksX = blocksX;
          s.domainBlocksZ = blocksZ;
          gpg::Logf(
            "Water simulation: distance to the shore of %ux%u height samples uploaded%s",
            hw,
            hh,
            wantDomains ? ", per water (domains)" : ""
          );
        }
      }
    }

    // real time between frames, for the fixed steps
    const auto now = std::chrono::steady_clock::now();
    float dt = 1.0f / 60.0f;
    if (s.haveLast) {
      dt = std::chrono::duration<float>(now - s.last).count();
    }
    s.last = now;
    s.haveLast = true;
    dt = std::min(std::max(dt, 0.0f), 0.1f);
    // The water keeps the time of the game, not the wall: it stops when the game is paused (no tick for a third of a
    // second) and runs as fast as the game does (the speed from the ticks that came over the real time since the last).
    {
      const int tick = REN_GetGameTick();
      if (!s.haveTick || tick != s.lastTick) {
        if (s.haveTick && tick > s.lastTick) {
          const float wall = std::chrono::duration<float>(now - s.lastTickWall).count();
          if (wall > 0.0005f) {
            const float rate = std::min(static_cast<float>(tick - s.lastTick) / wall * 0.1f, 8.0f);
            s.gameSpeed += (rate - s.gameSpeed) * 0.3f;
          }
        }
        s.lastTick = tick;
        s.lastTickWall = now;
        s.haveTick = true;
      }
      const bool paused = std::chrono::duration<float>(now - s.lastTickWall).count() > 0.35f;
      dt = paused ? 0.0f : dt * std::min(std::max(s.gameSpeed, 0.1f), 6.0f);
      dt = std::min(dt, 0.1f);
    }
    s.time += dt;
    // What a moving hull pushes in is meant per step of the simulation (90 a second), but the feeds run once per frame:
    // at 200 frames a second the sources of two frames land in one step and a wake grows to a slab of foam and thick
    // ridges, at 30 it is thin, and while the game is paused the pending list filled up and burst on the next frame.
    // The feeds weigh their continuous sources with the game time of the last frame.
    s.sourceWeight = std::min(dt / kStepSeconds, 4.0f);
    // the parts of impacts that are handed over in pieces: a crater opens over a tenth of a second, and the column
    // falls back into it later
    s.timed.Advance(
      dt,
      [](
        const float x,
        const float z,
        const float radius,
        const float push,
        const float foam,
        const float kind,
        const bool shown
      ) {
      SimAddSource(x, z, radius, push, foam, shown, kind);
    }
    );

    // the window follows the point of the water the middle of the view looks at
    const float w = camera.viewport.r[3].z;
    const float h = camera.viewport.r[3].w;
    const GeomLine3 ray = camera.Unproject(Wm3::Vector2f(w * 0.5f, h * 0.5f));
    float centreX = s.centreX;
    float centreZ = s.centreZ;
    if (s.hasBodies && ren_WaterDomains != 0 && s.field != nullptr) {
      // several levels: follow the ray down to the first surface of any water (WaterDomains.h)
      float cx = centreX;
      float cz = centreZ;
      if (
        WaterWindowCentre(
          ray.pos.x,
          ray.pos.y,
          ray.pos.z,
          ray.dir.x,
          ray.dir.y,
          ray.dir.z,
          6000.0f,
          8.0f,
          [&s](const float x, const float z) {
        const float gx = std::min(std::max(x, 0.0f), static_cast<float>(s.field->Width() - 1));
        const float gz = std::min(std::max(z, 0.0f), static_cast<float>(s.field->Height() - 1));
        return s.field->GetElevation(gx, gz);
      },
          [](const float x, const float z, float& level) {
        return SimLevelAt(x, z, level);
      },
          cx,
          cz
        )
      ) {
        centreX = cx;
        centreZ = cz;
      }
    } else if (ray.dir.y < -0.01f) {
      const float t = (elevation - ray.pos.y) / ray.dir.y;
      if (t > 0.0f && t < 6000.0f) {
        centreX = ray.pos.x + ray.dir.x * t;
        centreZ = ray.pos.z + ray.dir.z * t;
      }
    }
    const float tileWorld = static_cast<float>(kTile) * kCell;
    const int originX =
      static_cast<int>(std::floor(centreX / tileWorld)) * static_cast<int>(kTile) - static_cast<int>(kN / 2U);
    const int originZ =
      static_cast<int>(std::floor(centreZ / tileWorld)) * static_cast<int>(kTile) - static_cast<int>(kN / 2U);
    if (!s.hasHistory) {
      s.originX = originX;
      s.originZ = originZ;
    }

    // test impacts and a test hull (diagnostics: they use the same code as the real ones)
    {
      static int sImpactCounter = 0;
      static int sBurstLeft = 0;
      static int sBurstGap = 0;
      if (ren_WaterSimImpactTest > 0) {
        if ((++sImpactCounter % ren_WaterSimImpactTest) == 0) {
          sBurstLeft = std::max(ren_WaterSimImpactBurst, 1);
          sBurstGap = 0;
        }
        if (sBurstLeft > 0 && sBurstGap-- <= 0) {
          SimImpact(centreX, centreZ, static_cast<float>(std::max(ren_WaterSimImpactSize, 1)), 1.0f, true);
          --sBurstLeft;
          sBurstGap = 12;
        }
      }
      static HullWake sTestHull;
      static float sHullPhase = 0.0f;
      if (ren_WaterSimHullTest > 0) {
        const float speed = static_cast<float>(ren_WaterSimHullTest);
        sHullPhase += dt * speed;
        const float circle =
          11.0f; // a circle of this radius around the middle of the view (a lake is not a straight line)
        const float angle = sHullPhase / circle;
        HullState hull;
        hull.x = centreX + circle * std::cos(angle);
        hull.z = centreZ + circle * std::sin(angle);
        hull.hx = -std::sin(angle);
        hull.hz = std::cos(angle);
        hull.speed = speed;
        hull.halfLength = 2.9f;
        hull.halfBeam = 0.6f;
        hull.radius = 3.4f;
        hull.foamScale = kHullFoam * SimFoamScale();
        SimRecordHull(hull.x, hull.z, hull.hx, hull.hz, speed, hull.halfLength, hull.halfBeam, hull.radius);
        sTestHull.Move(
          hull,
          s.time,
          s.sourceWeight,
          SimWakeScale(),
          [](const float x, const float z, const float radius, const float push, const float foam) {
          SimAddSource(x, z, radius, push, foam, true);
        }
        );
      }
    }
    static int sTestCounter = 0;
    if (ren_WaterSimTest > 0 && (++sTestCounter % ren_WaterSimTest) == 0) {
      SimAddSource(centreX, centreZ, 5.0f, 40.0f);
    }

    if (ren_WaterRec > 0) {
      s.recSources = s.pending;
    }
    s.accumulator += dt;
    int steps = std::min(kMaxSteps, static_cast<int>(s.accumulator / kStepSeconds));
    s.accumulator -= static_cast<float>(steps) * kStepSeconds;
    if (s.accumulator > kStepSeconds * 2.0f) {
      s.accumulator = 0.0f; // never run behind
    }

    static int sLogCounter = 0;
    static std::size_t sPeakSources = 0;
    sPeakSources = std::max(sPeakSources, s.pending.size());
    if ((++sLogCounter % 240) == 1) {
      // (a map with water bodies: how many waters had a grid of their own in the last frame, and whether per water)
      char gridNote[96] = "";
      if (s.hasBodies) {
        std::snprintf(gridNote, sizeof(gridNote), ", %d water grids%s", s.gridPasses, s.domainsOn ? ", per water" : "");
      }
      gpg::Logf(
        "Water simulation: %d steps, up to %u sources a frame, window centre (%.0f, %.0f), water %.1f%s; since the "
        "last "
        "line: %u impacts, %u sources, %u impact parts queued",
        steps,
        static_cast<unsigned>(sPeakSources),
        centreX,
        centreZ,
        elevation,
        gridNote,
        s.statImpacts,
        s.statSources,
        static_cast<unsigned>(s.timed.Size())
      );
      s.statImpacts = 0U;
      s.statSources = 0U;
      sPeakSources = 0;
    }
    OutputContext saved;
    device->GetContext(&saved);
    D3DVIEWPORT9 savedViewport{};
    device->GetViewport(&savedViewport);
    {
      const RenderProfileScope profile("WaterSim");
      SimConstants constants{};
      constants.b[0] = kCell;
      constants.b[1] = static_cast<float>(kN);
      constants.b[3] = kStepSeconds;
      // The waves of a hull travel at about 2.5 units a second (the term is (speed x step / cell)^2); a wake is a few
      // dozen units long and fades in seven seconds.
      constants.c[0] = kWaveTerm;
      constants.c[1] = 1.0f - kDamping * 0.01f * static_cast<float>(std::max(ren_WaterSimDamping, 0));
      constants.d[3] = kCapillary * 0.01f * static_cast<float>(std::max(ren_WaterSimCapillary, 0));
      constants.f[0] = s.time;
      constants.f[1] = 0.01f * static_cast<float>(ren_WaterSwell);
      constants.f[2] = kFoamKept; // foam kept per step: gone in a couple of seconds
      constants.f[3] = 1.0f;      // surf at the beach
      constants.e[0] = static_cast<float>(s.heightWidth);
      constants.e[1] = static_cast<float>(s.heightHeight);
      constants.e[2] = (elevation - kLandMargin) * 128.0f; // raw height units (1 / 128 world unit)
      constants.e[3] = landMask ? 1.0f : 0.0f;
      constants.c[2] = centreX;
      constants.c[3] = centreZ;
      constants.d[0] = 0.5f * static_cast<float>(kN) * kCell;
      const bool shoreField =
        landMask && s.shore != nullptr && s.shoreWidth == s.heightWidth && s.shoreHeight == s.heightHeight;
      s.domainsOn =
        shoreField && s.hasBodies && s.domainBlocksX > 0U && s.shoreMap == s.map && EnsureDomainProgram(s, *device);
      constants.g[0] = static_cast<float>(s.domainBlocksX);
      constants.g[1] = static_cast<float>(s.domainBlocksZ);
      constants.g[2] = s.domainsOn ? 1.0f : 0.0f;
      constants.d[2] = WaterSeedValue(s.heightWidth, s.heightHeight, elevation);
      constants.d[1] = shoreField ? 0.01f * static_cast<float>(std::max(ren_WaterShoreWave, 0))
                                  : 0.0f; // the shore waves need the distance to the shore
      for (int step = 0; step < steps; ++step) {
        const std::uint32_t sourceCount = step == 0 ? static_cast<std::uint32_t>(s.pending.size()) : 0U;
        if (sourceCount > 0U) {
          device->UpdateGpuBuffer(*s.sources, 0U, sourceCount * 2U, s.pending.data());
        }
        constants.a[0] = static_cast<float>(originX);
        constants.a[1] = static_cast<float>(originZ);
        constants.a[2] = static_cast<float>(step == 0 ? s.originX : originX);
        constants.a[3] = static_cast<float>(step == 0 ? s.originZ : originZ);
        constants.b[2] = static_cast<float>(sourceCount);
        GpuDispatch dispatch;
        dispatch.program = (s.domainsOn ? s.stepDomains : s.step).get();
        dispatch.bindings.constants = &constants;
        dispatch.bindings.constantBytes = sizeof(constants);
        dispatch.bindings.readBuffers[0] = s.state[s.current].get();
        dispatch.bindings.readBuffers[1] = s.sources.get();
        dispatch.bindings.readBuffers[2] = landMask ? s.heights.get() : s.sources.get();
        dispatch.bindings.readBuffers[3] = shoreField ? s.shore.get() : s.sources.get();
        dispatch.bindings.writeBuffers[0] = s.state[s.current ^ 1U].get();
        dispatch.groupsX = kN / kTile;
        dispatch.groupsY = kN / kTile;
        dispatch.groupsZ = 1U;
        device->DispatchGpuProgram(dispatch);
        s.current ^= 1U;
        if (step == 0) {
          s.pending.clear();
        }
      }
      if (steps > 0) {
        s.originX = originX;
        s.originZ = originZ;
        s.hasHistory = true;
      }

      s.lastSteps = steps;
      s.lastDt = dt;
      if (ren_WaterRec > 0 && ++s.recFrame >= std::max(ren_WaterRecEvery, 1)) {
        s.recFrame = 0;
        // a window of 256 x 256 cells (128 units) around the first hull of the frame, else around where the view looks
        constexpr int kCrop = 256;
        float fx = centreX;
        float fz = centreZ;
        if (!s.recHulls.empty()) {
          fx = s.recHulls[0].x;
          fz = s.recHulls[0].z;
        }
        int cx0 = static_cast<int>(std::floor(fx / kCell)) - kCrop / 2;
        int cz0 = static_cast<int>(std::floor(fz / kCell)) - kCrop / 2;
        cx0 = std::min(std::max(cx0, originX), originX + static_cast<int>(kN) - kCrop);
        cz0 = std::min(std::max(cz0, originZ), originZ + static_cast<int>(kN) - kCrop);
        std::vector<float> all(static_cast<std::size_t>(kN) * kN * 4U);
        if (device->ReadGpuBuffer(*s.state[s.current], 0U, kN * kN, all.data())) {
          const char* const dirEnv = std::getenv("FAF_WATERREC_DIR");
          const std::string dir = dirEnv != nullptr ? dirEnv : "C:/ProgramData/FAForever/logs/waterrec";
          std::error_code ec;
          std::filesystem::create_directories(dir, ec);
          char name[512];
          std::snprintf(name, sizeof(name), "%s/rec_%05d.bin", dir.c_str(), s.recIndex++);
          if (FILE* const f = std::fopen(name, "wb")) {
            const std::uint32_t header[4] = {
              0x31435257u /* WRC1 */,
              static_cast<std::uint32_t>(kCrop),
              static_cast<std::uint32_t>(s.recHulls.size()),
              static_cast<std::uint32_t>(std::min<std::size_t>(s.recSources.size(), 8192))
            };
            const float info[12] = {
              kCell,
              static_cast<float>(cx0) * kCell,
              static_cast<float>(cz0) * kCell,
              s.time,
              static_cast<float>(REN_GetGameTick()),
              s.gameSpeed,
              s.sourceWeight,
              static_cast<float>(steps),
              dt,
              centreX,
              centreZ,
              elevation
            };
            std::fwrite(header, sizeof(header), 1, f);
            std::fwrite(info, sizeof(info), 1, f);
            for (const HullRecord& h : s.recHulls) {
              std::fwrite(&h, sizeof(h), 1, f);
            }
            for (std::size_t i = 0; i < header[3]; ++i) {
              std::fwrite(&s.recSources[i], sizeof(Source), 1, f);
            }
            std::vector<float> height(static_cast<std::size_t>(kCrop) * kCrop);
            std::vector<float> foam(height.size());
            std::vector<std::uint8_t> land(height.size());
            const int n = static_cast<int>(kN);
            for (int j = 0; j < kCrop; ++j) {
              for (int i = 0; i < kCrop; ++i) {
                const int bx = ((cx0 + i) % n + n) % n;
                const int bz = ((cz0 + j) % n + n) % n;
                const std::size_t src = (static_cast<std::size_t>(bz) * kN + static_cast<std::size_t>(bx)) * 4U;
                const std::size_t dst = static_cast<std::size_t>(j) * kCrop + static_cast<std::size_t>(i);
                height[dst] = all[src];
                foam[dst] = all[src + 2U];
                land[dst] = all[src + 3U] > 0.5f ? 1U : 0U;
              }
            }
            std::fwrite(height.data(), sizeof(float), height.size(), f);
            std::fwrite(foam.data(), sizeof(float), foam.size(), f);
            std::fwrite(land.data(), 1, land.size(), f);
            std::fclose(f);
          }
        }
        --ren_WaterRec;
      }
      s.recHulls.clear();

      static int sSimLogCounter = 0;
      if (ren_WaterSimLog > 0 && (++sSimLogCounter % ren_WaterSimLog) == 0) {
        std::vector<float> state(static_cast<std::size_t>(kN) * kN * 4U);
        if (device->ReadGpuBuffer(*s.state[s.current], 0U, kN * kN, state.data())) {
          float hi = 0.0f;
          float lo = 0.0f;
          float foamMax = 0.0f;
          std::size_t foamy = 0;
          double sum = 0.0;
          std::size_t moving = 0;
          for (std::size_t i = 0; i < static_cast<std::size_t>(kN) * kN; ++i) {
            const float v = state[i * 4U];
            foamMax = std::max(foamMax, state[i * 4U + 2U]);
            foamy += state[i * 4U + 2U] > 0.2f ? 1U : 0U;
            hi = std::max(hi, v);
            lo = std::min(lo, v);
            sum += std::fabs(v);
            moving += std::fabs(v) > 0.02f ? 1U : 0U;
          }
          gpg::Logf(
            "Water simulation: wave height %.3f .. %.3f, mean |h| %.5f, %u cells above 0.02, foam up to %.2f, %u cells "
            "above 0.2",
            lo,
            hi,
            sum / (static_cast<double>(kN) * kN),
            static_cast<unsigned>(moving),
            foamMax,
            static_cast<unsigned>(foamy)
          );
        }
      }

      // the result: slope and height of the current state
      const std::shared_ptr<DepthStencilTarget> noDepth;
      const OutputContext target(s.texture, noDepth);
      device->ClearTarget(&target);
      D3DVIEWPORT9 viewport{};
      viewport.Width = kN;
      viewport.Height = kN;
      viewport.MaxZ = 1.0f;
      device->SetViewport(&viewport);
      constants.b[2] = 0.0f;
      GpuDrawCall call;
      call.program = s.copy.get();
      call.bindings.constants = &constants;
      call.bindings.constantBytes = sizeof(constants);
      call.bindings.readBuffers[0] = s.state[s.current].get();
      call.bindings.readBuffers[3] = shoreField ? s.shore.get() : s.sources.get();
      constants.a[0] = static_cast<float>(s.originX);
      constants.a[1] = static_cast<float>(s.originZ);
      call.vertexCountPerInstance = 3U;
      call.instanceCount = 1U;
      device->DrawGpuProgram(call);
    }
    device->ClearTarget(&saved);
    device->SetViewport(&savedViewport);
    s.centreX = centreX;
    s.centreZ = centreZ;
    // (the sources of a frame that runs no step wait for the next one: a frame shorter than a step must not lose the
    // volume a body pushed in it)
    if (steps > 0) {
      s.pending.clear();
    }

    if (s.vars.params2.Exists()) {
      // the bend grows with the slope up to a cap (a gain of 20 reached the cap at a slope of 0.015: every wave of a
      // ship was bent as far as every other)
      const float strength = 0.05f * static_cast<float>(ren_WaterSimStrength);
      const float params[4] = {
        1.0f / (static_cast<float>(kN) * kCell), centreX, centreZ, 0.5f * static_cast<float>(kN) * kCell
      };
      const float params2[4] = {1.0f, strength, 0.12f, 0.01f * static_cast<float>(ren_WaterSolid)};
      if (s.vars.texture.Exists()) {
        s.vars.texture.mEffectVariable->SetRenderTarget(s.texture);
      }
      if (s.vars.owner.Exists()) {
        s.vars.owner.mEffectVariable->SetRenderTarget(s.texture); // (a map without water bodies never reads it)
      }
      if (s.vars.params.Exists()) {
        s.vars.params.mEffectVariable->SetVector(params);
      }
      s.vars.params2.mEffectVariable->SetVector(params2);
    }
  }

  bool BindWaterGrid(
    const GeomCamera3& camera,
    const float mapExtentX,
    const float mapExtentZ
  )
  {
    State& s = GetState();
    s.gridPasses = 0;
    // (a map with water bodies is drawn by WaterBodySurfaces, one water at a time: the grid of a level is
    // BindWaterGridLevel's, and this call only switches the grid off for the draws that are not one. The ripples bend
    // the normals of the meshes too.)
    const bool on = ren_WaterSim != 0 && ren_WaterGrid != 0 && s.waterEnabled && !s.hasBodies && s.texture != nullptr &&
      s.vars.gridParams.Exists() && s.vars.gridInverse.Exists() && mapExtentX > 1.0f && mapExtentZ > 1.0f;
    const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    const float full[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    if (s.vars.levelParams.Exists()) {
      s.vars.levelParams.mEffectVariable->SetVector(off);
    }
    if (s.vars.gridWindow.Exists()) {
      s.vars.gridWindow.mEffectVariable->SetVector(full);
    }
    if (!on) {
      if (s.vars.gridParams.Exists()) {
        s.vars.gridParams.mEffectVariable->SetVector(off);
      }
      if (s.vars.gridParams2.Exists()) { // the mask diagnostic works on the flat quad too
        const float debug[4] = {0.0f, 0.0f, static_cast<float>(ren_WaterMaskDebug), 0.0f};
        s.vars.gridParams2.mEffectVariable->SetVector(debug);
      }
      return false;
    }
    s.vars.gridInverse.SetMatrix4x4(&camera.inverseViewProjection);
    const float params[4] = {1.0f, 12000.0f, mapExtentX, mapExtentZ};
    s.vars.gridParams.mEffectVariable->SetVector(params);
    if (s.vars.gridParams2.Exists()) {
      const float params2[4] = {
        0.01f * static_cast<float>(ren_WaterDisplace),
        0.01f * static_cast<float>(ren_WaterSwell),
        static_cast<float>(ren_WaterMaskDebug),
        0.0f
      };
      s.vars.gridParams2.mEffectVariable->SetVector(params2);
    }
    return true;
  }

  namespace
  {
    // The part of the screen (the uv the grid vertex shader takes: 0 .. 1 over the screen with a margin of 25 % in x
    // and 15 % in y, FafWaterGridPosition) that holds the rectangle of a water at its level, with a margin for the lift
    // of the waves. False when it is off the screen. A corner behind the camera takes the whole screen.
    bool GridWindowOf(
      const GeomCamera3& camera,
      const GridLevel& level,
      float (&window)[4]
    )
    {
      const gpg::gal::Matrix& m = camera.viewProjection;
      float minX = 1.0e30f;
      float minY = 1.0e30f;
      float maxX = -1.0e30f;
      float maxY = -1.0e30f;
      bool behind = false;
      for (int i = 0; i < 8 && !behind; ++i) {
        const float x = (i & 1) != 0 ? level.x1 : level.x0;
        const float z = (i & 2) != 0 ? level.z1 : level.z0;
        const float y = level.elevation + ((i & 4) != 0 ? 2.0f : -2.0f);
        const float cx = x * m.r[0].x + y * m.r[1].x + z * m.r[2].x + m.r[3].x;
        const float cy = x * m.r[0].y + y * m.r[1].y + z * m.r[2].y + m.r[3].y;
        const float cw = x * m.r[0].w + y * m.r[1].w + z * m.r[2].w + m.r[3].w;
        if (!(cw > 0.01f)) {
          behind = true;
          break;
        }
        minX = std::min(minX, cx / cw);
        maxX = std::max(maxX, cx / cw);
        minY = std::min(minY, cy / cw);
        maxY = std::max(maxY, cy / cw);
      }
      if (behind) {
        window[0] = 0.0f;
        window[1] = 0.0f;
        window[2] = 1.0f;
        window[3] = 1.0f;
        return true;
      }
      if (maxX < -1.25f || minX > 1.25f || maxY < -1.15f || minY > 1.15f) {
        return false;
      }
      constexpr float kPad = 0.05f;
      const float u0 = std::clamp(((minX - kPad) / 1.25f + 1.0f) * 0.5f, 0.0f, 1.0f);
      const float u1 = std::clamp(((maxX + kPad) / 1.25f + 1.0f) * 0.5f, 0.0f, 1.0f);
      const float v0 = std::clamp((1.0f - (maxY + kPad) / 1.15f) * 0.5f, 0.0f, 1.0f);
      const float v1 = std::clamp((1.0f - (minY - kPad) / 1.15f) * 0.5f, 0.0f, 1.0f);
      if (!(u1 > u0) || !(v1 > v0)) {
        return false;
      }
      window[0] = u0;
      window[1] = v0;
      window[2] = u1 - u0;
      window[3] = v1 - v0;
      return true;
    }
  } // namespace

  bool BindWaterGridLevel(
    const GeomCamera3& camera,
    const GridLevel& level,
    const std::shared_ptr<ID3DTextureSheet>& owner
  )
  {
    State& s = GetState();
    const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    const float full[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    float window[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    const bool ready = ren_WaterSim != 0 && ren_WaterGrid != 0 && ren_WaterDomains != 0 && s.waterEnabled &&
      s.hasBodies && s.texture != nullptr && owner != nullptr && level.sheetReady && level.extentX > 1.0f &&
      level.extentZ > 1.0f && s.gridPasses < kMaxGridLevels && s.vars.gridParams.Exists() &&
      s.vars.gridInverse.Exists() && s.vars.owner.Exists() && s.vars.levelParams.Exists() && s.vars.gridWindow.Exists();
    if (!ready || !GridWindowOf(camera, level, window)) {
      if (s.vars.gridParams.Exists()) {
        s.vars.gridParams.mEffectVariable->SetVector(off);
      }
      if (s.vars.levelParams.Exists()) {
        s.vars.levelParams.mEffectVariable->SetVector(off);
      }
      if (s.vars.gridWindow.Exists()) {
        s.vars.gridWindow.mEffectVariable->SetVector(full);
      }
      return false;
    }
    ++s.gridPasses;
    s.vars.gridInverse.SetMatrix4x4(&camera.inverseViewProjection);
    const float params[4] = {1.0f, 12000.0f, level.extentX, level.extentZ};
    s.vars.gridParams.mEffectVariable->SetVector(params);
    if (s.vars.gridParams2.Exists()) {
      const float params2[4] = {
        0.01f * static_cast<float>(ren_WaterDisplace),
        0.01f * static_cast<float>(ren_WaterSwell),
        static_cast<float>(ren_WaterMaskDebug),
        0.0f
      };
      s.vars.gridParams2.mEffectVariable->SetVector(params2);
    }
    const float levelParams[4] = {1.0f, static_cast<float>(level.body), 0.0f, 0.0f};
    s.vars.levelParams.mEffectVariable->SetVector(levelParams);
    s.vars.gridWindow.mEffectVariable->SetVector(window);
    s.vars.owner.GetTexture(owner);
    return true;
  }

  void BindWaterGridLevelOff()
  {
    State& s = GetState();
    const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    const float full[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    if (s.vars.gridParams.Exists()) {
      s.vars.gridParams.mEffectVariable->SetVector(off);
    }
    if (s.vars.levelParams.Exists()) {
      s.vars.levelParams.mEffectVariable->SetVector(off);
    }
    if (s.vars.gridWindow.Exists()) {
      s.vars.gridWindow.mEffectVariable->SetVector(full);
    }
  }

  void EndWaterGridLevels()
  {
    State& s = GetState();
    const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    const float full[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    if (s.vars.gridParams.Exists()) {
      s.vars.gridParams.mEffectVariable->SetVector(off);
    }
    if (s.vars.levelParams.Exists()) {
      s.vars.levelParams.mEffectVariable->SetVector(off);
    }
    if (s.vars.gridWindow.Exists()) {
      s.vars.gridWindow.mEffectVariable->SetVector(full);
    }
    if (s.vars.owner.Exists() && s.texture != nullptr) {
      s.vars.owner.mEffectVariable->SetRenderTarget(s.texture);
    }
  }

  void ReleaseWaterSimulation()
  {
    State& s = GetState();
    if (s.vars.texture.mEffectVariable && s.vars.texture.Exists()) {
      s.vars.texture.mEffectVariable->SetRenderTarget(std::shared_ptr<RenderTarget>());
    }
    s.state[0].reset();
    s.state[1].reset();
    s.sources.reset();
    s.heights.reset();
    s.shore.reset();
    s.shoreWidth = 0U;
    s.domainBlocksX = 0U;
    s.heightRevision = ~0ull;
    s.field = nullptr;
    s.map = nullptr;
    s.step.reset();
    s.stepDomains.reset();
    s.domainProgramFailed = false;
    s.copy.reset();
    s.texture.reset();
    s.device = nullptr;
    s.hasHistory = false;
    s.failed = false;
  }

  // ------------------------------------------------------------------------------------------------ the effect patch
  namespace
  {
    constexpr const char* kDeclarations = R"HLSL(
// ---- FAF water simulation (WaterSimulation.cpp, docs/LIGHTING_V2.md): ripples of the GPU wave simulation ----
texture waterSim;
sampler2D waterSimSampler = sampler_state
{
    Texture   = (waterSim);
    MipFilter = NONE;
    MinFilter = LINEAR;
    MagFilter = LINEAR;
    AddressU  = WRAP;
    AddressV  = WRAP;
};
texture waterOwner;       // per 2 x 2 unit block (a texel of the water map): the number of the water that owns it, 0 the sea
sampler2D waterOwnerSampler = sampler_state
{
    Texture   = (waterOwner);
    MipFilter = NONE;
    MinFilter = POINT;
    MagFilter = POINT;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};
float4 waterLevelParams;  // x: 1 = the projected grid draws one water of a map with water bodies and drops the pixels that are not its own, y: its number
float4 waterGridWindow = float4(0, 0, 1, 1); // the part of the screen the projected grid covers: u0, v0, du, dv
float4 waterSimParams;    // 1 / (cell size x cells), centre x, centre z, half extent
float4 waterSimParams2;   // x: 1 = on, y: how much the slope bends the normal, z: how much height makes foam, w: the least colour of the water over the bed

static const float4 kSwellWave[8] = { float4(0.955, 0.296, 1.047, 0.0477), float4(0.814, 0.581, 1.396, 0.0358), float4(0.989, -0.149, 1.745, 0.0286), float4(0.582, 0.813, 2.094, 0.0239), float4(0.999, 0.050, 2.618, 0.0191), float4(0.697, 0.717, 3.142, 0.0159), float4(0.900, -0.435, 3.927, 0.0127), float4(0.362, 0.932, 4.833, 0.0103) };
static const float kSwellSpeed[8] = { 1.36, 1.68, 1.92, 2.09, 2.49, 2.83, 3.34, 3.87 };   // rad / s: phase speeds of about one unit a second

// the wind sea: eight short travelling waves (direction x, z, wave number, height) with sharp crests (1.273 - 2 |sin(theta / 2)| has a cusp at
// the crest, flat troughs and no mean). It bends the normals and drives the surf; it does not lift the mesh (a coarse grid shows it as facets).
float FafSwellHeight(float2 p, float t)
{
    float h = 0.0;
    [unroll] for (int i = 0; i < 8; ++i)
    {
        float4 w = kSwellWave[i];
        h += w.w * (1.273 - 2.0 * abs(sin(0.5 * (dot(w.xy, p) * w.z - kSwellSpeed[i] * t + (float)i * 1.7))));
    }
    return h;
}

float2 FafSwellSlope(float2 p, float t)
{
    float2 s = float2(0.0, 0.0);
    [unroll] for (int i = 0; i < 8; ++i)
    {
        float4 w = kSwellWave[i];
        float th = 0.5 * (dot(w.xy, p) * w.z - kSwellSpeed[i] * t + (float)i * 1.7);
        s += w.xy * (-w.w * w.z * cos(th) * (sin(th) >= 0.0 ? 1.0 : -1.0));
    }
    return s;
}

// the foam of the simulation at a world position (0 outside its window)
float FafWaterFoam(float2 xz)
{
    float f = 0.0;
    if (waterSimParams2.x > 0.5)
    {
        float2 d = abs(xz - waterSimParams.yz);
        float weight = saturate((waterSimParams.w - max(d.x, d.y)) / (waterSimParams.w * 0.15));
        // four taps on the diagonals, a bit more than a cell out: the foam is a grid of half units, one bilinear tap of it shows as blocks
        float2 uv = xz * waterSimParams.x;
        float o = 0.45 * waterSimParams.x;
        f = 0.25 * (tex2Dlod(waterSimSampler, float4(uv + float2(o, o), 0, 0)).w + tex2Dlod(waterSimSampler, float4(uv + float2(-o, o), 0, 0)).w
                  + tex2Dlod(waterSimSampler, float4(uv + float2(o, -o), 0, 0)).w + tex2Dlod(waterSimSampler, float4(uv + float2(-o, -o), 0, 0)).w);
        f *= weight;
    }
    return f;
}

// slope x, slope z, height, weight (0 outside the window the simulation follows)
float4 FafWaterRipple(float2 xz)
{
    float4 r = float4(0, 0, 0, 0);
    if (waterSimParams2.x > 0.5)
    {
        float2 d = abs(xz - waterSimParams.yz);
        float weight = saturate((waterSimParams.w - max(d.x, d.y)) / (waterSimParams.w * 0.15));
        float4 t = tex2Dlod(waterSimSampler, float4(xz * waterSimParams.x, 0, 0));
        r = float4(t.x, t.y, t.z, weight);
    }
    return r;
}

// The projected grid: the vertex's uv is its place on the screen; its position is where that screen ray meets the water plane (limited to
// the map), lifted by the height of the wave simulation.
float4x4 waterGridInv;     // inverse view projection of the camera
float4 waterGridParams;    // x: 1 = projected grid, y: far distance, z, w: extent of the map in x and z
float4 waterGridParams2;   // x: how much of the simulated height lifts the geometry, y: the swell

float3 FafWaterGridPosition(float2 uv, float elevation)
{
    // (a margin around the screen: the lifted water is seen further in than where its flat surface is, so a grid that ends at the screen edge leaves gaps there)
    float2 ndc = float2(uv.x * 2.0 - 1.0, 1.0 - uv.y * 2.0) * float2(1.25, 1.15);
    float4 pn = mul(float4(ndc, 0.0, 1.0), waterGridInv);
    float4 pf = mul(float4(ndc, 1.0, 1.0), waterGridInv);
    float3 a = pn.xyz / pn.w;
    float3 d = normalize(pf.xyz / pf.w - a);
    float t = d.y < -0.0005 ? (elevation - a.y) / d.y : waterGridParams.y;
    t = clamp(t, 0.0, waterGridParams.y);
    float3 p = a + d * t;
    p.xz = clamp(p.xz, float2(0.0, 0.0), waterGridParams.zw);
    float4 ripple = FafWaterRipple(p.xz);
    p.y = elevation + ripple.z * ripple.w * waterGridParams2.x;
    return p;
}

)HLSL";
    // What goes after the alpha line of the pixel shader, in the shipped water and in the detailed one: the mask
    // diagnostics (ren_WaterMaskDebug, waterGridParams2.z is set by BindWaterGrid) and the owner clip of the grid.
    constexpr const char* kMaskTailHlsl =
      "\n    if (waterGridParams2.z > 0.5 && waterGridParams2.z < 1.5 && mask > 0.01) { returnPixels.rgb = "
      "float3(1.0, 0.0, 1.0); returnPixels.a = 1.0; }"
      "\n    if (waterGridParams2.z > 1.5 && waterGridParams2.z < 2.5) { returnPixels.rgb = lerp(returnPixels.rgb, "
      "float3(0.0, 1.0, 0.0), 0.8); returnPixels.a = 1.0; }"
      // 3: the inputs of the mask: red = the cut-out alpha of the frame (land and units above the water), green = the
      // baked water map's b channel, blue = the baked water depth (g channel) scaled; 4: the cut-out alpha as grey
      // levels (0 .. 0.1)
      "\n    if (waterGridParams2.z > 2.5 && waterGridParams2.z < 3.5) { returnPixels.rgb = "
      "float3(saturate(backGroundPixels.a * 255.0), waterTexture.b, saturate(waterDepth * 0.5)); returnPixels.a = "
      "1.0; }"
      "\n    if (waterGridParams2.z > 3.5) { returnPixels.rgb = saturate(backGroundPixels.a * 10.0).xxx; "
      "returnPixels.a = 1.0; }"
      // the grid of one water of a map with water bodies covers more than that water: the pixels of other waters (and
      // of dry ground) are dropped by the alpha test (the owner texture holds the number of the water of each block)
      "\n    if (waterLevelParams.x > 0.5)"
      "\n    {"
      "\n        float fafOwner = tex2Dlod(waterOwnerSampler, float4(inV.mTexUV, 0, 0)).r * 255.0;"
      "\n        if (abs(fafOwner - waterLevelParams.y) > 0.5) { returnPixels.a = 0.0; }"
      "\n    }";
  } // namespace

  SimPatchResult PatchWaterSimulation(
    std::string& source
  )
  {
    SimPatchResult result;
    const auto count = [&](const std::string& needle) {
      std::size_t n = 0;
      for (std::size_t p = source.find(needle); p != std::string::npos; p = source.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    };
    const std::string shader = "float4 HighFidelityPS(";
    const std::string vertexShader = "VS_OUTPUT WaterVS(";
    const std::string elevation = "inPos.y = WaterElevation;";
    const std::string crest = "float waveCrest = saturate( sum.a - waveCrestThreshold );";
    const std::string normal = "N = normalize(N.xzy);";
    if (
      count(shader) != 1 || count(crest) != 1 || count(normal) != 1 || count(vertexShader) != 1 ||
      count(elevation) != 1 || source.find("FafWaterRipple") != std::string::npos ||
      source.find(vertexShader) > source.find(shader)
    ) {
      result.error = "HighFidelityPS, WaterVS, their anchor lines not found exactly once in the expected order";
      return result;
    }
    std::string text = source;
    const std::size_t normalAt = text.find(normal);
    text.insert(
      normalAt + normal.size(),
      "\n    // the tilt the waves add to the normal is limited: a steep one (a hull's hump, a splash) swings the "
      "reflection and the refraction across the"
      "\n    // screen and paints the hull's colours around the ship in smears"
      "\n    float2 fafBend = float2(-simRipple.x, -simRipple.y) * (simRipple.w * waterSimParams2.y);"
      "\n    fafBend *= min(1.0, 0.5 / max(length(fafBend), 0.0001));"
      "\n    N = normalize(N + float3(fafBend.x, 0.0, fafBend.y));"
      "\n    // sharper highlights, and a slow, large scale undulation from two low frequency reads of the shipped "
      "normal maps (noise: no lattice)"
      "\n    N = normalize(float3(N.x * 1.45, N.y, N.z * 1.45));"
      "\n    float2 fafUv = ViewPosition.xz - inV.mViewVec.xz;"
      "\n    float4 fafU0 = tex2D(NormalSampler1, (fafUv + normal2Movement * Time * 0.6 + 17.0) * normalRepeatRate.y * "
      "0.4);"
      "\n    float4 fafU1 = tex2D(NormalSampler2, (fafUv - normal3Movement * Time * 4.0) * normalRepeatRate.z * 0.7);"
      "\n    float3 fafU = (fafU0.xyz + fafU1.xyz) - 1.0;"
      "\n    N = normalize(N + float3(fafU.x, 0.0, fafU.y) * waterGridParams2.y * 0.9);"
    );
    const std::size_t crestAt = text.find(crest);
    if (crestAt > normalAt) {
      result.error = "the wave crest line comes after the normal line";
      return result;
    }
    text.insert(
      crestAt + crest.size(),
      "\n    float4 simRipple = FafWaterRipple(ViewPosition.xz - inV.mViewVec.xz);"
      "\n    waveCrest = saturate(waveCrest + simRipple.w * saturate(abs(simRipple.z) * waterSimParams2.z));"
    );
    // the vertex shader: the projected grid (the input uv is the screen position of the vertex) or the flat quad
    const std::size_t elevationAt = text.find(elevation);
    text.replace(
      elevationAt,
      elevation.size(),
      "if (waterGridParams.x > 0.5)\n"
      "\t{\n"
      "\t\tinPos.xyz = FafWaterGridPosition(waterGridWindow.xy + inTexUV * waterGridWindow.zw, WaterElevation);\n"
      "\t\tinTexUV = inPos.xz / waterGridParams.zw;\n"
      "\t}\n"
      "\telse\n"
      "\t{\n"
      "\t\tinPos.y = WaterElevation;\n"
      "\t}"
    );
    // The foam over the colour of the water, and a least colour of the water over the sea bed (a more solid sea).
    // Anchors of the shipped shader; a shader that has them changed is left as it is.
    const std::string crestMix =
      "water = lerp(water, waveCrestColor, (1 - waterTexture.a) * (1 - waterTexture.b) * waveCrest);";
    if (count(crestMix) == 1) {
      const std::size_t at = text.find(crestMix) + crestMix.size();
      text.insert(
        at,
        "\n    float fafFoam = FafWaterFoam(ViewPosition.xz - inV.mViewVec.xz);"
        "\n    float fafFoamAmount = FafFoamAmount(fafFoam, ViewPosition.xz - inV.mViewVec.xz, sum.a);"
        "\n    float3 fafFoamColor = float3(0.95, 0.98, 1.0) * (0.8 + 0.2 * saturate(dot(N, SunDirection)));"
        "\n    water = lerp(water, fafFoamColor, fafFoamAmount * 0.92);"
      );
    }
    // The mask diagnostic: the shipped shader returns alpha 1 - mask and an alpha test drops the land cut-out.
    // (waterGridParams2.z is set by BindWaterGrid.)
    const std::string maskAlpha = "returnPixels.a = 1 - mask;";
    if (count(maskAlpha) != 1) {
      result.error =
        "the alpha line of HighFidelityPS (the owner clip of the projected grid goes after it) not found once";
      return result;
    }
    text.insert(text.find(maskAlpha) + maskAlpha.size(), kMaskTailHlsl);
    const std::string colourFactor = "float factor = clamp(waterDepth, waterLerp.x, waterLerp.y);";
    if (count(colourFactor) == 1) {
      text.replace(
        text.find(colourFactor),
        colourFactor.size(),
        "float factor = max(clamp(waterDepth, waterLerp.x, waterLerp.y), waterSimParams2.w);"
      );
    }
    text.insert(
      text.find(vertexShader),
      std::string(kDeclarations) + kWaterNoiseHlsl + kWaterGradientNoiseHlsl + kWaterFoamLookHlsl
    );
    source = std::move(text);
    result.patched = true;
    return result;
  }

  SimPatchResult PatchWaterDetail(
    std::string& source
  )
  {
    SimPatchResult result;
    const auto count = [&](const std::string& needle) {
      std::size_t n = 0;
      for (std::size_t p = source.find(needle); p != std::string::npos; p = source.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    };
    const std::string shader = "float4 WaterHdPS(";
    const std::string crest = "const float waveCrest = saturate(W0.a + W1.a + W2.a + W3.a - waveCrestThreshold);";
    const std::string normal = "float3 N = normalize(float3(-gradient.x, 1.0, -gradient.y));";
    const std::string crestMix =
      "water = lerp(water, waveCrestColor, (1 - waterTexture.a) * (1 - waterTexture.b) * waveCrest);";
    const std::string maskAlpha = "returnPixels.a = 1 - mask;";
    if (
      count(shader) != 1 || count(crest) != 1 || count(normal) != 1 || count(crestMix) != 1 || count(maskAlpha) != 1 ||
      source.find("FafWaterRipple") != std::string::npos
    ) {
      result.error = "WaterHdPS, its anchor lines not found exactly once";
      return result;
    }
    std::string text = source;
    // the crest line comes first: it becomes a variable the ripples add to
    text.replace(
      text.find(crest), crest.size(), "float waveCrest = saturate(W0.a + W1.a + W2.a + W3.a - waveCrestThreshold);"
    );
    const std::size_t normalAt = text.find(normal);
    if (text.find("float waveCrest") > normalAt || text.find(crestMix) < normalAt || text.find(maskAlpha) < normalAt) {
      result.error = "the anchor lines of WaterHdPS are not in the expected order";
      return result;
    }
    // The ripples of the simulation bend the normal (limited as in the shipped water: a steep one smears the
    // reflection and the refraction) and raise the crest, as in HighFidelityPS (PatchWaterSimulation).
    text.insert(
      normalAt + normal.size(),
      "\n    float4 simRipple = FafWaterRipple(worldPos.xz);"
      "\n    float2 fafBend = float2(-simRipple.x, -simRipple.y) * (simRipple.w * waterSimParams2.y);"
      "\n    fafBend *= min(1.0, 0.5 / max(length(fafBend), 0.0001));"
      "\n    N = normalize(N + float3(fafBend.x, 0.0, fafBend.y));"
      "\n    waveCrest = saturate(waveCrest + simRipple.w * saturate(abs(simRipple.z) * waterSimParams2.z));"
    );
    // the foam of the simulation over the colour of the water
    text.insert(
      text.find(crestMix) + crestMix.size(),
      "\n    float fafFoam = FafWaterFoam(worldPos.xz);"
      "\n    float fafFoamAmount = FafFoamAmount(fafFoam, worldPos.xz, W0.a + W1.a + W2.a + W3.a);"
      "\n    float3 fafFoamColor = float3(0.95, 0.98, 1.0) * (0.8 + 0.2 * saturate(dot(N, SunDirection)));"
      "\n    water = lerp(water, fafFoamColor, fafFoamAmount * 0.92);"
    );
    // the mask diagnostics and the owner clip of the grid of one water
    text.insert(text.find(maskAlpha) + maskAlpha.size(), kMaskTailHlsl);
    source = std::move(text);
    result.patched = true;
    return result;
  }
} // namespace moho::water

// Headless lab of the water simulation (docs/WATER_SIMULATION.md, "Water lab").
//
// It runs the REAL compute shader of the game (the HLSL raw string of src/moho/terrain/water/WaterSimulation.cpp is
// read from the source at start) on a software D3D11 device (WARP: the CPU, so a running game is not disturbed), over a
// synthetic coast, with the real distance-to-shore field (src/moho/terrain/water/ShoreField.h), and writes captures in
// the format of the in-game recorder (tools/waterrec.py reads them; tools/watersimlab.py measures and renders them). No
// game, no window, no GPU.
//
//   watersimlab --src <WaterSimulation.cpp> --out <dir> [--terrain coast|beach|bay] [--n 512] [--seconds 40] [--every
//   0.5] [--from 10] [--swell 100]
//               [--shorewave 100] [--ship]
//
// The window is n x n cells of half a unit at the world origin (n = 512: 256 x 256 units), fixed (no scrolling).

#define NOMINMAX
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../../src/moho/terrain/water/HullDisplacement.h"
#include "../../src/moho/terrain/water/ShoreField.h"
#include "../../src/moho/terrain/water/WaterHull.h"
#include "../../src/moho/terrain/water/WaterImpact.h"
#include "../../src/moho/terrain/water/WaterSimParams.h"
#include "../../src/moho/terrain/water/WaterSourceGate.h"

using Microsoft::WRL::ComPtr;

#include "domains.h"

namespace
{
  constexpr float kCell = 0.5f;
  constexpr float kStep = 1.0f / 90.0f;
  constexpr float kElevation = 25.0f; // world units: the sea level of the synthetic maps
  constexpr float kMargin = 0.1f;     // the land margin of the game

  struct Constants
  {
    float a[4], b[4], c[4], d[4], e[4], f[4], g[4]; // g: the domain table (zero: no domains)
  };

  std::string ReadFile(
    const std::string& path
  )
  {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
  }

  // ---- synthetic terrain
  // -----------------------------------------------------------------------------------------------------------
  float Hash2(
    int x,
    int z
  )
  {
    std::uint32_t h = static_cast<std::uint32_t>(x) * 374761393u + static_cast<std::uint32_t>(z) * 668265263u;
    h = (h ^ (h >> 13)) * 1274126177u;
    h ^= h >> 16;
    return static_cast<float>(h & 0xFFFFFF) / 16777215.0f;
  }

  float ValueNoise(
    float x,
    float z
  )
  {
    const int ix = static_cast<int>(std::floor(x));
    const int iz = static_cast<int>(std::floor(z));
    const float fx = x - static_cast<float>(ix);
    const float fz = z - static_cast<float>(iz);
    const float sx = fx * fx * (3.0f - 2.0f * fx);
    const float sz = fz * fz * (3.0f - 2.0f * fz);
    const float a = Hash2(ix, iz), b = Hash2(ix + 1, iz), c = Hash2(ix, iz + 1), d = Hash2(ix + 1, iz + 1);
    return (a + (b - a) * sx) + ((c + (d - c) * sx) - (a + (b - a) * sx)) * sz;
  }

  // The ground of a synthetic map relative to the sea level, world units (positive is land). `s` is the signed distance
  // from the coast, positive in the water.
  float GroundAt(
    const std::string& terrain,
    const float x,
    const float z
  )
  {
    float s = 0.0f;
    float slope = 0.10f;
    if (terrain == "beach") {
      s = 140.0f - x; // a straight beach, to the right of x = 140
      slope = 0.05f;
    } else if (terrain == "bay") {
      const float dx = x - 190.0f;
      const float dz = z - 128.0f;
      s = std::sqrt(dx * dx + dz * dz) - 70.0f; // a round bay: land outside, water inside
      s = -s;                                   // (water inside the circle)
      slope = 0.12f;
    } else { // "coast": a wandering coast, a headland, an island, slopes from a flat beach to a cliff
      const float coast = 150.0f + 22.0f * std::sin(z * 0.035f) + 10.0f * std::sin(z * 0.11f + 1.0f) +
        8.0f * (ValueNoise(z * 0.05f, 3.0f) - 0.5f);
      const float shore = coast - x;
      const float ix = x - 60.0f;
      const float iz = z - 70.0f;
      const float island = std::sqrt(ix * ix + iz * iz) - 18.0f;
      s = std::min(shore, island);
      slope = 0.07f + 0.13f * (0.5f + 0.5f * std::sin(z * 0.02f + 0.5f));
    }
    float h;
    if (s > 0.0f) {
      h = -std::min(slope * s + 0.25f * std::sqrt(s) * 0.3f, 14.0f); // the sea bed
    } else {
      h = 0.3f * (-s) + 0.1f; // the land
    }
    // ground bumps: a sea bed and a beach are not smooth
    h += 0.30f * (ValueNoise(x * 0.9f, z * 0.9f) - 0.5f) + 0.5f * (ValueNoise(x * 0.12f, z * 0.12f) - 0.5f);
    return h;
  }

  struct Args
  {
    std::string src, out = "out", terrain = "coast";
    int n = 512;
    float seconds = 40.0f, every = 0.5f, from = 10.0f;
    int swell = 100, shoreWave = 100;
    int seed = 17;
    int look = 4;      // pixels per world unit of the look images (0: none)
    float suma = 0.5f; // the alpha of the shipped crest texture the foam threshold sees (a pixel of the game has a
                       // value of its own)
    // --impact: open sea (no land, no swell, no surf), `impacts` impacts of `impactSize` (the cube root of the energy:
    // a shell of 100 damage 4.6) one after the other every `impactGap` seconds at the middle of the window, starting at
    // 1 s; writes series.csv and rays.csv (see watersimlab.py impact)
    bool impact = false;
    float impactSize = 6.0f, impactGap = 0.25f, impactScale = 1.0f;
    int impacts = 1;
    int capillary = 100, damping = 100; // percent of the tuned values, to try them
    // --wake: open sea, one hull sails along +x through the middle at `hullSpeed` units a second; writes wake.csv (see
    // watersimlab.py wake)
    bool wake = false;
    float hullSpeed = 5.0f, hullHalfLength = 2.9f, hullHalfBeam = 0.6f, hullRadius = 3.4f, wakeScale = 2.0f;
    float hullFoam = -1.0f, foamKept = -1.0f; // replace kHullFoam, kFoamKept of WaterSimParams.h
    bool body = false; // --body: the hull is a volume (HullDisplacement.h) of draft `hullDraft` that displaces the
                       // water, not the hand-made wake
    float hullDraft = 1.2f, bodyPush = -1.0f, bodyFoam = 1.0f;
    float visc = -1.0f;     // replaces kViscosity of the shader (to try values)
    std::string causticSrc; // --caustic <file>: evaluate the caustic web of that shader source (no simulation)
    float causticRate = 0.25f, causticX = 100.0f, causticZ = 100.0f;
    bool legacy = false;  // the first impact model (one lump of discs, height only), for comparison
    bool domains = false; // --domains: the tests of the simulation per water (domains.h)
    bool dxbc = false; // --dxbc: the hash of the compiled compute shader and copy pixel shader (the same source gives
                       // the same hash)
  };
} // namespace

// ---- gate: where the simulation takes a source (WaterSourceGate.h), on a mock of a map with water bodies, no GPU
// ---------------------------------- The sea is at 20. A raised lake at 40 has its bed at 30 (above the sea: a
// sea-level test calls it land), a dry polder lies at the sea's ground height 5 and has no water, a second lake at 12
// (below the sea) is a basin of its own. `--gate` prints [ok] / [FAIL] lines and exits 1 when a decision is wrong.
int RunGate()
{
  struct Rect
  {
    float x0, z0, x1, z1;
    bool Has(
      const float x,
      const float z
    ) const
    {
      return x >= x0 && x < x1 && z >= z0 && z < z1;
    }
  };
  const Rect lake{200.0f, 200.0f, 260.0f, 260.0f};   // level 40, bed 30
  const Rect polder{100.0f, 100.0f, 140.0f, 140.0f}; // dry body: no water, ground 5
  const Rect basin{400.0f, 100.0f, 440.0f, 140.0f};  // level 12, bed 2
  const Rect island{300.0f, 300.0f, 340.0f, 340.0f}; // ground 25 in the sea
  constexpr float kSea = 20.0f;
  const auto ground = [&](const float x, const float z) {
    if (lake.Has(x, z))
      return 30.0f;
    if (basin.Has(x, z))
      return 2.0f;
    if (island.Has(x, z))
      return 25.0f;
    return 5.0f;
  };
  // STIMap::GetWaterElevationAt of the mock
  const auto mapLevel = [&](const float x, const float z, const bool hasSea) {
    if (lake.Has(x, z))
      return 40.0f;
    if (polder.Has(x, z))
      return moho::water::kNoWaterLevel;
    if (basin.Has(x, z))
      return 12.0f;
    return hasSea ? kSea : moho::water::kNoWaterLevel;
  };
  struct Case
  {
    const char* name;
    float x, z;
    bool withBodies, hasSea;
    bool expected;
  };
  const Case cases[] = {
    {"open sea, no bodies: kept", 50.0f, 50.0f, false, true, true},
    {"island ashore, no bodies: dropped", 320.0f, 320.0f, false, true, false},
    {"the single-level test on a raised lake's bed (30 > 20): dropped, what the old gate did",
     230.0f,
     230.0f,
     false,
     true,
     false},
    {"raised lake, with bodies: kept at its own level 40", 230.0f, 230.0f, true, true, true},
    {"just outside the raised lake, in the sea: kept at the sea's level", 199.0f, 230.0f, true, true, true},
    {"dry polder (ground 5, a dry body): dropped", 120.0f, 120.0f, true, true, false},
    {"basin below the sea (level 12, ground 2): kept", 420.0f, 120.0f, true, true, true},
    {"island ashore, with bodies: dropped", 320.0f, 320.0f, true, true, false},
    {"no sea, outside every body (ground 5): dropped", 50.0f, 50.0f, true, false, false},
    {"no sea, inside the raised lake: kept", 230.0f, 230.0f, true, false, true},
    {"no sea, dry polder: dropped", 120.0f, 120.0f, true, false, false},
  };
  bool ok = true;
  for (const Case& c : cases) {
    const auto levelAt = [&](const float x, const float z, float& level) {
      return moho::water::LevelAtPlace(
        c.withBodies, c.hasSea ? kSea : moho::water::kNoWaterLevel, [&](const float px, const float pz) {
        return mapLevel(px, pz, c.hasSea);
      }, x, z, level
      );
    };
    const bool got = moho::water::SourceOverWater(c.x, c.z, levelAt, ground);
    std::printf("  [%s] %s\n", got == c.expected ? "ok" : "FAIL", c.name);
    ok &= got == c.expected;
  }
  // a hull going down needs the level of its place too: the same lookup
  float level = 0.0f;
  const auto lakeLevel = [&](const float x, const float z, float& out) {
    return moho::water::LevelAtPlace(true, kSea, [&](const float px, const float pz) {
      return mapLevel(px, pz, true);
    }, x, z, out);
  };
  const bool lakeOk = lakeLevel(230.0f, 230.0f, level) && level == 40.0f;
  const bool polderOk = !lakeLevel(120.0f, 120.0f, level);
  std::printf("  [%s] the level at a place: the lake's 40, none over the polder\n", lakeOk && polderOk ? "ok" : "FAIL");
  ok &= lakeOk && polderOk;
  // a map without bodies has exactly one level everywhere, whatever the lookup says (here a lookup that would say 40)
  const bool singleOk = moho::water::LevelAtPlace(
                          false,
                          kSea,
                          [](const float, const float) {
    return 40.0f;
  },
                          230.0f,
                          230.0f,
                          level
                        ) &&
    level == kSea;
  std::printf(
    "  [%s] no water bodies: the sea's level everywhere (the lookup is not asked)\n", singleOk ? "ok" : "FAIL"
  );
  ok &= singleOk;
  std::printf("  checks: %s\n", ok ? "ok" : "FAILED");
  return ok ? 0 : 1;
}

// ---- caustic web: evaluates FafCausticWeb of the water shader patch on a grid at a few times (writes caustic_<n>.bin,
// raw float32, size x size) ----
int RunCaustic(
  const Args& args
)
{
  std::string text = ReadFile(args.causticSrc);
  std::string snippet;
  const std::size_t begin = text.find("// ---- CAUSTIC WEB BEGIN");
  const std::size_t end = text.find("// ---- CAUSTIC WEB END");
  if (begin != std::string::npos && end != std::string::npos) {
    snippet = text.substr(begin, end - begin);
  } else {
    std::fprintf(stderr, "no caustic web block in %s\n", args.causticSrc.c_str());
    return 2;
  }
  const std::string hlsl = snippet + R"HLSL(
cbuffer C : register(b0) { float4 a; };   // origin x, z, step, t
RWStructuredBuffer<float> Out : register(u0);
[numthreads(8, 8, 1)]
void CausticCS(uint3 id : SV_DispatchThreadID)
{
    float2 xz = a.xy + (float2)id.xy * a.z;
    Out[id.y * 256 + id.x] = FafCausticWeb(xz, a.w);
}
)HLSL";
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  D3D_FEATURE_LEVEL level{};
  if (
    FAILED(D3D11CreateDevice(
      nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &device, &level, &context
    ))
  ) {
    return 3;
  }
  ComPtr<ID3DBlob> code, errors;
  if (
    FAILED(D3DCompile(
      hlsl.data(), hlsl.size(), "Caustic.hlsl", nullptr, nullptr, "CausticCS", "cs_5_0", 0, 0, &code, &errors
    ))
  ) {
    std::fprintf(
      stderr, "caustic shader: %s\n", errors != nullptr ? static_cast<const char*>(errors->GetBufferPointer()) : "?"
    );
    return 4;
  }
  ComPtr<ID3D11ComputeShader> cs;
  device->CreateComputeShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, &cs);
  const UINT count = 256U * 256U;
  D3D11_BUFFER_DESC bd{};
  bd.ByteWidth = 4U * count;
  bd.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
  bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
  bd.StructureByteStride = 4;
  ComPtr<ID3D11Buffer> buffer, staging, constants;
  device->CreateBuffer(&bd, nullptr, &buffer);
  bd.BindFlags = 0;
  bd.Usage = D3D11_USAGE_STAGING;
  bd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
  device->CreateBuffer(&bd, nullptr, &staging);
  D3D11_UNORDERED_ACCESS_VIEW_DESC uv{};
  uv.Format = DXGI_FORMAT_UNKNOWN;
  uv.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
  uv.Buffer.NumElements = count;
  ComPtr<ID3D11UnorderedAccessView> uav;
  device->CreateUnorderedAccessView(buffer.Get(), &uv, &uav);
  D3D11_BUFFER_DESC cb{};
  cb.ByteWidth = 16;
  cb.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
  device->CreateBuffer(&cb, nullptr, &constants);
  std::filesystem::create_directories(args.out);
  int index = 0;
  for (const float seconds : {0.0f, 1.0f / 30.0f, 0.1f, 0.5f, 1.0f, 2.0f, 4.0f}) {
    const float a[4] = {args.causticX, args.causticZ, 0.25f, seconds * args.causticRate};
    context->UpdateSubresource(constants.Get(), 0, nullptr, a, 0, 0);
    context->CSSetShader(cs.Get(), nullptr, 0);
    context->CSSetConstantBuffers(0, 1, constants.GetAddressOf());
    ID3D11UnorderedAccessView* uavs[1] = {uav.Get()};
    context->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
    context->Dispatch(32, 32, 1);
    ID3D11UnorderedAccessView* none[1] = {};
    context->CSSetUnorderedAccessViews(0, 1, none, nullptr);
    context->CopyResource(staging.Get(), buffer.Get());
    D3D11_MAPPED_SUBRESOURCE map{};
    if (SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &map))) {
      char name[512];
      std::snprintf(name, sizeof(name), "%s/caustic_%d.bin", args.out.c_str(), index);
      if (FILE* const f = std::fopen(name, "wb")) {
        std::fwrite(map.pData, 4, count, f);
        std::fclose(f);
      }
      context->Unmap(staging.Get(), 0);
    }
    ++index;
  }
  std::printf("watersimlab: %d caustic grids (256 x 256, 0.25 unit) in %s\n", index, args.out.c_str());
  return 0;
}

int main(
  int argc,
  char** argv
)
{
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--gate") {
      return RunGate();
    }
  }
  Args args;
  for (int i = 1; i < argc; ++i) {
    const std::string key = argv[i];
    const auto next = [&]() -> std::string {
      return i + 1 < argc ? std::string(argv[++i]) : std::string();
    };
    if (key == "--src")
      args.src = next();
    else if (key == "--out")
      args.out = next();
    else if (key == "--terrain")
      args.terrain = next();
    else if (key == "--n")
      args.n = std::atoi(next().c_str());
    else if (key == "--seconds")
      args.seconds = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--every")
      args.every = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--from")
      args.from = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--swell")
      args.swell = std::atoi(next().c_str());
    else if (key == "--shorewave")
      args.shoreWave = std::atoi(next().c_str());
    else if (key == "--look")
      args.look = std::atoi(next().c_str());
    else if (key == "--seed")
      args.seed = std::atoi(next().c_str());
    else if (key == "--suma")
      args.suma = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--impact")
      args.impact = true;
    else if (key == "--impact-size")
      args.impactSize = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--impact-gap")
      args.impactGap = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--impact-scale")
      args.impactScale = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--impacts")
      args.impacts = std::atoi(next().c_str());
    else if (key == "--capillary")
      args.capillary = std::atoi(next().c_str());
    else if (key == "--damping")
      args.damping = std::atoi(next().c_str());
    else if (key == "--legacy")
      args.legacy = true;
    else if (key == "--domains")
      args.domains = true;
    else if (key == "--dxbc")
      args.dxbc = true;
    else if (key == "--wake")
      args.wake = true;
    else if (key == "--body")
      args.body = true;
    else if (key == "--hull-draft")
      args.hullDraft = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--body-push")
      args.bodyPush = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--body-foam")
      args.bodyFoam = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--hull-foam")
      args.hullFoam = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--foam-kept")
      args.foamKept = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--hull-speed")
      args.hullSpeed = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--hull-length")
      args.hullHalfLength = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--hull-beam")
      args.hullHalfBeam = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--hull-radius")
      args.hullRadius = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--wake-scale")
      args.wakeScale = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--visc")
      args.visc = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--caustic")
      args.causticSrc = next();
    else if (key == "--caustic-rate")
      args.causticRate = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--caustic-x")
      args.causticX = static_cast<float>(std::atof(next().c_str()));
    else if (key == "--caustic-z")
      args.causticZ = static_cast<float>(std::atof(next().c_str()));
  }
  if (!args.causticSrc.empty()) {
    return RunCaustic(args);
  }
  if (args.src.empty()) {
    std::fprintf(
      stderr,
      "usage: watersimlab --src <WaterSimulation.cpp> --out <dir> [--terrain coast|beach|bay] [--n 512] [--seconds 40] "
      "[--every 0.5] [--from 10]\n"
    );
    return 2;
  }
  const int n = args.n;
  const bool openSea = args.impact || args.wake; // no land, no swell, no surf: only what the scenario puts in

  // ---- the shader: the HLSL raw string of the game
  // ---------------------------------------------------------------------------------
  const std::string cpp = ReadFile(args.src);
  const std::size_t a = cpp.find("R\"HLSL(");
  const std::size_t b = a == std::string::npos ? a : cpp.find(")HLSL\"", a);
  if (a == std::string::npos || b == std::string::npos) {
    std::fprintf(stderr, "no HLSL raw string in %s\n", args.src.c_str());
    return 2;
  }
  // the shared noise comes first, as in the game (SimSource in WaterSimulation.cpp); the foam look is the shared code
  // of the pixel shader
  const std::string common = ReadFile((std::filesystem::path(args.src).parent_path() / "WaterShaderCommon.h").string());
  const auto rawString = [&](const std::size_t which) {
    std::size_t from = 0;
    for (std::size_t i = 0; i <= which; ++i) {
      from = common.find("R\"HLSL(", i == 0 ? 0 : from + 1);
    }
    const std::size_t end = common.find(")HLSL\"", from);
    return common.substr(from + 7, end - (from + 7));
  };
  const std::string noiseHlsl = rawString(0) + rawString(1); // value noise, then gradient noise
  const std::string foamHlsl = rawString(2);
  std::string hlsl = noiseHlsl + cpp.substr(a + 7, b - (a + 7));
  {
    const std::string key = "static const float kViscosity = 0.10;";
    const std::size_t at = hlsl.find(key);
    if (at != std::string::npos) {
      char text[96];
      std::snprintf(
        text,
        sizeof(text),
        "static const float kViscosity = %.5f;",
        args.visc >= 0.0f ? args.visc : moho::water::kViscosity
      );
      hlsl.replace(at, key.size(), text);
    }
  }

  if (args.domains) {
    return RunDomains(hlsl);
  }
  if (args.dxbc) {
    // the compiled shaders as bytes: a source that compiles to the same bytes runs the same instructions on any GPU
    const struct
    {
      const char* entry;
      const char* profile;
    } stages[] = {{"SimCS", "cs_5_0"}, {"SimCopyPS", "ps_5_0"}};
    for (const auto& stage : stages) {
      ComPtr<ID3DBlob> blob, messages;
      if (
        FAILED(D3DCompile(
          hlsl.data(),
          hlsl.size(),
          "WaterSimulation.hlsl",
          nullptr,
          nullptr,
          stage.entry,
          stage.profile,
          0,
          0,
          &blob,
          &messages
        ))
      ) {
        std::fprintf(
          stderr,
          "%s: %s\n",
          stage.entry,
          messages != nullptr ? static_cast<const char*>(messages->GetBufferPointer()) : "?"
        );
        return 4;
      }
      // the whole blob (it also holds the names and sizes of the constants) and its code chunk (SHEX: the instructions)
      const std::uint8_t* const bytes = static_cast<const std::uint8_t*>(blob->GetBufferPointer());
      const auto fnv = [](const std::uint8_t* data, const std::size_t count) {
        std::uint64_t hash = 1469598103934665603ull;
        for (std::size_t i = 0; i < count; ++i) {
          hash = (hash ^ data[i]) * 1099511628211ull;
        }
        return hash;
      };
      std::uint64_t code = 0;
      std::size_t codeBytes = 0;
      std::uint32_t chunks = 0;
      std::memcpy(&chunks, bytes + 28, 4);
      for (std::uint32_t c = 0; c < chunks; ++c) {
        std::uint32_t offset = 0;
        std::memcpy(&offset, bytes + 32 + 4 * c, 4);
        std::uint32_t size = 0;
        std::memcpy(&size, bytes + offset + 4, 4);
        if (std::memcmp(bytes + offset, "SHEX", 4) == 0 || std::memcmp(bytes + offset, "SHDR", 4) == 0) {
          code = fnv(bytes + offset + 8, size);
          codeBytes = size;
        }
      }
      std::printf(
        "%s %s %zu bytes %016llx, code %zu bytes %016llx\n",
        stage.entry,
        stage.profile,
        static_cast<std::size_t>(blob->GetBufferSize()),
        static_cast<unsigned long long>(fnv(bytes, blob->GetBufferSize())),
        codeBytes,
        static_cast<unsigned long long>(code)
      );
    }
    return 0;
  }

  // ---- the terrain, the land mask and the distance to the shore
  // ----------------------------------------------------------------------
  const std::uint32_t hw = static_cast<std::uint32_t>(n / 2 + 4); // height samples cover the window (one a world unit)
  const std::uint32_t hh = hw;
  std::vector<std::uint16_t> raw(static_cast<std::size_t>(hw) * hh);
  for (std::uint32_t z = 0; z < hh; ++z) {
    for (std::uint32_t x = 0; x < hw; ++x) {
      const float h = GroundAt(args.terrain, static_cast<float>(x), static_cast<float>(z));
      raw[static_cast<std::size_t>(z) * hw + x] =
        static_cast<std::uint16_t>(std::min(std::max((kElevation + h) * 128.0f, 0.0f), 65535.0f));
    }
  }
  const float levelRaw = (kElevation - kMargin) * 128.0f;
  const std::vector<float> shore = moho::water::ComputeShoreDistance([&](const std::uint32_t x, const std::uint32_t z) {
    return raw[static_cast<std::size_t>(z) * hw + x];
  }, hw, hh, levelRaw);
  std::vector<std::uint32_t> packed((raw.size() + 1U) / 2U, 0U);
  for (std::size_t i = 0; i < raw.size(); ++i) {
    packed[i >> 1U] |= static_cast<std::uint32_t>(raw[i]) << ((i & 1U) * 16U);
  }

  // ---- the device
  // -------------------------------------------------------------------------------------------------------------------
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  D3D_FEATURE_LEVEL level{};
  if (
    FAILED(D3D11CreateDevice(
      nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &device, &level, &context
    ))
  ) {
    std::fprintf(stderr, "no WARP device\n");
    return 3;
  }
  ComPtr<ID3DBlob> code, errors;
  if (
    FAILED(D3DCompile(
      hlsl.data(), hlsl.size(), "WaterSimulation.hlsl", nullptr, nullptr, "SimCS", "cs_5_0", 0, 0, &code, &errors
    ))
  ) {
    std::fprintf(
      stderr, "shader: %s\n", errors != nullptr ? static_cast<const char*>(errors->GetBufferPointer()) : "?"
    );
    return 4;
  }
  ComPtr<ID3D11ComputeShader> cs;
  device->CreateComputeShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, &cs);

  struct Buf
  {
    ComPtr<ID3D11Buffer> buffer;
    ComPtr<ID3D11ShaderResourceView> srv;
    ComPtr<ID3D11UnorderedAccessView> uav;
  };
  const auto makeBuffer = [&](const UINT stride, const UINT count, const void* init, const bool writable) {
    Buf r;
    D3D11_BUFFER_DESC d{};
    d.ByteWidth = stride * count;
    d.Usage = D3D11_USAGE_DEFAULT;
    d.BindFlags = D3D11_BIND_SHADER_RESOURCE | (writable ? D3D11_BIND_UNORDERED_ACCESS : 0U);
    d.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
    d.StructureByteStride = stride;
    std::vector<std::uint8_t> zero;
    if (init == nullptr) {
      zero.assign(d.ByteWidth, 0);
      init = zero.data();
    }
    D3D11_SUBRESOURCE_DATA data{init, 0, 0};
    device->CreateBuffer(&d, &data, &r.buffer);
    D3D11_SHADER_RESOURCE_VIEW_DESC sv{};
    sv.Format = DXGI_FORMAT_UNKNOWN;
    sv.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
    sv.Buffer.FirstElement = 0;
    sv.Buffer.NumElements = count;
    device->CreateShaderResourceView(r.buffer.Get(), &sv, &r.srv);
    if (writable) {
      D3D11_UNORDERED_ACCESS_VIEW_DESC uv{};
      uv.Format = DXGI_FORMAT_UNKNOWN;
      uv.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
      uv.Buffer.FirstElement = 0;
      uv.Buffer.NumElements = count;
      device->CreateUnorderedAccessView(r.buffer.Get(), &uv, &r.uav);
    }
    return r;
  };
  const UINT cells = static_cast<UINT>(n) * static_cast<UINT>(n);
  Buf state[2] = {makeBuffer(16, cells, nullptr, true), makeBuffer(16, cells, nullptr, true)};
  constexpr UINT kSourceSlots = 512;
  Buf sources = makeBuffer(16, kSourceSlots * 2U, nullptr, false);
  Buf heights = makeBuffer(4, static_cast<UINT>(packed.size()), packed.data(), false);
  Buf shoreBuf = makeBuffer(4, static_cast<UINT>(shore.size()), shore.data(), false);
  D3D11_BUFFER_DESC cbd{};
  cbd.ByteWidth = sizeof(Constants);
  cbd.Usage = D3D11_USAGE_DEFAULT;
  cbd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
  ComPtr<ID3D11Buffer> constantBuffer;
  device->CreateBuffer(&cbd, nullptr, &constantBuffer);
  D3D11_BUFFER_DESC sd{};
  sd.ByteWidth = 16U * cells;
  sd.Usage = D3D11_USAGE_STAGING;
  sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
  sd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
  sd.StructureByteStride = 16;
  ComPtr<ID3D11Buffer> staging;
  device->CreateBuffer(&sd, nullptr, &staging);

  // ---- the look pass: the foam as the water pixel shader shows it (shared code), over a plain blue sea, top down
  // -------------------------------
  const int lookSize =
    args.look > 0 ? static_cast<int>(static_cast<float>(args.look) * static_cast<float>(n) * kCell) : 0;
  ComPtr<ID3D11ComputeShader> lookCs;
  Buf lookOut;
  ComPtr<ID3D11Buffer> lookStaging, lookConstants;
  if (lookSize > 0) {
    // (the lab shades the foam in a compute shader: no screen derivatives, a pixel is a fixed 0.03 units)
    const std::string lookSrc = std::string(R"HLSL(#define fwidth(v) (0.03 + 0.0 * (v))
)HLSL") +
      noiseHlsl + foamHlsl + R"HLSL(
cbuffer LookConstants : register(b0)
{
    float4 lA;   // pixels per unit, cells, cell size, unused
    float4 lB;   // alpha of the crest texture, time, unused, unused
};
StructuredBuffer<float4> State : register(t0);   // height, last height, foam, land
RWStructuredBuffer<uint> Pixels : register(u0);

float4 Cell(int2 c)
{
    int n = (int)lA.y;
    return State[clamp(c.y, 0, n - 1) * n + clamp(c.x, 0, n - 1)];
}

// bilinear sample of the state at a world position
float4 Sample(float2 xz)
{
    float2 g = xz / lA.z - 0.5;
    int2 i = (int2)floor(g);
    float2 f = g - (float2)i;
    return lerp(lerp(Cell(i), Cell(i + int2(1, 0)), f.x), lerp(Cell(i + int2(0, 1)), Cell(i + int2(1, 1)), f.x), f.y);
}

[numthreads(8, 8, 1)]
void LookCS(uint3 id : SV_DispatchThreadID)
{
    int size = (int)(lA.x * lA.y * lA.z);
    if ((int)id.x >= size || (int)id.y >= size)
    {
        return;
    }
    float2 xz = ((float2)id.xy + 0.5) / lA.x;
    float4 here = Sample(xz);
    float3 color;
    if (here.w > 0.5)
    {
        color = float3(0.33, 0.35, 0.24) * (0.8 + 0.4 * FafNoise2(xz * 0.8));   // land
    }
    else
    {
        // the sea: a plain blue, lit by the slope of the waves
        float e = lA.z;
        float hx = Sample(xz + float2(e, 0)).x - Sample(xz - float2(e, 0)).x;
        float hz = Sample(xz + float2(0, e)).x - Sample(xz - float2(0, e)).x;
        float3 N = normalize(float3(-hx * 5.0 / e, 1.0, -hz * 5.0 / e));
        float sun = saturate(dot(N, normalize(float3(0.4, 0.8, 0.3))));
        color = float3(0.04, 0.20, 0.42) * (0.55 + 0.9 * sun);
        // the foam: four taps on the diagonals a bit more than a cell out, as FafWaterFoam does in the game
        float o = 0.45;
        float foam = 0.25 * (Sample(xz + float2(o, o)).z + Sample(xz + float2(-o, o)).z + Sample(xz + float2(o, -o)).z + Sample(xz + float2(-o, -o)).z);
        float amount = FafFoamAmount(foam, xz, lB.x);
        float3 foamColor = float3(0.95, 0.98, 1.0) * (0.8 + 0.2 * sun);
        color = lerp(color, foamColor, amount * 0.92);
    }
    uint3 q = (uint3)(saturate(color) * 255.0 + 0.5);
    Pixels[id.y * (uint)size + id.x] = q.x | (q.y << 8) | (q.z << 16);
}
)HLSL";
    ComPtr<ID3DBlob> lookCode, lookErrors;
    if (
      FAILED(D3DCompile(
        lookSrc.data(), lookSrc.size(), "Look.hlsl", nullptr, nullptr, "LookCS", "cs_5_0", 0, 0, &lookCode, &lookErrors
      ))
    ) {
      std::fprintf(
        stderr,
        "look shader: %s\n",
        lookErrors != nullptr ? static_cast<const char*>(lookErrors->GetBufferPointer()) : "?"
      );
      return 4;
    }
    device->CreateComputeShader(lookCode->GetBufferPointer(), lookCode->GetBufferSize(), nullptr, &lookCs);
    lookOut = makeBuffer(4, static_cast<UINT>(lookSize) * static_cast<UINT>(lookSize), nullptr, true);
    D3D11_BUFFER_DESC lsd{};
    lsd.ByteWidth = 4U * static_cast<UINT>(lookSize) * static_cast<UINT>(lookSize);
    lsd.Usage = D3D11_USAGE_STAGING;
    lsd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    lsd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
    lsd.StructureByteStride = 4;
    device->CreateBuffer(&lsd, nullptr, &lookStaging);
    D3D11_BUFFER_DESC lcd{};
    lcd.ByteWidth = 32;
    lcd.Usage = D3D11_USAGE_DEFAULT;
    lcd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    device->CreateBuffer(&lcd, nullptr, &lookConstants);
  }

  std::filesystem::create_directories(args.out);
  FILE* seriesFile = nullptr;
  FILE* raysFile = nullptr;
  FILE* wakeFile = nullptr;
  if (args.wake) {
    wakeFile = std::fopen((args.out + "/wake.csv").c_str(), "w");
    if (wakeFile != nullptr) {
      // behind the hull at 4, 8, 14, 22, 32, 45 units: the highest wave |h| across the track, how far from the track it
      // is, the foam peak, the width of the foam (> 0.15)
      std::fprintf(wakeFile, "time,hullx,d,hmax,lat,foammax,foamwidth,hmean_track\n");
    }
  }
  if (args.impact) {
    seriesFile = std::fopen((args.out + "/series.csv").c_str(), "w");
    raysFile = std::fopen((args.out + "/rays.csv").c_str(), "w");
    if (seriesFile != nullptr) {
      // time; height in the middle and 4, 8, 16 units out (+x); volume (sum of the height x cell area); energy
      // (height^2 + (speed x 12 steps)^2); highest |height|; foam; cells above 0.02; the wave front radius (outermost
      // cell above 5 % of the peak)
      std::fprintf(seriesFile, "time,h0,h4,h8,h16,volume,energy,maxabs,foam,active,front,foamcells\n");
    }
    if (raysFile != nullptr) {
      std::fprintf(raysFile, "time,ray,r,h\n");
    }
  }
  const float half = 0.5f * static_cast<float>(n) * kCell;
  int current = 0;
  int captureIndex = 0;
  float nextCapture = args.from;
  const int totalSteps = static_cast<int>(args.seconds / kStep);
  std::printf(
    "watersimlab: terrain %s, %d x %d cells, %d steps (%.1f s), shader of the game, WARP\n",
    args.terrain.c_str(),
    n,
    n,
    totalSteps,
    args.seconds
  );
  for (int step = 0; step < totalSteps; ++step) {
    const float time = static_cast<float>(step) * kStep;
    // the impacts of the scenario, handed to the shader the way the game does (parts over their duration, through the
    // gate)
    std::uint32_t sourceCount = 0;
    if (args.wake) {
      struct Emitted
      {
        float x, z, radius, push, foam, kind;
      };
      static std::vector<Emitted> hullSources;
      static moho::water::HullWake hull;
      hullSources.clear();
      const float t = time - 1.0f; // the hull starts at 1 s
      if (t >= 0.0f) {
        moho::water::HullState state;
        state.x = 30.0f + args.hullSpeed * t;
        state.z = half;
        state.hx = 1.0f;
        state.hz = 0.0f;
        state.speed = args.hullSpeed;
        state.halfLength = args.hullHalfLength;
        state.halfBeam = args.hullHalfBeam;
        state.radius = args.hullRadius;
        state.foamScale = args.hullFoam >= 0.0f ? args.hullFoam : moho::water::kHullFoam;
        if (!args.body) {
          hull.Move(
            state,
            time,
            1.0f,
            args.wakeScale,
            [&](const float x, const float z, const float radius, const float push, const float foam) {
            hullSources.push_back(Emitted{x, z, radius, push, foam, 0.0f});
          }
          );
        } else {
          // a ship-shaped volume: the length 2 x hullHalfLength along +x (bow at +x), the width of the beam, a pointed
          // bow, `hullDraft` below the water
          static moho::water::BodyTracker tracker;
          static moho::water::HullFoot foot;
          if (!foot.valid) {
            foot.nx = moho::water::kFootMax;
            foot.nz = 8;
            foot.x0 = -args.hullHalfLength;
            foot.z0 = -args.hullHalfBeam;
            foot.cellX = 2.0f * args.hullHalfLength / static_cast<float>(foot.nx);
            foot.cellZ = 2.0f * args.hullHalfBeam / static_cast<float>(foot.nz);
            for (int j = 0; j < foot.nz; ++j) {
              for (int i = 0; i < foot.nx; ++i) {
                const float u =
                  1.0f - (static_cast<float>(i) + 0.5f) / static_cast<float>(foot.nx); // 0 at the bow, 1 at the stern
                const float width = u < 0.35f ? std::pow(u / 0.35f, 0.65f) : 1.0f - 0.15f * ((u - 0.35f) / 0.65f);
                const float across =
                  std::fabs((static_cast<float>(j) + 0.5f) / static_cast<float>(foot.nz) * 2.0f - 1.0f);
                if (across <= width) {
                  const int k = j * moho::water::kFootMax + i;
                  foot.has[k] = true;
                  foot.bottom[k] = -args.hullDraft;
                  foot.top[k] = 1.0f;
                }
              }
            }
            foot.valid = true;
          }
          tracker.BeginFrame();
          std::vector<moho::water::BodyBin> bins;
          moho::water::BodyBins(
            foot,
            state.x,
            0.0f,
            state.z,
            1.0f,
            1.0f,
            1.0f,
            0.0f,
            [](const float x, const float y, const float z, float& wx, float& wy, float& wz) {
            wx = x;
            wy = y;
            wz = z;
          },
            bins
          );
          const float push = (args.bodyPush >= 0.0f ? args.bodyPush : moho::water::kBodyPush);
          tracker.Update(&foot, bins, [&](const float x, const float z, const float delta) {
            const float foam =
              (delta > 0.0f ? moho::water::kBodyBowFoam * delta : -moho::water::kBodyWashFoam * delta) * args.bodyFoam;
            hullSources.push_back(Emitted{x, z, moho::water::kBodyRadius, push * delta, foam, 0.0f});
          });
          tracker.EndFrame();
        }
      }
      sourceCount = static_cast<std::uint32_t>(std::min<std::size_t>(hullSources.size(), kSourceSlots));
      if (sourceCount > 0) {
        std::vector<float> packedSources(static_cast<std::size_t>(sourceCount) * 8U, 0.0f);
        for (std::uint32_t i = 0; i < sourceCount; ++i) {
          const Emitted& e = hullSources[i];
          float* d = &packedSources[static_cast<std::size_t>(i) * 8U];
          d[0] = e.x;
          d[1] = e.z;
          d[2] = e.radius;
          d[3] = e.push;
          d[4] = e.foam;
          d[5] = e.kind;
        }
        D3D11_BOX box{0, 0, 0, sourceCount * 2U * 16U, 1, 1};
        context->UpdateSubresource(sources.buffer.Get(), 0, &box, packedSources.data(), 0, 0);
      }
    }
    if (args.impact) {
      struct Emitted
      {
        float x, z, radius, push, foam, kind;
      };
      static std::vector<Emitted> emitted;
      emitted.clear();
      static moho::water::ImpactQueue queue;
      static moho::water::ImpactGate gate;
      static std::uint32_t seed = 2463534242u;
      static int fired = 0;
      const auto random = []() {
        seed = seed * 1664525u + 1013904223u;
        return static_cast<float>(seed >> 8) * (1.0f / 16777216.0f);
      };
      while (fired < args.impacts && time >= 1.0f + static_cast<float>(fired) * args.impactGap) {
        ++fired;
        const float cx = half, cz = half;
        const moho::water::ImpactGate::Result g =
          gate.Admit(cx, cz, moho::water::ImpactRadius(args.impactSize), time, random);
        std::vector<moho::water::ImpactPart> parts;
        if (args.legacy) {
          // the first model: 4 to 8 discs of height-only pushes, all in one frame
          const float radius = moho::water::ImpactRadius(args.impactSize);
          const float hump = std::min(std::max(0.03f * args.impactSize, 0.03f), 0.5f) * args.impactScale;
          const int count = 4 + std::min(static_cast<int>(args.impactSize / 4.0f), 4);
          for (int part = 0; part < count; ++part) {
            moho::water::ImpactPart q;
            const float angle = random() * 6.2831853f;
            const float distance = radius * (0.1f + 0.7f * random());
            q.dx = std::cos(angle) * distance;
            q.dz = std::sin(angle) * distance;
            q.radius = radius * (0.35f + 0.25f * random());
            q.push = hump * 90.0f * 0.05f * (0.5f + 0.7f * random()) * (part % 4 == 3 ? -0.6f : 1.0f);
            q.foam =
              std::min(0.03f + 0.01f * args.impactSize, 0.15f) * (0.4f + random()) / static_cast<float>(count) * 2.0f;
            q.kind = 0.0f;
            q.duration = kStep;
            parts.push_back(q);
          }
        } else {
          moho::water::BuildImpact(args.impactSize, 1.0f, args.impactScale * g.factor, random, parts);
        }
        for (const moho::water::ImpactPart& part : parts) {
          moho::water::QueuedPart queued;
          queued.x = cx + g.jitterX + part.dx;
          queued.z = cz + g.jitterZ + part.dz;
          queued.radius = part.radius;
          queued.push = part.push;
          queued.foam = part.foam * g.factor;
          queued.kind = part.kind;
          queued.delay = part.delay;
          queued.duration = std::max(part.duration, 0.01f);
          queued.remaining = queued.duration;
          queue.Add(queued);
        }
      }
      queue.Advance(
        kStep,
        [&](
          const float x,
          const float z,
          const float radius,
          const float push,
          const float foam,
          const float kind,
          const bool
        ) {
        emitted.push_back(Emitted{x, z, radius, push, foam, kind});
      }
      );
      sourceCount = static_cast<std::uint32_t>(std::min<std::size_t>(emitted.size(), kSourceSlots));
      if (sourceCount > 0) {
        // two float4 per source: x, z, radius, push; foam, kind, 0, 0
        std::vector<float> packedSources(static_cast<std::size_t>(sourceCount) * 8U, 0.0f);
        for (std::uint32_t i = 0; i < sourceCount; ++i) {
          const Emitted& e = emitted[i];
          float* d = &packedSources[static_cast<std::size_t>(i) * 8U];
          d[0] = e.x;
          d[1] = e.z;
          d[2] = e.radius;
          d[3] = e.push;
          d[4] = e.foam;
          d[5] = e.kind;
        }
        D3D11_BOX box{0, 0, 0, sourceCount * 2U * 16U, 1, 1};
        context->UpdateSubresource(sources.buffer.Get(), 0, &box, packedSources.data(), 0, 0);
      }
    }
    Constants k{};
    k.a[0] = 0;
    k.a[1] = 0;
    k.a[2] = 0;
    k.a[3] = 0; // origin and previous origin (cells)
    k.b[0] = kCell;
    k.b[1] = static_cast<float>(n);
    k.b[2] = static_cast<float>(sourceCount);
    k.b[3] = kStep; // cell, cells, sources, step seconds
    k.c[0] = moho::water::kWaveTerm;
    k.c[1] = 1.0f - moho::water::kDamping * 0.01f * static_cast<float>(args.damping);
    k.c[2] = half;
    k.c[3] = half; // wave speed term, damping, centre
    k.d[0] = half;
    k.d[1] = openSea ? 0.0f : 0.01f * static_cast<float>(args.shoreWave);
    k.d[2] = static_cast<float>(args.seed);                                        // half extent, shore wave factor
    k.d[3] = moho::water::kCapillary * 0.01f * static_cast<float>(args.capillary); // dispersion
    k.e[0] = static_cast<float>(hw);
    k.e[1] = static_cast<float>(hh);
    k.e[2] = levelRaw;
    k.e[3] = openSea ? 0.0f : 1.0f; // heights, level, land mask
    k.f[0] = time;
    k.f[1] = openSea ? 0.0f : 0.01f * static_cast<float>(args.swell);
    k.f[2] = args.foamKept >= 0.0f ? args.foamKept : moho::water::kFoamKept;
    k.f[3] = openSea ? 0.0f : 1.0f; // time, swell, foam kept, surf
    context->UpdateSubresource(constantBuffer.Get(), 0, nullptr, &k, 0, 0);
    ID3D11ShaderResourceView* srvs[4] = {
      state[current].srv.Get(), sources.srv.Get(), heights.srv.Get(), shoreBuf.srv.Get()
    };
    ID3D11UnorderedAccessView* uavs[1] = {state[current ^ 1].uav.Get()};
    context->CSSetShader(cs.Get(), nullptr, 0);
    context->CSSetConstantBuffers(0, 1, constantBuffer.GetAddressOf());
    context->CSSetShaderResources(0, 4, srvs);
    context->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
    context->Dispatch(static_cast<UINT>(n / 8), static_cast<UINT>(n / 8), 1);
    ID3D11ShaderResourceView* noSrv[4] = {};
    ID3D11UnorderedAccessView* noUav[1] = {};
    context->CSSetShaderResources(0, 4, noSrv);
    context->CSSetUnorderedAccessViews(0, 1, noUav, nullptr);
    current ^= 1;

    if (args.wake && time >= 1.5f && (step % 45) == 0) {
      context->CopyResource(staging.Get(), state[current].buffer.Get());
      D3D11_MAPPED_SUBRESOURCE map{};
      if (SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &map))) {
        const float* c = static_cast<const float*>(map.pData);
        const int mid = n / 2;
        const float hullX = 30.0f + args.hullSpeed * (time - 1.0f);
        for (const float d : {4.0f, 8.0f, 14.0f, 22.0f, 32.0f, 45.0f}) {
          const int cx = static_cast<int>(std::lround((hullX - d) / kCell));
          if (cx < 2 || cx >= n - 2) {
            continue;
          }
          float hmax = 0.0f, lat = 0.0f, foamMax = 0.0f, hTrack = 0.0f;
          int foamLo = 1 << 30, foamHi = -(1 << 30);
          for (int dz = -60; dz <= 60; ++dz) { // +-30 units across the track
            const float* cell =
              &c
                [(static_cast<std::size_t>(mid + dz) * static_cast<std::size_t>(n) + static_cast<std::size_t>(cx)) *
                 4U];
            if (std::fabs(cell[0]) > hmax) {
              hmax = std::fabs(cell[0]);
              lat = static_cast<float>(dz) * kCell;
            }
            foamMax = std::max(foamMax, cell[2]);
            if (cell[2] > 0.15f) {
              foamLo = std::min(foamLo, dz);
              foamHi = std::max(foamHi, dz);
            }
            if (std::abs(dz) <= 1)
              hTrack += cell[0] / 3.0f;
          }
          std::fprintf(
            wakeFile,
            "%.2f,%.1f,%.0f,%.4f,%.2f,%.3f,%.1f,%.4f\n",
            time - 1.0f,
            hullX,
            d,
            hmax,
            lat,
            foamMax,
            foamHi >= foamLo ? static_cast<float>(foamHi - foamLo) * kCell : 0.0f,
            hTrack
          );
        }
        context->Unmap(staging.Get(), 0);
      }
    }

    if (args.impact && time >= 0.9f && (step % 2) == 0) {
      context->CopyResource(staging.Get(), state[current].buffer.Get());
      D3D11_MAPPED_SUBRESOURCE map{};
      if (SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &map))) {
        const float* c = static_cast<const float*>(map.pData);
        const int mid = n / 2;
        const auto at = [&](const int x, const int z) {
          return c[(static_cast<std::size_t>(z) * static_cast<std::size_t>(n) + static_cast<std::size_t>(x)) * 4U];
        };
        double volume = 0.0, energy = 0.0, foam = 0.0;
        float maxabs = 0.0f;
        int active = 0;
        int foamCells = 0;
        for (int z = 0; z < n; ++z) {
          for (int x = 0; x < n; ++x) {
            const float* cell =
              &c[(static_cast<std::size_t>(z) * static_cast<std::size_t>(n) + static_cast<std::size_t>(x)) * 4U];
            const float height = cell[0];
            const float speed = (cell[0] - cell[1]) * 12.0f;
            volume += static_cast<double>(height) * kCell * kCell;
            energy += static_cast<double>(height) * height + static_cast<double>(speed) * speed;
            foam += cell[2];
            maxabs = std::max(maxabs, std::fabs(height));
            active += std::fabs(height) > 0.02f ? 1 : 0;
            foamCells += cell[2] > 0.5f ? 1 : 0;
          }
        }
        // the front: the outermost cell on the +x axis above 5 % of the peak, a measure of how far the waves have run
        int frontCells = 0;
        for (int x = mid; x < n; ++x) {
          if (std::fabs(at(x, mid)) > std::max(0.003f, 0.05f * maxabs)) {
            frontCells = x - mid;
          }
        }
        if (seriesFile != nullptr) {
          std::fprintf(
            seriesFile,
            "%.4f,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f,%.4f,%d,%.2f,%d\n",
            time - 1.0f,
            at(mid, mid),
            at(mid + 8, mid),
            at(mid + 16, mid),
            at(mid + 32, mid),
            volume,
            energy,
            maxabs,
            foam,
            active,
            static_cast<float>(frontCells) * kCell,
            foamCells
          );
        }
        // eight rays from the middle every quarter second: the radial profile of the waves (the python side counts
        // crests and measures roughness)
        if (raysFile != nullptr && (step % 22) == 0) {
          for (int ray = 0; ray < 8; ++ray) {
            const float angle = 0.7853982f * static_cast<float>(ray) + 0.2f;
            for (int i = 0; i < 160; ++i) {
              const float r = 0.5f * static_cast<float>(i);
              const int x = mid + static_cast<int>(std::lround(std::cos(angle) * r / kCell));
              const int z = mid + static_cast<int>(std::lround(std::sin(angle) * r / kCell));
              if (x >= 0 && x < n && z >= 0 && z < n) {
                std::fprintf(raysFile, "%.3f,%d,%.1f,%.5f\n", time - 1.0f, ray, r, at(x, z));
              }
            }
          }
        }
        context->Unmap(staging.Get(), 0);
      }
    }

    if (time >= nextCapture) {
      nextCapture += args.every;
      context->CopyResource(staging.Get(), state[current].buffer.Get());
      D3D11_MAPPED_SUBRESOURCE map{};
      if (SUCCEEDED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &map))) {
        const float* cellsData = static_cast<const float*>(map.pData);
        char name[512];
        std::snprintf(name, sizeof(name), "%s/rec_%05d.bin", args.out.c_str(), captureIndex++);
        if (FILE* const f = std::fopen(name, "wb")) {
          const std::uint32_t header[4] = {0x31435257u, static_cast<std::uint32_t>(n), 0u, 0u};
          const float info[12] = {
            kCell, 0.0f, 0.0f, time, static_cast<float>(step), 1.0f, 1.0f, 1.0f, kStep, half, half, kElevation
          };
          std::fwrite(header, sizeof(header), 1, f);
          std::fwrite(info, sizeof(info), 1, f);
          std::vector<float> height(cells), foam(cells);
          std::vector<std::uint8_t> land(cells);
          for (UINT i = 0; i < cells; ++i) {
            height[i] = cellsData[i * 4U];
            foam[i] = cellsData[i * 4U + 2U];
            land[i] = cellsData[i * 4U + 3U] > 0.5f ? 1U : 0U;
          }
          std::fwrite(height.data(), 4, cells, f);
          std::fwrite(foam.data(), 4, cells, f);
          std::fwrite(land.data(), 1, cells, f);
          std::fclose(f);
        }
        context->Unmap(staging.Get(), 0);
      }
      if (lookSize > 0) {
        const float lc[8] = {
          static_cast<float>(args.look), static_cast<float>(n), kCell, 0.0f, args.suma, time, 0.0f, 0.0f
        };
        context->UpdateSubresource(lookConstants.Get(), 0, nullptr, lc, 0, 0);
        ID3D11ShaderResourceView* lookSrv[1] = {state[current].srv.Get()};
        ID3D11UnorderedAccessView* lookUav[1] = {lookOut.uav.Get()};
        context->CSSetShader(lookCs.Get(), nullptr, 0);
        context->CSSetConstantBuffers(0, 1, lookConstants.GetAddressOf());
        context->CSSetShaderResources(0, 1, lookSrv);
        context->CSSetUnorderedAccessViews(0, 1, lookUav, nullptr);
        const UINT groups = (static_cast<UINT>(lookSize) + 7U) / 8U;
        context->Dispatch(groups, groups, 1);
        ID3D11ShaderResourceView* noLook[1] = {};
        ID3D11UnorderedAccessView* noLookUav[1] = {};
        context->CSSetShaderResources(0, 1, noLook);
        context->CSSetUnorderedAccessViews(0, 1, noLookUav, nullptr);
        context->CopyResource(lookStaging.Get(), lookOut.buffer.Get());
        D3D11_MAPPED_SUBRESOURCE lm{};
        if (SUCCEEDED(context->Map(lookStaging.Get(), 0, D3D11_MAP_READ, 0, &lm))) {
          const std::uint32_t* px = static_cast<const std::uint32_t*>(lm.pData);
          char bmpName[512];
          std::snprintf(bmpName, sizeof(bmpName), "%s/look_%05d.bmp", args.out.c_str(), captureIndex - 1);
          if (FILE* const f = std::fopen(bmpName, "wb")) {
            const std::uint32_t rowBytes = static_cast<std::uint32_t>(lookSize) * 3U;
            const std::uint32_t pad = (4U - rowBytes % 4U) % 4U;
            const std::uint32_t dataBytes = (rowBytes + pad) * static_cast<std::uint32_t>(lookSize);
            std::uint8_t header[54] = {'B', 'M'};
            const std::uint32_t fileBytes = 54U + dataBytes;
            std::memcpy(header + 2, &fileBytes, 4);
            const std::uint32_t offset = 54U, dib = 40U;
            const std::uint16_t planes = 1U, bits = 24U;
            std::memcpy(header + 10, &offset, 4);
            std::memcpy(header + 14, &dib, 4);
            const std::int32_t w = lookSize, h = lookSize;
            std::memcpy(header + 18, &w, 4);
            std::memcpy(header + 22, &h, 4);
            std::memcpy(header + 26, &planes, 2);
            std::memcpy(header + 28, &bits, 2);
            std::memcpy(header + 34, &dataBytes, 4);
            std::fwrite(header, 1, 54, f);
            std::vector<std::uint8_t> row(rowBytes + pad, 0);
            for (int y = lookSize - 1; y >= 0; --y) { // BMP rows run bottom up
              for (int x = 0; x < lookSize; ++x) {
                const std::uint32_t c =
                  px[static_cast<std::size_t>(y) * static_cast<std::size_t>(lookSize) + static_cast<std::size_t>(x)];
                row[static_cast<std::size_t>(x) * 3U + 0U] = static_cast<std::uint8_t>((c >> 16) & 255U);
                row[static_cast<std::size_t>(x) * 3U + 1U] = static_cast<std::uint8_t>((c >> 8) & 255U);
                row[static_cast<std::size_t>(x) * 3U + 2U] = static_cast<std::uint8_t>(c & 255U);
              }
              std::fwrite(row.data(), 1, row.size(), f);
            }
            std::fclose(f);
          }
          context->Unmap(lookStaging.Get(), 0);
        }
      }
    }
  }
  if (seriesFile != nullptr)
    std::fclose(seriesFile);
  if (raysFile != nullptr)
    std::fclose(raysFile);
  if (wakeFile != nullptr)
    std::fclose(wakeFile);
  std::printf("watersimlab: %d captures in %s\n", captureIndex, args.out.c_str());
  return 0;
}

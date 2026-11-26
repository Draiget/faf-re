// Engine addition, not in the binary: the flow texture and the shader variables of the rivers of a map, see
// RiverFlow.h.
#include "moho/terrain/water/RiverFlow.h"
#include "moho/terrain/water/RiverFlowBind.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>

#include <memory>
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/EffectVariable.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"

namespace moho::water
{
  int ren_River = 1;
  static int ren_RiverFlow = 100;
  static int ren_RiverFoam = 100;
  static int ren_RiverDebug = 0;

  static TConVar<int> gTConVar_ren_River(
    "ren_River",
    "Rivers (docs/projects/RIVERS.md): 1 (the default) the surface of a river is sloped, its water flows (the normals "
    "scroll along the current, faster where the river falls steeply) and steep reaches are white; 0 the rivers are "
    "drawn flat and still. Takes effect at the next map load for the shader patch. Render only.",
    &ren_River
  );
  static TConVar<int> gTConVar_ren_RiverFlow(
    "ren_RiverFlow",
    "How fast the water of a river flows, in percent of the speed its slope and depth give (default 100, 0 still "
    "water). Live; render only.",
    &ren_RiverFlow
  );
  static TConVar<int> gTConVar_ren_RiverFoam(
    "ren_RiverFoam",
    "How white the rapids and shallow fast reaches of a river are, in percent (default 100, 0 none). Live; render "
    "only.",
    &ren_RiverFoam
  );

  static TConVar<int> gTConVar_ren_RiverDebug(
    "ren_RiverDebug",
    "A view of the flow of the rivers instead of their colour: 1 the turbulence (white water), 2 the speed, 3 the "
    "weight of "
    "the river, 4 the direction, 5 the white water drawn, 6 to 8 the texel's alpha, blue and colour, 9 the third "
    "normal layer, 10 a grid of ten "
    "world units; 0 (the default) the water.",
    &ren_RiverDebug
  );

  namespace
  {
    // gal format 2: A8R8G8B8 (a texel is the 32-bit word PackRiverFlowTexel makes)
    constexpr int kFlowTextureFormat = 2;

    struct Vars
    {
      ShaderVar params{};
      ShaderVar debug{};
      ShaderVar flow{};
      Vars()
      {
        RegisterShaderVar("waterRiverParams", &params, "water2");
        RegisterShaderVar("waterRiverDebug", &debug, "water2");
        RegisterShaderVar("waterFlow", &flow, "water2");
      }
    };

    struct State
    {
      Vars vars;
      std::shared_ptr<CD3DDynamicTextureSheet> texture;
      const STIMap* map{nullptr};
      std::uint32_t generation{0};
      // what the effect holds: x 1 = a river's mesh is drawn, y flow scale, z white water scale, w phase ticks (0 off)
      float params[4]{0.0f, 0.0f, 0.0f, 0.0f};
      bool bound{false};
    };

    /// Never destroyed: the effect unlinks its shader vars on its own schedule, and the sheet must not outlive the
    /// device at exit.
    State& GetState()
    {
      static State* const state = new State();
      return *state;
    }

    void PushParams(
      State& s
    )
    {
      if (s.vars.params.Exists()) {
        s.vars.params.mEffectVariable->SetVector(s.params);
      }
      if (s.vars.debug.Exists()) {
        const float debug[4] = {static_cast<float>(ren_RiverDebug), 0.0f, 0.0f, 0.0f};
        s.vars.debug.mEffectVariable->SetVector(debug);
      }
    }

    // The 2 x 2 block whose first corner is vertex (x, z): what the shader reads.
    SRiverFlowTexel BlockTexel(
      const STIMap& map,
      const CWaterBodies& bodies,
      const std::int32_t x,
      const std::int32_t z
    )
    {
      const CWaterRiver* const river = bodies.River(bodies.BodyOfBlock(x, z));
      if (river == nullptr) {
        return {};
      }
      const float cx = static_cast<float>(x) + 1.0f;
      const float cz = static_cast<float>(z) + 1.0f;
      float level = 0.0f;
      if (!river->LevelAt(cx, cz, level)) {
        return {};
      }
      const auto levelOr = [&](const float px, const float pz) {
        float l = level;
        return river->LevelAt(px, pz, l) ? l : level;
      };
      float fx = 0.0f;
      float fz = 0.0f;
      if (!river->FlowAt(cx, cz, fx, fz)) {
        fx = 0.0f;
        fz = 0.0f;
      }
      bool fall = false;
      for (std::int32_t dz = 0; dz < 2 && !fall; ++dz) {
        for (std::int32_t dx = 0; dx < 2 && !fall; ++dx) {
          fall = river->IsFallCell(x + dx, z + dz);
        }
      }
      const float depth = level - map.GetHeightField()->GetElevation(cx, cz);
      return RiverBlockFlow(
        levelOr(cx - 1.0f, cz),
        levelOr(cx + 1.0f, cz),
        levelOr(cx, cz - 1.0f),
        levelOr(cx, cz + 1.0f),
        fx,
        fz,
        depth,
        fall,
        river->FlowScale()
      );
    }
  } // namespace

  bool RiverPatchWanted()
  {
    return ren_River != 0;
  }

  std::shared_ptr<CD3DDynamicTextureSheet> RiverFlowTexture(
    IWldTerrainRes* const terrainRes
  )
  {
    State& s = GetState();
    const STIMap* const map = terrainRes != nullptr ? terrainRes->mMap : nullptr;
    if (
      map == nullptr || !map->HasWaterBodies() || !map->mWaterBodies->HasRivers() || map->GetHeightField() == nullptr
    ) {
      s.texture.reset();
      s.map = nullptr;
      s.generation = 0u;
      return {};
    }
    const CWaterBodies& bodies = *map->mWaterBodies;
    if (s.texture != nullptr && s.map == map && s.generation == bodies.Generation()) {
      return s.texture;
    }
    s.texture.reset();
    const CHeightField* const field = map->GetHeightField();
    const std::int32_t texelsX = (field->width - 1) >> 1;
    const std::int32_t texelsZ = (field->height - 1) >> 1;
    ID3DDeviceResources::DynamicTextureSheetHandle sheet{};
    (void)D3D_GetDevice()->GetResources()->CreateDynamicTextureSheet2(sheet, texelsX, texelsZ, kFlowTextureFormat);
    std::uint32_t pitch = 0U;
    void* bits = nullptr;
    if (!sheet || !sheet->Lock(&pitch, &bits) || bits == nullptr) {
      gpg::Warnf("Rivers: the flow texture could not be made; the rivers do not flow");
      return {};
    }
    std::size_t riverTexels = 0;
    std::size_t whiteTexels = 0;
    double speedSum = 0.0;
    float speedMax = 0.0f;
    auto* const row0 = static_cast<std::uint8_t*>(bits);
    for (std::int32_t hz = 0; hz < texelsZ; ++hz) {
      auto* const row = reinterpret_cast<std::uint32_t*>(row0 + static_cast<std::size_t>(hz) * pitch);
      for (std::int32_t hx = 0; hx < texelsX; ++hx) {
        const SRiverFlowTexel texel = BlockTexel(*map, bodies, hx * 2, hz * 2);
        row[hx] = PackRiverFlowTexel(texel);
        if (texel.river) {
          ++riverTexels;
          whiteTexels += texel.turbulence > 0.5f ? 1u : 0u;
          speedSum += texel.speed;
          speedMax = std::max(speedMax, texel.speed);
        }
      }
    }
    sheet->Unlock();
    // with ren_RiverDebug on: the flow along each river's centreline, a dozen places (what the shader reads there)
    for (std::size_t number = 1; ren_RiverDebug != 0 && number <= bodies.BodyCount(); ++number) {
      const CWaterRiver* const river = bodies.River(static_cast<std::uint8_t>(number));
      if (river == nullptr) {
        continue;
      }
      const auto& segments = river->Segments();
      const std::size_t stride = std::max<std::size_t>(segments.size() / 12u, 1u);
      for (std::size_t i = 0; i < segments.size(); i += stride) {
        const SRiverSegment& seg = segments[i];
        const float mx = 0.5f * (seg.x0 + seg.x1);
        const float mz = 0.5f * (seg.z0 + seg.z1);
        const SRiverFlowTexel texel =
          BlockTexel(*map, bodies, static_cast<std::int32_t>(mx) & ~1, static_cast<std::int32_t>(mz) & ~1);
        gpg::Logf(
          "Rivers: body %zu at (%.0f, %.0f) level %.2f, bed %.2f: flow (%.2f, %.2f) speed %.2f white %.2f",
          number,
          static_cast<double>(mx),
          static_cast<double>(mz),
          static_cast<double>(0.5f * (seg.level0 + seg.level1)),
          static_cast<double>(map->GetHeightField()->GetElevation(
            static_cast<float>(static_cast<std::int32_t>(mx) | 1), static_cast<float>(static_cast<std::int32_t>(mz) | 1)
          )),
          static_cast<double>(texel.dx),
          static_cast<double>(texel.dz),
          static_cast<double>(texel.speed),
          static_cast<double>(texel.turbulence)
        );
      }
    }
    s.texture = sheet;
    s.map = map;
    s.generation = bodies.Generation();
    gpg::Logf(
      "Rivers: flow texture %dx%d, %zu river blocks, speed %.2f units/s on average and %.2f at most, %zu blocks white",
      texelsX,
      texelsZ,
      riverTexels,
      riverTexels != 0u ? speedSum / static_cast<double>(riverTexels) : 0.0,
      static_cast<double>(speedMax),
      whiteTexels
    );
    return s.texture;
  }

  void BindRiverFlow(
    IWldTerrainRes* const terrainRes
  )
  {
    State& s = GetState();
    std::shared_ptr<CD3DDynamicTextureSheet> texture;
    if (ren_River != 0) {
      texture = RiverFlowTexture(terrainRes);
    }
    s.params[0] = 0.0f;
    s.params[1] = 0.01f * static_cast<float>(std::max(ren_RiverFlow, 0));
    s.params[2] = 0.01f * static_cast<float>(std::max(ren_RiverFoam, 0));
    s.params[3] = texture != nullptr ? kRiverPhaseTicks : 0.0f;
    if (texture != nullptr && s.vars.flow.Exists()) {
      s.vars.flow.GetTexture(std::static_pointer_cast<ID3DTextureSheet>(texture));
      s.bound = true;
    } else if (s.bound && s.vars.flow.Exists()) {
      s.vars.flow.GetTexture(std::shared_ptr<ID3DTextureSheet>());
      s.bound = false;
    }
    PushParams(s);
  }

  void BindRiverMesh(
    const bool river
  )
  {
    State& s = GetState();
    const float value = river && s.params[3] > 0.5f ? 1.0f : 0.0f;
    if (s.params[0] != value) {
      s.params[0] = value;
      PushParams(s);
    }
  }

  void ReleaseRiverFlow()
  {
    State& s = GetState();
    s.texture.reset();
    s.map = nullptr;
    s.generation = 0u;
    s.bound = false;
    s.params[0] = s.params[1] = s.params[2] = s.params[3] = 0.0f;
  }
} // namespace moho::water

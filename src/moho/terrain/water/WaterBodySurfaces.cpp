// Engine addition, not in the binary: see WaterBodySurfaces.h.
#include "moho/terrain/water/WaterBodySurfaces.h"

#include <algorithm>
#include <cstdint>
#include <map>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"

namespace moho
{
  namespace
  {
    /// The water quad's vertex format: x, y, z, u, v (`HighFidelityWater::InitVerts`).
    constexpr int kWaterVertexFormatToken = 3;
    /// 16-bit indices: at most this many quads (4 vertices each) per sheet.
    constexpr std::size_t kQuadsPerChunk = 16000u;

    struct SWaterVertex
    {
      float x;
      float y;
      float z;
      float u;
      float v;
    };
    static_assert(sizeof(SWaterVertex) == 0x14, "the water quad's vertex is 0x14 bytes");

    /// One run of texels of one water along a texel row.
    struct SRun
    {
      std::int32_t hx0;
      std::int32_t hx1;
      std::int32_t hz;
    };

    struct SState
    {
      const STIMap* map{nullptr};
      std::uint32_t generation{0};
      std::vector<WaterBodySurfaces::Level> levels;

      bool mirrored{false};
      float mirroredLevel{0.0f};
      boost::shared_ptr<ID3DRenderTarget> bodyTarget;
      boost::shared_ptr<ID3DRenderTarget> emptyTarget;
    };

    /// Never destroyed: the sheets it holds must not outlive the device at exit.
    SState& State()
    {
      static SState* const state = new SState();
      return *state;
    }

    void ReleaseLevels(std::vector<WaterBodySurfaces::Level>& levels)
    {
      for (WaterBodySurfaces::Level& level : levels) {
        for (WaterBodySurfaces::Chunk& chunk : level.chunks) {
          delete chunk.vertices;
          delete chunk.indices;
        }
      }
      levels.clear();
    }

    [[nodiscard]] bool BuildChunk(
      const std::vector<SRun>& runs,
      const std::size_t first,
      const std::size_t count,
      const float elevation,
      const float extentX,
      const float extentZ,
      WaterBodySurfaces::Chunk& out
    )
    {
      ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
      CD3DVertexFormat* const format = resources->GetVertexFormat(kWaterVertexFormatToken);
      if (format == nullptr) {
        return false;
      }
      const int vertexCount = static_cast<int>(count * 4u);
      const int indexCount = static_cast<int>(count * 6u);
      CD3DVertexSheet* const vertices = resources->NewVertexSheet(0U, vertexCount, format);
      CD3DIndexSheet* const indices = resources->CreateIndexSheet(false, indexCount);
      if (vertices == nullptr || indices == nullptr) {
        delete vertices;
        delete indices;
        return false;
      }

      ID3DVertexStream* const stream = vertices->GetVertStream(0U);
      auto* const vertex = static_cast<SWaterVertex*>(stream->Lock(0, vertices->Func5(), false, false));
      std::int16_t* const index = indices->Lock(0U, indices->GetSize(), true, false);
      for (std::size_t i = 0; i < count; ++i) {
        const SRun& run = runs[first + i];
        const float x0 = static_cast<float>(run.hx0 * 2);
        const float x1 = static_cast<float>(run.hx1 * 2);
        const float z0 = static_cast<float>(run.hz * 2);
        const float z1 = z0 + 2.0f;
        SWaterVertex* const quad = vertex + i * 4u;
        quad[0] = {x0, elevation, z0, x0 / extentX, z0 / extentZ};
        quad[1] = {x1, elevation, z0, x1 / extentX, z0 / extentZ};
        quad[2] = {x0, elevation, z1, x0 / extentX, z1 / extentZ};
        quad[3] = {x1, elevation, z1, x1 / extentX, z1 / extentZ};
        // The sea quad's winding (`HighFidelityWater::InitVerts`): 0 2 1, 1 2 3.
        const auto base = static_cast<std::uint16_t>(i * 4u);
        std::int16_t* const tri = index + i * 6u;
        tri[0] = static_cast<std::int16_t>(base + 0u);
        tri[1] = static_cast<std::int16_t>(base + 2u);
        tri[2] = static_cast<std::int16_t>(base + 1u);
        tri[3] = static_cast<std::int16_t>(base + 1u);
        tri[4] = static_cast<std::int16_t>(base + 2u);
        tri[5] = static_cast<std::int16_t>(base + 3u);
      }
      stream->Unlock();
      indices->Unlock();

      out.vertices = vertices;
      out.indices = indices;
      return true;
    }

    void Build(const STIMap& map, std::vector<WaterBodySurfaces::Level>& levels)
    {
      const CHeightField* const field = map.mHeightField.get();
      const std::int32_t texelsX = (field->width - 1) >> 1;
      const std::int32_t texelsZ = (field->height - 1) >> 1;
      const float extentX = static_cast<float>(texelsX * 2);
      const float extentZ = static_cast<float>(texelsZ * 2);

      // Runs of texels per water, keyed by body number (0 the sea).
      std::map<std::uint8_t, std::vector<SRun>> runsOf;
      std::map<std::uint8_t, float> levelOf;
      for (std::int32_t hz = 0; hz < texelsZ; ++hz) {
        std::int32_t hx = 0;
        while (hx < texelsX) {
          const SWaterOfBlock water = WaterOfBlock(map, hx * 2, hz * 2);
          std::int32_t end = hx + 1;
          while (end < texelsX && WaterOfBlock(map, end * 2, hz * 2).body == water.body) {
            ++end;
          }
          if (water.level != kWaterBodyNoWater) {
            runsOf[water.body].push_back({hx, end, hz});
            levelOf[water.body] = water.level;
          }
          hx = end;
        }
      }

      std::size_t quads = 0;
      for (const auto& [body, runs] : runsOf) {
        WaterBodySurfaces::Level level;
        level.elevation = levelOf[body];
        level.sea = body == 0u;
        for (std::size_t first = 0; first < runs.size(); first += kQuadsPerChunk) {
          WaterBodySurfaces::Chunk chunk;
          const std::size_t count = std::min(kQuadsPerChunk, runs.size() - first);
          if (BuildChunk(runs, first, count, level.elevation, extentX, extentZ, chunk)) {
            level.chunks.push_back(chunk);
            quads += count;
          }
        }
        levels.push_back(std::move(level));
      }
      gpg::Logf("Water bodies: drawing %zu waters in %zu quads", levels.size(), quads);
    }
  } // namespace

  SWaterOfBlock WaterOfBlock(const STIMap& map, const std::int32_t x, const std::int32_t z) noexcept
  {
    const bool sea = map.mWaterEnabled != 0u;
    SWaterOfBlock water{
      sea ? map.mWaterElevation : kWaterBodyNoWater,
      sea ? map.mWaterElevationDeep : kWaterBodyNoWater,
      sea ? map.mWaterElevationAbyss : kWaterBodyNoWater,
      0u,
    };
    if (!map.HasWaterBodies()) {
      return water;
    }
    const std::uint8_t body = map.mWaterBodies->BodyOfBlock(x, z);
    if (body != 0u) {
      const SWaterBody& owner = map.mWaterBodies->Body(body);
      water = {owner.elevation, owner.deep, owner.abyss, body};
    }
    return water;
  }

  std::uint32_t WaterBodiesGeneration(const STIMap& map) noexcept
  {
    return map.HasWaterBodies() ? map.mWaterBodies->Generation() : 0u;
  }

  float WaterBodyTerrainShaderLevel(const STIMap& map) noexcept
  {
    const float sea = map.mWaterEnabled != 0u ? map.mWaterElevation : kWaterBodyNoWater;
    return map.HasWaterBodies() ? std::max(sea, map.mWaterBodies->HighestLevel()) : sea;
  }

  const std::vector<WaterBodySurfaces::Level>* WaterBodySurfaces::For(IWldTerrainRes* const terrainRes)
  {
    SState& state = State();
    const STIMap* const map = terrainRes != nullptr ? terrainRes->mMap : nullptr;
    const std::uint32_t generation = map != nullptr ? WaterBodiesGeneration(*map) : 0u;
    if (generation == 0u) {
      if (!state.levels.empty()) {
        ReleaseLevels(state.levels);
      }
      state.map = nullptr;
      state.generation = 0u;
      return nullptr;
    }
    if (state.map != map || state.generation != generation) {
      ReleaseLevels(state.levels);
      Build(*map, state.levels);
      state.map = map;
      state.generation = generation;
    }
    return &state.levels;
  }

  void WaterBodySurfaces::Release()
  {
    SState& state = State();
    ReleaseLevels(state.levels);
    state.map = nullptr;
    state.generation = 0u;
    state.mirrored = false;
    state.bodyTarget.reset();
    state.emptyTarget.reset();
  }

  boost::shared_ptr<ID3DRenderTarget> WaterBodySurfaces::ReflectionFor(const float level)
  {
    const SState& state = State();
    if (state.mirrored && state.mirroredLevel == level && state.bodyTarget) {
      return state.bodyTarget;
    }
    return state.emptyTarget;
  }

  void WaterBodySurfaces::SetBodyReflection(
    const bool mirrored,
    const float level,
    const boost::shared_ptr<ID3DRenderTarget>& bodyTarget,
    const boost::shared_ptr<ID3DRenderTarget>& emptyTarget
  )
  {
    SState& state = State();
    state.mirrored = mirrored;
    state.mirroredLevel = level;
    state.bodyTarget = bodyTarget;
    state.emptyTarget = emptyTarget;
  }
} // namespace moho

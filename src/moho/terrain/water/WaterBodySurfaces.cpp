// Engine addition, not in the binary: see WaterBodySurfaces.h.
#include "moho/terrain/water/WaterBodySurfaces.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <mutex>

#include "gpg/core/utils/Logging.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WaterBodies.h"
#include "moho/terrain/water/RiverFlow.h"
#include "moho/terrain/water/RiverFlowBind.h"
#include "moho/terrain/water/WaterBanks.h"
#include "moho/terrain/water/WaterBanksBind.h"
#include "moho/terrain/water/WaterLevelTexel.h"

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
      /// The rectangle in world units: a run of blocks of one water (two units high), or one cell of a river.
      std::int32_t x0;
      std::int32_t x1;
      std::int32_t z0;
      std::int32_t z1;
      /// The heights of the four corners (a river's cell; the others use the water's level).
      float y[4];
    };

    struct SState
    {
      const STIMap* map{nullptr};
      std::uint32_t generation{0};
      std::vector<WaterBodySurfaces::Level> levels;
      std::shared_ptr<CD3DDynamicTextureSheet> owner;
      std::uint32_t ownerGeneration{0};
      const STIMap* ownerMap{nullptr};
      std::shared_ptr<CD3DDynamicTextureSheet> levelMap;
      std::uint32_t levelGeneration{0};
      const STIMap* levelMapOf{nullptr};

      bool mirrored{false};
      float mirroredLevel{0.0f};
      std::shared_ptr<ID3DRenderTarget> bodyTarget;
      std::shared_ptr<ID3DRenderTarget> emptyTarget;
    };

    /// Never destroyed: the sheets it holds must not outlive the device at exit.
    SState& State()
    {
      static SState* const state = new SState();
      return *state;
    }

    /// The banks of a map's rivers (WaterBanks.h): the vertices the renderer adds to a river's water, per vertex of
    /// the height field. Made once for a map's bodies (the console variable is read then), shared by every reader
    /// of `WaterOfBlock`.
    struct SBanks
    {
      const STIMap* map{nullptr};
      std::uint32_t generation{0};
      std::int32_t width{0};
      std::int32_t height{0};
      std::size_t grown{0};
      /// Empty when no vertex was grown.
      std::vector<std::uint8_t> body;
      std::vector<float> level;
    };

    std::mutex& BanksLock()
    {
      static std::mutex* const lock = new std::mutex();
      return *lock;
    }

    SBanks& BanksState()
    {
      static SBanks* const banks = new SBanks();
      return *banks;
    }

    /// What `water::GrowBanks` asks of a map's bodies: the level of the water of a body at a vertex beside it.
    struct SBankField
    {
      const CWaterBodies* bodies{nullptr};
      /// World units past a river's half width, cells from a lake's water.
      float reach{0.0f};
    };

    /// A river's own level field where it has one (the sim's, quantised), else the level of the nearest point of the
    /// centreline (the way the field is made, carried on past its support), as long as the vertex is within the half
    /// width there plus the reach.
    bool BankLevel(
      const void* const context,
      const std::uint8_t body,
      const std::int32_t x,
      const std::int32_t z,
      const std::int32_t ring,
      float& level
    )
    {
      const SBankField& field = *static_cast<const SBankField*>(context);
      const CWaterRiver* const river = field.bodies->River(body);
      if (river == nullptr) {
        // a lake: its level, as many cells from its water as the reach
        level = field.bodies->Body(body).elevation;
        return static_cast<float>(ring) < field.reach;
      }
      if (river->VertexLevel(x, z, level)) {
        return true;
      }
      const float px = static_cast<float>(x);
      const float pz = static_cast<float>(z);
      float bestDistance = 1.0e30f;
      float bestLevel = 0.0f;
      float bestHalf = 0.0f;
      for (const SRiverSegment& segment : river->Segments()) {
        const float dx = segment.x1 - segment.x0;
        const float dz = segment.z1 - segment.z0;
        const float lengthSquared = dx * dx + dz * dz;
        float t = lengthSquared > 0.0f ? ((px - segment.x0) * dx + (pz - segment.z0) * dz) / lengthSquared : 0.0f;
        t = std::clamp(t, 0.0f, 1.0f);
        const float ex = px - (segment.x0 + dx * t);
        const float ez = pz - (segment.z0 + dz * t);
        const float distance = ex * ex + ez * ez;
        if (distance < bestDistance) {
          bestDistance = distance;
          bestLevel = segment.level0 + (segment.level1 - segment.level0) * t;
          bestHalf = segment.half0 + (segment.half1 - segment.half0) * t;
        }
      }
      const float limit = bestHalf + field.reach;
      if (!(bestDistance <= limit * limit)) {
        return false;
      }
      level = bestLevel;
      return true;
    }

    /// The grown vertices of `map`'s bodies, null when there are none (no bodies, the switch off). Call with
    /// `BanksLock()` held; the result is valid until the next call for another map or generation.
    const SBanks* GrownBanks(
      const STIMap& map
    )
    {
      SBanks& banks = BanksState();
      const std::uint32_t generation = WaterBodiesGeneration(map);
      if (banks.map == &map && banks.generation == generation) {
        return banks.body.empty() ? nullptr : &banks;
      }
      banks.map = &map;
      banks.generation = generation;
      banks.grown = 0;
      banks.body.clear();
      banks.level.clear();
      const CHeightField* const field = map.mHeightField.get();
      if (
        generation == 0u || !map.HasWaterBodies() || field == nullptr || field->data == nullptr ||
        !water::BankGrowthWanted()
      ) {
        return nullptr;
      }
      const CWaterBodies& bodies = *map.mWaterBodies;
      const std::int32_t width = field->width;
      const std::int32_t height = field->height;
      const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
      std::vector<float> terrain(count);
      std::vector<std::uint8_t> body(count);
      bool grows[256] = {};
      for (std::size_t number = 1; number <= bodies.BodyCount() && number < 256u; ++number) {
        // a river or a lake with water (a dry body is no water to grow)
        grows[number] = bodies.Body(static_cast<std::uint8_t>(number)).elevation != kWaterBodyNoWater;
      }
      for (std::int32_t z = 0; z < height; ++z) {
        for (std::int32_t x = 0; x < width; ++x) {
          const std::size_t i =
            static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x);
          terrain[i] = static_cast<float>(field->data[i]) * (1.0f / 128.0f);
          const std::uint8_t owner = bodies.BodyOfVertex(x, z);
          body[i] = owner;
        }
      }
      const float seaLevel = map.mWaterEnabled != 0u ? map.mWaterElevation : kWaterBodyNoWater;
      std::vector<std::uint8_t> grownBody(count);
      std::vector<float> grownLevel(count);
      // four-neighbour rings are at most 1.5 times the straight distance, and the field's own limit is the reach
      const SBankField bankField{&bodies, static_cast<float>(water::BankReach())};
      const std::size_t grown = water::GrowBanks(
        width,
        height,
        terrain.data(),
        body.data(),
        grows,
        seaLevel,
        water::BankReach() * 3 / 2 + 2,
        &BankLevel,
        &bankField,
        grownBody.data(),
        grownLevel.data()
      );
      gpg::Logf("Water banks: %zu vertices beside the bodies join their water (reach %d)", grown, water::BankReach());
      if (grown == 0u) {
        return nullptr;
      }
      banks.width = width;
      banks.height = height;
      banks.grown = grown;
      banks.body = std::move(grownBody);
      banks.level = std::move(grownLevel);
      return &banks;
    }

    /// The body of the block whose first corner is vertex `(x, z)`, with the banks of the rivers: the sim's, and for a
    /// block that no body owns the lowest body among the grown vertices of its nine.
    std::uint8_t BlockBody(
      const STIMap& map,
      const std::int32_t x,
      const std::int32_t z
    )
    {
      std::uint8_t owner = map.mWaterBodies->BodyOfBlock(x, z);
      if (owner != 0u) {
        return owner;
      }
      const std::scoped_lock lock(BanksLock());
      if (const SBanks* const banks = GrownBanks(map); banks != nullptr) {
        for (std::int32_t dz = 0; dz < 3; ++dz) {
          for (std::int32_t dx = 0; dx < 3; ++dx) {
            const std::int32_t vx = std::clamp(x + dx, 0, banks->width - 1);
            const std::int32_t vz = std::clamp(z + dz, 0, banks->height - 1);
            const std::uint8_t grown =
              banks->body
                [static_cast<std::size_t>(vz) * static_cast<std::size_t>(banks->width) + static_cast<std::size_t>(vx)];
            if (grown != 0u && (owner == 0u || grown < owner)) {
              owner = grown;
            }
          }
        }
      }
      return owner;
    }

    /// The level of a grown vertex of river `body`; false when the vertex is not one of its grown vertices.
    bool GrownLevel(
      const STIMap& map,
      const std::uint8_t body,
      const std::int32_t x,
      const std::int32_t z,
      float& level
    )
    {
      const std::scoped_lock lock(BanksLock());
      const SBanks* const banks = GrownBanks(map);
      if (banks == nullptr || x < 0 || z < 0 || x >= banks->width || z >= banks->height) {
        return false;
      }
      const std::size_t i =
        static_cast<std::size_t>(z) * static_cast<std::size_t>(banks->width) + static_cast<std::size_t>(x);
      if (banks->body[i] != body) {
        return false;
      }
      level = banks->level[i];
      return true;
    }

    void ReleaseLevels(
      std::vector<WaterBodySurfaces::Level>& levels
    )
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
      const bool sloped,
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
        const float x0 = static_cast<float>(run.x0);
        const float x1 = static_cast<float>(run.x1);
        const float z0 = static_cast<float>(run.z0);
        const float z1 = static_cast<float>(run.z1);
        SWaterVertex* const quad = vertex + i * 4u;
        quad[0] = {x0, sloped ? run.y[0] : elevation, z0, x0 / extentX, z0 / extentZ};
        quad[1] = {x1, sloped ? run.y[1] : elevation, z0, x1 / extentX, z0 / extentZ};
        quad[2] = {x0, sloped ? run.y[2] : elevation, z1, x0 / extentX, z1 / extentZ};
        quad[3] = {x1, sloped ? run.y[3] : elevation, z1, x1 / extentX, z1 / extentZ};
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

    void Build(
      const STIMap& map,
      std::vector<WaterBodySurfaces::Level>& levels
    )
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
          if (water.body != 0u && map.mWaterBodies->IsRiver(water.body)) {
            // a river: a quad for each of the block's four cells, each corner at the river's level there
            float vertex[9];
            if (RiverBlockVertices(map, hx * 2, hz * 2, vertex)) {
              for (std::int32_t j = 0; j < 2; ++j) {
                for (std::int32_t i = 0; i < 2; ++i) {
                  runsOf[water.body].push_back(
                    {hx * 2 + i,
                     hx * 2 + i + 1,
                     hz * 2 + j,
                     hz * 2 + j + 1,
                     {vertex[3 * j + i], vertex[3 * j + i + 1], vertex[3 * (j + 1) + i], vertex[3 * (j + 1) + i + 1]}}
                  );
                }
              }
              levelOf[water.body] = map.mWaterBodies->Body(water.body).elevation;
            }
            ++hx;
            continue;
          }
          std::int32_t end = hx + 1;
          while (end < texelsX && WaterOfBlock(map, end * 2, hz * 2).body == water.body) {
            ++end;
          }
          if (water.level != kWaterBodyNoWater) {
            runsOf[water.body].push_back({hx * 2, end * 2, hz * 2, hz * 2 + 2, {0.0f, 0.0f, 0.0f, 0.0f}});
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
        level.body = body;
        level.river = body != 0u && map.HasWaterBodies() && map.mWaterBodies->IsRiver(body);
        level.x0 = 1.0e30f;
        level.z0 = 1.0e30f;
        level.x1 = -1.0e30f;
        level.z1 = -1.0e30f;
        for (const SRun& run : runs) {
          level.x0 = std::min(level.x0, static_cast<float>(run.x0));
          level.x1 = std::max(level.x1, static_cast<float>(run.x1));
          level.z0 = std::min(level.z0, static_cast<float>(run.z0));
          level.z1 = std::max(level.z1, static_cast<float>(run.z1));
        }
        for (std::size_t first = 0; first < runs.size(); first += kQuadsPerChunk) {
          WaterBodySurfaces::Chunk chunk;
          const std::size_t count = std::min(kQuadsPerChunk, runs.size() - first);
          if (BuildChunk(runs, first, count, level.elevation, level.river, extentX, extentZ, chunk)) {
            level.chunks.push_back(chunk);
            quads += count;
          }
        }
        levels.push_back(std::move(level));
      }
      gpg::Logf("Water bodies: drawing %zu waters in %zu quads", levels.size(), quads);
    }
  } // namespace

  SWaterOfBlock WaterOfBlock(
    const STIMap& map,
    const std::int32_t x,
    const std::int32_t z
  ) noexcept
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
    const std::uint8_t body = BlockBody(map, x, z);
    if (body != 0u) {
      const SWaterBody& owner = map.mWaterBodies->Body(body);
      water = {owner.elevation, owner.deep, owner.abyss, body};
      float corner[4];
      if (owner.elevation != kWaterBodyNoWater && RiverBlockCorners(map, x, z, corner)) {
        // a river's surface slopes: the block has the level of its own place and its shading depths follow it (the
        // body's deep and abyss are as far below its highest level as they were authored)
        const float level = water::RiverBlockLevel(corner);
        water.level = level;
        water.deep = level - (owner.elevation - owner.deep);
        water.abyss = level - (owner.elevation - owner.abyss);
      }
    }
    return water;
  }

  bool RiverBlockVertices(
    const STIMap& map,
    const std::int32_t x,
    const std::int32_t z,
    float (&level)[9]
  ) noexcept
  {
    if (!map.HasWaterBodies()) {
      return false;
    }
    const CWaterBodies& bodies = *map.mWaterBodies;
    const std::uint8_t body = BlockBody(map, x, z);
    const CWaterRiver* const river = bodies.River(body);
    if (river == nullptr) {
      return false;
    }
    bool valid[9];
    for (int i = 0; i < 9; ++i) {
      level[i] = 0.0f;
      valid[i] =
        river->VertexLevel(x + i % 3, z + i / 3, level[i]) || GrownLevel(map, body, x + i % 3, z + i / 3, level[i]);
    }
    float fallback = bodies.Body(body).elevation;
    float centre = 0.0f;
    if (river->LevelAt(static_cast<float>(x) + 1.0f, static_cast<float>(z) + 1.0f, centre)) {
      fallback = centre;
    }
    water::FillRiverBlockCorners(level, valid, fallback);
    return true;
  }

  bool RiverBlockCorners(
    const STIMap& map,
    const std::int32_t x,
    const std::int32_t z,
    float (&level)[4]
  ) noexcept
  {
    float vertex[9];
    if (!RiverBlockVertices(map, x, z, vertex)) {
      return false;
    }
    level[0] = vertex[0];
    level[1] = vertex[2];
    level[2] = vertex[6];
    level[3] = vertex[8];
    return true;
  }

  std::uint32_t WaterBodiesGeneration(
    const STIMap& map
  ) noexcept
  {
    return map.HasWaterBodies() ? map.mWaterBodies->Generation() : 0u;
  }

  float WaterBodyTerrainShaderLevel(
    const STIMap& map
  ) noexcept
  {
    const float sea = map.mWaterEnabled != 0u ? map.mWaterElevation : kWaterBodyNoWater;
    return map.HasWaterBodies() ? std::max(sea, map.mWaterBodies->HighestLevel()) : sea;
  }

  const std::vector<WaterBodySurfaces::Level>* WaterBodySurfaces::For(
    IWldTerrainRes* const terrainRes
  )
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

  std::shared_ptr<CD3DDynamicTextureSheet> WaterBodySurfaces::OwnerTexture(
    IWldTerrainRes* const terrainRes
  )
  {
    SState& state = State();
    const STIMap* const map = terrainRes != nullptr ? terrainRes->mMap : nullptr;
    const std::uint32_t generation = map != nullptr ? WaterBodiesGeneration(*map) : 0u;
    if (generation == 0u) {
      state.owner.reset();
      state.ownerGeneration = 0u;
      state.ownerMap = nullptr;
      return {};
    }
    if (state.owner != nullptr && state.ownerMap == map && state.ownerGeneration == generation) {
      return state.owner;
    }
    state.owner.reset();
    const CHeightField* const field = map->mHeightField.get();
    const std::int32_t texelsX = (field->width - 1) >> 1;
    const std::int32_t texelsZ = (field->height - 1) >> 1;
    ID3DDeviceResources::DynamicTextureSheetHandle sheet{};
    // gal format 6: one 8-bit channel (L8 / R8_UNORM)
    (void)D3D_GetDevice()->GetResources()->CreateDynamicTextureSheet2(sheet, texelsX, texelsZ, 6);
    std::uint32_t pitch = 0U;
    void* bits = nullptr;
    if (!sheet || !sheet->Lock(&pitch, &bits) || bits == nullptr) {
      gpg::Warnf("Water bodies: the owner texture could not be made; the projected grid draws no lakes");
      return {};
    }
    auto* const row0 = static_cast<std::uint8_t*>(bits);
    for (std::int32_t hz = 0; hz < texelsZ; ++hz) {
      std::uint8_t* const row = row0 + static_cast<std::size_t>(hz) * pitch;
      for (std::int32_t hx = 0; hx < texelsX; ++hx) {
        row[hx] = WaterOfBlock(*map, hx * 2, hz * 2).body;
      }
    }
    sheet->Unlock();
    state.owner = sheet;
    state.ownerGeneration = generation;
    state.ownerMap = map;
    return state.owner;
  }

  std::shared_ptr<CD3DDynamicTextureSheet> WaterBodySurfaces::LevelTexture(
    IWldTerrainRes* const terrainRes
  )
  {
    SState& state = State();
    const STIMap* const map = terrainRes != nullptr ? terrainRes->mMap : nullptr;
    const std::uint32_t generation = map != nullptr ? WaterBodiesGeneration(*map) : 0u;
    if (generation == 0u) {
      state.levelMap.reset();
      state.levelGeneration = 0u;
      state.levelMapOf = nullptr;
      return {};
    }
    if (state.levelMap != nullptr && state.levelMapOf == map && state.levelGeneration == generation) {
      return state.levelMap;
    }
    state.levelMap.reset();
    const CHeightField* const field = map->mHeightField.get();
    const std::int32_t texelsX = (field->width - 1) >> 1;
    const std::int32_t texelsZ = (field->height - 1) >> 1;
    ID3DDeviceResources::DynamicTextureSheetHandle sheet{};
    // gal format 2: B8G8R8A8, the byte order of the water map (a texel is the word of WaterLevelTexel.h)
    (void)D3D_GetDevice()->GetResources()->CreateDynamicTextureSheet2(sheet, texelsX, texelsZ, 2);
    std::uint32_t pitch = 0U;
    void* bits = nullptr;
    if (!sheet || !sheet->Lock(&pitch, &bits) || bits == nullptr) {
      gpg::Warnf("Water bodies: the level map of the terrain could not be made; the terrain keeps the baked depth");
      return {};
    }
    auto* const row0 = static_cast<std::uint8_t*>(bits);
    for (std::int32_t hz = 0; hz < texelsZ; ++hz) {
      auto* const row = reinterpret_cast<std::uint32_t*>(row0 + static_cast<std::size_t>(hz) * pitch);
      for (std::int32_t hx = 0; hx < texelsX; ++hx) {
        const SWaterOfBlock water = WaterOfBlock(*map, hx * 2, hz * 2);
        row[hx] = water::PackLevelTexel(water.level, water.abyss);
      }
    }
    sheet->Unlock();
    state.levelMap = sheet;
    state.levelGeneration = generation;
    state.levelMapOf = map;
    return state.levelMap;
  }

  void WaterBodySurfaces::Release()
  {
    water::ReleaseRiverFlow();
    SState& state = State();
    state.levelMap.reset();
    state.levelGeneration = 0u;
    state.levelMapOf = nullptr;
    state.owner.reset();
    state.ownerGeneration = 0u;
    state.ownerMap = nullptr;
    ReleaseLevels(state.levels);
    state.map = nullptr;
    state.generation = 0u;
    state.mirrored = false;
    state.bodyTarget.reset();
    state.emptyTarget.reset();
  }

  std::shared_ptr<ID3DRenderTarget> WaterBodySurfaces::ReflectionFor(
    const float level
  )
  {
    const SState& state = State();
    if (state.mirrored && state.mirroredLevel == level && state.bodyTarget) {
      return state.bodyTarget;
    }
    return state.emptyTarget;
  }

  std::shared_ptr<ID3DRenderTarget> WaterBodySurfaces::EmptyReflection()
  {
    return State().emptyTarget;
  }

  void WaterBodySurfaces::SetBodyReflection(
    const bool mirrored,
    const float level,
    const std::shared_ptr<ID3DRenderTarget>& bodyTarget,
    const std::shared_ptr<ID3DRenderTarget>& emptyTarget
  )
  {
    SState& state = State();
    state.mirrored = mirrored;
    state.mirroredLevel = level;
    state.bodyTarget = bodyTarget;
    state.emptyTarget = emptyTarget;
  }
} // namespace moho

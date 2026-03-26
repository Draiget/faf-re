#include "STIMap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

#include "moho/sim/COGrid.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaTableIterator.h"

namespace
{
  constexpr std::size_t kTerrainTypeCount = moho::TerrainTypesVectorN::kInlineCount;

  void DestroyTerrainTypeRange(LuaPlus::LuaObject* first, LuaPlus::LuaObject* last)
  {
    while (first != last) {
      first->~LuaObject();
      ++first;
    }
  }

  /**
   * Address: 0x005786F0 (FUN_005786F0, sub_5786F0)
   *
   * What it does:
   * Shrinks terrain-type Lua-object vector tail to `newFinish`.
   */
  void ShrinkTerrainTypesTail(moho::TerrainTypes& terrainTypes, LuaPlus::LuaObject* newFinish)
  {
    auto& terrainVec = terrainTypes.ttvec;
    if (!terrainVec.IsInitialized()) {
      return;
    }

    if (newFinish < terrainVec.begin()) {
      newFinish = terrainVec.begin();
    }
    if (newFinish > terrainVec.end()) {
      newFinish = terrainVec.end();
    }

    DestroyTerrainTypeRange(newFinish, terrainVec.end());
    terrainVec.finish = newFinish;
  }

  void ReserveTerrainTypes(moho::TerrainTypes& terrainTypes, const std::size_t newCapacity)
  {
    auto& terrainVec = terrainTypes.ttvec;
    const std::size_t currentSize = terrainVec.Size();
    if (newCapacity <= terrainVec.Capacity()) {
      return;
    }

    auto* const newBuffer = static_cast<LuaPlus::LuaObject*>(::operator new(sizeof(LuaPlus::LuaObject) * newCapacity));
    std::size_t copied = 0u;
    try {
      for (; copied < currentSize; ++copied) {
        ::new (static_cast<void*>(newBuffer + copied)) LuaPlus::LuaObject(terrainVec.begin()[copied]);
      }
    } catch (...) {
      DestroyTerrainTypeRange(newBuffer, newBuffer + copied);
      ::operator delete(newBuffer);
      throw;
    }

    DestroyTerrainTypeRange(terrainVec.begin(), terrainVec.end());
    if (!terrainVec.UsingInlineStorage()) {
      ::operator delete(terrainVec.start);
    }

    terrainVec.BindHeapStorage(newBuffer, currentSize, newCapacity);
  }

  /**
   * Address: 0x00578460 (FUN_00578460, func_ConstructTerrainTypes)
   *
   * What it does:
   * Resizes terrain-type Lua-object storage and fills newly-created slots from `fillValue`.
   */
  void ConstructTerrainTypes(
    moho::TerrainTypes& terrainTypes, const std::uint32_t targetSize, const LuaPlus::LuaObject& fillValue
  )
  {
    auto& terrainVec = terrainTypes.ttvec;
    const std::size_t currentSize = terrainVec.Size();
    if (targetSize < currentSize) {
      ShrinkTerrainTypesTail(terrainTypes, terrainVec.begin() + targetSize);
      return;
    }

    if (targetSize == currentSize) {
      return;
    }

    if (targetSize > terrainVec.Capacity()) {
      ReserveTerrainTypes(terrainTypes, targetSize);
    }

    auto* targetFinish = terrainVec.begin() + targetSize;
    while (terrainVec.end() != targetFinish) {
      ::new (static_cast<void*>(terrainVec.finish)) LuaPlus::LuaObject(fillValue);
      ++terrainVec.finish;
    }
  }

  /**
   * Address: 0x005783E0 (FUN_005783E0, sub_5783E0)
   *
   * What it does:
   * Initializes terrain-type storage to inline buffer mode.
   */
  void InitTerrainTypes(moho::TerrainTypes& terrainTypes)
  {
    auto& terrainVec = terrainTypes.ttvec;
    terrainVec.BindInlineEmpty();

    LuaPlus::LuaObject defaultObject{};
    ConstructTerrainTypes(terrainTypes, 0u, defaultObject);
  }

  void DestroyTerrainTypes(moho::TerrainTypes& terrainTypes)
  {
    auto& terrainVec = terrainTypes.ttvec;
    if (!terrainVec.IsInitialized()) {
      return;
    }

    DestroyTerrainTypeRange(terrainVec.begin(), terrainVec.end());
    if (!terrainVec.UsingInlineStorage()) {
      ::operator delete(terrainVec.start);
    }

    terrainVec.BindInlineEmpty();
  }

  /**
   * Address: 0x00578540 (FUN_00578540, sub_578540)
   *
   * What it does:
   * Deep-copies raw terrain type byte grid.
   */
  void CopyTerrainTypeGrid(const moho::TerrainTypeGrid& src, moho::TerrainTypeGrid& dst)
  {
    dst.width = src.width;
    dst.height = src.height;

    const std::size_t byteCount = static_cast<std::size_t>(src.width) * static_cast<std::size_t>(src.height);
    dst.data = byteCount != 0u ? new std::uint8_t[byteCount] : nullptr;
    for (std::size_t i = 0; i < byteCount; ++i) {
      dst.data[i] = src.data[i];
    }
  }

  /**
   * Address: 0x0042AC30 (FUN_0042AC30, nullsub_1)
   *
   * What it does:
   * No-op helper reached from shared-pointer setup path.
   */
  void NullSub_0042AC30() {}

  /**
   * Address: 0x005790E0 (FUN_005790E0, func_CreateBoostPtrCHeightField)
   *
   * What it does:
   * Creates a shared ownership control block for `CHeightField*`.
   */
  void CreateBoostPtrCHeightField(boost::shared_ptr<moho::CHeightField>& out, moho::CHeightField* field)
  {
    out = boost::shared_ptr<moho::CHeightField>(field);
  }

  /**
   * Address: 0x00578DC0 (FUN_00578DC0, func_CreateCHeightFieldPtr)
   *
   * What it does:
   * Assigns `CHeightField` shared pointer into STIMap with prior-reference release.
   */
  void CreateCHeightFieldPtr(moho::CHeightField* field, boost::shared_ptr<moho::CHeightField>& out)
  {
    boost::shared_ptr<moho::CHeightField> tmp;
    CreateBoostPtrCHeightField(tmp, field);
    NullSub_0042AC30();
    out = tmp;
  }

  [[nodiscard]] bool
  DoScriptIntoEnv(LuaPlus::LuaState* state, const char* scriptPath, const LuaPlus::LuaObject& envTable)
  {
    if (!state || !scriptPath || !*scriptPath || !envTable) {
      return false;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return false;
    }

    const int savedTop = lua_gettop(lstate);
    lua_getglobal(lstate, "doscript");
    if (!lua_isfunction(lstate, -1)) {
      lua_settop(lstate, savedTop);
      return false;
    }

    lua_pushstring(lstate, scriptPath);
    const_cast<LuaPlus::LuaObject&>(envTable).PushStack(lstate);

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      lua_settop(lstate, savedTop);
      return false;
    }

    const bool ok = lua_toboolean(lstate, -1) != 0;
    lua_settop(lstate, savedTop);
    return ok;
  }

  /**
   * Address: 0x00478D00 (FUN_00478D00, sub_478D00)
   *
   * What it does:
   * Initializes one `SMinMax<uint16_t>` entry to {0,0}.
   */
  void InitMinMaxEntry(moho::SMinMax<std::uint16_t>& entry)
  {
    entry.min = 0u;
    entry.max = 0u;
  }

  /**
   * Address: 0x00478630 (FUN_00478630, func_iGridMakeData1)
   *
   * What it does:
   * Allocates min/max tier grid and zero-initializes each pair.
   */
  void CreateMinMaxGridData(moho::CHeightFieldMinMaxGrid& grid, const std::int32_t width, const std::int32_t height)
  {
    grid.width = width;
    grid.height = height;

    const std::size_t sampleCount = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    grid.data = sampleCount != 0u ? new moho::SMinMax<std::uint16_t>[sampleCount] : nullptr;
    for (std::size_t i = 0; i < sampleCount; ++i) {
      InitMinMaxEntry(grid.data[i]);
    }
  }

  [[nodiscard]] std::int32_t ClampIndex(const std::int32_t value, const std::int32_t limitInclusive) noexcept
  {
    if (limitInclusive <= 0) {
      return 0;
    }

    if (value < 0) {
      return 0;
    }
    if (value >= limitInclusive) {
      return limitInclusive;
    }
    return value;
  }

  [[nodiscard]] Wm3::Vec3f PointOnLine(const moho::GeomLine3& line, const float t) noexcept
  {
    return {line.pos.x + line.dir.x * t, line.pos.y + line.dir.y * t, line.pos.z + line.dir.z * t};
  }

  /**
   * Address: 0x00577540 (FUN_00577540, Moho__CColHitResult__PlaneIntersection)
   *
   * What it does:
   * Intersects parametric segment line against plane `{normal,dist}` and
   * returns NaN vector when outside segment range.
   */
  [[nodiscard]] Wm3::Vec3f
  PlaneIntersection(const moho::GeomLine3& line, const moho::VecDist& plane, moho::CGeomHitResult* outHit)
  {
    const float dotDen = line.dir.x * plane.dir.x + line.dir.y * plane.dir.y + line.dir.z * plane.dir.z;
    if (dotDen == 0.0f) {
      return Wm3::Vec3f::NaN();
    }

    const float dotPos = line.pos.x * plane.dir.x + line.pos.y * plane.dir.y + line.pos.z * plane.dir.z;
    const float t = (plane.dist - dotPos) / dotDen;
    if (t < line.closest || line.farthest < t) {
      return Wm3::Vec3f::NaN();
    }

    if (outHit) {
      outHit->distance = t;
    }

    return PointOnLine(line, t);
  }

  constexpr float kHeightWordScale = 0.0078125f;
  constexpr float kNoWaterElevation = -10000.0f;

  [[nodiscard]] constexpr std::uint8_t OccupancyMask(const moho::EOccupancyCaps caps) noexcept
  {
    return static_cast<std::uint8_t>(caps);
  }

  [[nodiscard]] constexpr moho::EOccupancyCaps ToOccupancyCaps(const std::uint8_t mask) noexcept
  {
    return static_cast<moho::EOccupancyCaps>(mask);
  }

  constexpr std::uint8_t kOccLand = static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_LAND);
  constexpr std::uint8_t kOccSeabed = static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SEABED);
  constexpr std::uint8_t kOccSub = static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SUB);
  constexpr std::uint8_t kOccWater = static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_WATER);
  constexpr std::uint8_t kOccLandSeabed = static_cast<std::uint8_t>(kOccLand | kOccSeabed);
  constexpr std::uint8_t kOccWaterSubSeabed = static_cast<std::uint8_t>(kOccWater | kOccSub | kOccSeabed);

  [[nodiscard]] constexpr std::uint8_t RemoveCaps(const std::uint8_t mask, const std::uint8_t bitsToClear) noexcept
  {
    return static_cast<std::uint8_t>(mask & static_cast<std::uint8_t>(~bitsToClear));
  }

  struct GridTraversalLine
  {
    float x0;           // +0x00
    float z0;           // +0x04
    float x1;           // +0x08
    float z1;           // +0x0C
    float dx;           // +0x10
    float dz;           // +0x14
    std::int32_t step;  // +0x18
    std::int32_t xEdge; // +0x1C
    std::int32_t zEdge; // +0x20
    std::int32_t xMask; // +0x24
    std::int32_t zMask; // +0x28
  };

  static_assert(sizeof(GridTraversalLine) == 0x2C, "GridTraversalLine size must be 0x2C");

  [[nodiscard]] std::int32_t FloorToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  [[nodiscard]] std::int32_t CeilToInt(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::ceil(value));
  }

  [[nodiscard]] std::int32_t HighestBitIndex(std::int32_t value) noexcept
  {
    if (value <= 0) {
      return -1;
    }

    std::int32_t index = -1;
    while (value != 0) {
      ++index;
      value >>= 1;
    }
    return index;
  }

  [[nodiscard]] float Dot3(const Wm3::Vec3f& a, const Wm3::Vec3f& b) noexcept
  {
    return a.x * b.x + a.y * b.y + a.z * b.z;
  }

  [[nodiscard]] float PlaneSide(const Wm3::Vec3f& point, const Wm3::Vec3f& normal, const float planeDistance) noexcept
  {
    return Dot3(point, normal) - planeDistance;
  }

  /**
   * Address: 0x0040D860 (FUN_0040D860, ??0struct_Line@@QAE@@Z)
   *
   * What it does:
   * Initializes grid-walker line state from segment endpoints and step size.
   */
  void InitGridTraversalLine(
    GridTraversalLine& line,
    const std::int32_t step,
    const float xEnd,
    const float xStart,
    const float zStart,
    const float zEnd
  )
  {
    line.step = step;

    if (xEnd < xStart) {
      line.x0 = -xStart;
      line.x1 = -xEnd;
      line.xMask = -step;
    } else {
      line.x0 = xStart;
      line.x1 = xEnd;
      line.xMask = 0;
    }

    std::int32_t zMask = 0;
    if (zEnd < zStart) {
      line.z0 = -zStart;
      line.z1 = -zEnd;
      zMask = -step;
    } else {
      line.z0 = zStart;
      line.z1 = zEnd;
    }

    line.dx = line.x1 - line.x0;
    line.dz = line.z1 - line.z0;
    line.zMask = zMask;

    const std::int32_t alignMask = -step;
    line.xEdge = FloorToInt(line.x0) & alignMask;
    line.zEdge = FloorToInt(line.z0) & alignMask;
  }

  /**
   * Address: 0x0040D960 (FUN_0040D960, sub_40D960)
   *
   * What it does:
   * Re-aligns grid-walker state when the traversal step is reduced/increased.
   */
  void UpdateGridTraversalStep(GridTraversalLine& line, const std::int32_t newStep)
  {
    if (newStep < line.step) {
      if (line.x0 < static_cast<float>(line.xEdge) || line.z0 < static_cast<float>(line.zEdge)) {
        const float zMax = line.z1;
        const float xSpan = line.dx;
        const float xMax = line.x1;
        const float zSpan = line.dz;

        do {
          line.step >>= 1;
          const std::int32_t halfStep = line.step;
          const std::int32_t currentZEdge = line.zEdge;
          const std::int32_t currentXEdge = line.xEdge;
          line.xMask >>= 1;
          line.zMask >>= 1;

          const float lhs = (static_cast<float>(currentXEdge) - xMax) * zSpan;
          const float rhs = (static_cast<float>(halfStep + currentZEdge) - zMax) * xSpan;
          if (lhs < rhs) {
            const std::int32_t candidate = halfStep + currentXEdge;
            const float candidateCmp = (static_cast<float>(candidate) - xMax) * zSpan;
            const float edgeCmp = (static_cast<float>(currentZEdge) - zMax) * xSpan;
            if (edgeCmp >= candidateCmp) {
              line.xEdge = candidate;
            }
          } else {
            line.zEdge = halfStep + currentZEdge;
          }
        } while (newStep < line.step);
      } else {
        line.step = newStep;
        line.xMask = (line.xMask == 0) ? 0 : -newStep;
        line.zMask = (line.zMask == 0) ? 0 : -newStep;

        const std::int32_t alignMask = -newStep;
        line.xEdge = FloorToInt(line.x0) & alignMask;
        line.zEdge = FloorToInt(line.z0) & alignMask;
      }
      return;
    }

    const std::int32_t alignMask = -newStep;
    line.xMask &= alignMask;
    line.zMask &= alignMask;
    line.xEdge &= alignMask;
    line.zEdge &= alignMask;
    line.step = newStep;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00476090 (FUN_00476090)
   *
   * int width, int height
   *
   * IDA signature:
   * Moho::CHeightField *__stdcall Moho::CHeightField::CHeightField(Moho::CHeightField *this, int width, int height);
   *
   * What it does:
   * Builds base + tier grids used by terrain sampling and broad collision logic.
   */
  CHeightField::CHeightField(const std::int32_t widthArg, const std::int32_t heightArg)
    : data(nullptr)
    , width(0)
    , height(0)
    , mGrids()
  {
    InitField(widthArg + 1, heightArg + 1);

    const std::int32_t largest = (widthArg < heightArg) ? heightArg : widthArg;
    std::int32_t numSubgrids = 0;
    if (largest > 1) {
      std::uint32_t v = static_cast<std::uint32_t>(largest - 1);
      while (v != 0u) {
        ++numSubgrids;
        v >>= 1u;
      }
    }

    mGrids.resize(static_cast<std::size_t>(numSubgrids));
    for (std::int32_t level = 0; level < numSubgrids; ++level) {
      const std::int32_t shift = level + 1;
      const std::int32_t levelHeight = std::max(heightArg >> shift, 1);
      const std::int32_t levelWidth = std::max(widthArg >> shift, 1);

      CHeightFieldTier& tier = mGrids[static_cast<std::size_t>(level)];

      delete[] tier.data1.data;
      tier.data1.data = nullptr;
      CreateMinMaxGridData(tier.data1, levelWidth, levelHeight);

      delete[] tier.data2.data;
      tier.data2.data = nullptr;
      tier.data2.width = levelWidth;
      tier.data2.height = levelHeight;
      const std::size_t auxCount = static_cast<std::size_t>(levelWidth) * static_cast<std::size_t>(levelHeight);
      tier.data2.data = auxCount != 0u ? new std::int16_t[auxCount] : nullptr;
    }
  }

  /**
   * Address: 0x004784F0 (+ chunk 0x00478420 from ctor cleanup island)
   *
   * What it does:
   * Releases all tier subgrid buffers and base height data.
   */
  CHeightField::~CHeightField()
  {
    delete[] data;
    data = nullptr;

    for (CHeightFieldTier* it = mGrids.begin(); it != mGrids.end(); ++it) {
      delete[] it->data1.data;
      delete[] it->data2.data;
      it->data1.data = nullptr;
      it->data2.data = nullptr;
    }

    mGrids.clear();
  }

  /**
   * Address: 0x004783D0 (FUN_004783D0)
   *
   * int width, int height
   *
   * IDA signature:
   * Moho::CHeightField *__usercall Moho::CHeightField::InitField@<eax>(int width@<eax>, int height@<ecx>,
   * Moho::CHeightField *this@<esi>);
   *
   * What it does:
   * Allocates and zeroes 16-bit base height samples.
   */
  void CHeightField::InitField(const std::int32_t widthArg, const std::int32_t heightArg)
  {
    width = widthArg;
    height = heightArg;

    const std::size_t sampleCount = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    data = sampleCount != 0u ? new std::uint16_t[sampleCount] : nullptr;

    const std::int32_t size = width * height;
    for (std::int32_t i = 0; i < size; ++i) {
      data[i] = 0u;
    }
  }

  /**
   * Address: 0x00478490
   *
   * What it does:
   * Returns a clamped sample from the base 16-bit height grid.
   */
  std::uint16_t CHeightField::GetHeightAt(std::int32_t x, std::int32_t z) const
  {
    if (!data || width <= 0 || height <= 0) {
      return 0u;
    }

    if (x < 0) {
      x = 0;
    } else if (x >= width) {
      x = width - 1;
    }

    if (z < 0) {
      z = 0;
    } else if (z >= height) {
      z = height - 1;
    }

    return data[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
  }

  /**
   * Address: 0x0044FB90 (FUN_0044FB90)
   *
   * float x, float z
   *
   * IDA signature:
   * double __thiscall Moho::CHeightField::GetElevation(Moho::CHeightField *this, float x, float z);
   *
   * What it does:
   * Bilinearly samples scaled terrain elevation at world coordinates.
   */
  float CHeightField::GetElevation(const float x, const float z) const
  {
    if (!data || width <= 0 || height <= 0) {
      return 0.0f;
    }

    const int fx = static_cast<int>(std::floor(static_cast<double>(x)));
    const int fz = static_cast<int>(std::floor(static_cast<double>(z)));

    const float fracX = x - static_cast<float>(fx);
    const float fracZ = z - static_cast<float>(fz);

    const int wMax = width - 1;
    const int hMax = height - 1;

    const int x0 = ClampIndex(fx, wMax);
    const int x1 = ClampIndex(fx + 1, wMax);
    const int z0 = ClampIndex(fz, hMax);
    const int z1 = ClampIndex(fz + 1, hMax);

    const float h00 = static_cast<float>(data[x0 + z0 * width]) * 0.0078125f;
    const float h01 = static_cast<float>(data[x0 + z1 * width]) * 0.0078125f;
    const float h10 = static_cast<float>(data[x1 + z0 * width]) * 0.0078125f;
    const float h11 = static_cast<float>(data[x1 + z1 * width]) * 0.0078125f;

    const float h0 = h00 + (h01 - h00) * fracZ;
    const float h1 = h10 + (h11 - h10) * fracZ;
    return h0 + (h1 - h0) * fracX;
  }

  /**
   * Address: 0x00475BF0 (FUN_00475BF0)
   *
   * int tier, int x, int z
   *
   * IDA signature:
   * Moho::SMinMax_ushort *__fastcall Moho::CHeightField::GetTierBoundsUWord(int tier, int x, Moho::CHeightField *this,
   * Moho::SMinMax_ushort *dest, int z);
   *
   * What it does:
   * Returns min/max height word pair for one tier cell (or 2x2 base sample block for tier 0).
   */
  SMinMax<std::uint16_t>
  CHeightField::GetTierBoundsUWord(const std::int32_t tier, const std::int32_t x, const std::int32_t z) const
  {
    SMinMax<std::uint16_t> out{};
    if (!data || width <= 0 || height <= 0) {
      return out;
    }

    if (tier <= 0) {
      const int wMax = width - 1;
      const int hMax = height - 1;

      const int x0 = ClampIndex(x, wMax);
      const int x1 = ClampIndex(x + 1, wMax);
      const int z0 = ClampIndex(z, hMax);
      const int z1 = ClampIndex(z + 1, hMax);

      const std::uint16_t a = data[x0 + z0 * width];
      const std::uint16_t b = data[x1 + z0 * width];
      const std::uint16_t c = data[x0 + z1 * width];
      const std::uint16_t d = data[x1 + z1 * width];

      out.max = std::max(std::max(a, b), std::max(c, d));
      out.min = std::min(std::min(a, b), std::min(c, d));
      return out;
    }

    if (!mGrids.begin()) {
      return out;
    }

    const std::ptrdiff_t gridCount = mGrids.end() - mGrids.begin();
    if (tier - 1 >= gridCount) {
      return out;
    }

    const CHeightFieldTier& sub = mGrids[static_cast<std::size_t>(tier - 1)];
    const int subWMax = sub.data1.width - 1;
    const int subHMax = sub.data1.height - 1;
    const int sx = ClampIndex(x, subWMax);
    const int sz = ClampIndex(z, subHMax);
    if (!sub.data1.data || sub.data1.width <= 0 || sub.data1.height <= 0) {
      return out;
    }

    return sub.data1.data[sx + sz * sub.data1.width];
  }

  /**
   * Address: 0x00475DF0 (FUN_00475DF0)
   *
   * int x, int z, int tier
   *
   * IDA signature:
   * Wm3::AxisAlignedBox3f *__userpurge Moho::CHeightField::GetTierBox@<eax>(int z@<eax>, int x@<ecx>, int tier@<esi>,
   * Moho::CHeightField *this, Wm3::AxisAlignedBox3f *out);
   *
   * What it does:
   * Builds clamped world-space AABB for one tier cell with min/max sampled heights.
   */
  Wm3::AxisAlignedBox3f
  CHeightField::GetTierBox(const std::int32_t x, const std::int32_t z, const std::int32_t tier) const
  {
    const SMinMax<std::uint16_t> bounds = GetTierBoundsUWord(tier, x, z);
    const float minY = static_cast<float>(bounds.min) * 0.0078125f;
    const float maxY = static_cast<float>(bounds.max) * 0.0078125f;

    const int safeTier = (tier < 0) ? 0 : tier;
    const float step = static_cast<float>(1 << safeTier);
    const float mapMaxX = static_cast<float>(width - 1);
    const float mapMaxZ = static_cast<float>(height - 1);

    float minX = static_cast<float>(x << safeTier);
    float minZ = static_cast<float>(z << safeTier);
    float maxX = minX + step;
    float maxZ = minZ + step;

    if (mapMaxX <= maxX) {
      maxX = mapMaxX;
    }
    if (maxX < 0.0f) {
      maxX = 0.0f;
    }
    if (mapMaxX <= minX) {
      minX = mapMaxX;
    }
    if (minX < 0.0f) {
      minX = 0.0f;
    }

    if (mapMaxZ <= maxZ) {
      maxZ = mapMaxZ;
    }
    if (maxZ < 0.0f) {
      maxZ = 0.0f;
    }
    if (mapMaxZ <= minZ) {
      minZ = mapMaxZ;
    }
    if (minZ < 0.0f) {
      minZ = 0.0f;
    }

    Wm3::AxisAlignedBox3f out{};
    out.Min.x = minX;
    out.Min.y = minY;
    out.Min.z = minZ;
    out.Max.x = maxX;
    out.Max.y = maxY;
    out.Max.z = maxZ;
    return out;
  }

  /**
   * Address: 0x004776E0 (FUN_004776E0)
   *
   * Wm3::Vector3<float> const&, Wm3::Vector3<float> const&, float&, float&
   *
   * IDA signature:
   * bool __userpurge Moho::CHeightField::ClipSegmentToWorld@<al>(Wm3::Vector3f *pos@<ebx>, Wm3::Vector3f *dir@<edi>,
   * Moho::CHeightField *this@<esi>, float *min, float *max);
   *
   * What it does:
   * Clips `[min,max]` segment parameter range to map XY bounds and top-height ceiling.
   */
  bool CHeightField::ClipSegmentToWorld(const Wm3::Vec3f& pos, const Wm3::Vec3f& dir, float& min, float& max) const
  {
    float newMin = min;
    float newMax = max;

    if (dir.x == 0.0f) {
      if (pos.x < 0.0f || pos.x > static_cast<float>(width - 1)) {
        return false;
      }
    } else {
      const float t0 = (-1.0f / dir.x) * pos.x;
      const float t1 = (static_cast<float>(width - 1) - pos.x) / dir.x;
      const float nearT = (t1 <= t0) ? t1 : t0;
      const float farT = (t1 <= t0) ? t0 : t1;

      if (nearT > newMin) {
        newMin = nearT;
      }
      if (farT <= newMax) {
        newMax = farT;
      }
    }

    if (dir.z == 0.0f) {
      if (pos.z < 0.0f || pos.z > static_cast<float>(height - 1)) {
        return false;
      }
    } else {
      const float t0 = (-1.0f / dir.z) * pos.z;
      const float t1 = (static_cast<float>(height - 1) - pos.z) / dir.z;
      const float nearT = (t1 <= t0) ? t1 : t0;
      const float farT = (t1 <= t0) ? t0 : t1;

      if (nearT > newMin) {
        newMin = nearT;
      }
      if (farT <= newMax) {
        newMax = farT;
      }
    }

    if (dir.y != 0.0f) {
      const std::int32_t tierCount = mGrids.begin() ? static_cast<std::int32_t>(mGrids.end() - mGrids.begin()) : 0;
      const SMinMax<std::uint16_t> topBounds = GetTierBoundsUWord(tierCount, 0, 0);
      const float maxTerrainY = static_cast<float>(topBounds.max) * 0.0078125f;
      const float t = (maxTerrainY - pos.y) / dir.y;

      if (dir.y >= 0.0f) {
        if (t <= newMax) {
          newMax = t;
        }
      } else if (t > newMin) {
        newMin = t;
      }
    }

    min = newMin;
    max = newMax;
    return newMax >= newMin;
  }

  /**
   * Address: 0x004778F0 (FUN_004778F0)
   *
   * Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const &,
   * int x, int z, float def, Moho::CGeomHitResult *
   *
   * IDA signature:
   * bool __userpurge Moho::CHeightField::DoIntersectionLL@<al>(Moho::CHeightField *this@<eax>, int x@<edi>,
   * Wm3::Vector3f *pos, Wm3::Vector3f *dir, Wm3::Vector3f *p1, Wm3::Vector3f *p2, int z, float def,
   * Moho::CGeomHitResult *res);
   *
   * What it does:
   * Tests line chunk against the lower-left terrain triangle in cell `(x,z)`.
   */
  bool CHeightField::DoIntersectionLL(
    const Wm3::Vec3f& pos,
    const Wm3::Vec3f& dir,
    const Wm3::Vec3f& p1,
    const Wm3::Vec3f& p2,
    const std::int32_t x,
    const std::int32_t z,
    const float def,
    CGeomHitResult* const res
  ) const
  {
    if (!res) {
      return false;
    }

    const float y00 = static_cast<float>(GetHeightAt(x, z)) * kHeightWordScale;
    const float y01 = static_cast<float>(GetHeightAt(x, z + 1)) * kHeightWordScale;
    const float y11 = static_cast<float>(GetHeightAt(x + 1, z + 1)) * kHeightWordScale;

    Wm3::Vec3f normal{};
    normal.x = y01 - y11;
    normal.y = 1.0f;
    normal.z = y00 - y01;
    Wm3::Vector3f::Normalize(&normal);

    const Wm3::Vec3f basePoint{static_cast<float>(x), y00, static_cast<float>(z)};
    const float planeDistance = Dot3(normal, basePoint);

    const float sideP1 = PlaneSide(p1, normal, planeDistance);
    if (sideP1 < 0.0f) {
      res->distance = def;
      return true;
    }

    const float sideP2 = PlaneSide(p2, normal, planeDistance);
    if (sideP2 >= 0.0f) {
      return false;
    }

    const float numerator = PlaneSide(pos, normal, planeDistance);
    const float denominator = Dot3(dir, normal);
    res->distance = -(numerator / denominator);
    return true;
  }

  /**
   * Address: 0x00477B80 (FUN_00477B80)
   *
   * Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const &,
   * int x, int z, float def, Moho::CGeomHitResult *
   *
   * IDA signature:
   * bool __userpurge Moho::CHeightField::DoIntersectionUR@<al>(Moho::CHeightField *this@<eax>, Wm3::Vector3f *pos,
   * Wm3::Vector3f *dir, Wm3::Vector3f *p1, Wm3::Vector3f *p2, int x, int z, float def, Moho::CGeomHitResult *res);
   *
   * What it does:
   * Tests line chunk against the upper-right terrain triangle in cell `(x,z)`.
   */
  bool CHeightField::DoIntersectionUR(
    const Wm3::Vec3f& pos,
    const Wm3::Vec3f& dir,
    const Wm3::Vec3f& p1,
    const Wm3::Vec3f& p2,
    const std::int32_t x,
    const std::int32_t z,
    const float def,
    CGeomHitResult* const res
  ) const
  {
    if (!res) {
      return false;
    }

    const float y00 = static_cast<float>(GetHeightAt(x, z)) * kHeightWordScale;
    const float y10 = static_cast<float>(GetHeightAt(x + 1, z)) * kHeightWordScale;
    const float y11 = static_cast<float>(GetHeightAt(x + 1, z + 1)) * kHeightWordScale;

    Wm3::Vec3f normal{};
    normal.x = y00 - y10;
    normal.y = 1.0f;
    normal.z = y10 - y11;
    Wm3::Vector3f::Normalize(&normal);

    const Wm3::Vec3f basePoint{static_cast<float>(x), y00, static_cast<float>(z)};
    const float planeDistance = Dot3(normal, basePoint);

    const float sideP1 = PlaneSide(p1, normal, planeDistance);
    if (sideP1 < 0.0f) {
      res->distance = def;
      return true;
    }

    const float sideP2 = PlaneSide(p2, normal, planeDistance);
    if (sideP2 >= 0.0f) {
      return false;
    }

    const float numerator = PlaneSide(pos, normal, planeDistance);
    const float denominator = Dot3(dir, normal);
    res->distance = -(numerator / denominator);
    return true;
  }

  /**
   * Address: 0x00477030 (FUN_00477030)
   *
   * Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, float, float, Moho::CGeomHitResult *
   *
   * IDA signature:
   * bool __userpurge Moho::CHeightField::DoIntersection@<al>(Wm3::Vector3f *pos@<eax>, Moho::CHeightField *this,
   * Wm3::Vector3f *dir, float start, float end, Moho::CGeomHitResult *res);
   *
   * What it does:
   * Walks a clipped line segment through terrain cells/subgrids and resolves
   * the first terrain-triangle intersection distance.
   */
  bool CHeightField::DoIntersection(
    const Wm3::Vec3f& pos, const Wm3::Vec3f& dir, float start, float end, CGeomHitResult* const res
  ) const
  {
    if (!res) {
      return false;
    }

    if (!ClipSegmentToWorld(pos, dir, start, end)) {
      return false;
    }

    if (dir.x == 0.0f && dir.z == 0.0f) {
      const float elevation = GetElevation(pos.x, pos.z);
      const float t = (elevation - pos.y) / dir.y;
      if (t >= start && end >= t) {
        res->distance = t;
        return true;
      }
      return false;
    }

    const float absX = std::fabs(dir.x);
    const float absZ = std::fabs(dir.z);
    const float dirMax = (absZ <= absX) ? absX : absZ;

    const std::int32_t tierCount = mGrids.begin() ? static_cast<std::int32_t>(mGrids.end() - mGrids.begin()) : 0;

    std::int32_t tier = tierCount;
    const float scaledSpan = (end - start) * dirMax * 2.0f;
    const std::int32_t walkSpanCeil = CeilToInt(scaledSpan);
    const std::int32_t spanBit = HighestBitIndex(walkSpanCeil);
    if (spanBit < tier) {
      tier = spanBit;
    }
    if (tier < 0) {
      tier = 0;
    }

    GridTraversalLine walkLine{};
    InitGridTraversalLine(
      walkLine,
      1 << tier,
      pos.x + (dir.x * end),
      pos.x + (dir.x * start),
      pos.z + (dir.z * start),
      pos.z + (dir.z * end)
    );

    std::int32_t cellX = walkLine.xEdge ^ walkLine.xMask;
    std::int32_t cellZ = walkLine.zMask ^ walkLine.zEdge;

    while (true) {
      bool reachedEnd = false;
      float nextT = end;
      std::int32_t nextCellX = cellX;
      std::int32_t nextCellZ = cellZ;

      while (true) {
        while (true) {
          const float lhs = (static_cast<float>(walkLine.zEdge + walkLine.step) - walkLine.z1) * walkLine.dx;
          const float rhs = (static_cast<float>(walkLine.step + walkLine.xEdge) - walkLine.x1) * walkLine.dz;
          if (lhs <= rhs) {
            walkLine.zEdge += walkLine.step;
          } else {
            walkLine.xEdge += walkLine.step;
          }

          if (static_cast<float>(walkLine.xEdge) > walkLine.x1 || static_cast<float>(walkLine.zEdge) > walkLine.z1) {
            nextT = end;
            reachedEnd = true;
          } else {
            reachedEnd = false;
            nextCellX = walkLine.xEdge ^ walkLine.xMask;
            nextCellZ = walkLine.zMask ^ walkLine.zEdge;
            if (cellX == nextCellX) {
              std::int32_t boundary = cellZ;
              if (cellZ < nextCellZ) {
                boundary = nextCellZ;
              }
              nextT = (static_cast<float>(boundary) - pos.z) / dir.z;
            } else {
              std::int32_t boundary = cellX;
              if (cellX < nextCellX) {
                boundary = nextCellX;
              }
              nextT = (static_cast<float>(boundary) - pos.x) / dir.x;
            }
          }

          if (cellX >= 0 && cellX < width - 1 && cellZ >= 0 && cellZ < height - 1) {
            break;
          }

          if (reachedEnd) {
            return false;
          }

          cellX = nextCellX;
          cellZ = nextCellZ;
          start = nextT;
        }

        if (tier <= 0) {
          break;
        }

        const SMinMax<std::uint16_t> tierBounds = GetTierBoundsUWord(tier, cellX >> tier, cellZ >> tier);
        const float cellMaxY = static_cast<float>(tierBounds.max) * kHeightWordScale;
        if (cellMaxY >= (dir.y * start + pos.y) || cellMaxY >= (dir.y * nextT + pos.y)) {
          const float lhs = (static_cast<float>(walkLine.zEdge) - walkLine.z1) * walkLine.dx;
          const float rhs = (static_cast<float>(walkLine.xEdge) - walkLine.x1) * walkLine.dz;
          if (lhs <= rhs) {
            walkLine.xEdge -= walkLine.step;
          } else {
            walkLine.zEdge -= walkLine.step;
          }

          const std::int32_t newStep = 1 << --tier;
          UpdateGridTraversalStep(walkLine, newStep);
          cellX = walkLine.xEdge ^ walkLine.xMask;
          cellZ = walkLine.zMask ^ walkLine.zEdge;
        } else {
          if (reachedEnd) {
            return false;
          }
          cellX = nextCellX;
          cellZ = nextCellZ;
          start = nextT;
        }
      }

      Wm3::Vec3f pStart{};
      pStart.x = pos.x + (dir.x * start);
      pStart.y = pos.y + (dir.y * start);
      pStart.z = pos.z + (dir.z * start);

      Wm3::Vec3f pEnd{};
      pEnd.x = pos.x + (dir.x * nextT);
      pEnd.y = pos.y + (dir.y * nextT);
      pEnd.z = pos.z + (dir.z * nextT);

      const float cellDiag = static_cast<float>(cellX - cellZ);
      const float startDiag = pStart.x - pStart.z;
      const float endDiag = pEnd.x - pEnd.z;

      bool hit = false;
      if (cellDiag <= startDiag) {
        if (endDiag < cellDiag) {
          const float splitT = (cellDiag - (pos.x - pos.z)) / (dir.x - dir.z);
          Wm3::Vec3f split{};
          split.x = pos.x + (dir.x * splitT);
          split.y = pos.y + (dir.y * splitT);
          split.z = pos.z + (dir.z * splitT);

          if (DoIntersectionUR(pos, dir, pStart, split, cellX, cellZ, start, res)) {
            return true;
          }
          hit = DoIntersectionLL(pos, dir, split, pEnd, cellX, cellZ, start, res);
        } else {
          hit = DoIntersectionUR(pos, dir, pStart, pEnd, cellX, cellZ, start, res);
        }
      } else if (cellDiag <= endDiag) {
        const float splitT = (cellDiag - (pos.x - pos.z)) / (dir.x - dir.z);
        Wm3::Vec3f split{};
        split.x = pos.x + (dir.x * splitT);
        split.y = pos.y + (dir.y * splitT);
        split.z = pos.z + (dir.z * splitT);

        if (DoIntersectionLL(pos, dir, pStart, split, cellX, cellZ, start, res)) {
          return true;
        }
        hit = DoIntersectionUR(pos, dir, split, pEnd, cellX, cellZ, start, res);
      } else {
        hit = DoIntersectionLL(pos, dir, pStart, pEnd, cellX, cellZ, start, res);
      }

      if (hit) {
        return true;
      }

      if (reachedEnd) {
        return false;
      }

      start = nextT;
      cellX = nextCellX;
      cellZ = nextCellZ;
    }
  }

  /**
   * Address: 0x00476F30 (FUN_00476F30)
   *
   * Moho::GeomLine3 const &, Moho::CGeomHitResult *
   *
   * IDA signature:
   * Wm3::Vector3f *__userpurge Moho::CHeightField::Intersection@<eax>(Moho::CHeightField *this@<eax>, Wm3::Vector3f
   * *dest@<ebx>, Moho::GeomLine3 *line@<esi>, Moho::CGeomHitResult *res);
   *
   * What it does:
   * Intersects segment line with terrain surface and returns hit point or NaN vector.
   */
  Wm3::Vec3f CHeightField::Intersection(const GeomLine3& line, CGeomHitResult* res) const
  {
    CGeomHitResult temp{};
    temp.distance = std::numeric_limits<float>::quiet_NaN();
    temp.v1 = std::numeric_limits<float>::quiet_NaN();

    CGeomHitResult* const hit = res ? res : &temp;
    if (!DoIntersection(line.pos, line.dir, line.closest, line.farthest, hit)) {
      return Wm3::Vec3f::NaN();
    }

    return PointOnLine(line, hit->distance);
  }

  /**
   * Address: 0x005779C0 (FUN_005779C0)
   *
   * unsigned int width, unsigned int height
   *
   * IDA signature:
   * Moho::STIMap *__userpurge Moho::STIMap::STIMap@<eax>(int height@<esi>, Moho::STIMap *this, int width);
   *
   * What it does:
   * Initializes playable rect, terrain type bytes, water defaults, and height-field store.
   */
  STIMap::STIMap(const std::uint32_t width, const std::uint32_t height)
    : mHeightField()
    , mPlayableRect{}
    , mTerrainTypes{}
    , mTerrainType{}
    , mBlocking{}
    , mWaterEnabled(0u)
    , pad_1535{}
    , mWaterElevation(0.0f)
    , mWaterElevationDeep(0.0f)
    , mWaterElevationAbyss(0.0f)
  {
    mPlayableRect.x0 = 0;
    mPlayableRect.z0 = 0;
    mPlayableRect.x1 = static_cast<std::int32_t>(width);
    mPlayableRect.z1 = static_cast<std::int32_t>(height);

    InitTerrainTypes(mTerrainTypes);

    mTerrainType.width = static_cast<std::int32_t>(width);
    mTerrainType.height = static_cast<std::int32_t>(height);
    const std::size_t terrainByteCount =
      static_cast<std::size_t>(mTerrainType.width) * static_cast<std::size_t>(mTerrainType.height);
    mTerrainType.data = terrainByteCount != 0u ? new std::uint8_t[terrainByteCount] : nullptr;
    for (std::size_t i = 0; i < terrainByteCount; ++i) {
      mTerrainType.data[i] = 1u;
    }

    CHeightField* const field = new CHeightField(static_cast<std::int32_t>(width), static_cast<std::int32_t>(height));
    CreateCHeightFieldPtr(field, mHeightField);

    std::memset(mBlocking, 0, sizeof(mBlocking));
  }

  /**
   * Address: 0x00577890 (FUN_00577890)
   *
   * Moho::STIMap *
   *
   * IDA signature:
   * Moho::STIMap *__thiscall Moho::STIMap::STIMap(Moho::STIMap *src, Moho::STIMap *this);
   *
   * What it does:
   * Creates a map clone using source dimensions/height samples and water settings.
   */
  STIMap::STIMap(STIMap* src)
    : mHeightField()
    , mPlayableRect{}
    , mTerrainTypes{}
    , mTerrainType{}
    , mBlocking{}
    , mWaterEnabled(0u)
    , pad_1535{}
    , mWaterElevation(0.0f)
    , mWaterElevationDeep(0.0f)
    , mWaterElevationAbyss(0.0f)
  {
    CHeightField* const sourceField = src ? src->mHeightField.get() : nullptr;
    const std::int32_t sourceWidth = sourceField ? sourceField->width : 1;
    const std::int32_t sourceHeight = sourceField ? sourceField->height : 1;

    mPlayableRect.x0 = 0;
    mPlayableRect.z0 = 0;
    mPlayableRect.x1 = sourceWidth - 1;
    mPlayableRect.z1 = sourceHeight - 1;

    InitTerrainTypes(mTerrainTypes);
    if (src) {
      CopyTerrainTypeGrid(src->mTerrainType, mTerrainType);
      mWaterEnabled = src->mWaterEnabled;
      mWaterElevation = src->mWaterElevation;
      mWaterElevationDeep = src->mWaterElevationDeep;
      mWaterElevationAbyss = src->mWaterElevationAbyss;
    }

    CHeightField* const copiedField = new CHeightField(sourceWidth - 1, sourceHeight - 1);
    CreateCHeightFieldPtr(copiedField, mHeightField);

    if (src && sourceField && copiedField && sourceField->data && copiedField->data) {
      const std::size_t sampleCount =
        static_cast<std::size_t>(sourceField->width) * static_cast<std::size_t>(sourceField->height);
      std::memcpy(copiedField->data, sourceField->data, sampleCount * sizeof(std::uint16_t));
    }

    std::memset(mBlocking, 0, sizeof(mBlocking));
  }

  /**
   * Address: 0x00577AD0 (FUN_00577AD0)
   *
   * What it does:
   * Releases terrain byte-grid and Lua terrain type table entries.
   */
  STIMap::~STIMap()
  {
    delete[] mTerrainType.data;
    mTerrainType.data = nullptr;
    DestroyTerrainTypes(mTerrainTypes);
  }

  /**
   * Address: 0x00577DF0 (FUN_00577DF0)
   *
   * gpg::Rect2<int> const &
   *
   * IDA signature:
   * char __usercall Moho::STIMap::SetPlayableMapRect@<al>(gpg::Rect2i *rect@<eax>, Moho::STIMap *this@<ebx>);
   *
   * What it does:
   * Clamps playable rect to valid sample bounds and stores it when non-empty.
   */
  bool STIMap::SetPlayableMapRect(const gpg::Rect2i& rect)
  {
    CHeightField* const field = mHeightField.get();
    if (!field || field->width <= 0 || field->height <= 0) {
      return false;
    }

    const std::int32_t maxX = field->width - 1;
    const std::int32_t maxZ = field->height - 1;

    std::int32_t x0 = rect.x0;
    std::int32_t z0 = rect.z0;
    std::int32_t x1 = maxX;
    std::int32_t z1 = rect.z1;

    if (x0 >= maxX) {
      x0 = maxX;
    }
    if (x0 < 0) {
      x0 = 0;
    }

    if (z0 >= maxZ) {
      z0 = maxZ;
    }
    if (z0 < 0) {
      z0 = 0;
    }

    if (rect.x1 < maxX) {
      x1 = rect.x1;
    }
    if (x1 < 0) {
      x1 = 0;
    }

    if (z1 >= maxZ) {
      z1 = maxZ;
    }
    if (z1 < 0) {
      z1 = 0;
    }

    if (x1 <= x0 || z1 <= z0) {
      return false;
    }

    mPlayableRect.x0 = x0;
    mPlayableRect.z0 = z0;
    mPlayableRect.x1 = x1;
    mPlayableRect.z1 = z1;
    return true;
  }

  /**
   * Address: 0x00577EC0 (FUN_00577EC0)
   *
   * unsigned int x, unsigned int z, unsigned char type
   *
   * IDA signature:
   * void __userpurge Moho::STIMap::SetTerrainType(unsigned int z@<ebx>, unsigned int x@<edi>, Moho::STIMap *this@<esi>,
   * char type);
   *
   * What it does:
   * Writes terrain type map byte for one in-bounds cell.
   */
  void STIMap::SetTerrainType(const std::uint32_t x, const std::uint32_t z, const std::uint8_t type)
  {
    CHeightField* const field = mHeightField.get();
    if (!field || !mTerrainType.data) {
      return;
    }

    if (field->width <= 0 || field->height <= 0) {
      return;
    }

    if (x < static_cast<std::uint32_t>(field->width - 1) && z < static_cast<std::uint32_t>(field->height - 1)) {
      if (x >= static_cast<std::uint32_t>(mTerrainType.width) || z >= static_cast<std::uint32_t>(mTerrainType.height)) {
        gpg::HandleAssertFailure(
          "x < mSizeX && y < mSizeY", 135, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/containers/Array2D.h"
        );
      }

      const std::size_t index = static_cast<std::size_t>(z) * static_cast<std::size_t>(mTerrainType.width) + x;
      mTerrainType.data[index] = type;
    }
  }

  /**
   * Address: 0x00577F20 (FUN_00577F20)
   *
   * unsigned int z, unsigned int x
   *
   * IDA signature:
   * bool __usercall Moho::STIMap::IsBlockingTerrain@<al>(Moho::STIMap *this@<ecx>, unsigned int x@<edi>, unsigned int y@<esi>);
   *
   * What it does:
   * Returns whether terrain cell `(x,z)` is blocked by map terrain-type flags.
   */
  bool STIMap::IsBlockingTerrain(const std::uint32_t z, const std::uint32_t x) const
  {
    const CHeightField* const field = mHeightField.get();
    return x >= static_cast<std::uint32_t>(field->width - 1) ||
           z >= static_cast<std::uint32_t>(field->height - 1) ||
           mBlocking[mTerrainType.data[static_cast<std::size_t>(z) * static_cast<std::size_t>(mTerrainType.width) + x]] != 0u;
  }

  /**
   * Address: 0x00564DF0 (FUN_00564DF0)
   *
   * Moho::SOCellPos const &, Moho::SFootprint const &
   *
   * IDA signature:
   * Moho::EOccupancyCaps callcnv_F3 Moho::STIMap::OccupancyCapsOfFootprintAt@<al>(Moho::SOCellPos *pos@<eax>, Moho::STIMap *map@<ecx>, const Moho::SFootprint *fp);
   *
   * What it does:
   * Computes terrain/water/slope occupancy caps for one footprint origin.
   */
  EOccupancyCaps STIMap::OccupancyCapsOfFootprintAt(const SOCellPos& pos, const SFootprint& footprint) const
  {
    const CHeightField* const field = mHeightField.get();
    const std::uint32_t x = static_cast<std::uint32_t>(static_cast<std::int32_t>(pos.x));
    const std::uint32_t z = static_cast<std::uint32_t>(static_cast<std::int32_t>(pos.z));
    if (x >= static_cast<std::uint32_t>(field->width - 1) ||
        z >= static_cast<std::uint32_t>(field->height - 1) ||
        IsBlockingTerrain(z, x)) {
      return static_cast<EOccupancyCaps>(0u);
    }

    const float waterElevation = (mWaterEnabled != 0u) ? mWaterElevation : kNoWaterElevation;
    const std::size_t row0 = static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width);
    const std::size_t row1 = static_cast<std::size_t>(z + 1u) * static_cast<std::size_t>(field->width);

    const std::uint16_t h00 = field->data[row0 + x];
    const std::uint16_t h10 = field->data[row0 + x + 1u];
    const std::uint16_t h01 = field->data[row1 + x];
    const std::uint16_t h11 = field->data[row1 + x + 1u];

    const std::uint16_t minHeight = std::min(std::min(h00, h10), std::min(h01, h11));
    const std::uint16_t maxHeight = std::max(std::max(h00, h10), std::max(h01, h11));

    std::uint8_t capsMask = OccupancyMask(footprint.mOccupancyCaps);
    if (footprint.mMinWaterDepth > (waterElevation - static_cast<float>(maxHeight) * kHeightWordScale)) {
      capsMask = RemoveCaps(capsMask, kOccWaterSubSeabed);
    }
    if ((waterElevation - static_cast<float>(minHeight) * kHeightWordScale) > footprint.mMaxWaterDepth) {
      capsMask = RemoveCaps(capsMask, kOccLandSeabed);
    }

    if ((capsMask & kOccLandSeabed) != 0u && footprint.mMaxSlope != 0.0f) {
      int maxDelta = std::abs(static_cast<int>(h11) - static_cast<int>(h01));
      maxDelta = std::max(maxDelta, std::abs(static_cast<int>(h11) - static_cast<int>(h10)));
      maxDelta = std::max(maxDelta, std::abs(static_cast<int>(h01) - static_cast<int>(h00)));
      maxDelta = std::max(maxDelta, std::abs(static_cast<int>(h10) - static_cast<int>(h00)));
      if (static_cast<float>(maxDelta) * kHeightWordScale > footprint.mMaxSlope) {
        capsMask = RemoveCaps(capsMask, kOccLandSeabed);
      }
    }

    return ToOccupancyCaps(capsMask);
  }

  /**
   * Address: 0x00577F60 (FUN_00577F60)
   *
   * LuaPlus::LuaState *
   *
   * IDA signature:
   * LuaPlus::LuaObject *__thiscall Moho::STIMap::LoadTerrainTypes(LuaPlus::LuaState *state, Moho::STIMap *this);
   *
   * What it does:
   * Loads `/lua/TerrainTypes.lua`, filters valid entries by `TypeCode`, then
   * writes terrain type descriptors + blocking flags.
   */
  void STIMap::LoadTerrainTypes(LuaPlus::LuaState* state)
  {
    if (!state) {
      gpg::Warnf("No terrain types found.");
      return;
    }

    LuaPlus::LuaObject scriptEnv{};
    scriptEnv.AssignNewTable(state, 0, 0);

    bool loaded = DoScriptIntoEnv(state, "/lua/TerrainTypes.lua", scriptEnv);
    if (!loaded) {
      LuaPlus::LuaObject imported = moho::SCR_ImportLuaModule(state, "/lua/TerrainTypes.lua");
      if (imported) {
        scriptEnv = imported;
        loaded = true;
      }
    }

    if (!loaded) {
      gpg::Warnf("No terrain types found.");
      return;
    }

    LuaPlus::LuaObject terrainTypesTable = moho::SCR_GetLuaTableField(state, scriptEnv, "TerrainTypes");
    if (!terrainTypesTable || !terrainTypesTable.IsTable()) {
      scriptEnv.Reset();
      return;
    }

    msvc8::vector<LuaPlus::LuaObject> parsedEntries{};
    for (LuaPlus::LuaTableIterator iter(&terrainTypesTable, 1); !iter.m_isDone; iter.Next()) {
      LuaPlus::LuaObject entry = iter.GetValue();
      if (!entry || !entry.IsTable()) {
        continue;
      }

      LuaPlus::LuaObject typeCodeObj = moho::SCR_GetLuaTableField(state, entry, "TypeCode");
      if (typeCodeObj.IsNil()) {
        continue;
      }

      parsedEntries.push_back(entry);
    }

    LuaPlus::LuaObject defaultTerrainType(state);
    ConstructTerrainTypes(mTerrainTypes, static_cast<std::uint32_t>(kTerrainTypeCount), defaultTerrainType);

    for (LuaPlus::LuaObject* it = parsedEntries.begin(); it != parsedEntries.end(); ++it) {
      LuaPlus::LuaObject typeCodeObj = moho::SCR_GetLuaTableField(state, *it, "TypeCode");
      const std::uint8_t typeCode = static_cast<std::uint8_t>(static_cast<int>(typeCodeObj.GetNumber()));
      mTerrainTypes.ttvec.begin()[typeCode] = *it;

      LuaPlus::LuaObject blockingObj = moho::SCR_GetLuaTableField(state, *it, "Blocking");
      if (!blockingObj.IsNil() && blockingObj.GetBoolean()) {
        mBlocking[typeCode] = 1u;
      }
    }

    scriptEnv.Reset();
  }

  /**
   * Address: 0x00758E10 (FUN_00758E10)
   *
   * unsigned int x, unsigned int z
   *
   * IDA signature:
   * LuaPlus::LuaObject *__usercall Moho::STIMap::GetTerrainType@<eax>(Moho::STIMap *this@<eax>, LuaPlus::LuaObject
   * *out@<ebx>, unsigned int z@<edi>, unsigned int x@<esi>);
   *
   * What it does:
   * Returns terrain-type Lua descriptor for cell `(x,z)`, defaulting to type `1`.
   */
  LuaPlus::LuaObject STIMap::GetTerrainType(const std::uint32_t x, const std::uint32_t z) const
  {
    std::uint8_t terrainType = 1u;

    CHeightField* const field = mHeightField.get();
    if (field && mTerrainType.data && field->width > 0 && field->height > 0 &&
        x < static_cast<std::uint32_t>(field->width - 1) && z < static_cast<std::uint32_t>(field->height - 1)) {
      const std::size_t index =
        static_cast<std::size_t>(x) + static_cast<std::size_t>(z) * static_cast<std::size_t>(mTerrainType.width);
      terrainType = mTerrainType.data[index];
    }

    return GetTerrainType(terrainType);
  }

  /**
   * Address: 0x006A4C20 (FUN_006A4C20)
   *
   * unsigned char typeIndex
   *
   * IDA signature:
   * LuaPlus::LuaObject *__usercall Moho::STIMap::GetTerrainType@<eax>(Moho::STIMap *this@<ecx>, unsigned __int8
   * typeIndex@<al>, LuaPlus::LuaObject *out@<esi>);
   *
   * What it does:
   * Returns terrain-type Lua descriptor by direct type index.
   */
  LuaPlus::LuaObject STIMap::GetTerrainType(const std::uint8_t typeIndex) const
  {
    if (!mTerrainTypes.ttvec.IsInitialized()) {
      return {};
    }
    return LuaPlus::LuaObject(mTerrainTypes.ttvec.begin()[typeIndex]);
  }

  /**
   * Address: 0x00758E90 (FIND_GetTerrainTypeOffset_exe)
   *
   * float x, float z
   *
   * IDA signature:
   * float __userpurge Moho::STIMap::GetTerrainTypeOffset@<xmm0>(Moho::STIMap *this, float x, float z);
   *
   * What it does:
   * Reads optional per-terrain-type `HeightOffset`; defaults to 0.0f.
   */
  float STIMap::GetTerrainTypeOffset(const float x, const float z) const
  {
    float value = 0.0f;

    LuaPlus::LuaObject terrainType = GetTerrainType(static_cast<std::uint32_t>(x), static_cast<std::uint32_t>(z));
    if (terrainType.IsTable()) {
      LuaPlus::LuaState* const state = terrainType.GetActiveState();
      LuaPlus::LuaObject heightOffset = moho::SCR_GetLuaTableField(state, terrainType, "HeightOffset");
      if (!heightOffset.IsNil()) {
        value = static_cast<float>(heightOffset.GetNumber());
      }
    }

    return value;
  }

  /**
   * Address: 0x00577B60 (FUN_00577B60)
   *
   * IDA signature:
   * Wm3::AxisAlignedBox3f *__userpurge Moho::STIMap::GetBounds3D@<eax>(Moho::STIMap *this@<ebx>, Wm3::AxisAlignedBox3f
   * *out);
   *
   * What it does:
   * Returns map world bounds from coarsest height tier and extends top Y by water level.
   */
  Wm3::AxisAlignedBox3f STIMap::GetBounds3D() const
  {
    Wm3::AxisAlignedBox3f out{};
    CHeightField* const field = mHeightField.get();
    if (!field) {
      return out;
    }

    const std::int32_t tierCount =
      field->mGrids.begin() ? static_cast<std::int32_t>(field->mGrids.end() - field->mGrids.begin()) : 0;
    out = field->GetTierBox(0, 0, tierCount);

    if (mWaterEnabled != 0u && mWaterElevation > out.Max.y) {
      out.Max.y = mWaterElevation;
    }
    return out;
  }

  /**
   * Address: 0x00577BC0 (FUN_00577BC0)
   *
   * Wm3::GeomLine3<float> const &, Moho::CColHitResult *
   *
   * IDA signature:
   * Wm3::Vector3f *__userpurge Moho::STIMap::SurfaceIntersection@<eax>(Moho::CGeomHitResult *res@<eax>, Moho::STIMap
   * *this, Wm3::Vector3f *dest, Moho::GeomLine3 *line);
   *
   * What it does:
   * Intersects line segment against terrain/water and falls back to plane hit when needed.
   */
  Wm3::Vec3f STIMap::SurfaceIntersection(const GeomLine3& line, CColHitResult* res) const
  {
    CHeightField* const field = mHeightField.get();
    if (!field) {
      return Wm3::Vec3f::NaN();
    }

    if (mWaterEnabled == 0u) {
      const std::int32_t tierCount =
        field->mGrids.begin() ? static_cast<std::int32_t>(field->mGrids.end() - field->mGrids.begin()) : 0;
      const Wm3::AxisAlignedBox3f terrainBounds = field->GetTierBox(0, 0, tierCount);
      const Wm3::Vec3f terrainHit = field->Intersection(line, reinterpret_cast<CGeomHitResult*>(res));

      if (res && Wm3::Vec3f::IsntNaN(terrainHit)) {
        res->hitKind = 1;
      }

      if (Wm3::Vec3f::IsntNaN(terrainHit) && terrainHit.y > terrainBounds.Min.y) {
        return terrainHit;
      }

      VecDist plane{};
      plane.dir.x = 0.0f;
      plane.dir.y = 1.0f;
      plane.dir.z = 0.0f;
      plane.dist = terrainBounds.Min.y;
      if (res) {
        res->hitKind = 3;
      }
      return PlaneIntersection(line, plane, reinterpret_cast<CGeomHitResult*>(res));
    }

    if (line.closest > -std::numeric_limits<float>::max()) {
      const Wm3::Vec3f closestPoint = PointOnLine(line, line.closest);
      if (mWaterElevation > closestPoint.y) {
        if (res) {
          res->distance = line.closest;
        }
        return closestPoint;
      }
    }

    const Wm3::Vec3f terrainHit = field->Intersection(line, reinterpret_cast<CGeomHitResult*>(res));
    if (res && Wm3::Vec3f::IsntNaN(terrainHit)) {
      res->hitKind = 1;
    }

    if (terrainHit.y < mWaterElevation || !Wm3::Vec3f::IsntNaN(terrainHit)) {
      VecDist plane{};
      plane.dir.x = 0.0f;
      plane.dir.y = 1.0f;
      plane.dir.z = 0.0f;
      plane.dist = mWaterElevation;
      if (res) {
        res->hitKind = 3;
      }
      return PlaneIntersection(line, plane, reinterpret_cast<CGeomHitResult*>(res));
    }

    if (res) {
      res->hitKind = 1;
    }
    return terrainHit;
  }

  /**
   * Address: 0x00541A30 (FUN_00541A30), 0x1012F3B0 (FUN_1012F3B0)
   *
   * Wm3::Vector3<float> const &
   *
   * IDA signature:
   * int __usercall sub_541A30@<xmm0>(float *position@<eax>, Moho::STIMap *this@<esi>);
   *
   * What it does:
   * Returns max(terrain elevation, water elevation when water is enabled).
   */
  float STIMap::GetSurface(const Wm3::Vec3f& position) const
  {
    const float terrainElevation = mHeightField->GetElevation(position.x, position.z);
    if (mWaterEnabled == 0u) {
      return terrainElevation;
    }

    return mWaterElevation > terrainElevation ? mWaterElevation : terrainElevation;
  }

  /**
   * Address: 0x00564AB0 (FUN_00564AB0, ?OCCUPY_MobileCheck@Moho@@YA?AW4ELayer@1@ABUSFootprint@1@ABUSOCellPos@1@PBVSTIMap@1@@Z)
   *
   * Moho::SFootprint const &, Moho::STIMap const &, Moho::SOCellPos const &
   *
   * IDA signature:
   * Moho::EOccupancyCaps callcnv_F3 Moho::OCCUPY_MobileCheck@<al>(const Moho::SFootprint *a1, Moho::STIMap *map, Moho::SOCellPos *v1@<ecx>);
   *
   * What it does:
   * Computes dynamic occupancy caps for multi-cell footprints using terrain,
   * blocking-map, depth, and slope checks.
   */
  EOccupancyCaps OCCUPY_MobileCheck(const SFootprint& footprint, const STIMap& map, const SOCellPos& pos)
  {
    const int x0 = static_cast<int>(pos.x);
    const int z0 = static_cast<int>(pos.z);
    const int x1 = x0 + static_cast<int>(footprint.mSizeX);
    const int z1 = z0 + static_cast<int>(footprint.mSizeZ);
    if (x0 < 0 || z0 < 0) {
      return static_cast<EOccupancyCaps>(0u);
    }

    const CHeightField* const field = map.mHeightField.get();
    if (static_cast<std::uint32_t>(x1) > static_cast<std::uint32_t>(field->width - 1) ||
        static_cast<std::uint32_t>(z1) > static_cast<std::uint32_t>(field->height - 1)) {
      return static_cast<EOccupancyCaps>(0u);
    }

    const float waterElevation = map.mWaterEnabled != 0u ? map.mWaterElevation : kNoWaterElevation;

    std::uint32_t maxHeight = 0u;
    std::uint32_t minHeight = std::numeric_limits<std::uint32_t>::max();
    for (int z = z0; z <= z1; ++z) {
      const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width);
      for (int x = x0; x <= x1; ++x) {
        const std::uint32_t sample = static_cast<std::uint32_t>(field->data[row + static_cast<std::size_t>(x)]);
        if (sample < minHeight) {
          minHeight = sample;
        }
        if (sample > maxHeight) {
          maxHeight = sample;
        }

        if (map.IsBlockingTerrain(static_cast<std::uint32_t>(z), static_cast<std::uint32_t>(x))) {
          return static_cast<EOccupancyCaps>(0u);
        }
      }
    }

    std::uint8_t capsMask = OccupancyMask(footprint.mOccupancyCaps);
    if (footprint.mMinWaterDepth > (waterElevation - static_cast<float>(maxHeight) * kHeightWordScale)) {
      capsMask = RemoveCaps(capsMask, kOccWaterSubSeabed);
    }
    if ((waterElevation - static_cast<float>(minHeight) * kHeightWordScale) > footprint.mMaxWaterDepth) {
      capsMask = RemoveCaps(capsMask, kOccLandSeabed);
    }

    if ((capsMask & kOccLandSeabed) != 0u && footprint.mMaxSlope != 0.0f) {
      int maxDelta = 0;

      for (int z = z0; z <= z1; ++z) {
        const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width);
        int previous = static_cast<int>(field->data[row + static_cast<std::size_t>(x0)]);
        for (int x = x0 + 1; x <= x1; ++x) {
          const int current = static_cast<int>(field->data[row + static_cast<std::size_t>(x)]);
          maxDelta = std::max(maxDelta, std::abs(current - previous));
          previous = current;
        }
      }

      for (int x = x0; x <= x1; ++x) {
        std::size_t row = static_cast<std::size_t>(z0) * static_cast<std::size_t>(field->width);
        int previous = static_cast<int>(field->data[row + static_cast<std::size_t>(x)]);
        for (int z = z0 + 1; z <= z1; ++z) {
          row = static_cast<std::size_t>(z) * static_cast<std::size_t>(field->width);
          const int current = static_cast<int>(field->data[row + static_cast<std::size_t>(x)]);
          maxDelta = std::max(maxDelta, std::abs(current - previous));
          previous = current;
        }
      }

      if (static_cast<float>(maxDelta) * kHeightWordScale > footprint.mMaxSlope) {
        capsMask = RemoveCaps(capsMask, kOccLandSeabed);
      }
    }

    return ToOccupancyCaps(capsMask);
  }

  /**
   * Address: 0x00720AA0 (FUN_00720AA0, Moho::SFootprint::FitsAt)
   *
   * Moho::SCoordsVec2 const &, Moho::COGrid const &
   *
   * What it does:
   * Computes footprint origin cell from world-space center coordinates and
   * forwards to `OCCUPY_FootprintFits(..., OC_ANY)`.
   */
  EOccupancyCaps SFootprint::FitsAt(const SCoordsVec2& worldPos, const COGrid& grid) const
  {
    const float originZ = worldPos.z - static_cast<float>(mSizeZ) * 0.5f;

    SOCellPos cellPos{};
    cellPos.x = static_cast<std::int16_t>(static_cast<int>(worldPos.x - static_cast<float>(mSizeX) * 0.5f));
    cellPos.z = static_cast<std::int16_t>(static_cast<int>(originZ));
    return OCCUPY_FootprintFits(grid, cellPos, *this, EOccupancyCaps::OC_ANY);
  }

  /**
   * Address: 0x00720920 (FUN_00720920)
   *
   * Moho::SFootprint const &, Moho::COGrid const &, Moho::SOCellPos const &, Moho::EOccupancyCaps
   *
   * IDA signature:
   * Moho::EOccupancyCaps __userpurge Moho::OCCUPY_Filter@<al>(const Moho::SFootprint *fp@<ecx>, Moho::COGrid *a2@<esi>, Moho::SOCellPos *pos, Moho::EOccupancyCaps a4);
   *
   * What it does:
   * Applies single-cell occupancy filtering against terrain/water occupation bitmaps.
   */
  EOccupancyCaps OCCUPY_Filter(
    const SFootprint& footprint, const COGrid& grid, const SOCellPos& pos, EOccupancyCaps occupancyCaps
  )
  {
    EOccupancyCaps caps = occupancyCaps;
    if (caps == EOccupancyCaps::OC_ANY) {
      caps = grid.sim->mMapData->OccupancyCapsOfFootprintAt(pos, footprint);
    }

    std::uint8_t capsMask = OccupancyMask(caps);
    const int footprintX = static_cast<int>(pos.x);
    const int footprintZ = static_cast<int>(pos.z);
    const std::uint8_t footprintFlags = static_cast<std::uint8_t>(footprint.mFlags);
    if ((footprintFlags & static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures)) == 0u &&
        (capsMask & kOccLandSeabed) != 0u &&
        grid.terrainOccupation.IsBitSetOrOutOfBounds(footprintX, footprintZ)) {
        capsMask = RemoveCaps(capsMask, kOccLandSeabed);
    }

    if ((capsMask & kOccWater) != 0u && grid.waterOccupation.IsBitSetOrOutOfBounds(footprintX, footprintZ)) {
      capsMask = RemoveCaps(capsMask, kOccWater);
    }

    return ToOccupancyCaps(capsMask);
  }

  /**
   * Address: 0x007209E0 (FUN_007209E0)
   *
   * Moho::COGrid const &, Moho::SOCellPos const &, Moho::SFootprint const &, Moho::EOccupancyCaps
   *
   * IDA signature:
   * Moho::EOccupancyCaps callcnv_E3 Moho::OCCUPY_FootprintFits@<al>(Moho::COGrid *eax0@<eax>, Moho::SOCellPos *a2@<edi>, const Moho::SFootprint *a1, Moho::EOccupancyCaps a4);
   *
   * What it does:
   * Returns occupancy-fit caps for a footprint at one origin using mobile
   * terrain checks plus terrain/water occupation bit arrays.
   */
  EOccupancyCaps OCCUPY_FootprintFits(
    const COGrid& grid, const SOCellPos& pos, const SFootprint& footprint, const EOccupancyCaps occupancyCaps
  )
  {
    const std::uint8_t sizeX = footprint.mSizeX;
    const std::uint8_t sizeZ = footprint.mSizeZ;
    const std::uint8_t sizeMax = sizeX > sizeZ ? sizeX : sizeZ;
    if (sizeMax == 1u) {
      return OCCUPY_Filter(footprint, grid, pos, occupancyCaps);
    }

    EOccupancyCaps caps = occupancyCaps;
    if (caps == EOccupancyCaps::OC_ANY) {
      caps = OCCUPY_MobileCheck(footprint, *grid.sim->mMapData, pos);
    }

    std::uint8_t capsMask = OccupancyMask(caps);
    const std::uint8_t footprintFlags = static_cast<std::uint8_t>(footprint.mFlags);
    if ((footprintFlags & static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures)) == 0u &&
        (capsMask & kOccLandSeabed) != 0u &&
        grid.terrainOccupation.GetRectOr(pos.x, pos.z, sizeX, sizeZ, true)) {
      capsMask = RemoveCaps(capsMask, kOccLandSeabed);
    }

    if ((capsMask & kOccWater) != 0u && grid.waterOccupation.GetRectOr(pos.x, pos.z, sizeX, sizeZ, true)) {
      capsMask = RemoveCaps(capsMask, kOccWater);
    }

    return ToOccupancyCaps(capsMask);
  }

  CHeightField* STIMap::GetHeightField() const noexcept
  {
    return mHeightField.get();
  }

  bool STIMap::IsWaterEnabled() const noexcept
  {
    return mWaterEnabled != 0u;
  }

  float STIMap::GetWaterElevation() const noexcept
  {
    return mWaterElevation;
  }
} // namespace moho

// Sim targets on engine objects: retail builds the object with its own
// constructor (its allocator redirected to the harness heap, main.cpp
// kRetailHeapEntries), runs the function and frees the object; ours does the
// same with the engine's class. The objects' contents come from a few input
// words (size, seed, shape) through one integer expander both sides share, so
// a row stays inside kMaxWords and every platform builds the same object.
//
// The standalone difffuzz build cannot compile the engine TUs these classes
// live in, so there `ours` is null: difffuzz writes retail's outputs (--dump,
// --values) and faf_math_dump, linked against the engine, checks them. See
// README.md, "Sim targets on engine objects".
#include "fuzz.h"
#include "retail_thunks.h"
#include "gpg/core/containers/BitArray2D.h"

#include <cmath>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>
#include <vector>

#if defined(DIFFFUZZ_ENGINE_LINKED)
extern "C" int luaO_log2(unsigned int x);           // src/lua/LuaObject.cpp, extern "C" block
extern "C" unsigned int luaO_int2fb(unsigned int x); // src/lua/LuaObject.cpp, extern "C" block
#include "lua/LuaArena.h"
#include "lua/LuaRuntimeTypes.h"
extern "C" const LuaPlus::TObject luaO_nilobject;                          // src/lua/LuaObject.cpp, extern "C" block
extern "C" const LuaPlus::TObject* luaH_getstr(Table* t, TString* key);     // src/lua/LuaObject.cpp, extern "C" block
extern "C" const LuaPlus::TObject* luaH_getnum(Table* t, int key);          // src/lua/LuaObject.cpp, extern "C" block
extern "C" const LuaPlus::TObject* luaH_get(Table* t, const LuaPlus::TObject* key); // src/lua/LuaObject.cpp, extern "C" block
extern "C" Node* luaH_mainposition(const Table* t, const LuaPlus::TObject* key);     // src/lua/LuaObject.cpp, extern "C" block
extern "C" int luaV_equalval(lua_State* L, const LuaPlus::TObject* l, const LuaPlus::TObject* r); // src/lua/LuaObject.cpp, extern "C" block
extern "C" int luaH_index(lua_State* L, Table* t, const LuaPlus::TObject* key);      // src/lua/LuaObject.cpp, extern "C" block
extern "C" int luaH_next(lua_State* L, Table* t, LuaPlus::TObject* key);             // src/lua/LuaObject.cpp, extern "C" block
extern "C" LuaPlus::TObject* luaH_set(lua_State* L, Table* t, const LuaPlus::TObject* key); // src/lua/LuaObject.cpp, extern "C" block
extern "C" LuaPlus::TObject* luaH_setnum(lua_State* L, Table* t, int key);          // src/lua/LuaObject.cpp, extern "C" block
extern "C" int luaV_lessthan(lua_State* L, const LuaPlus::TObject* l, const LuaPlus::TObject* r); // src/lua/LuaObject.cpp, extern "C" block
extern "C" LuaPlus::TObject* luaA_index(lua_State* L, int idx);                      // src/lua/LuaObject.cpp, extern "C" block
extern "C" LuaPlus::TObject* negindex(lua_State* L, int idx);                        // src/lua/LuaObject.cpp, extern "C" block
extern "C" int lua_type(lua_State* L, int idx);                                      // src/lua/LuaObject.cpp, extern "C" block
extern "C" int lua_gettop(lua_State* L);                                             // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_settop(lua_State* L, int idx);                                   // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_pushvalue(lua_State* L, int idx);                                // src/lua/LuaObject.cpp, extern "C" block
extern "C" float lua_tonumber(lua_State* L, int idx);                                // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_rawgeti(lua_State* L, int idx, int n);                           // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_pushnumber(lua_State* L, float n);                               // src/lua/LuaObject.cpp, extern "C" block
extern "C" int lua_next(lua_State* L, int idx);                                      // src/lua/LuaObject.cpp, extern "C" block
extern "C" const LuaPlus::TObject* luaT_gettm(Table* events, int event, TString* ename); // src/lua/LuaObject.cpp, extern "C" block
extern "C" const LuaPlus::TObject* luaV_index(lua_State* L, const LuaPlus::TObject* t, const LuaPlus::TObject* key, int loop); // src/lua/LuaObject.cpp
extern "C" const LuaPlus::TObject* luaV_gettable(lua_State* L, const LuaPlus::TObject* t, const LuaPlus::TObject* key, int loop); // src/lua/LuaObject.cpp
extern "C" void luaV_settable(lua_State* L, const LuaPlus::TObject* t, LuaPlus::TObject* key, LuaPlus::TObject* val); // src/lua/LuaObject.cpp
extern "C" int lua_toboolean(lua_State* L, int idx);                                 // src/lua/LuaObject.cpp, extern "C" block
extern "C" int lua_isnumber(lua_State* L, int idx);                                  // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_pushnil(lua_State* L);                                           // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_pushboolean(lua_State* L, int b);                                // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_rawget(lua_State* L, int idx);                                   // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_rawseti(lua_State* L, int idx, int n);                           // src/lua/LuaObject.cpp, extern "C" block
extern "C" void lua_rawset(lua_State* L, int idx);                                   // src/lua/LuaObject.cpp, extern "C" block
extern "C" void computesizes(int ntotal, int* narray, int* nhash, const int* nums);  // src/lua/LuaObject.cpp, extern "C" block
#include "moho/sim/CollisionShape.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CIntelGrid.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/sim/GridTraversalLine.h"
#include "moho/math/MathReflection.h"
#include "moho/math/VMatrix4.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#define ENGINE_ONLY(fn) fn
#else
#define ENGINE_ONLY(fn) nullptr
#endif

namespace difffuzz
{
  namespace
  {
    using u32 = std::uint32_t;

    [[nodiscard]] float F(const u32* in, const int i) noexcept { return FromBits(in[i]); }
    void Put(u32* out, const int i, const float f) noexcept { out[i] = Bits(f); }

    [[nodiscard]] float NearFloat(Rng& rng, const double value)
    {
      const u32 bits = Bits(static_cast<float>(value));
      return FromBits(bits + rng.Below(7) - 3u);
    }

    // ---- height fields --------------------------------------------------------
    //
    // A field of cellsW x cellsH cells has (cellsW + 1) x (cellsH + 1) 16-bit
    // samples; elevation is sample / 128 (0..512). The constructor builds one
    // min/max tier per halving of the larger side, so sides up to 32 cells give
    // up to five tiers.

    enum FieldShape : u32
    {
      kShapeFlat,       // one level everywhere: every triangle edge ties
      kShapeRandom,     // every sample a random word, 0..0xFFFF
      kShapeRolling,    // a gentle slope plus small noise, the usual map
      kShapeTerraced,   // a few plateaus with cliffs between them
      kShapeExtremes,   // 0 and 0xFFFF in a checkerboard
      kShapeDiagonal,   // a function of x + z or x - z: ridges along the cell diagonals
      kShapeCount
    };

    /// Fills the samples from the seed and shape with 32-bit integer arithmetic
    /// only, so every build and platform fills the same field.
    void FillFieldSamples(std::uint16_t* samples, const int sampleW, const int sampleH, const u32 seed, const u32 shape)
    {
      u32 state = seed | 1u;
      const auto next = [&state]() noexcept {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
      };
      const u32 base = next() & 0x7FFFu;
      const u32 levels[4] = {next() & 0xFFFFu, next() & 0xFFFFu, next() & 0xFFFFu, next() & 0xFFFFu};
      const u32 antiDiagonal = next() & 1u;
      for (int z = 0; z < sampleH; ++z) {
        for (int x = 0; x < sampleW; ++x) {
          u32 value = 0;
          switch (shape % kShapeCount) {
          case kShapeFlat:
            value = base;
            break;
          case kShapeRandom:
            value = next() & 0xFFFFu;
            break;
          case kShapeRolling:
            value = base + static_cast<u32>(x) * 97u + static_cast<u32>(z) * 61u + (next() & 0xFFu);
            break;
          case kShapeTerraced:
            value = levels[((static_cast<u32>(x) / 3u) + (static_cast<u32>(z) / 2u)) & 3u];
            break;
          case kShapeExtremes:
            value = ((x + z) & 1) != 0 ? 0xFFFFu : 0u;
            break;
          default: {
            const int d = antiDiagonal != 0 ? x - z + sampleH : x + z;
            value = base + static_cast<u32>(d) * 211u;
            break;
          }
          }
          samples[z * sampleW + x] = static_cast<std::uint16_t>(value);
        }
      }
    }

    /// in[0..3] = cellsW, cellsH, seed, shape. Each side is a power of two, as
    /// every map's is: for an odd side the constructor's tier 0 is cells >> 1
    /// wide (0x00476138..0x00476153) but UpdateBounds over the whole field
    /// writes column (cells + 1) >> 1 - 1 = cells >> 1, one past it, in retail
    /// and in ours alike.
    void GenFieldSpec(Rng& rng, u32* in)
    {
      const u32 sizeMode = rng.Below(100);
      // 2..64 cells a side: a 1-cell field has no tier grid (0x00476090 makes
      // none when the larger side is 1), and the tier readers fault on it.
      const u32 cellsW = 2u << rng.Below(6);
      u32 cellsH = 2u << rng.Below(6);
      if (sizeMode < 40) {
        cellsH = cellsW; // square fields: the diagonal runs corner to corner
      }
      in[0] = cellsW;
      in[1] = cellsH;
      in[2] = rng.U32();
      in[3] = rng.Below(kShapeCount);
    }

    /// A coordinate across a side of `cells` cells: inside, on and near the
    /// sample lines and the cell centres, past the edges, or any float.
    [[nodiscard]] float GenFieldAxis(Rng& rng, const u32 cells)
    {
      const u32 mode = rng.Below(100);
      const double size = static_cast<double>(cells);
      if (mode < 50) {
        return static_cast<float>(rng.Range(-2.0, size + 2.0));
      }
      if (mode < 70) {
        return NearFloat(rng, static_cast<double>(static_cast<int>(rng.Below(cells + 3u)) - 1));
      }
      if (mode < 85) {
        return NearFloat(rng, static_cast<double>(static_cast<int>(rng.Below(cells + 3u)) - 1) + 0.5);
      }
      return GenFloat(rng);
    }

    struct RetailField
    {
      unsigned char bytes[0x1C];
    };

    /// Retail's field: its constructor, the samples, and UpdateBounds over the
    /// whole field as the sim does after loading a map (Sim.cpp, fullBounds).
    void BuildRetailField(RetailField& field, const u32* spec)
    {
      std::memset(field.bytes, 0, sizeof(field.bytes));
      const int cellsW = static_cast<int>(spec[0]);
      const int cellsH = static_cast<int>(spec[1]);
      retail::HeightFieldConstruct(&field, cellsW, cellsH);
      std::uint16_t* samples;
      std::memcpy(&samples, field.bytes + 0x00, 4);
      FillFieldSamples(samples, cellsW + 1, cellsH + 1, spec[2], spec[3]);
      retail::HeightFieldUpdateBounds(&field, 0, 0, 0x7FFFFFFF, 0x7FFFFFFF);
    }

    /// ~CHeightField (0x004784F0): delete[] each tier's two grids (+0x00,
    /// +0x0C in a 0x18-byte tier), the tier array (+0x10 begin, +0x14 end)
    /// and the samples (+0x00), all through retail's operator delete.
    void FreeRetailField(RetailField& field)
    {
      unsigned char* begin;
      unsigned char* end;
      std::memcpy(&begin, field.bytes + 0x10, 4);
      std::memcpy(&end, field.bytes + 0x14, 4);
      for (unsigned char* tier = begin; tier < end; tier += 0x18) {
        void* grid;
        std::memcpy(&grid, tier + 0x00, 4);
        retail::OperatorDelete(grid);
        std::memcpy(&grid, tier + 0x0C, 4);
        retail::OperatorDelete(grid);
      }
      retail::OperatorDelete(begin);
      void* samples;
      std::memcpy(&samples, field.bytes + 0x00, 4);
      retail::OperatorDelete(samples);
    }

    /// FNV-1a over 16-bit values, folded into two output words.
    struct Fnv
    {
      std::uint64_t h = 0xCBF29CE484222325ull;
      void Add16(const std::uint16_t v) noexcept
      {
        h = (h ^ (v & 0xFFu)) * 0x100000001B3ull;
        h = (h ^ (v >> 8)) * 0x100000001B3ull;
      }
      void Add32(const u32 v) noexcept
      {
        Add16(static_cast<std::uint16_t>(v));
        Add16(static_cast<std::uint16_t>(v >> 16));
      }
    };

#if defined(DIFFFUZZ_ENGINE_LINKED)
    void BuildOurField(moho::CHeightField& field, const u32* spec)
    {
      FillFieldSamples(field.data, static_cast<int>(spec[0]) + 1, static_cast<int>(spec[1]) + 1, spec[2], spec[3]);
      field.UpdateBounds(gpg::Rect2i{0, 0, 0x7FFFFFFF, 0x7FFFFFFF});
    }
#endif

    // CHeightField::UpdateBounds 0x00476BB0: in = field spec, a second seed and
    // shape, and a rect. The field is built and bounded whole, its samples
    // are refilled from the second seed, and UpdateBounds runs over the rect
    // (SetElevationRect's pattern: only the rect's tiers move). out = tier
    // count, then an FNV hash of every tier's dimensions and min/max words.
    [[nodiscard]] int GenRectEdge(Rng& rng, const u32 cells)
    {
      const u32 mode = rng.Below(100);
      if (mode < 70) {
        return static_cast<int>(rng.Below(cells + 3u)) - 1;
      }
      if (mode < 80) {
        return 0x7FFFFFFF;
      }
      if (mode < 90) {
        return -0x7FFFFFFF - 1;
      }
      return static_cast<int>(rng.U32());
    }
    void GenUpdateBounds(Rng& rng, u32* in)
    {
      GenFieldSpec(rng, in);
      in[4] = rng.U32();
      in[5] = rng.Below(kShapeCount);
      if (rng.Chance(15)) {
        in[6] = 0u;
        in[7] = 0u;
        in[8] = 0x7FFFFFFFu;
        in[9] = 0x7FFFFFFFu;
        return;
      }
      in[6] = static_cast<u32>(GenRectEdge(rng, in[0]));
      in[7] = static_cast<u32>(GenRectEdge(rng, in[1]));
      in[8] = static_cast<u32>(GenRectEdge(rng, in[0]));
      in[9] = static_cast<u32>(GenRectEdge(rng, in[1]));
    }
    void UpdateBoundsRetail(const u32* in, u32* out)
    {
      RetailField field;
      BuildRetailField(field, in);
      std::uint16_t* samples;
      std::memcpy(&samples, field.bytes + 0x00, 4);
      FillFieldSamples(samples, static_cast<int>(in[0]) + 1, static_cast<int>(in[1]) + 1, in[4], in[5]);
      retail::HeightFieldUpdateBounds(
        &field, static_cast<int>(in[6]), static_cast<int>(in[7]), static_cast<int>(in[8]), static_cast<int>(in[9])
      );
      unsigned char* begin;
      unsigned char* end;
      std::memcpy(&begin, field.bytes + 0x10, 4);
      std::memcpy(&end, field.bytes + 0x14, 4);
      Fnv hash;
      u32 tiers = 0;
      for (unsigned char* tier = begin; tier < end; tier += 0x18, ++tiers) {
        const std::uint16_t* grid; // SMinMax<uint16_t>: {min, max}
        int w;
        int h;
        std::memcpy(&grid, tier + 0x00, 4);
        std::memcpy(&w, tier + 0x04, 4);
        std::memcpy(&h, tier + 0x08, 4);
        hash.Add32(static_cast<u32>(w));
        hash.Add32(static_cast<u32>(h));
        for (int i = 0; i < w * h; ++i) {
          hash.Add16(grid[2 * i]);
          hash.Add16(grid[2 * i + 1]);
        }
      }
      FreeRetailField(field);
      out[0] = tiers;
      out[1] = static_cast<u32>(hash.h);
      out[2] = static_cast<u32>(hash.h >> 32);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void UpdateBoundsOurs(const u32* in, u32* out)
    {
      moho::CHeightField field(static_cast<int>(in[0]), static_cast<int>(in[1]));
      BuildOurField(field, in);
      FillFieldSamples(field.data, static_cast<int>(in[0]) + 1, static_cast<int>(in[1]) + 1, in[4], in[5]);
      field.UpdateBounds(
        gpg::Rect2i{static_cast<int>(in[6]), static_cast<int>(in[7]), static_cast<int>(in[8]), static_cast<int>(in[9])}
      );
      Fnv hash;
      u32 tiers = 0;
      for (const moho::CHeightFieldTier& tier : field.mGrids) {
        hash.Add32(static_cast<u32>(tier.data1.width));
        hash.Add32(static_cast<u32>(tier.data1.height));
        for (int i = 0; i < tier.data1.width * tier.data1.height; ++i) {
          hash.Add16(tier.data1.data[i].min);
          hash.Add16(tier.data1.data[i].max);
        }
        ++tiers;
      }
      out[0] = tiers;
      out[1] = static_cast<u32>(hash.h);
      out[2] = static_cast<u32>(hash.h >> 32);
    }
#endif

    // CHeightField::Intersection 0x00476F30 (DoIntersection 0x00477030, the
    // triangle tests 0x004778F0 / 0x00477B80, ClipSegmentToWorld 0x004776E0):
    // in = field spec, line pos[3] dir[3] closest farthest. out = the point,
    // then the hit record's distance and v1.
    //
    // A line start that is NaN, infinite or far off the map gives the cell
    // walk no end, in retail as in ours: a NaN z passes the dir.z == 0 bounds
    // test, every unordered edge compare advances z (0x00475FFA) and the end
    // test against a NaN z1 (0x00476070) never fires; at 1e30 one float step
    // is 7e22 cells. The clip's x and z limits must stay finite too: with a
    // direction lane near zero, (cells - p) / d overflows to infinity and the
    // walk runs to it (FLT_MIN with farthest = inf), and a subnormal lane
    // makes (-1/d) * 0 a NaN that replaces max (0x004777DB) until the next
    // finite limit replaces that (0x004778B1) and the other axis' bound is
    // gone. Starts stay within 2^20 and direction lanes are 0 or at least
    // 2^-100, so every limit is under 2^121 and finite.
    [[nodiscard]] bool WalkableStart(const float v)
    {
      return std::fabs(v) <= 1048576.0f;
    }
    [[nodiscard]] bool WalkableDirection(const float v)
    {
      return v == 0.0f || (std::isfinite(v) && std::fabs(v) >= 7.88860905e-31f); // 2^-100
    }
    [[nodiscard]] float WalkableFieldAxis(Rng& rng, const u32 cells)
    {
      float v;
      do {
        v = GenFieldAxis(rng, cells);
      } while (!WalkableStart(v));
      return v;
    }

    void GenIntersection(Rng& rng, u32* in)
    {
      GenFieldSpec(rng, in);
      const double cellsW = static_cast<double>(in[0]);
      const double cellsH = static_cast<double>(in[1]);
      float pos[3];
      float dir[3];
      const u32 mode = rng.Below(100);
      if (mode < 35) {
        // Aimed at a point near the surface from above, any heading.
        const double tx = rng.Range(-1.0, cellsW + 1.0);
        const double tz = rng.Range(-1.0, cellsH + 1.0);
        const double ty = rng.Range(0.0, 520.0);
        const double dx = rng.Range(-1.0, 1.0);
        const double dy = rng.Range(-1.0, 0.05);
        const double dz = rng.Range(-1.0, 1.0);
        const double len = std::sqrt(dx * dx + dy * dy + dz * dz) + 1e-30;
        const double back = rng.Range(1.0, 200.0);
        dir[0] = static_cast<float>(dx / len);
        dir[1] = static_cast<float>(dy / len);
        dir[2] = static_cast<float>(dz / len);
        pos[0] = static_cast<float>(tx - dir[0] * back);
        pos[1] = static_cast<float>(ty - dir[1] * back);
        pos[2] = static_cast<float>(tz - dir[2] * back);
      } else if (mode < 55) {
        // Along a cell diagonal: |dir.x| == |dir.z| exactly, and the start on
        // a diagonal sample line (x - z or x + z a whole number), the case
        // that divides by zero in the triangle split (0x00477AFE, 0x00477D90).
        const double flat = rng.Range(0.05, 1.0);
        const double down = rng.Range(0.0, 1.0);
        const double len = std::sqrt(2.0 * flat * flat + down * down);
        const float h = static_cast<float>(flat / len);
        const u32 signs = rng.Below(4);
        dir[0] = (signs & 1u) != 0 ? -h : h;
        dir[1] = static_cast<float>(-down / len);
        dir[2] = (signs & 2u) != 0 ? -h : h;
        const double x0 = static_cast<double>(static_cast<int>(rng.Below(in[0] + 1u)));
        const double offset = static_cast<double>(static_cast<int>(rng.Below(5u)) - 2);
        const double along = rng.Chance(50) ? 0.0 : rng.Range(-4.0, 4.0);
        pos[0] = static_cast<float>(x0 + along);
        pos[2] = static_cast<float>(((signs == 0u || signs == 3u) ? x0 + offset : cellsH - x0 + offset) + along);
        pos[1] = static_cast<float>(rng.Range(0.0, 600.0));
      } else if (mode < 65) {
        // Along a grid axis, or straight down.
        const u32 axis = rng.Below(3);
        const double down = rng.Range(0.0, 1.0);
        const double flat = axis == 2u ? 0.0 : rng.Range(0.0, 1.0);
        const double len = std::sqrt(flat * flat + down * down) + 1e-30;
        const float sign = rng.Chance(50) ? -1.0f : 1.0f;
        dir[0] = axis == 0u ? sign * static_cast<float>(flat / len) : 0.0f;
        dir[1] = static_cast<float>(-down / len);
        dir[2] = axis == 1u ? sign * static_cast<float>(flat / len) : 0.0f;
        pos[0] = WalkableFieldAxis(rng, in[0]);
        pos[2] = WalkableFieldAxis(rng, in[1]);
        pos[1] = static_cast<float>(rng.Range(0.0, 600.0));
      } else if (mode < 75) {
        // Level, at or just above the terrain.
        const double angle = rng.Range(0.0, 6.283185307179586);
        dir[0] = static_cast<float>(std::cos(angle));
        dir[1] = 0.0f;
        dir[2] = static_cast<float>(std::sin(angle));
        pos[0] = WalkableFieldAxis(rng, in[0]);
        pos[2] = WalkableFieldAxis(rng, in[1]);
        pos[1] = static_cast<float>(rng.Range(0.0, 512.0));
      } else if (mode < 85) {
        // From outside the map towards it (ClipSegmentToWorld).
        const double side = rng.Range(-60.0, -0.5);
        const double tx = rng.Range(0.0, cellsW);
        const double tz = rng.Range(0.0, cellsH);
        const double ty = rng.Range(0.0, 512.0);
        const double sy = rng.Range(0.0, 700.0);
        const u32 edge = rng.Below(4);
        const double sx = edge == 0u ? side : edge == 1u ? cellsW - side : tx;
        const double sz = edge == 2u ? side : edge == 3u ? cellsH - side : tz;
        const double dx = tx - sx;
        const double dy = ty - sy;
        const double dz = tz - sz;
        const double len = std::sqrt(dx * dx + dy * dy + dz * dz) + 1e-30;
        dir[0] = static_cast<float>(dx / len);
        dir[1] = static_cast<float>(dy / len);
        dir[2] = static_cast<float>(dz / len);
        pos[0] = static_cast<float>(sx);
        pos[1] = static_cast<float>(sy);
        pos[2] = static_cast<float>(sz);
      } else {
        // Any floats the walk can finish (see WalkableStart).
        for (float& lane : pos) {
          do {
            lane = GenFloat(rng);
          } while (!WalkableStart(lane));
        }
        for (float& lane : dir) {
          do {
            lane = GenFloat(rng);
          } while (!WalkableDirection(lane));
        }
      }
      float closest = 0.0f;
      float farthest = 10000.0f;
      const u32 range = rng.Below(100);
      if (range < 15) {
        farthest = 3.402823466e38f;
      } else if (range < 25) {
        farthest = FromBits(0x7F800000u);
      } else if (range < 40) {
        closest = static_cast<float>(rng.Range(0.0, 50.0));
        farthest = closest + static_cast<float>(rng.Range(0.0, 300.0));
      } else if (range < 45) {
        closest = static_cast<float>(rng.Range(0.0, 300.0));
        farthest = static_cast<float>(rng.Range(0.0, 300.0));
      } else if (range < 50) {
        closest = GenFloat(rng);
        farthest = GenFloat(rng);
      }
      for (int i = 0; i < 3; ++i) {
        in[4 + i] = Bits(pos[i]);
        in[7 + i] = Bits(dir[i]);
      }
      in[10] = Bits(closest);
      in[11] = Bits(farthest);
    }
    void IntersectionRetail(const u32* in, u32* out)
    {
      RetailField field;
      BuildRetailField(field, in);
      float line[8]; // GeomLine3: pos, dir, closest, farthest
      std::memcpy(line, in + 4, sizeof(line));
      u32 point[3] = {kCanary, kCanary, kCanary};
      u32 res[2] = {kCanary, kCanary};
      retail::HeightFieldIntersection(&field, line, point, res);
      FreeRetailField(field);
      std::memcpy(out, point, sizeof(point));
      std::memcpy(out + 3, res, sizeof(res));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void IntersectionOurs(const u32* in, u32* out)
    {
      moho::CHeightField field(static_cast<int>(in[0]), static_cast<int>(in[1]));
      BuildOurField(field, in);
      moho::GeomLine3 line{};
      std::memcpy(&line, in + 4, sizeof(line));
      moho::CGeomHitResult res{};
      std::memcpy(&res, &kCanary, 4);
      std::memcpy(&res.v1, &kCanary, 4);
      const Wm3::Vec3f point = field.Intersection(line, &res);
      std::memcpy(out, &point, 12);
      std::memcpy(out + 3, &res, 8);
    }
    static_assert(sizeof(moho::GeomLine3) == 32 && sizeof(moho::CGeomHitResult) == 8);
#endif

    // CHeightField::GetNormal 0x0069A620: in = field spec, x, z. out = the
    // normalised gradient.
    void GenNormal(Rng& rng, u32* in)
    {
      GenFieldSpec(rng, in);
      in[4] = Bits(GenFieldAxis(rng, in[0]));
      in[5] = Bits(GenFieldAxis(rng, in[1]));
    }
    void NormalRetail(const u32* in, u32* out)
    {
      RetailField field;
      BuildRetailField(field, in);
      u32 normal[3] = {kCanary, kCanary, kCanary};
      retail::HeightFieldNormal(&field, F(in, 4), F(in, 5), normal);
      FreeRetailField(field);
      std::memcpy(out, normal, sizeof(normal));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void NormalOurs(const u32* in, u32* out)
    {
      moho::CHeightField field(static_cast<int>(in[0]), static_cast<int>(in[1]));
      BuildOurField(field, in);
      const Wm3::Vec3f normal = field.GetNormal(F(in, 4), F(in, 5));
      std::memcpy(out, &normal, 12);
    }
#endif

    // CHeightField::ClipSegmentToWorld 0x004776E0 alone: the Intersection
    // row's lines with any lane, the range included, sometimes swapped for
    // any float (NaN, infinite, denormal). The clip walks no cells, so the
    // inputs the Intersection row must avoid are safe here. out = the result,
    // then min and max as the clip left them.
    void GenClip(Rng& rng, u32* in)
    {
      GenIntersection(rng, in);
      for (int lane = 4; lane < 12; ++lane) {
        if (rng.Chance(20)) {
          in[lane] = Bits(GenFloat(rng));
        }
      }
    }
    void ClipRetail(const u32* in, u32* out)
    {
      RetailField field;
      BuildRetailField(field, in);
      u32 range[2] = {in[10], in[11]};
      const int clipped = retail::HeightFieldClipSegment(&field, in + 4, in + 7, &range[0], &range[1]);
      FreeRetailField(field);
      out[0] = static_cast<u32>(clipped);
      out[1] = range[0];
      out[2] = range[1];
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void ClipOurs(const u32* in, u32* out)
    {
      moho::CHeightField field(static_cast<int>(in[0]), static_cast<int>(in[1]));
      BuildOurField(field, in);
      Wm3::Vec3f pos;
      Wm3::Vec3f dir;
      std::memcpy(&pos, in + 4, 12);
      std::memcpy(&dir, in + 7, 12);
      float min = F(in, 10);
      float max = F(in, 11);
      const bool clipped = field.ClipSegmentToWorld(pos, dir, min, max);
      out[0] = clipped ? 1u : 0u;
      out[1] = Bits(min);
      out[2] = Bits(max);
    }
#endif

    // CHeightField::GetTierBounds 0x00475DA0 (GetTierBoundsUWord 0x00475BF0):
    // in = field spec, x, z, tier. Tier 0 reads the 2x2 samples, tier n the
    // min/max grid n-1. Retail indexes the tier vector without a bound
    // (0x00475C0E), so the tier stays within the field's count; x and z go
    // anywhere, both sides clamp them. out = min and max in world units.
    [[nodiscard]] u32 TierCount(const u32 cellsW, const u32 cellsH)
    {
      u32 v = (cellsW < cellsH ? cellsH : cellsW) - 1u;
      u32 count = 0;
      while (v != 0u) {
        ++count;
        v >>= 1u;
      }
      return count;
    }
    [[nodiscard]] u32 GenTierCoord(Rng& rng, const u32 cells)
    {
      const u32 mode = rng.Below(100);
      if (mode < 80) {
        return rng.Below(cells + 7u) - 3u;
      }
      if (mode < 90) {
        return 0x7FFFFFFFu - rng.Below(3);
      }
      return rng.U32();
    }
    void GenTierBounds(Rng& rng, u32* in)
    {
      GenFieldSpec(rng, in);
      in[4] = GenTierCoord(rng, in[0]);
      in[5] = GenTierCoord(rng, in[1]);
      in[6] = rng.Below(TierCount(in[0], in[1]) + 1u);
    }
    void TierBoundsRetail(const u32* in, u32* out)
    {
      RetailField field;
      BuildRetailField(field, in);
      u32 bounds[2] = {kCanary, kCanary};
      retail::HeightFieldTierBounds(
        &field, static_cast<int>(in[4]), static_cast<int>(in[5]), static_cast<int>(in[6]), bounds
      );
      FreeRetailField(field);
      out[0] = bounds[0];
      out[1] = bounds[1];
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void TierBoundsOurs(const u32* in, u32* out)
    {
      moho::CHeightField field(static_cast<int>(in[0]), static_cast<int>(in[1]));
      BuildOurField(field, in);
      const Wm3::Vec2f bounds =
        field.GetTierBounds(static_cast<int>(in[4]), static_cast<int>(in[5]), static_cast<int>(in[6]));
      out[0] = Bits(bounds.x);
      out[1] = Bits(bounds.y);
    }
#endif

    // ---- influence grids (InfluenceGrid, CInfluenceMap.cpp) ----------------------
    //
    // One threat record is 14 floats (SThreat, 0x38 bytes); a grid holds the
    // cell's aggregate `threat` (+0x1C), its `decay` rates (+0x54) and a
    // vector of per-army records (`threats`, begin/end at +0x10/+0x14).
    // GetThreat and DecayInfluence read only those, so retail's grid is a
    // plain buffer with the vector pointing at harness memory. The lanes come
    // from a seed through an integer expander: mode 0 small exact values
    // (k / 4), mode 1 any bits (NaN, infinite, denormal), mode 2 a mix.
    constexpr int kThreatLanes = 14;
    constexpr u32 kMaxThreatArmies = 6;

    struct ThreatLaneSource
    {
      u32 state;
      u32 mode;

      [[nodiscard]] u32 Next() noexcept
      {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
      }
      [[nodiscard]] float Lane() noexcept
      {
        const u32 r = Next();
        const float small = static_cast<float>(static_cast<int>(r & 1023u)) * 0.25f;
        if (mode == 0u) {
          return small;
        }
        if (mode == 1u) {
          return FromBits(Next());
        }
        return (r >> 29) == 0u ? FromBits(Next()) : small;
      }
    };

    /// threat[14], decay[14], then armies x 14, in that order on both sides.
    void ExpandThreatLanes(const u32 seed, const u32 mode, const u32 armies, float* lanes)
    {
      ThreatLaneSource source{seed != 0u ? seed : 0x9E3779B9u, mode};
      const int count = kThreatLanes * static_cast<int>(2u + armies);
      for (int i = 0; i < count; ++i) {
        lanes[i] = source.Lane();
      }
    }

    struct RetailInfluenceGrid
    {
      std::uint8_t bytes[0x8C];
    };
    static_assert(sizeof(float) * kThreatLanes == 0x38);

    void BuildRetailInfluenceGrid(RetailInfluenceGrid& grid, const float* lanes, float* armyLanes, const u32 armies)
    {
      std::memset(grid.bytes, 0, sizeof(grid.bytes));
      std::memcpy(grid.bytes + 0x1C, lanes, 0x38);
      std::memcpy(grid.bytes + 0x54, lanes + kThreatLanes, 0x38);
      if (armies != 0u) {
        std::memcpy(armyLanes, lanes + 2 * kThreatLanes, 0x38u * armies);
      }
      float* const begin = armyLanes;
      float* const end = armyLanes != nullptr ? armyLanes + kThreatLanes * armies : nullptr;
      std::memcpy(grid.bytes + 0x10, &begin, 4);
      std::memcpy(grid.bytes + 0x14, &end, 4);
      std::memcpy(grid.bytes + 0x18, &end, 4);
    }

    // InfluenceGrid::GetThreat 0x00715750: in = type, army, armies, seed,
    // mode. Types run past the jump table's 0..14 (both ends); an army is
    // negative (the all-armies sum) or inside the vector, since the binary
    // indexes it without a bound (0x00715788). out = the threat.
    void GenGetThreat(Rng& rng, u32* in)
    {
      in[0] = rng.Below(19) - 2u;
      in[2] = rng.Below(kMaxThreatArmies + 1u);
      const u32 armyMode = rng.Below(100);
      if (armyMode < 30 || in[2] == 0u) {
        in[1] = 0xFFFFFFFFu;
      } else if (armyMode < 35) {
        in[1] = 0x80000000u + rng.Below(4);
      } else {
        in[1] = rng.Below(in[2]);
      }
      in[3] = rng.U32();
      in[4] = rng.Below(3);
    }
    void GetThreatRetail(const u32* in, u32* out)
    {
      float lanes[kThreatLanes * (2 + kMaxThreatArmies)];
      ExpandThreatLanes(in[3], in[4], in[2], lanes);
      float armyLanes[kThreatLanes * kMaxThreatArmies];
      RetailInfluenceGrid grid;
      BuildRetailInfluenceGrid(grid, lanes, armyLanes, in[2]);
      out[0] = retail::InfluenceGetThreatBits(grid.bytes, static_cast<int>(in[0]), static_cast<int>(in[1]));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void BuildOurInfluenceGrid(moho::InfluenceGrid& grid, const float* lanes, const u32 armies)
    {
      std::memcpy(&grid.threat, lanes, 0x38);
      std::memcpy(&grid.decay, lanes + kThreatLanes, 0x38);
      grid.threats.resize(armies, moho::SThreat{});
      for (u32 a = 0; a < armies; ++a) {
        std::memcpy(&grid.threats[a], lanes + kThreatLanes * (2u + a), 0x38);
      }
    }
    void GetThreatOurs(const u32* in, u32* out)
    {
      float lanes[kThreatLanes * (2 + kMaxThreatArmies)];
      ExpandThreatLanes(in[3], in[4], in[2], lanes);
      moho::InfluenceGrid grid;
      BuildOurInfluenceGrid(grid, lanes, in[2]);
      const float threat =
        grid.GetThreat(static_cast<moho::EThreatType>(static_cast<int>(in[0])), static_cast<int>(in[1]));
      out[0] = Bits(threat);
    }
    static_assert(sizeof(moho::SThreat) == 0x38);
#endif

    // InfluenceGrid::DecayInfluence 0x00715130: in = seed, mode. out = the
    // 14 threat lanes after one decay step.
    void GenDecayInfluence(Rng& rng, u32* in)
    {
      in[0] = rng.U32();
      in[1] = rng.Below(3);
    }
    void DecayInfluenceRetail(const u32* in, u32* out)
    {
      float lanes[kThreatLanes * 2];
      ExpandThreatLanes(in[0], in[1], 0u, lanes);
      RetailInfluenceGrid grid;
      BuildRetailInfluenceGrid(grid, lanes, nullptr, 0u);
      retail::InfluenceDecay(grid.bytes);
      std::memcpy(out, grid.bytes + 0x1C, 0x38);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void DecayInfluenceOurs(const u32* in, u32* out)
    {
      float lanes[kThreatLanes * 2];
      ExpandThreatLanes(in[0], in[1], 0u, lanes);
      moho::InfluenceGrid grid;
      BuildOurInfluenceGrid(grid, lanes, 0u);
      grid.DecayInfluence();
      std::memcpy(out, &grid.threat, 0x38);
    }
#endif

    // ---- MathReflection.cpp (engine-only TU) ------------------------------------
    //
    // VEC_LookAt 0x004ECBD0: in = up[3], forward[3]; out = the 9-float VAxes3
    // (left as it was when forward has no length). Forward is a random
    // heading, parallel to up (the collapsed cross product), zero or tiny, or
    // any floats.
    [[nodiscard]] float AnyOrRange(Rng& rng, const double lo, const double hi)
    {
      if (rng.Chance(10)) {
        return GenFloat(rng);
      }
      return static_cast<float>(rng.Range(lo, hi));
    }
    void GenLookAt(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      float up[3];
      float forward[3];
      if (mode < 75) {
        for (float& lane : up) {
          lane = static_cast<float>(rng.Range(-1.0, 1.0));
        }
        if (rng.Chance(50)) {
          up[0] = 0.0f;
          up[1] = 1.0f;
          up[2] = 0.0f;
        }
        if (mode < 50) {
          for (float& lane : forward) {
            lane = static_cast<float>(rng.Range(-100.0, 100.0));
          }
        } else if (mode < 65) {
          const float scale = static_cast<float>(rng.Range(-50.0, 50.0));
          for (int i = 0; i < 3; ++i) {
            forward[i] = up[i] * scale;
          }
        } else {
          for (float& lane : forward) {
            lane = rng.Chance(50) ? 0.0f : FromBits(rng.Below(0x00900000u));
          }
        }
      } else {
        for (float& lane : up) {
          lane = GenFloat(rng);
        }
        for (float& lane : forward) {
          lane = GenFloat(rng);
        }
      }
      for (int i = 0; i < 3; ++i) {
        in[i] = Bits(up[i]);
        in[3 + i] = Bits(forward[i]);
      }
    }
    void LookAtRetail(const u32* in, u32* out)
    {
      u32 axes[9];
      for (u32& lane : axes) {
        lane = kCanary;
      }
      retail::VecLookAt(in, in + 3, axes);
      std::memcpy(out, axes, sizeof(axes));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void LookAtOurs(const u32* in, u32* out)
    {
      Wm3::Vector3f up;
      Wm3::Vector3f forward;
      std::memcpy(&up, in, 12);
      std::memcpy(&forward, in + 3, 12);
      moho::VAxes3 axes;
      u32 canary[9];
      for (u32& lane : canary) {
        lane = kCanary;
      }
      std::memcpy(&axes, canary, sizeof(canary));
      moho::VEC_LookAt(up, forward, &axes);
      std::memcpy(out, &axes, sizeof(canary));
    }
    static_assert(sizeof(moho::VAxes3) == 36);
#endif

    // VEC_Mul4x3 0x004EE710: in = lhs[16], rhs[16] (row-major, 4 floats a
    // row); out = the 16 output lanes, the w lanes left as they were.
    void GenMul4x3(Rng& rng, u32* in)
    {
      for (int i = 0; i < 32; ++i) {
        in[i] = Bits(AnyOrRange(rng, -4.0, 4.0));
      }
    }
    void Mul4x3Retail(const u32* in, u32* out)
    {
      u32 result[16];
      for (u32& lane : result) {
        lane = kCanary;
      }
      retail::VecMul4x3(in, result, in + 16);
      std::memcpy(out, result, sizeof(result));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void Mul4x3Ours(const u32* in, u32* out)
    {
      moho::VMatrix4 lhs;
      moho::VMatrix4 rhs;
      moho::VMatrix4 result;
      std::memcpy(&lhs, in, 64);
      std::memcpy(&rhs, in + 16, 64);
      u32 canary[16];
      for (u32& lane : canary) {
        lane = kCanary;
      }
      std::memcpy(&result, canary, sizeof(canary));
      moho::VEC_Mul4x3(lhs, result, rhs);
      std::memcpy(out, &result, sizeof(canary));
    }
    static_assert(sizeof(moho::VMatrix4) == 64);
#endif

    // ---- map terrain blocking (STIMap, STIMap.cpp) -------------------------------
    //
    // STIMap::IsBlockingTerrain 0x00577F20 (465 million calls in the 3 coverage
    // replays) reads only the height field's width and height (bounds), the
    // terrain-type byte grid (data +0x1428, width +0x142C) and the 256-byte
    // blocking table (+0x1434). Retail's map is a buffer with just those;
    // ours is an STIMap(cellsW, cellsH) with the same grid and table. The game
    // writes the table with 0 and 1 only (STIMap.cpp memset and the
    // `mBlocking[typeCode] = 1u` load), so the rows do too: retail returns the
    // raw byte, ours `!= 0`.
    // in = cellsW, cellsH, seed, x, z; out = blocking (0 or 1).
    constexpr std::size_t kMapBytes = 0x1544;

    void ExpandTerrainBytes(const u32 seed, const u32 count, std::uint8_t* types, std::uint8_t* blocking)
    {
      u32 s = seed != 0u ? seed : 0x2545F491u;
      auto next = [&s]() {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        return s;
      };
      for (u32 i = 0; i < count; ++i) {
        types[i] = static_cast<std::uint8_t>(next() & 0x3Fu); // the first 64 terrain types
      }
      for (int t = 0; t < 0x100; ++t) {
        blocking[t] = (next() % 5u) == 0u ? 1u : 0u;
      }
    }
    [[nodiscard]] u32 GenMapCoord(Rng& rng, const u32 cells)
    {
      const u32 mode = rng.Below(100);
      if (mode < 70) {
        return rng.Below(cells);
      }
      if (mode < 85) {
        return cells - 1u + rng.Below(3);
      }
      if (mode < 95) {
        return 0xFFFFFFFFu - rng.Below(3);
      }
      return rng.U32();
    }
    void GenBlocking(Rng& rng, u32* in)
    {
      in[0] = 2u + rng.Below(63);
      in[1] = 2u + rng.Below(63);
      in[2] = rng.U32();
      in[3] = GenMapCoord(rng, in[0]);
      in[4] = GenMapCoord(rng, in[1]);
    }
    void BlockingRetail(const u32* in, u32* out)
    {
      std::vector<std::uint8_t> types(static_cast<std::size_t>(in[0]) * in[1]);
      std::vector<std::uint8_t> map(kMapBytes, 0);
      std::uint8_t* const blocking = map.data() + 0x1434;
      ExpandTerrainBytes(in[2], static_cast<u32>(types.size()), types.data(), blocking);
      const u32 field[3] = {0u, in[0] + 1u, in[1] + 1u}; // CHeightField: data, width, height
      const void* const fieldPtr = field;
      std::uint8_t* const typesPtr = types.data();
      std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
      std::memcpy(map.data() + 0x1428, &typesPtr, 4);
      std::memcpy(map.data() + 0x142C, &in[0], 4);
      std::memcpy(map.data() + 0x1430, &in[1], 4);
      out[0] = retail::MapIsBlockingTerrain(map.data(), in[3], in[4]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void BlockingOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      ExpandTerrainBytes(in[2], in[0] * in[1], map.mTerrainType.data, map.mBlocking);
      out[0] = map.IsBlockingTerrain(in[4], in[3]) ? 1u : 0u;
    }
#endif

    // STIMap::OccupancyCapsOfFootprintAt 0x00564DF0 (197 million calls): which
    // layers (land, seabed, sub, water) a footprint may occupy at one cell,
    // from the cell's four heights against the water level and the
    // footprint's depth and slope limits. It reads the height field (data,
    // width, height), IsBlockingTerrain's grid and table, mWaterEnabled
    // (+0x1534) and mWaterElevation (+0x1538).
    // in = cellsW cellsH seed shape waterOn waterElevation x z caps maxSlope
    // minWaterDepth maxWaterDepth; out = the caps byte.
    void GenOccupancyCaps(Rng& rng, u32* in)
    {
      in[0] = 2u + rng.Below(63);
      in[1] = 2u + rng.Below(63);
      in[2] = rng.U32();
      in[3] = rng.Below(kShapeCount);
      in[4] = rng.Chance(70) ? 1u : 0u;
      in[5] = Bits(AnyOrRange(rng, -10.0, 520.0));
      in[6] = GenMapCoord(rng, in[0]) & 0xFFFFu;
      in[7] = GenMapCoord(rng, in[1]) & 0xFFFFu;
      in[8] = rng.Below(256);
      in[9] = rng.Chance(30) ? 0u : Bits(AnyOrRange(rng, 0.0, 8.0));
      in[10] = Bits(AnyOrRange(rng, -50.0, 300.0));
      in[11] = Bits(AnyOrRange(rng, -50.0, 300.0));
    }
    void FillFootprintBytes(const u32* in, std::uint8_t* footprint)
    {
      std::memset(footprint, 0, 16);
      footprint[0] = 1;
      footprint[1] = 1;
      footprint[2] = static_cast<std::uint8_t>(in[8]);
      std::memcpy(footprint + 4, &in[9], 4);
      std::memcpy(footprint + 8, &in[10], 4);
      std::memcpy(footprint + 12, &in[11], 4);
    }
    void OccupancyCapsRetail(const u32* in, u32* out)
    {
      const int sampleW = static_cast<int>(in[0]) + 1;
      const int sampleH = static_cast<int>(in[1]) + 1;
      std::vector<std::uint16_t> samples(static_cast<std::size_t>(sampleW) * sampleH);
      FillFieldSamples(samples.data(), sampleW, sampleH, in[2], in[3]);
      std::vector<std::uint8_t> types(static_cast<std::size_t>(in[0]) * in[1]);
      std::vector<std::uint8_t> map(kMapBytes, 0);
      ExpandTerrainBytes(in[2] ^ 0x5A5A5A5Au, static_cast<u32>(types.size()), types.data(), map.data() + 0x1434);
      // x86 only at run time (the retail call); the x64 build compiles it unused.
      const u32 field[3] = {
        static_cast<u32>(reinterpret_cast<std::uintptr_t>(samples.data())), static_cast<u32>(sampleW),
        static_cast<u32>(sampleH)
      };
      const void* const fieldPtr = field;
      std::uint8_t* const typesPtr = types.data();
      std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
      std::memcpy(map.data() + 0x1428, &typesPtr, 4);
      std::memcpy(map.data() + 0x142C, &in[0], 4);
      std::memcpy(map.data() + 0x1430, &in[1], 4);
      map[0x1534] = static_cast<std::uint8_t>(in[4]);
      std::memcpy(map.data() + 0x1538, &in[5], 4);
      const std::int16_t pos[2] = {static_cast<std::int16_t>(in[6]), static_cast<std::int16_t>(in[7])};
      std::uint8_t footprint[16];
      FillFootprintBytes(in, footprint);
      out[0] = retail::MapOccupancyCaps(map.data(), pos, footprint);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void OccupancyCapsOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      moho::CHeightField* const field = map.mHeightField.get();
      FillFieldSamples(field->data, field->width, field->height, in[2], in[3]);
      ExpandTerrainBytes(in[2] ^ 0x5A5A5A5Au, in[0] * in[1], map.mTerrainType.data, map.mBlocking);
      map.mWaterEnabled = static_cast<std::uint8_t>(in[4]);
      map.mWaterElevation = F(in, 5);
      moho::SOCellPos pos;
      pos.x = static_cast<std::int16_t>(in[6]);
      pos.z = static_cast<std::int16_t>(in[7]);
      moho::SFootprint footprint;
      std::uint8_t bytes[16];
      FillFootprintBytes(in, bytes);
      std::memcpy(&footprint, bytes, sizeof(bytes));
      out[0] = static_cast<u32>(map.OccupancyCapsOfFootprintAt(pos, footprint));
    }
    static_assert(sizeof(moho::SFootprint) == 16);
#endif

    // CalculateMapWaterRatio 0x0062D7E0 (85 million calls under
    // AIBrain:GetMapWaterRatio): the share of terrain samples on an 8-cell
    // grid below the water level (-10000 with water off, 0x0062D819), heights
    // times 1/128, x and z clamped to the field. ecx = map; the result comes
    // back in xmm0 (0x0062DA41), and a map without samples gives 0/0 on both
    // sides. Retail's map is the OccupancyCaps buffer (height field at +0,
    // water at +0x1534/+0x1538); ours a real STIMap.
    // in = cellsW cellsH seed shape waterOn waterElevation; out = the ratio.
    void GenWaterRatio(Rng& rng, u32* in)
    {
      in[0] = 2u + rng.Below(71);
      in[1] = 2u + rng.Below(71);
      in[2] = rng.U32();
      in[3] = rng.Below(kShapeCount);
      in[4] = rng.Chance(70) ? 1u : 0u;
      in[5] = Bits(AnyOrRange(rng, -10.0, 520.0));
    }
    void WaterRatioRetail(const u32* in, u32* out)
    {
      const int sampleW = static_cast<int>(in[0]) + 1;
      const int sampleH = static_cast<int>(in[1]) + 1;
      std::vector<std::uint16_t> samples(static_cast<std::size_t>(sampleW) * sampleH);
      FillFieldSamples(samples.data(), sampleW, sampleH, in[2], in[3]);
      std::vector<std::uint8_t> map(kMapBytes, 0);
      // x86 only at run time (the retail call); the x64 build compiles it unused.
      const u32 field[3] = {
        static_cast<u32>(reinterpret_cast<std::uintptr_t>(samples.data())), static_cast<u32>(sampleW),
        static_cast<u32>(sampleH)
      };
      const void* const fieldPtr = field;
      std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
      map[0x1534] = static_cast<std::uint8_t>(in[4]);
      std::memcpy(map.data() + 0x1538, &in[5], 4);
      out[0] = retail::MapWaterRatio(map.data());
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void WaterRatioOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      moho::CHeightField* const field = map.mHeightField.get();
      FillFieldSamples(field->data, field->width, field->height, in[2], in[3]);
      map.mWaterEnabled = static_cast<std::uint8_t>(in[4]);
      map.mWaterElevation = F(in, 5);
      out[0] = Bits(moho::CalculateMapWaterRatio(map));
    }
#endif

    // COORDS_ToWorldPos 0x0050B0F0 (14 million calls): a cell's world
    // position, x = cell + sizeX * 0.5 (0x00E4F724), z likewise, y the
    // terrain elevation (CHeightField::GetElevation, 0x0050B14C), raised to
    // the water level when water is on, above the terrain and the layer byte
    // lacks bit 2 (seabed, 0x0050B151). eax = cell, edi = map, esi = out,
    // [layer] [sizeX] [sizeZ] caller-popped; the layer is a byte (`E` in the
    // mangled name). Retail's map is the OccupancyCaps buffer, ours a real
    // STIMap.
    // in = cellsW cellsH seed shape waterOn waterElev x z layer sizeX sizeZ;
    // out = pos[3].
    void GenToWorldPos(Rng& rng, u32* in)
    {
      in[0] = 2u + rng.Below(63);
      in[1] = 2u + rng.Below(63);
      in[2] = rng.U32();
      in[3] = rng.Below(kShapeCount);
      in[4] = rng.Chance(70) ? 1u : 0u;
      in[5] = Bits(AnyOrRange(rng, -10.0, 520.0));
      in[6] = GenMapCoord(rng, in[0]) & 0xFFFFu;
      in[7] = GenMapCoord(rng, in[1]) & 0xFFFFu;
      in[8] = rng.Chance(70) ? (1u << rng.Below(5)) : rng.Below(256);
      in[9] = rng.Chance(90) ? rng.Below(11) : rng.U32();
      in[10] = rng.Chance(90) ? rng.Below(11) : rng.U32();
    }
    void ToWorldPosRetail(const u32* in, u32* out)
    {
      const int sampleW = static_cast<int>(in[0]) + 1;
      const int sampleH = static_cast<int>(in[1]) + 1;
      std::vector<std::uint16_t> samples(static_cast<std::size_t>(sampleW) * sampleH);
      FillFieldSamples(samples.data(), sampleW, sampleH, in[2], in[3]);
      std::vector<std::uint8_t> map(kMapBytes, 0);
      // x86 only at run time (the retail call); the x64 build compiles it unused.
      const u32 field[3] = {
        static_cast<u32>(reinterpret_cast<std::uintptr_t>(samples.data())), static_cast<u32>(sampleW),
        static_cast<u32>(sampleH)
      };
      const void* const fieldPtr = field;
      std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
      map[0x1534] = static_cast<std::uint8_t>(in[4]);
      std::memcpy(map.data() + 0x1538, &in[5], 4);
      const std::int16_t pos[2] = {static_cast<std::int16_t>(in[6]), static_cast<std::int16_t>(in[7])};
      float world[3] = {};
      retail::CoordsToWorldPos(pos, map.data(), world, in[8] & 0xFFu, static_cast<int>(in[9]), static_cast<int>(in[10]));
      std::memcpy(out, world, 12);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void ToWorldPosOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      moho::CHeightField* const field = map.mHeightField.get();
      FillFieldSamples(field->data, field->width, field->height, in[2], in[3]);
      map.mWaterEnabled = static_cast<std::uint8_t>(in[4]);
      map.mWaterElevation = F(in, 5);
      moho::SOCellPos pos;
      pos.x = static_cast<std::int16_t>(in[6]);
      pos.z = static_cast<std::int16_t>(in[7]);
      const Wm3::Vector3f world = moho::COORDS_ToWorldPos(
        &map, pos, static_cast<moho::ELayer>(in[8] & 0xFFu), static_cast<int>(in[9]), static_cast<int>(in[10])
      );
      std::memcpy(out, &world, 12);
    }
#endif

    // CIntelGrid::IsVisible(rect) 0x005BE210 (15 million calls): whether
    // any cell under a world rect is strictly positive. RectToGridCellBounds
    // (0x005BE080) scales by 1 / gridSize (+0x20) with x87 floor of the
    // minimum and ceil of the maximum, then 0x005C55F0 clamps to the grid
    // (+0x04 cells, +0x08 width, +0x0C height) and scans with a signed
    // compare (cells are int8, Raster can drive one below 0). eax = grid,
    // ecx = rect; the mangled bool argument is never read. Ours is a real
    // CIntelGrid (width = cellsW / gridSize) on a real STIMap; its extra
    // gridSize == 0 early-out is unreachable here (sizes 1..16).
    // in = cellsW cellsH gridSize seed density rect[4]; out = visible.
    [[nodiscard]] u32 GenRectInt(Rng& rng);
    void GenIntelRect(Rng& rng, u32* in)
    {
      in[0] = 2u + rng.Below(127);
      in[1] = 2u + rng.Below(127);
      static const u32 kSizes[] = {1u, 2u, 4u, 8u, 16u, 3u, 5u};
      in[2] = kSizes[rng.Below(7)];
      in[3] = rng.U32();
      in[4] = rng.Chance(30) ? 0u : rng.Below(30);
      for (int i = 0; i < 4; ++i) {
        const u32 cells = (i % 2 == 0) ? in[0] : in[1];
        in[5 + i] = rng.Chance(85) ? static_cast<u32>(static_cast<int>(rng.Below(cells + 40u)) - 20) : GenRectInt(rng);
      }
    }
    void FillIntelCells(const u32* in, std::int8_t* cells, const u32 count)
    {
      u32 s = in[3] != 0u ? in[3] : 0x2545F491u;
      for (u32 i = 0; i < count; ++i) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        const u32 roll = s % 100u;
        cells[i] = roll < in[4] ? static_cast<std::int8_t>(1 + (s >> 8) % 3) : (roll < in[4] + 5u ? static_cast<std::int8_t>(-1) : 0);
      }
    }
    void IntelRectRetail(const u32* in, u32* out)
    {
      const u32 width = in[0] / in[2];
      const u32 height = in[1] / in[2];
      std::vector<std::int8_t> cells(static_cast<std::size_t>(width) * height + 1u);
      FillIntelCells(in, cells.data(), width * height);
      std::vector<std::uint8_t> grid(0x24, 0);
      const u32 cellsPtr = static_cast<u32>(reinterpret_cast<std::uintptr_t>(cells.data()));
      std::memcpy(grid.data() + 0x04, &cellsPtr, 4);
      std::memcpy(grid.data() + 0x08, &width, 4);
      std::memcpy(grid.data() + 0x0C, &height, 4);
      std::memcpy(grid.data() + 0x20, &in[2], 4);
      out[0] = retail::IntelGridIsVisibleRect(grid.data(), &in[5]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void IntelRectOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      moho::CIntelGrid grid(&map, in[2]);
      FillIntelCells(in, grid.mGrid.get(), grid.mWidth * grid.mHeight);
      gpg::Rect2i rect;
      std::memcpy(&rect, &in[5], 16);
      out[0] = grid.IsVisible(rect, false) ? 1u : 0u;
    }
#endif

    // OCCUPY_Filter 0x00720920 (one-cell OCCUPY_FootprintFits and the path
    // tables' occupation source): caps -1 asks OccupancyCapsOfFootprintAt
    // through grid->sim->mMapData (0x00720932, +0x8CC), then land/seabed is
    // cleared on a set or out-of-bounds terrainOccupation bit unless the
    // footprint ignores structures (0x00720949), and water on a set or
    // out-of-bounds waterOccupation bit (0x0072098F). Bounds are unsigned
    // compares of the sign-extended shorts (0x0072095A), so negative cells
    // are out of bounds. Retail gets a sim buffer holding mMapData and a grid
    // buffer holding the two bit arrays (+0x38, +0x48); ours a real COGrid
    // whose bit arrays point at the same words, and a Sim storage with only
    // mMapData written, since COGrid(Sim*) needs a whole sim.
    // Retail compares the full caps dword with -1; ours takes one byte, so a
    // caps of 0x000000FF is left out (ours reads it as OC_ANY).
    // in = the OccupancyCapsOfFootprintAt words, then fpFlags caps gridSeed
    // terrainPct waterPct gridW gridH; out = the caps byte.
    void FillOccupationWords(u32 seed, const u32 percent, const u32 count, u32* words)
    {
      u32 s = seed != 0u ? seed : 0x2545F491u;
      for (u32 i = 0; i < count; ++i) {
        u32 word = 0;
        for (int bit = 0; bit < 32; ++bit) {
          s ^= s << 13;
          s ^= s >> 17;
          s ^= s << 5;
          if (s % 100u < percent) {
            word |= 1u << bit;
          }
        }
        words[i] = word;
      }
    }
    [[nodiscard]] u32 OccupationWordCount(const u32* in)
    {
      return in[17] * ((in[18] + 31u) >> 5);
    }
    void GenOccupyFilter(Rng& rng, u32* in)
    {
      GenOccupancyCaps(rng, in);
      in[12] = rng.Below(256);
      in[13] = rng.Chance(40) ? 0xFFFFFFFFu : rng.Below(255);
      in[14] = rng.U32();
      in[15] = rng.Below(101);
      in[16] = rng.Below(101);
      in[17] = rng.Chance(80) ? in[0] : rng.Below(71);
      in[18] = rng.Chance(80) ? in[1] : rng.Below(71);
    }
    void OccupyFilterRetail(const u32* in, u32* out)
    {
      const int sampleW = static_cast<int>(in[0]) + 1;
      const int sampleH = static_cast<int>(in[1]) + 1;
      std::vector<std::uint16_t> samples(static_cast<std::size_t>(sampleW) * sampleH);
      FillFieldSamples(samples.data(), sampleW, sampleH, in[2], in[3]);
      std::vector<std::uint8_t> types(static_cast<std::size_t>(in[0]) * in[1]);
      std::vector<std::uint8_t> map(kMapBytes, 0);
      ExpandTerrainBytes(in[2] ^ 0x5A5A5A5Au, static_cast<u32>(types.size()), types.data(), map.data() + 0x1434);
      // x86 only at run time (the retail call); the x64 build compiles it unused.
      const u32 field[3] = {
        static_cast<u32>(reinterpret_cast<std::uintptr_t>(samples.data())), static_cast<u32>(sampleW),
        static_cast<u32>(sampleH)
      };
      const void* const fieldPtr = field;
      std::uint8_t* const typesPtr = types.data();
      std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
      std::memcpy(map.data() + 0x1428, &typesPtr, 4);
      std::memcpy(map.data() + 0x142C, &in[0], 4);
      std::memcpy(map.data() + 0x1430, &in[1], 4);
      map[0x1534] = static_cast<std::uint8_t>(in[4]);
      std::memcpy(map.data() + 0x1538, &in[5], 4);

      const u32 wordCount = OccupationWordCount(in);
      std::vector<u32> terrain(wordCount + 1u), water(wordCount + 1u);
      FillOccupationWords(in[14], in[15], wordCount, terrain.data());
      FillOccupationWords(in[14] ^ 0xA5A5A5A5u, in[16], wordCount, water.data());
      std::vector<std::uint8_t> sim(0x900, 0);
      const void* const mapPtr = map.data();
      std::memcpy(sim.data() + 0x8CC, &mapPtr, 4);
      std::vector<std::uint8_t> grid(0x58, 0);
      const void* const simPtr = sim.data();
      const u32* const terrainPtr = terrain.data();
      const u32* const waterPtr = water.data();
      std::memcpy(grid.data() + 0x00, &simPtr, 4);
      std::memcpy(grid.data() + 0x38, &terrainPtr, 4);
      std::memcpy(grid.data() + 0x3C, &wordCount, 4);
      std::memcpy(grid.data() + 0x40, &in[17], 4);
      std::memcpy(grid.data() + 0x44, &in[18], 4);
      std::memcpy(grid.data() + 0x48, &waterPtr, 4);
      std::memcpy(grid.data() + 0x4C, &wordCount, 4);
      std::memcpy(grid.data() + 0x50, &in[17], 4);
      std::memcpy(grid.data() + 0x54, &in[18], 4);

      const std::int16_t pos[2] = {static_cast<std::int16_t>(in[6]), static_cast<std::int16_t>(in[7])};
      std::uint8_t footprint[16];
      FillFootprintBytes(in, footprint);
      footprint[3] = static_cast<std::uint8_t>(in[12]);
      out[0] = retail::OccupyFilter(footprint, grid.data(), pos, in[13]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void OccupyFilterOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      moho::CHeightField* const field = map.mHeightField.get();
      FillFieldSamples(field->data, field->width, field->height, in[2], in[3]);
      ExpandTerrainBytes(in[2] ^ 0x5A5A5A5Au, in[0] * in[1], map.mTerrainType.data, map.mBlocking);
      map.mWaterEnabled = static_cast<std::uint8_t>(in[4]);
      map.mWaterElevation = F(in, 5);

      const u32 wordCount = OccupationWordCount(in);
      std::vector<u32> terrain(wordCount + 1u), water(wordCount + 1u);
      FillOccupationWords(in[14], in[15], wordCount, terrain.data());
      FillOccupationWords(in[14] ^ 0xA5A5A5A5u, in[16], wordCount, water.data());
      std::vector<std::max_align_t> simStore(sizeof(moho::Sim) / sizeof(std::max_align_t) + 1u);
      auto* const sim = reinterpret_cast<moho::Sim*>(simStore.data());
      sim->mMapData = &map;
      std::vector<std::max_align_t> gridStore(sizeof(moho::COGrid) / sizeof(std::max_align_t) + 1u);
      auto* const grid = reinterpret_cast<moho::COGrid*>(gridStore.data());
      grid->sim = sim;
      gpg::BitArray2D* const arrays[2] = {&grid->terrainOccupation, &grid->waterOccupation};
      u32* const words[2] = {terrain.data(), water.data()};
      for (int i = 0; i < 2; ++i) {
        arrays[i]->ptr = reinterpret_cast<std::int32_t*>(words[i]);
        arrays[i]->size = static_cast<std::int32_t>(wordCount);
        arrays[i]->width = static_cast<std::int32_t>(in[17]);
        arrays[i]->height = static_cast<std::int32_t>(in[18]);
      }

      moho::SOCellPos pos;
      pos.x = static_cast<std::int16_t>(in[6]);
      pos.z = static_cast<std::int16_t>(in[7]);
      moho::SFootprint footprint;
      std::uint8_t bytes[16];
      FillFootprintBytes(in, bytes);
      bytes[3] = static_cast<std::uint8_t>(in[12]);
      std::memcpy(&footprint, bytes, sizeof(bytes));
      const auto caps = static_cast<moho::EOccupancyCaps>(in[13] == 0xFFFFFFFFu ? 0xFFu : in[13]);
      out[0] = static_cast<u32>(moho::OCCUPY_Filter(footprint, *grid, pos, caps));
    }
#endif

    // ---- multi-cell footprints: OCCUPY_MobileCheck, OCCUPY_FootprintFits ------------
    //
    // OCCUPY_MobileCheck 0x00564AB0 (34 million calls): which layers a
    // footprint of sizeX x sizeZ cells may occupy from origin pos, from the
    // map's heights, water and blocking terrain. ecx = pos, [footprint]
    // [map] on the stack, caller-popped, eax = the caps. OCCUPY_FootprintFits
    // 0x007209E0 (30M): a 1x1 footprint goes to OCCUPY_Filter (0x00720A01);
    // otherwise caps -1 is OCCUPY_MobileCheck through grid->sim->mMapData
    // (0x00720A1F), then land/seabed cleared when terrainOccupation's
    // GetRectOr over the footprint finds a bit (0x00720A55) unless the
    // footprint ignores structures, and water when waterOccupation's does.
    // eax = grid, edi = pos, [footprint] [caps], ret 8, al = the caps. Both
    // run on the OCCUPY_Filter row's world (same 19 words) with the footprint
    // sized by two more.
    // in = the OCCUPY_Filter words, sizeX sizeZ; out = the caps.
    struct RetailOccupancyWorld
    {
      std::vector<std::uint16_t> samples;
      std::vector<std::uint8_t> types, map, sim, grid;
      std::vector<u32> terrain, water;
      u32 field[3] = {};
      std::int16_t pos[2] = {};
      std::uint8_t footprint[16] = {};

      explicit RetailOccupancyWorld(const u32* in)
        : samples(static_cast<std::size_t>(in[0] + 1u) * (in[1] + 1u))
        , types(static_cast<std::size_t>(in[0]) * in[1])
        , map(kMapBytes, 0)
        , sim(0x900, 0)
        , grid(0x58, 0)
      {
        const int sampleW = static_cast<int>(in[0]) + 1;
        const int sampleH = static_cast<int>(in[1]) + 1;
        FillFieldSamples(samples.data(), sampleW, sampleH, in[2], in[3]);
        ExpandTerrainBytes(in[2] ^ 0x5A5A5A5Au, static_cast<u32>(types.size()), types.data(), map.data() + 0x1434);
        // x86 only at run time (the retail call); the x64 build compiles it unused.
        field[0] = static_cast<u32>(reinterpret_cast<std::uintptr_t>(samples.data()));
        field[1] = static_cast<u32>(sampleW);
        field[2] = static_cast<u32>(sampleH);
        const void* const fieldPtr = field;
        std::uint8_t* const typesPtr = types.data();
        std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
        std::memcpy(map.data() + 0x1428, &typesPtr, 4);
        std::memcpy(map.data() + 0x142C, &in[0], 4);
        std::memcpy(map.data() + 0x1430, &in[1], 4);
        map[0x1534] = static_cast<std::uint8_t>(in[4]);
        std::memcpy(map.data() + 0x1538, &in[5], 4);
        const u32 wordCount = OccupationWordCount(in);
        terrain.assign(wordCount + 1u, 0u);
        water.assign(wordCount + 1u, 0u);
        FillOccupationWords(in[14], in[15], wordCount, terrain.data());
        FillOccupationWords(in[14] ^ 0xA5A5A5A5u, in[16], wordCount, water.data());
        const void* const mapPtr = map.data();
        std::memcpy(sim.data() + 0x8CC, &mapPtr, 4);
        const void* const simPtr = sim.data();
        const u32* const terrainPtr = terrain.data();
        const u32* const waterPtr = water.data();
        std::memcpy(grid.data() + 0x00, &simPtr, 4);
        std::memcpy(grid.data() + 0x38, &terrainPtr, 4);
        std::memcpy(grid.data() + 0x3C, &wordCount, 4);
        std::memcpy(grid.data() + 0x40, &in[17], 4);
        std::memcpy(grid.data() + 0x44, &in[18], 4);
        std::memcpy(grid.data() + 0x48, &waterPtr, 4);
        std::memcpy(grid.data() + 0x4C, &wordCount, 4);
        std::memcpy(grid.data() + 0x50, &in[17], 4);
        std::memcpy(grid.data() + 0x54, &in[18], 4);
        pos[0] = static_cast<std::int16_t>(in[6]);
        pos[1] = static_cast<std::int16_t>(in[7]);
        FillFootprintBytes(in, footprint);
        footprint[0] = static_cast<std::uint8_t>(in[19]);
        footprint[1] = static_cast<std::uint8_t>(in[20]);
        footprint[3] = static_cast<std::uint8_t>(in[12]);
      }
    };
    void GenFootprintWorld(Rng& rng, u32* in)
    {
      GenOccupyFilter(rng, in);
      in[19] = 1u + rng.Below(8);
      in[20] = 1u + rng.Below(8);
    }
    void MobileCheckRetail(const u32* in, u32* out)
    {
      RetailOccupancyWorld w(in);
      out[0] = retail::OccupyMobileCheck(w.pos, w.footprint, w.map.data()) & 0xFFu;
    }
    void FootprintFitsRetail(const u32* in, u32* out)
    {
      RetailOccupancyWorld w(in);
      out[0] = retail::OccupyFootprintFits(w.grid.data(), w.pos, w.footprint, in[13]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    struct OursOccupancyWorld
    {
      moho::STIMap map;
      std::vector<u32> terrain, water;
      std::vector<std::max_align_t> simStore, gridStore;
      moho::COGrid* grid = nullptr;
      moho::SOCellPos pos{};
      moho::SFootprint footprint{};

      explicit OursOccupancyWorld(const u32* in)
        : map(in[0], in[1])
        , simStore(sizeof(moho::Sim) / sizeof(std::max_align_t) + 1u)
        , gridStore(sizeof(moho::COGrid) / sizeof(std::max_align_t) + 1u)
      {
        moho::CHeightField* const field = map.mHeightField.get();
        FillFieldSamples(field->data, field->width, field->height, in[2], in[3]);
        ExpandTerrainBytes(in[2] ^ 0x5A5A5A5Au, in[0] * in[1], map.mTerrainType.data, map.mBlocking);
        map.mWaterEnabled = static_cast<std::uint8_t>(in[4]);
        map.mWaterElevation = F(in, 5);
        const u32 wordCount = OccupationWordCount(in);
        terrain.assign(wordCount + 1u, 0u);
        water.assign(wordCount + 1u, 0u);
        FillOccupationWords(in[14], in[15], wordCount, terrain.data());
        FillOccupationWords(in[14] ^ 0xA5A5A5A5u, in[16], wordCount, water.data());
        auto* const sim = reinterpret_cast<moho::Sim*>(simStore.data());
        sim->mMapData = &map;
        grid = reinterpret_cast<moho::COGrid*>(gridStore.data());
        grid->sim = sim;
        gpg::BitArray2D* const arrays[2] = {&grid->terrainOccupation, &grid->waterOccupation};
        u32* const words[2] = {terrain.data(), water.data()};
        for (int i = 0; i < 2; ++i) {
          arrays[i]->ptr = reinterpret_cast<std::int32_t*>(words[i]);
          arrays[i]->size = static_cast<std::int32_t>(wordCount);
          arrays[i]->width = static_cast<std::int32_t>(in[17]);
          arrays[i]->height = static_cast<std::int32_t>(in[18]);
        }
        pos.x = static_cast<std::int16_t>(in[6]);
        pos.z = static_cast<std::int16_t>(in[7]);
        std::uint8_t bytes[16];
        FillFootprintBytes(in, bytes);
        bytes[0] = static_cast<std::uint8_t>(in[19]);
        bytes[1] = static_cast<std::uint8_t>(in[20]);
        bytes[3] = static_cast<std::uint8_t>(in[12]);
        std::memcpy(&footprint, bytes, sizeof(bytes));
      }
    };
    void MobileCheckOurs(const u32* in, u32* out)
    {
      OursOccupancyWorld w(in);
      out[0] = static_cast<u32>(moho::OCCUPY_MobileCheck(w.footprint, w.map, w.pos));
    }
    void FootprintFitsOurs(const u32* in, u32* out)
    {
      OursOccupancyWorld w(in);
      const auto caps = static_cast<moho::EOccupancyCaps>(in[13] == 0xFFFFFFFFu ? 0xFFu : in[13]);
      out[0] = static_cast<u32>(moho::OCCUPY_FootprintFits(*w.grid, w.pos, w.footprint, caps));
    }
#endif

    // STIMap::IsWithin 0x0062CA60 (29 million calls): whether pos +- border
    // stays inside the map. Whole map: x - border and z - border against 0
    // by comiss (0x0062CA85), x + border and z + border against width - 1
    // and height - 1 on the x87 (fild, 2^32 added when negative, fcomip at
    // 0x0062CAC4/0x0062CAE8); else the playable rect (+0x08..+0x14). eax =
    // map, edx = pos, [border] [wholeMap], caller-popped, al = inside.
    // in = cellsW cellsH x0 z0 x1 z1 posX posY posZ border wholeMap; out = inside.
    [[nodiscard]] u32 GenRectInt(Rng& rng);
    void GenIsWithin(Rng& rng, u32* in)
    {
      in[0] = 2u + rng.Below(63);
      in[1] = 2u + rng.Below(63);
      in[2] = rng.Chance(80) ? rng.Below(8) : GenRectInt(rng);
      in[3] = rng.Chance(80) ? rng.Below(8) : GenRectInt(rng);
      in[4] = rng.Chance(80) ? in[0] - rng.Below(8) : GenRectInt(rng);
      in[5] = rng.Chance(80) ? in[1] - rng.Below(8) : GenRectInt(rng);
      in[6] = Bits(AnyOrRange(rng, -8.0, static_cast<double>(in[0]) + 8.0));
      in[7] = Bits(AnyOrRange(rng, -50.0, 200.0));
      in[8] = Bits(AnyOrRange(rng, -8.0, static_cast<double>(in[1]) + 8.0));
      in[9] = rng.Chance(30) ? 0u : Bits(AnyOrRange(rng, 0.0, 10.0));
      in[10] = rng.Chance(50) ? 1u : 0u;
    }
    void IsWithinRetail(const u32* in, u32* out)
    {
      const u32 field[3] = {0u, in[0] + 1u, in[1] + 1u};
      std::vector<std::uint8_t> map(kMapBytes, 0);
      const void* const fieldPtr = field;
      std::memcpy(map.data() + 0x0000, &fieldPtr, 4);
      std::memcpy(map.data() + 0x08, &in[2], 16);
      out[0] = retail::MapIsWithin(map.data(), &in[6], F(in, 9), in[10]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void IsWithinOurs(const u32* in, u32* out)
    {
      moho::STIMap map(in[0], in[1]);
      map.mPlayableRect.x0 = static_cast<int>(in[2]);
      map.mPlayableRect.z0 = static_cast<int>(in[3]);
      map.mPlayableRect.x1 = static_cast<int>(in[4]);
      map.mPlayableRect.z1 = static_cast<int>(in[5]);
      const Wm3::Vec3f pos{F(in, 6), F(in, 7), F(in, 8)};
      out[0] = map.IsWithin(pos, F(in, 9), in[10] != 0u) ? 1u : 0u;
    }
#endif

    // CAiPathFinder::IsInBounds 0x005AA680 (the path search's edge filter):
    // true when mUseWholeMap (+0x74) is set or mInsidePlayableRect (+0x75) is
    // clear, else whether the destination cell, widened as unsigned shorts,
    // keeps mMaxFootprintSpan (+0x78, as int) inside the map's playable rect
    // (sim +0x8CC, map +0x08..+0x14), all compared as floats (0x005AA698 on).
    // Retail gets buffers with just those fields; ours a CAiPathFinder and a
    // Sim storage with only these members written (the real ones need a unit
    // and a whole sim) and a real STIMap, called non-virtually.
    // in = useWholeMap inside span x z x0 z0 x1 z1; out = in bounds (0 or 1).
    [[nodiscard]] u32 GenRectInt(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 75) {
        return rng.Below(1100);
      }
      if (mode < 85) {
        return (1u << 24) + rng.Below(8) - 4u; // where int -> float rounds
      }
      if (mode < 92) {
        return 0u - rng.Below(64);
      }
      return rng.U32();
    }
    void GenPathInBounds(Rng& rng, u32* in)
    {
      in[0] = rng.Chance(80) ? 0u : rng.Below(256);
      in[1] = rng.Chance(15) ? 0u : (rng.Chance(80) ? 1u : rng.Below(256));
      const u32 spanMode = rng.Below(100);
      in[2] = spanMode < 70 ? rng.Below(16) : (spanMode < 85 ? rng.Below(1u << 25) : rng.U32());
      for (int i = 3; i < 5; ++i) {
        const u32 mode = rng.Below(100);
        in[i] = mode < 60 ? rng.Below(1100) : (mode < 80 ? 0x7FFDu + rng.Below(6) : (mode < 90 ? 0xFFFFu - rng.Below(4) : rng.Below(0x10000)));
      }
      in[5] = GenRectInt(rng);
      in[6] = GenRectInt(rng);
      in[7] = rng.Chance(80) ? in[5] + rng.Below(1100) : GenRectInt(rng);
      in[8] = rng.Chance(80) ? in[6] + rng.Below(1100) : GenRectInt(rng);
    }
    void PathInBoundsRetail(const u32* in, u32* out)
    {
      std::vector<std::uint8_t> map(0x18, 0);
      std::memcpy(map.data() + 0x08, &in[5], 16);
      std::vector<std::uint8_t> sim(0x900, 0);
      const void* const mapPtr = map.data();
      std::memcpy(sim.data() + 0x8CC, &mapPtr, 4);
      std::vector<std::uint8_t> finder(0x80, 0);
      const void* const simPtr = sim.data();
      std::memcpy(finder.data() + 0x28, &simPtr, 4);
      finder[0x74] = static_cast<std::uint8_t>(in[0]);
      finder[0x75] = static_cast<std::uint8_t>(in[1]);
      std::memcpy(finder.data() + 0x78, &in[2], 4);
      const std::int16_t from[2] = {0x1234, 0x0567}; // not read
      const std::int16_t to[2] = {static_cast<std::int16_t>(in[3]), static_cast<std::int16_t>(in[4])};
      float cost = 1.0f;
      out[0] = retail::PathFinderIsInBounds(finder.data(), from, to, &cost);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void PathInBoundsOurs(const u32* in, u32* out)
    {
      moho::STIMap map(2, 2);
      map.mPlayableRect.x0 = static_cast<int>(in[5]);
      map.mPlayableRect.z0 = static_cast<int>(in[6]);
      map.mPlayableRect.x1 = static_cast<int>(in[7]);
      map.mPlayableRect.z1 = static_cast<int>(in[8]);
      std::vector<std::max_align_t> simStore(sizeof(moho::Sim) / sizeof(std::max_align_t) + 1u);
      auto* const sim = reinterpret_cast<moho::Sim*>(simStore.data());
      sim->mMapData = &map;
      std::vector<std::max_align_t> finderStore(sizeof(moho::CAiPathFinder) / sizeof(std::max_align_t) + 1u);
      auto* const finder = reinterpret_cast<moho::CAiPathFinder*>(finderStore.data());
      finder->mSim = sim;
      finder->mUseWholeMap = static_cast<std::uint8_t>(in[0]);
      finder->mInsidePlayableRect = static_cast<std::uint8_t>(in[1]);
      finder->mMaxFootprintSpan = in[2];
      moho::SOCellPos from;
      from.x = 0x1234;
      from.z = 0x0567;
      moho::SOCellPos to;
      to.x = static_cast<std::int16_t>(in[3]);
      to.z = static_cast<std::int16_t>(in[4]);
      float cost = 1.0f;
      out[0] = finder->moho::CAiPathFinder::IsInBounds(from, to, &cost) ? 1u : 0u;
    }
#endif

    // CAiPathFinder::ShouldSearchRect 0x005AA860 (55 million calls): whether
    // the cluster search may refine inside rect. Search type 0 or the probe
    // flag (+0x16): true when the anchor cell (+0x34, two zero-extended
    // words, 0x005AA8D5) lies in rect; otherwise true when a node of the
    // recent-rect list (head at +0x6C, next at +0, rect at +8) touches rect,
    // both non-empty (0x005AA886..0x005AA8B6). Then the goal arm: rect
    // strictly overlapping the goal's outer rect (+0x3C), the goal non-empty,
    // rect non-empty (0x00416F40) and not inside the inner rect (+0x4C).
    // thiscall, [rect], ret 4, al. Anchors cover the whole 0..0xFFFF range
    // (ours used to sign-extend them through an int16 SOCellPos).
    // in = searchType probe anchorX anchorZ goal[8] history count rects[12]
    // rect[4]; out = search.
    void GenShouldSearchRect(Rng& rng, u32* in)
    {
      const auto coord = [&rng]() { return static_cast<u32>(static_cast<int>(rng.Below(48)) - 8); };
      in[0] = rng.Chance(50) ? 0u : 1u + rng.Below(3);
      in[1] = rng.Chance(80) ? 0u : 1u;
      in[2] = rng.Chance(95) ? rng.Below(40) : rng.Below(0x10000);
      in[3] = rng.Chance(95) ? rng.Below(40) : rng.Below(0x10000);
      for (int i = 4; i < 12; ++i) {
        in[i] = coord();
      }
      in[12] = rng.Below(4);
      for (int i = 13; i < 25; ++i) {
        in[i] = coord();
      }
      for (int i = 25; i < 29; ++i) {
        in[i] = coord();
      }
    }
    void ShouldSearchRectRetail(const u32* in, u32* out)
    {
      std::vector<std::uint8_t> finder(0x7C, 0);
      std::memcpy(finder.data() + 0x60, &in[0], 4);
      finder[0x16] = static_cast<std::uint8_t>(in[1]);
      const std::uint16_t anchor[2] = {static_cast<std::uint16_t>(in[2]), static_cast<std::uint16_t>(in[3])};
      std::memcpy(finder.data() + 0x34, anchor, 4);
      std::memcpy(finder.data() + 0x3C, &in[4], 32);
      // Ring list: the head node, then count nodes of next, prev, rect.
      std::vector<std::uint8_t> nodes(0x18 * 4, 0);
      const auto addr = [&nodes](const u32 i) { return static_cast<u32>(reinterpret_cast<std::uintptr_t>(nodes.data()) + i * 0x18u); };
      const u32 count = in[12];
      for (u32 i = 0; i <= count; ++i) {
        const u32 next = addr(i == count ? 0u : i + 1u);
        const u32 prev = addr(i == 0u ? count : i - 1u);
        std::memcpy(nodes.data() + i * 0x18, &next, 4);
        std::memcpy(nodes.data() + i * 0x18 + 4, &prev, 4);
        if (i > 0u) {
          std::memcpy(nodes.data() + i * 0x18 + 8, &in[13 + (i - 1u) * 4u], 16);
        }
      }
      const u32 head = addr(0);
      std::memcpy(finder.data() + 0x6C, &head, 4);
      std::memcpy(finder.data() + 0x70, &count, 4);
      out[0] = retail::PathFinderShouldSearchRect(finder.data(), &in[25]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void ShouldSearchRectOurs(const u32* in, u32* out)
    {
      std::vector<std::max_align_t> store(sizeof(moho::CAiPathFinder) / sizeof(std::max_align_t) + 1u);
      auto* const finder = reinterpret_cast<moho::CAiPathFinder*>(store.data());
      finder->mSearchType = static_cast<moho::EAiPathSearchType>(in[0]);
      finder->mUseGoalBoundaryProbe = static_cast<std::uint8_t>(in[1]);
      finder->mAnchorCell.x = static_cast<std::uint16_t>(in[2]);
      finder->mAnchorCell.z = static_cast<std::uint16_t>(in[3]);
      std::memcpy(&finder->mGoal, &in[4], 32);
      auto* const history = new (&finder->mRecentSearchRects) moho::SRectList();
      for (u32 i = 0; i < in[12]; ++i) {
        gpg::Rect2i r;
        std::memcpy(&r, &in[13 + i * 4u], 16);
        history->push_back(r);
      }
      gpg::Rect2i rect;
      std::memcpy(&rect, &in[25], 16);
      out[0] = finder->moho::CAiPathFinder::ShouldSearchRect(rect) ? 1u : 0u;
      std::destroy_at(history);
    }
#endif

    // ComputeOctileDistanceCore 0x005A9D60 (16 million calls under the path
    // heuristic): max(|a|,|b|) + min(|a|,|b|) * 0.41421354f (0x00E4F788) on
    // the x87, NaN leaving the order as given (fcomi/jbe at 0x005A9D70),
    // cdecl, st0. The x87 at precision 24 rounds a denormal product twice
    // where SSE rounds it once, so inputs keep products out of the denormal
    // range (the game passes whole cell counts).
    // in = a b; out = the distance.
    [[nodiscard]] u32 GenOctileLane(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 50) {
        return Bits(static_cast<float>(rng.Below(2000)));
      }
      if (mode < 80) {
        return Bits(static_cast<float>(rng.Range(-1.0e6, 1.0e6)));
      }
      if (mode < 90) {
        static const u32 kSpecial[] = {0x7F800000u, 0xFF800000u, 0x7FC00000u, 0x80000000u, 0x00000000u};
        return kSpecial[rng.Below(5)];
      }
      return Bits(static_cast<float>(rng.Range(-1.0e30, 1.0e30)));
    }
    void GenOctile(Rng& rng, u32* in)
    {
      in[0] = GenOctileLane(rng);
      in[1] = GenOctileLane(rng);
    }
    void OctileRetail(const u32* in, u32* out)
    {
      out[0] = Bits(retail::OctileDistanceCore(F(in, 0), F(in, 1)));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void OctileOurs(const u32* in, u32* out)
    {
      out[0] = Bits(moho::ComputeOctileDistanceCore(F(in, 0), F(in, 1)));
    }
#endif

    // computesizes 0x00927090 (13 million calls, Lua's rehash): from the
    // per-power-of-two counts of integer keys, the array size (the largest
    // 2^n more than half used) and the hash share. nums in eax, cdecl
    // (ntotal, narray*, nhash*). The loop stops once 2^i passes *narray,
    // so narray < 2^24 reads at most 26 buckets.
    // in = ntotal narray nums[26]; out = narray nhash.
    constexpr int kSizeBuckets = 26;
    void GenComputeSizes(Rng& rng, u32* in)
    {
      u32 sum = 0;
      for (int i = 0; i < kSizeBuckets; ++i) {
        const u32 cap = i == 0 ? 1u : (i < 12 ? (1u << (i - 1)) : 0u);
        const u32 n = rng.Chance(30) ? 0u : (rng.Chance(80) ? rng.Below(cap + 1u) : rng.Below(64));
        in[2 + i] = n;
        sum += n;
      }
      in[1] = rng.Chance(80) ? sum : rng.Below(sum + 8u);
      in[0] = in[1] + rng.Below(64);
    }
    void ComputeSizesRetail(const u32* in, u32* out)
    {
      int nums[32] = {};
      std::memcpy(nums, &in[2], sizeof(int) * kSizeBuckets);
      int narray = static_cast<int>(in[1]);
      int nhash = 0x5A5A5A5A;
      retail::LuaComputeSizes(nums, static_cast<int>(in[0]), &narray, &nhash);
      out[0] = static_cast<u32>(narray);
      out[1] = static_cast<u32>(nhash);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void ComputeSizesOurs(const u32* in, u32* out)
    {
      int nums[32] = {};
      std::memcpy(nums, &in[2], sizeof(int) * kSizeBuckets);
      int narray = static_cast<int>(in[1]);
      int nhash = 0x5A5A5A5A;
      computesizes(static_cast<int>(in[0]), &narray, &nhash, nums);
      out[0] = static_cast<u32>(narray);
      out[1] = static_cast<u32>(nhash);
    }
#endif

    // func_AABoxToRect 0x004FCBE0 (15 million calls): a world box's X/Z
    // extent to collision cells: floor (frndint + compare, 0x004FCBFD) of
    // the minimum and ceil of the maximum, (+3) >> 2, clamped to 0..0xFFFF
    // with the extents measured from the clamped start (0x004FCCCE). eax =
    // box, ebx = out, eax = out. NaN and huge bounds take fistp's integer
    // indefinite.
    // in = min[3] max[3]; out = startX | startZ << 16, width | height << 16.
    [[nodiscard]] u32 GenBoxLane(Rng& rng)
    {
      return rng.Chance(85) ? Bits(static_cast<float>(rng.Range(-200.0, 4200.0))) : Bits(GenFloat(rng));
    }
    void GenAABoxToRect(Rng& rng, u32* in)
    {
      for (int i = 0; i < 6; ++i) {
        in[i] = GenBoxLane(rng);
      }
      if (rng.Chance(70)) { // a proper box: max above min
        for (int i = 0; i < 3; ++i) {
          in[3 + i] = Bits(F(in, i) + static_cast<float>(rng.Range(0.0, 64.0)));
        }
      }
    }
    void AABoxToRectRetail(const u32* in, u32* out)
    {
      std::uint16_t rect[4] = {0x1111, 0x2222, 0x3333, 0x4444};
      retail::AABoxToRect(in, rect);
      out[0] = rect[0] | (static_cast<u32>(rect[1]) << 16);
      out[1] = rect[2] | (static_cast<u32>(rect[3]) << 16);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void AABoxToRectOurs(const u32* in, u32* out)
    {
      Wm3::AxisAlignedBox3f box;
      std::memcpy(&box, in, 24);
      moho::CollisionDBRect rect{0x1111, 0x2222, 0x3333, 0x4444};
      moho::func_AABoxToRect(&rect, box);
      out[0] = rect.mStartX | (static_cast<u32>(rect.mStartZ) << 16);
      out[1] = rect.mWidth | (static_cast<u32>(rect.mHeight) << 16);
    }
    static_assert(sizeof(Wm3::AxisAlignedBox3f) == 24);
#endif

    // ---- Lua table lookups (lua/LuaObject.cpp) -----------------------------------
    //
    // luaH_getstr 0x009274D0, luaH_get 0x00927510 and luaH_getnum 0x00927450
    // are the three most-called functions under the sim checksum (1.7, 1.5 and
    // 0.67 billion calls in the 3 coverage replays). A table is built from a
    // few words by one index-only builder both sides share: 1..32 hash nodes
    // (lsizenode 0..5), an array part of 0..12, and keys placed the way Lua
    // 5.0's luaH_set does (main position; on a collision a free node from the
    // top, the colliding key moved out when it is not in its own main
    // position). Main positions as luaH_mainposition 0x00926F70 computes
    // them: boolean value & mask (0x00926FC7), string hash & mask
    // (0x00926FA4), number bits(n + 1.0f) % ((size - 1) | 1) (0x00926F8B),
    // light userdata value % ((size - 1) | 1) (0x00926FE7). Retail's table is
    // raw x86 bytes (Table 0x24: lsizenode +0x09, array +0x10, node +0x14,
    // sizearray +0x20; Node 0x14: key +0, value +8, next +0x10; TString hash
    // +0x0C); ours the real Table, Node and TString. out = the slot the
    // lookup returned: a node index, 0x10000 + an array index, or 0xFFFFFFFF
    // for luaO_nilobject.
    // in = seed sizearray lsizenode fill pool, then the key words.
    constexpr u32 kLuaNil = 0;
    constexpr u32 kLuaBoolean = 1;
    constexpr u32 kLuaLightUserdata = 2;
    constexpr u32 kLuaNumber = 3;
    constexpr u32 kLuaString = 4;
    constexpr u32 kNoNode = 0xFFFFFFFFu;

    struct LuaTableDesc
    {
      u32 sizearray = 0;
      u32 lsizenode = 0;
      std::vector<u32> keyTt, keyBits, next; // per node; a string key's bits are its pool index
      std::vector<u32> poolHash;             // pool strings; the last one is never a key
      std::vector<std::uint8_t> valueNil;    // per node: a free node, or a dead key whose value went nil
      std::vector<std::uint8_t> arrayNil;    // per array slot
    };
    [[nodiscard]] u32 LuaMainPosition(const LuaTableDesc& d, const u32 tt, const u32 bits)
    {
      const u32 size = 1u << d.lsizenode;
      switch (tt) {
      case kLuaBoolean:
        return bits & (size - 1u);
      case kLuaNumber: {
        float n = 0.0f;
        std::memcpy(&n, &bits, 4);
        const float shifted = n + 1.0f;
        u32 hash = 0;
        std::memcpy(&hash, &shifted, 4);
        return hash % ((size - 1u) | 1u);
      }
      case kLuaString:
        return d.poolHash[bits] & (size - 1u);
      default:
        return bits % ((size - 1u) | 1u);
      }
    }
    [[nodiscard]] bool LuaSameKey(const u32 tt, const u32 bits, const u32 otherTt, const u32 otherBits)
    {
      if (tt != otherTt) {
        return false;
      }
      if (tt == kLuaNumber) {
        float a = 0.0f, b = 0.0f;
        std::memcpy(&a, &bits, 4);
        std::memcpy(&b, &otherBits, 4);
        return a == b;
      }
      return bits == otherBits;
    }
    [[nodiscard]] u32 LuaNumberKeyBits(Rng& rng, const u32 sizearray, const u32 nodes)
    {
      const u32 mode = rng.Below(100);
      float n = 0.0f;
      if (mode < 60) {
        n = static_cast<float>(static_cast<int>(rng.Below(sizearray + 3u * nodes + 6u)) - 4);
      } else if (mode < 75) {
        n = static_cast<float>(static_cast<int>(rng.Below(64))) + 0.5f;
      } else if (mode < 85) {
        n = static_cast<float>((1 << 24) + static_cast<int>(rng.Below(8)) - 4);
      } else if (mode < 90) {
        n = -0.0f;
      } else {
        return Bits(AnyOrRange(rng, -1.0e9, 1.0e9));
      }
      return Bits(n);
    }
    // The builder's own number keys: integer arithmetic and raw bit patterns
    // only. The builder runs once under the generators' x87 precision 53 and
    // again inside the row under the game's precision 24, and GenFloat's
    // ldexp (x87 on Win32) rounds a denormal result twice under precision 24:
    // a key the generator picked from its table was then missing from the
    // row's (luaH_next's retail call raised "invalid key for `next'").
    [[nodiscard]] u32 LuaBuilderNumberBits(Rng& rng, const u32 sizearray, const u32 nodes)
    {
      const u32 mode = rng.Below(100);
      if (mode < 60) {
        return Bits(static_cast<float>(static_cast<int>(rng.Below(sizearray + 3u * nodes + 6u)) - 4));
      }
      if (mode < 75) {
        return Bits(static_cast<float>(static_cast<int>(rng.Below(64))) + 0.5f);
      }
      if (mode < 85) {
        return Bits(static_cast<float>((1 << 24) + static_cast<int>(rng.Below(8)) - 4));
      }
      if (mode < 90) {
        return 0x80000000u; // -0.0f
      }
      return rng.U32(); // any bits: NaN, infinities and denormals as words
    }
    void BuildLuaTable(const u32* in, LuaTableDesc& d)
    {
      Rng rng(in[0] ^ 0x1A2B3C4Du);
      d.sizearray = in[1];
      d.lsizenode = in[2];
      const u32 size = 1u << d.lsizenode;
      d.keyTt.assign(size, kLuaNil);
      d.keyBits.assign(size, 0u);
      d.next.assign(size, kNoNode);
      d.poolHash.resize(in[4] + 1u);
      for (u32 i = 0; i < d.poolHash.size(); ++i) {
        // Equal hashes 1 time in 4, so string chains share main positions.
        d.poolHash[i] = i > 0u && rng.Chance(25) ? d.poolHash[rng.Below(i)] : rng.U32();
      }
      u32 freeTop = size;
      for (u32 k = 0; k < in[3]; ++k) {
        u32 tt = kLuaNumber;
        u32 bits = 0;
        const u32 kind = rng.Below(100);
        if (kind < 40) {
          tt = kLuaString;
          bits = rng.Below(in[4]);
        } else if (kind < 85) {
          bits = LuaBuilderNumberBits(rng, d.sizearray, size);
        } else if (kind < 93) {
          tt = kLuaBoolean;
          bits = rng.Below(2);
        } else {
          tt = kLuaLightUserdata;
          bits = rng.Below(1000);
        }
        bool present = false;
        for (u32 i = 0; i < size; ++i) {
          present = present || LuaSameKey(tt, bits, d.keyTt[i], d.keyBits[i]);
        }
        if (present) {
          continue;
        }
        u32 mp = LuaMainPosition(d, tt, bits);
        if (d.keyTt[mp] != kLuaNil) {
          while (freeTop > 0u && d.keyTt[freeTop - 1u] != kLuaNil) {
            --freeTop;
          }
          if (freeTop == 0u) {
            break; // full: luaH_set would rehash here
          }
          const u32 n = freeTop - 1u;
          const u32 other = LuaMainPosition(d, d.keyTt[mp], d.keyBits[mp]);
          if (other != mp) {
            // The colliding key is not in its own main position: move it to
            // the free node and relink its chain.
            u32 prev = other;
            while (d.next[prev] != mp) {
              prev = d.next[prev];
            }
            d.next[prev] = n;
            d.keyTt[n] = d.keyTt[mp];
            d.keyBits[n] = d.keyBits[mp];
            d.next[n] = d.next[mp];
            d.next[mp] = kNoNode;
          } else {
            d.next[n] = d.next[mp];
            d.next[mp] = n;
            mp = n;
          }
        }
        d.keyTt[mp] = tt;
        d.keyBits[mp] = bits;
      }
      // Nil values from a stream of their own, so the key layout above (all
      // the lookup rows read) stays as it was before values were added.
      Rng values(in[0] ^ 0x7E57A11Du);
      d.valueNil.resize(size);
      for (u32 i = 0; i < size; ++i) {
        d.valueNil[i] = d.keyTt[i] == kLuaNil || values.Chance(15) ? 1u : 0u;
      }
      d.arrayNil.resize(d.sizearray);
      for (u32 i = 0; i < d.sizearray; ++i) {
        d.arrayNil[i] = values.Chance(20) ? 1u : 0u;
      }
    }
    void GenLuaTableBase(Rng& rng, u32* in)
    {
      in[0] = rng.U32();
      in[1] = rng.Chance(30) ? 0u : rng.Below(13);
      in[2] = rng.Below(6);
      const u32 size = 1u << in[2];
      in[3] = rng.Chance(20) ? size : rng.Below(size + 1u);
      in[4] = 1u + rng.Below(12);
    }
    void GenLuaGetStr(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      in[5] = rng.Below(in[4] + 1u); // the last pool string is never a key
    }
    void GenLuaGetNum(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      const u32 mode = rng.Below(100);
      if (mode < 45) {
        in[5] = rng.Below(in[1] + 2u);
      } else if (mode < 75) {
        in[5] = static_cast<u32>(static_cast<int>(rng.Below(3u * (1u << in[2]) + 8u)) - 4);
      } else if (mode < 85) {
        in[5] = (1u << 24) + rng.Below(8) - 4u; // int -> float rounds past 2^24
      } else if (mode < 90) {
        in[5] = rng.Chance(50) ? 0x80000000u : 0x7FFFFFFFu;
      } else {
        in[5] = rng.U32();
      }
    }
    void GenLuaGet(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      const u32 mode = rng.Below(100);
      if (mode < 40) {
        in[5] = kLuaNumber;
        in[6] = rng.Chance(80) ? LuaNumberKeyBits(rng, in[1], 1u << in[2]) : (rng.Chance(50) ? Bits(-2147483648.0f) : Bits(AnyOrRange(rng, -3.0e9, 3.0e9)));
      } else if (mode < 70) {
        in[5] = kLuaString;
        in[6] = rng.Below(in[4] + 1u);
      } else if (mode < 82) {
        in[5] = kLuaBoolean;
        in[6] = rng.Below(3);
      } else if (mode < 94) {
        in[5] = kLuaLightUserdata;
        in[6] = rng.Below(1000);
      } else {
        in[5] = kLuaNil;
        in[6] = 0u;
      }
    }

    // Retail's table as x86 bytes (run time is x86 only; the x64 build
    // compiles it unused, hence the uintptr_t truncation).
    struct RetailLuaTable
    {
      std::vector<std::uint8_t> table, nodes, array, strings;
      [[nodiscard]] u32 Addr(const std::vector<std::uint8_t>& v, const std::size_t at) const
      {
        return static_cast<u32>(reinterpret_cast<std::uintptr_t>(v.data()) + at);
      }
      explicit RetailLuaTable(const LuaTableDesc& d)
        : table(0x24, 0)
        , nodes(static_cast<std::size_t>(d.keyTt.size()) * 0x14, 0)
        , array(static_cast<std::size_t>(d.sizearray) * 8 + 8, 0)
        , strings(d.poolHash.size() * 0x20, 0)
      {
        for (std::size_t i = 0; i < d.poolHash.size(); ++i) {
          strings[i * 0x20 + 4] = static_cast<std::uint8_t>(kLuaString);
          std::memcpy(strings.data() + i * 0x20 + 0x0C, &d.poolHash[i], 4);
        }
        for (std::size_t i = 0; i < d.keyTt.size(); ++i) {
          std::uint8_t* const n = nodes.data() + i * 0x14;
          const u32 bits = d.keyTt[i] == kLuaString ? Addr(strings, d.keyBits[i] * 0x20u) : d.keyBits[i];
          const u32 valTt = d.valueNil[i] != 0u ? kLuaNil : kLuaNumber;
          const u32 valBits = d.valueNil[i] != 0u ? 0u : Bits(static_cast<float>(i));
          const u32 next = d.next[i] == kNoNode ? 0u : Addr(nodes, d.next[i] * 0x14u);
          std::memcpy(n + 0x00, &d.keyTt[i], 4);
          std::memcpy(n + 0x04, &bits, 4);
          std::memcpy(n + 0x08, &valTt, 4);
          std::memcpy(n + 0x0C, &valBits, 4);
          std::memcpy(n + 0x10, &next, 4);
        }
        for (u32 i = 0; i < d.sizearray; ++i) {
          const u32 valTt = d.arrayNil[i] != 0u ? kLuaNil : kLuaNumber;
          const u32 valBits = d.arrayNil[i] != 0u ? 0u : Bits(static_cast<float>(i));
          std::memcpy(array.data() + i * 8, &valTt, 4);
          std::memcpy(array.data() + i * 8 + 4, &valBits, 4);
        }
        table[0x04] = 5; // LUA_TTABLE
        table[0x08] = 0xFF;
        table[0x09] = static_cast<std::uint8_t>(d.lsizenode);
        const u32 arrayAddr = Addr(array, 0);
        const u32 nodeAddr = Addr(nodes, 0);
        std::memcpy(table.data() + 0x10, &arrayAddr, 4);
        std::memcpy(table.data() + 0x14, &nodeAddr, 4);
        std::memcpy(table.data() + 0x20, &d.sizearray, 4);
      }
      [[nodiscard]] u32 Slot(const u32 result) const
      {
        if (result == 0x00D463FCu) {
          return 0xFFFFFFFFu; // luaO_nilobject
        }
        const u32 arrayBase = Addr(array, 0);
        if (result >= arrayBase && result < arrayBase + array.size()) {
          return 0x10000u + (result - arrayBase) / 8u;
        }
        return (result - Addr(nodes, 0) - 8u) / 0x14u;
      }
    };
    void LuaGetStrRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const RetailLuaTable t(d);
      out[0] = t.Slot(retail::LuaHGetStr(t.table.data(), t.strings.data() + in[5] * 0x20u));
    }
    void LuaGetNumRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const RetailLuaTable t(d);
      out[0] = t.Slot(retail::LuaHGetNum(t.table.data(), static_cast<int>(in[5])));
    }
    void LuaGetRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const RetailLuaTable t(d);
      const u32 key[2] = {in[5], in[5] == kLuaString ? t.Addr(t.strings, in[6] * 0x20u) : in[6]};
      out[0] = t.Slot(retail::LuaHGet(t.table.data(), key));
    }

    // luaH_mainposition 0x00926F70 (117 million calls): the node a key hashes
    // to, by tag through the jump table at 0x00927038. Keys of every tag 0..8;
    // a tag other than boolean, number or string hashes its value word as a
    // pointer (0x00926FE7, 0x0092700E), so those carry small plain words, the
    // same on retail's x86 and ours. out = the node index.
    void GenLuaMainPosition(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      in[5] = rng.Chance(85) ? kLuaBoolean + rng.Below(4) : rng.Below(9);
      if (in[5] == kLuaNumber) {
        in[6] = rng.Chance(70) ? LuaNumberKeyBits(rng, in[1], 1u << in[2]) : Bits(GenFloat(rng));
      } else if (in[5] == kLuaString) {
        in[6] = rng.Below(in[4] + 1u);
      } else {
        in[6] = rng.Chance(70) ? rng.Below(1000) : rng.U32();
      }
    }
    void LuaMainPositionRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const RetailLuaTable t(d);
      const u32 key[2] = {in[5], in[5] == kLuaString ? t.Addr(t.strings, in[6] * 0x20u) : in[6]};
      out[0] = (retail::LuaHMainPosition(t.table.data(), key) - t.Addr(t.nodes, 0)) / 0x14u;
    }

    // luaV_equalval 0x00929810 (283 million calls): two values of one tag,
    // through the jump table at 0x009298E8: nil equal (0x0092982B), boolean
    // value words (0x0092984F), number ucomiss (0x00929835), table (5) and
    // userdata (8) equal on the same object (0x00929879, 0x00929863) and
    // otherwise an __eq lookup through the state, every other tag the value
    // words (0x009298D2). Tables and userdata get the same word on both sides
    // only, so the state (null here) is never read. Value words stay 32-bit,
    // so ours' x64 pointers carry no high bits.
    // in = tag left right; out = equal (0 or 1).
    void GenLuaEqualVal(Rng& rng, u32* in)
    {
      in[0] = rng.Chance(90) ? rng.Below(12) : rng.U32();
      if (in[0] == kLuaNumber) {
        in[1] = rng.Chance(60) ? LuaNumberKeyBits(rng, 8, 8) : Bits(GenFloat(rng));
        const u32 mode = rng.Below(100);
        in[2] = mode < 40 ? in[1] : (mode < 50 ? in[1] ^ 0x80000000u : (mode < 60 ? in[1] + 1u : Bits(GenFloat(rng))));
      } else {
        in[1] = rng.Chance(50) ? rng.Below(4) : rng.U32();
        in[2] = in[0] == 5u || in[0] == 8u || rng.Chance(40) ? in[1] : (rng.Chance(50) ? rng.Below(4) : rng.U32());
      }
    }
    void LuaEqualValRetail(const u32* in, u32* out)
    {
      const u32 left[2] = {in[0], in[1]};
      const u32 right[2] = {in[0], in[2]};
      out[0] = retail::LuaVEqualVal(nullptr, left, right);
    }

    // luaV_lessthan 0x009296F0 (192 million calls): different tags compare
    // as signed tags (0x00929706, this fork's order instead of an error),
    // numbers as right > left by comiss (0x00929718, NaN false). Two strings
    // go through the image's strcoll (0x00A8E7F4), whose locale state CRT
    // init would set up, and other same-tag pairs to __lt through the state,
    // so the rows pass different tags or two numbers only.
    // in = tagLeft tagRight left right; out = less (0 or 1).
    void GenLuaLessThan(Rng& rng, u32* in)
    {
      if (rng.Chance(55)) {
        in[0] = in[1] = kLuaNumber;
        in[2] = rng.Chance(60) ? LuaNumberKeyBits(rng, 8, 8) : Bits(GenFloat(rng));
        const u32 mode = rng.Below(100);
        in[3] = mode < 25 ? in[2] : (mode < 35 ? in[2] ^ 0x80000000u : (mode < 50 ? in[2] + 1u : (mode < 60 ? in[2] - 1u : Bits(GenFloat(rng)))));
        return;
      }
      in[0] = rng.Chance(90) ? rng.Below(12) : rng.U32();
      do {
        in[1] = rng.Chance(90) ? rng.Below(12) : rng.U32();
      } while (in[1] == in[0]);
      in[2] = rng.U32();
      in[3] = rng.U32();
    }
    void LuaLessThanRetail(const u32* in, u32* out)
    {
      const u32 left[2] = {in[0], in[2]};
      const u32 right[2] = {in[1], in[3]};
      out[0] = retail::LuaVLessThan(nullptr, left, right);
    }

    // luaH_index 0x00927610 (89 million calls) and luaH_next 0x009276A0
    // (78 million): the traversal behind next/pairs. luaH_index: nil -1, an
    // integer key 1..sizearray (key - 1 below 2^24, 0x00927646) its array
    // slot, any other key its node through luaH_get plus sizearray; a key
    // not in the table raises through the state (0x0092766F), so the rows
    // only pass keys the table holds (or nil) and the state stays null.
    // luaH_next then skips nil values in the array (0x009276D0) and the nodes
    // (0x00927700) and writes the next key and value over key[0] and key[1].
    // in = seed sizearray lsizenode fill pool keyTt keyBits.
    // out = index; or ret keyTt keyBits valTt valBits (a string key as its
    // pool index).
    void PickPresentKey(Rng& rng, const LuaTableDesc& d, u32* key)
    {
      key[0] = kLuaNil;
      key[1] = 0u;
      const u32 mode = rng.Below(100);
      if (mode < 15) {
        return;
      }
      if (mode < 50 && d.sizearray > 0u) {
        key[0] = kLuaNumber;
        key[1] = Bits(static_cast<float>(1u + rng.Below(d.sizearray)));
        return;
      }
      std::vector<u32> held;
      for (u32 i = 0; i < d.keyTt.size(); ++i) {
        float n = 0.0f;
        std::memcpy(&n, &d.keyBits[i], 4);
        if (d.keyTt[i] != kLuaNil && !(d.keyTt[i] == kLuaNumber && n != n)) {
          held.push_back(i); // a NaN key is never found again
        }
      }
      if (!held.empty()) {
        const u32 i = held[rng.Below(static_cast<u32>(held.size()))];
        key[0] = d.keyTt[i];
        key[1] = d.keyBits[i];
      }
    }
    void GenLuaTraverse(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      PickPresentKey(rng, d, in + 5);
    }
    void LuaIndexRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const RetailLuaTable t(d);
      const u32 key[2] = {in[5], in[5] == kLuaString ? t.Addr(t.strings, in[6] * 0x20u) : in[6]};
      out[0] = retail::LuaHIndex(nullptr, t.table.data(), key);
    }
    void LuaNextRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const RetailLuaTable t(d);
      u32 key[4] = {in[5], in[5] == kLuaString ? t.Addr(t.strings, in[6] * 0x20u) : in[6], 0u, 0u};
      out[0] = retail::LuaHNext(nullptr, t.table.data(), key);
      out[1] = key[0];
      out[2] = key[0] == kLuaString ? (key[1] - t.Addr(t.strings, 0)) / 0x20u : key[1];
      out[3] = key[2];
      out[4] = key[3];
    }

    // luaH_set 0x00927560 (154 million calls) on a key the table holds: the
    // luaH_get dispatch (0x00927566..0x009275B5), flags cleared to 0 for every
    // call (0x009275BD), the slot returned. A missing key goes to newkey and
    // a nil or NaN one raises, both through the state, so the rows pass held
    // keys only (array slots 1..sizearray count as held) and a null state.
    // in = seed sizearray lsizenode fill pool keyTt keyBits; out = slot flags.
    void GenLuaSet(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      for (int tries = 0; tries < 8 && (tries == 0 || in[5] == kLuaNil); ++tries) {
        PickPresentKey(rng, d, in + 5);
      }
      if (in[5] == kLuaNil) {
        in[1] = in[1] > 0u ? in[1] : 1u; // array slot 1 is always held
        in[5] = kLuaNumber;
        in[6] = Bits(1.0f);
      }
    }
    void LuaSetRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      RetailLuaTable t(d);
      const u32 key[2] = {in[5], in[5] == kLuaString ? t.Addr(t.strings, in[6] * 0x20u) : in[6]};
      out[0] = t.Slot(retail::LuaHSet(nullptr, t.table.data(), key));
      out[1] = t.table[0x08];
    }

    // luaH_setnum 0x00927AC0 (73 million calls): luaH_getnum, and newkey
    // through the state on a miss (0x00927AFB); flags untouched. The rows pass
    // integer keys the table holds: 1..sizearray, or a whole-number hash key.
    // in = seed sizearray lsizenode fill pool key; out = slot flags.
    void GenLuaSetNumKey(Rng& rng, u32* in);
    void GenLuaSetNum(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      GenLuaSetNumKey(rng, in);
    }
    // An integer key the table of in[0..4] holds, into in[5] (in[1] raised to
    // 1 when the table holds none).
    void GenLuaSetNumKey(Rng& rng, u32* in)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      std::vector<u32> held;
      for (u32 i = 0; i < d.keyTt.size(); ++i) {
        float n = 0.0f;
        std::memcpy(&n, &d.keyBits[i], 4);
        if (d.keyTt[i] == kLuaNumber && n >= -2147483648.0f && n < 2147483648.0f &&
            static_cast<float>(static_cast<int>(n)) == n) {
          held.push_back(static_cast<u32>(static_cast<int>(n)));
        }
      }
      if (d.sizearray > 0u && (held.empty() || rng.Chance(40))) {
        in[5] = 1u + rng.Below(d.sizearray);
      } else if (!held.empty()) {
        in[5] = held[rng.Below(static_cast<u32>(held.size()))];
      } else {
        in[1] = 1u; // array slot 1 is always held
        in[5] = 1u;
      }
    }
    void LuaSetNumRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      RetailLuaTable t(d);
      out[0] = t.Slot(retail::LuaHSetNum(nullptr, t.table.data(), static_cast<int>(in[5])));
      out[1] = t.table[0x08];
    }

    // ---- Lua stack API on a minimal state (lua/LuaObject.cpp) --------------------
    //
    // luaA_index 0x0090C3D0 (526 million calls), negindex 0x0090C340 (308M),
    // lua_type 0x0090C740 (303M), lua_settop 0x0090C5A0 (222M), lua_pushvalue
    // 0x0090C6E0 (182M) and lua_gettop 0x0090C590 (116M) read a state's top
    // (+0x08), base (+0x0C), global state (+0x10, registry TObject at +0x30),
    // call frame (+0x14, its top at +4), stack_last (+0x18) and _gt (+0x30),
    // and the running C closure in base[-1] (upvalue count byte +8, upvalue
    // k at +0x38 + 8k). negindex: idx > -10000 top-relative, < -40000 this
    // fork's registry integer slots through luaH_getnum (0x0090C35F), -10001
    // _gt, -10000 the registry, else upvalue -10001 - idx, null past the
    // count (0x0090C3A7). One builder both sides share makes a 32-slot stack,
    // base at 1..4 (the closure below it), 0..top values, 0..4 upvalues and
    // the Lua rows' table as the registry; the frame's top lies far past the
    // stack, so lua_pushvalue never grows it through the state. A returned
    // slot is classified the same on both sides: 0 null, 0x100 + a stack
    // slot, 0x200 the registry, 0x201 _gt, 0x300 + k an upvalue lane, else
    // the registry table's slot code (luaO_nilobject 0xFFFFFFFF).
    // in = seed sizearray lsizenode fill pool (registry), stateSeed base top
    // upvalues, then idx.
    constexpr u32 kLuaStackSlots = 32;
    constexpr u32 kLuaFunction = 6;
    constexpr u32 kLuaTable = 5;
    constexpr u32 kGlobalsWord = 0x6A7B8C9Du; // _gt's value word, never dereferenced

    struct LuaStackDesc
    {
      u32 base = 1, top = 0, upvalues = 0;
      u32 slotTt[kLuaStackSlots] = {}, slotBits[kLuaStackSlots] = {};
      u32 upTt[8] = {}, upBits[8] = {};
    };
    void BuildLuaStack(const u32* in, LuaStackDesc& s)
    {
      Rng rng(in[5] ^ 0x51A7C0DEu);
      s.base = in[6];
      s.top = in[7];
      s.upvalues = in[8];
      const auto value = [&rng](u32& tt, u32& bits) {
        tt = rng.Below(4); // nil, boolean, light userdata, number: plain words
        bits = tt == kLuaNumber ? Bits(static_cast<float>(static_cast<int>(rng.Below(200)) - 100) * 0.25f) : rng.Below(1000);
      };
      for (u32 i = 0; i < kLuaStackSlots; ++i) {
        value(s.slotTt[i], s.slotBits[i]);
      }
      for (u32 i = 0; i < 8; ++i) {
        value(s.upTt[i], s.upBits[i]);
      }
    }
    void GenLuaStackBase(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      in[5] = rng.U32();
      in[6] = 1u + rng.Below(4);
      in[7] = rng.Below(kLuaStackSlots - in[6] - 2u);
      in[8] = rng.Below(5);
    }
    // An index any of the functions accepts without reading outside the
    // stack: positive up to the stack's end, top-relative down to its start,
    // the two pseudo-indices, upvalues (some past the count), registry
    // integer slots.
    [[nodiscard]] u32 GenLuaStackIndex(Rng& rng, const u32* in, const bool positive, const bool nonNull)
    {
      const u32 base = in[6], top = in[7], upvalues = in[8];
      const u32 mode = rng.Below(100);
      if (positive && mode < 30) {
        return 1u + rng.Below(kLuaStackSlots - base);
      }
      if (mode < 50) {
        return static_cast<u32>(-static_cast<int>(rng.Below((nonNull ? top : base + top) + 1u)));
      }
      if (mode < 60) {
        return static_cast<u32>(-10000);
      }
      if (mode < 70) {
        return static_cast<u32>(-10001);
      }
      if (mode < 85) {
        if (nonNull) {
          return upvalues > 0u ? static_cast<u32>(-10001 - 1 - static_cast<int>(rng.Below(upvalues))) : static_cast<u32>(-10001);
        }
        return rng.Chance(85) ? static_cast<u32>(-10002 - static_cast<int>(rng.Below(8))) : static_cast<u32>(-20000);
      }
      return static_cast<u32>(-40001 - static_cast<int>(rng.Below(in[1] + 3u * (1u << in[2]) + 4u)));
    }
    void GenLuaIndexAny(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = GenLuaStackIndex(rng, in, true, false);
    }
    void GenLuaIndexNeg(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = GenLuaStackIndex(rng, in, false, false);
    }
    void GenLuaSetTop(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = rng.Chance(60) ? rng.Below(kLuaStackSlots - in[6]) : static_cast<u32>(-1 - static_cast<int>(rng.Below(in[7] + 2u)));
    }
    void GenLuaPushValue(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = GenLuaStackIndex(rng, in, true, true);
    }

    struct RetailLuaStack
    {
      LuaTableDesc tableDesc;
      RetailLuaTable registry;
      std::vector<std::uint8_t> state, global, frame, stack, closure;

      [[nodiscard]] static u32 Addr(const std::vector<std::uint8_t>& v, const std::size_t at)
      {
        return static_cast<u32>(reinterpret_cast<std::uintptr_t>(v.data()) + at);
      }
      [[nodiscard]] static LuaTableDesc Table(const u32* in)
      {
        LuaTableDesc d;
        BuildLuaTable(in, d);
        return d;
      }
      explicit RetailLuaStack(const u32* in)
        : tableDesc(Table(in))
        , registry(tableDesc)
        , state(0x48, 0)
        , global(0x160, 0)
        , frame(0x28, 0)
        , stack(kLuaStackSlots * 8, 0)
        , closure(0x40 + 8 * 8, 0)
      {
        LuaStackDesc s;
        BuildLuaStack(in, s);
        for (u32 i = 0; i < kLuaStackSlots; ++i) {
          std::memcpy(stack.data() + i * 8, &s.slotTt[i], 4);
          std::memcpy(stack.data() + i * 8 + 4, &s.slotBits[i], 4);
        }
        closure[0x04] = static_cast<std::uint8_t>(kLuaFunction);
        closure[0x08] = static_cast<std::uint8_t>(s.upvalues);
        closure[0x09] = 1; // isC
        for (u32 k = 0; k < 8; ++k) {
          std::memcpy(closure.data() + 0x40 + k * 8, &s.upTt[k], 4);
          std::memcpy(closure.data() + 0x40 + k * 8 + 4, &s.upBits[k], 4);
        }
        const u32 function = kLuaFunction;
        const u32 closureAddr = Addr(closure, 0);
        std::memcpy(stack.data() + (s.base - 1u) * 8, &function, 4);
        std::memcpy(stack.data() + (s.base - 1u) * 8 + 4, &closureAddr, 4);
        const u32 table = kLuaTable;
        const u32 tableAddr = registry.Addr(registry.table, 0);
        std::memcpy(global.data() + 0x30, &table, 4);
        std::memcpy(global.data() + 0x34, &tableAddr, 4);
        const u32 frameTop = Addr(stack, (kLuaStackSlots + 64u) * 8u);
        std::memcpy(frame.data() + 0x04, &frameTop, 4);
        const u32 top = Addr(stack, (s.base + s.top) * 8u);
        const u32 base = Addr(stack, s.base * 8u);
        const u32 globalAddr = Addr(global, 0);
        const u32 frameAddr = Addr(frame, 0);
        const u32 last = Addr(stack, (kLuaStackSlots - 1u) * 8u);
        const u32 stackAddr = Addr(stack, 0);
        state[0x04] = 8; // LUA_TTHREAD
        std::memcpy(state.data() + 0x08, &top, 4);
        std::memcpy(state.data() + 0x0C, &base, 4);
        std::memcpy(state.data() + 0x10, &globalAddr, 4);
        std::memcpy(state.data() + 0x14, &frameAddr, 4);
        std::memcpy(state.data() + 0x18, &last, 4);
        std::memcpy(state.data() + 0x1C, &stackAddr, 4);
        std::memcpy(state.data() + 0x30, &table, 4);
        std::memcpy(state.data() + 0x34, &kGlobalsWord, 4);
      }
      [[nodiscard]] u32 Classify(const u32 p) const
      {
        const u32 stackAddr = Addr(stack, 0);
        if (p == 0u) {
          return 0u;
        }
        if (p >= stackAddr && p < stackAddr + kLuaStackSlots * 8u) {
          return 0x100u + (p - stackAddr) / 8u;
        }
        if (p == Addr(global, 0x30)) {
          return 0x200u;
        }
        if (p == Addr(state, 0x30)) {
          return 0x201u;
        }
        if (p >= Addr(closure, 0x38) && p < Addr(closure, closure.size())) {
          return 0x300u + (p - Addr(closure, 0x38)) / 8u;
        }
        return registry.Slot(p);
      }
      [[nodiscard]] u32 TopSlot() const
      {
        u32 top = 0;
        std::memcpy(&top, state.data() + 0x08, 4);
        return Classify(top);
      }
      // Stack slot `index` set to a key of the registry table (a string key's
      // bits are its pool index).
      void SetSlot(const u32 index, const u32 tt, const u32 bits)
      {
        const u32 word = tt == kLuaString ? registry.Addr(registry.strings, bits * 0x20u) : bits;
        std::memcpy(stack.data() + index * 8, &tt, 4);
        std::memcpy(stack.data() + index * 8 + 4, &word, 4);
      }
      // Every value word of the registry table, nodes then array.
      [[nodiscard]] std::vector<u32> TableValues() const
      {
        std::vector<u32> v((tableDesc.keyTt.size() + tableDesc.sizearray) * 2u);
        for (std::size_t i = 0; i < tableDesc.keyTt.size(); ++i) {
          std::memcpy(&v[i * 2u], registry.nodes.data() + i * 0x14 + 0x08, 8);
        }
        for (u32 i = 0; i < tableDesc.sizearray; ++i) {
          std::memcpy(&v[(tableDesc.keyTt.size() + i) * 2u], registry.array.data() + i * 8, 8);
        }
        return v;
      }
      // The pushed or written slot's tt and value word, a string as its pool
      // index and the registry table as a constant.
      void Value(const u32 index, u32* out) const
      {
        std::memcpy(&out[0], stack.data() + index * 8, 4);
        std::memcpy(&out[1], stack.data() + index * 8 + 4, 4);
        if (out[0] == kLuaString) {
          out[1] = (out[1] - registry.Addr(registry.strings, 0)) / 0x20u;
        } else if (out[0] == kLuaTable && out[1] == registry.Addr(registry.table, 0)) {
          out[1] = 0xAAAA0001u;
        }
      }
    };
    void LuaIndexAnyRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = s.Classify(retail::LuaAIndex(s.state.data(), static_cast<int>(in[9])));
    }
    void LuaNegIndexRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = s.Classify(retail::LuaNegIndex(s.state.data(), static_cast<int>(in[9])));
    }
    void LuaTypeRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = retail::LuaType(s.state.data(), static_cast<int>(in[9]));
    }
    void LuaGetTopRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = retail::LuaGetTop(s.state.data());
    }
    void LuaSetTopRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      retail::LuaSetTop(s.state.data(), static_cast<int>(in[9]));
      out[0] = s.TopSlot();
      for (u32 i = 0; i < 8; ++i) {
        std::memcpy(&out[1 + i], s.stack.data() + (in[6] + in[7] + i) % kLuaStackSlots * 8, 4);
      }
    }
    void LuaPushValueRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      u32 top = 0;
      std::memcpy(&top, s.state.data() + 0x08, 4);
      retail::LuaPushValue(s.state.data(), static_cast<int>(in[9]));
      out[0] = s.TopSlot();
      const std::uint8_t* const pushed = s.stack.data() + (top - RetailLuaStack::Addr(s.stack, 0));
      std::memcpy(&out[1], pushed, 4);
      std::memcpy(&out[2], pushed + 4, 4);
      if (out[1] == kLuaTable && out[2] == s.registry.Addr(s.registry.table, 0)) {
        out[2] = 0xAAAA0001u; // the registry table itself
      }
    }

    // luaT_gettm 0x00928420 (211 million calls): luaH_getstr on the
    // metatable; a nil value sets bit `event` in flags with an 8-bit shl
    // (0x0092843E: events 8..31 set nothing) and returns null, else the slot.
    // Events stay in 0..31, where ours' int shift is defined; flags start
    // from any byte, so the OR shows.
    // in = seed sizearray lsizenode fill pool event key flags; out = slot flags.
    void GenLuaGetTm(Rng& rng, u32* in)
    {
      GenLuaTableBase(rng, in);
      in[5] = rng.Chance(80) ? rng.Below(16) : rng.Below(32);
      in[6] = rng.Below(in[4] + 1u);
      in[7] = rng.Chance(30) ? 0u : rng.Below(256);
    }
    void LuaGetTmRetail(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      RetailLuaTable t(d);
      t.table[0x08] = static_cast<std::uint8_t>(in[7]);
      const u32 slot = retail::LuaTGetTm(t.table.data(), static_cast<int>(in[5]), t.strings.data() + in[6] * 0x20u);
      out[0] = slot == 0u ? 0xEEEE0000u : t.Slot(slot);
      out[1] = t.table[0x08];
    }

    // lua_tonumber 0x0090C9F0 (119 million calls): 0 past top or on a null
    // slot (0x0090CA0B), a number's float, else luaV_tonumber (0x00929150),
    // which parses strings with the image's own CRT; the stack holds no
    // strings, so it returns 0 here. Returned in st0 (0x0090CA39).
    // lua_rawgeti 0x0090D0A0 (97M): luaH_getnum on the table at idx, pushed;
    // idx is always the registry, the one table. lua_pushnumber 0x0090CD40
    // (80M): the float pushed (movss, 0x0090CD4E). lua_next 0x0090D6D0 (78M):
    // luaH_next with the key at top - 1, then push (more) or pop (done); the
    // key slot holds a key the registry holds, or nil.
    // in = the stack words, then idx | key | number bits | keyTt keyBits.
    void GenLuaToNumber(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = GenLuaStackIndex(rng, in, true, false);
    }
    void GenLuaRawGetI(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = static_cast<u32>(-10000);
      const u32 mode = rng.Below(100);
      in[10] = mode < 50 ? rng.Below(in[1] + 2u) : (mode < 85 ? static_cast<u32>(static_cast<int>(rng.Below(3u * (1u << in[2]) + 8u)) - 4) : rng.U32());
    }
    void GenLuaPushNumber(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = Bits(GenFloat(rng));
    }
    void GenLuaNext(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[7] = in[7] > 0u ? in[7] : 1u; // the key slot sits at top - 1
      in[9] = static_cast<u32>(-10000);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      PickPresentKey(rng, d, in + 10);
    }
    void LuaToNumberRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = Bits(retail::LuaToNumber(s.state.data(), static_cast<int>(in[9])));
    }
    void LuaRawGetIRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      retail::LuaRawGetI(s.state.data(), static_cast<int>(in[9]), static_cast<int>(in[10]));
      out[0] = s.TopSlot();
      s.Value(in[6] + in[7], out + 1);
    }
    void LuaPushNumberRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      retail::LuaPushNumber(s.state.data(), F(in, 9));
      out[0] = s.TopSlot();
      s.Value(in[6] + in[7], out + 1);
    }
    // luaV_gettable 0x009293E0 (228 million calls) and luaV_index 0x00929BF0
    // (286M) on the registry table as t: luaH_get, and on a nil result
    // luaV_index, which reads t's metatable unchecked (0x00929BF9), returns
    // nil when its flags bit 0 is set (0x00929BFC) and otherwise looks up
    // G->tmname[0] (+0x5C) with luaT_gettm (0x00929C10). A found handler is
    // called or chained through the state, so t is its own metatable and
    // tmname[0] is a name t lacks or holds with a nil value: every fallback
    // ends in nil, by the cached bit or by a miss that sets it. Any key
    // (nil and NaN resolve to nil through luaH_getany).
    // in = the stack words, then keyTt keyBits flags loop tmname0; out = slot
    // flags.
    void GenLuaGetTable(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      const u32 mode = rng.Below(100);
      if (mode < 60) {
        PickPresentKey(rng, d, in + 9);
      } else if (mode < 75) {
        in[9] = kLuaString;
        in[10] = in[4]; // the pool string that is never a key
      } else {
        in[9] = kLuaNumber;
        in[10] = rng.Chance(80) ? LuaNumberKeyBits(rng, in[1], 1u << in[2]) : Bits(GenFloat(rng));
      }
      in[11] = rng.Chance(40) ? 0u : rng.Below(256);
      in[12] = rng.Below(101);
      std::vector<u32> names(1, in[4]);
      for (u32 k = 0; k < in[4]; ++k) {
        bool live = false;
        for (u32 i = 0; i < d.keyTt.size(); ++i) {
          live = live || (d.keyTt[i] == kLuaString && d.keyBits[i] == k && d.valueNil[i] == 0u);
        }
        if (!live) {
          names.push_back(k); // absent, or held with a nil value
        }
      }
      in[13] = names[rng.Below(static_cast<u32>(names.size()))];
    }
    template <bool Index>
    void LuaGetTableRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      const u32 tableAddr = s.registry.Addr(s.registry.table, 0);
      std::memcpy(s.registry.table.data() + 0x0C, &tableAddr, 4); // its own metatable
      s.registry.table[0x08] = static_cast<std::uint8_t>(in[11]);
      const u32 name = s.registry.Addr(s.registry.strings, in[13] * 0x20u);
      std::memcpy(s.global.data() + 0x5C, &name, 4);
      const u32 key[2] = {in[9], in[9] == kLuaString ? s.registry.Addr(s.registry.strings, in[10] * 0x20u) : in[10]};
      const u32 t[2] = {kLuaTable, tableAddr};
      const u32 slot = Index ? retail::LuaVIndex(s.state.data(), t, key, static_cast<int>(in[12]))
                             : retail::LuaVGetTable(s.state.data(), t, key, static_cast<int>(in[12]));
      out[0] = s.registry.Slot(slot);
      out[1] = s.registry.table[0x08];
    }
    // luaV_settable 0x00929450 jumps to FAF's replacement body at 0x0128C4F4:
    // luaH_set (which clears flags), store when the slot is non-nil, else the
    // metatable read unchecked, store when its flags bit 1 is set, else
    // luaT_gettm on G->tmname[1] (+0x60, 0x0128C538) and store on a miss. A
    // found handler is called or chained through the state, so as for the
    // reads t is its own metatable, tmname[1] a name it lacks or holds with
    // a nil value, and the key one t holds (luaH_set never allocates).
    // in = the stack words, then keyTt keyBits valTt valBits tmname1; out =
    // flags, the slot that changed (none 0xFFFFFFFF), FNV-1a of every value.
    void GenLuaSetTable(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      for (int tries = 0; tries < 8 && (tries == 0 || in[9] == kLuaNil); ++tries) {
        PickPresentKey(rng, d, in + 9);
      }
      if (in[9] == kLuaNil) {
        in[1] = in[1] > 0u ? in[1] : 1u; // array slot 1 is always held
        in[9] = kLuaNumber;
        in[10] = Bits(1.0f);
        BuildLuaTable(in, d);
      }
      in[11] = rng.Below(4);
      in[12] = in[11] == kLuaNumber ? Bits(static_cast<float>(static_cast<int>(rng.Below(200)) - 100) * 0.25f) : rng.Below(1000);
      std::vector<u32> names(1, in[4]);
      for (u32 k = 0; k < in[4]; ++k) {
        bool live = false;
        for (u32 i = 0; i < d.keyTt.size(); ++i) {
          live = live || (d.keyTt[i] == kLuaString && d.keyBits[i] == k && d.valueNil[i] == 0u);
        }
        if (!live) {
          names.push_back(k);
        }
      }
      in[13] = names[rng.Below(static_cast<u32>(names.size()))];
    }
    // Every value word of a table in node then array order: the changed
    // slot's code and an FNV-1a fold.
    void LuaTableValueDiff(const std::vector<u32>& before, const std::vector<u32>& after, const u32 nodes, u32* out)
    {
      out[0] = 0xFFFFFFFFu;
      u32 hash = 0x811C9DC5u;
      for (std::size_t i = 0; i < after.size(); ++i) {
        hash = (hash ^ after[i]) * 0x01000193u;
        if (out[0] == 0xFFFFFFFFu && before[i] != after[i]) {
          const u32 slot = static_cast<u32>(i / 2u);
          out[0] = slot < nodes ? slot : 0x10000u + (slot - nodes);
        }
      }
      out[1] = hash;
    }
    void LuaSetTableRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      const u32 tableAddr = s.registry.Addr(s.registry.table, 0);
      std::memcpy(s.registry.table.data() + 0x0C, &tableAddr, 4); // its own metatable
      const u32 name = s.registry.Addr(s.registry.strings, in[13] * 0x20u);
      std::memcpy(s.global.data() + 0x60, &name, 4);
      const u32 nodes = static_cast<u32>(s.tableDesc.keyTt.size());
      const auto values = [&s, nodes]() {
        std::vector<u32> v;
        for (u32 i = 0; i < nodes; ++i) {
          v.push_back(0u);
          v.push_back(0u);
          std::memcpy(&v[v.size() - 2], s.registry.nodes.data() + i * 0x14 + 0x08, 8);
        }
        for (u32 i = 0; i < s.tableDesc.sizearray; ++i) {
          v.push_back(0u);
          v.push_back(0u);
          std::memcpy(&v[v.size() - 2], s.registry.array.data() + i * 8, 8);
        }
        return v;
      };
      const std::vector<u32> before = values();
      u32 key[2] = {in[9], in[9] == kLuaString ? s.registry.Addr(s.registry.strings, in[10] * 0x20u) : in[10]};
      u32 val[2] = {in[11], in[12]};
      const u32 t[2] = {kLuaTable, tableAddr};
      retail::LuaVSetTable(s.state.data(), t, key, val);
      out[0] = s.registry.table[0x08];
      LuaTableValueDiff(before, values(), nodes, out + 1);
    }

    // lua_toboolean 0x0090CA40 (49 million calls): 0 past top, on a null
    // slot, nil or false (0x0090CA6F..0x0090CA7C), else 1. lua_isnumber
    // 0x0090C7A0 (28M): a number, or luaV_tonumber (no strings here, so 0).
    // lua_pushnil 0x0090CD00 (27M) writes only the tag (0x0090CD08);
    // lua_pushboolean 0x0090CF80 (15M) pushes b != 0. lua_rawget 0x0090D050
    // (42M) replaces the key at top - 1 with luaH_get on the registry (any
    // key). lua_rawseti 0x0090D2F0 (46M) stores top - 1 at luaH_setnum and
    // pops one; lua_rawset 0x0090D2A0 (8M) stores top - 1 at luaH_set with
    // the key at top - 2 and pops two: held keys only (a missing one
    // allocates through the state).
    // in = the stack words, then idx | b | key words.
    void GenLuaPushBoolean(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[9] = rng.Chance(50) ? rng.Below(2) : rng.U32();
    }
    void GenLuaRawGet(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[7] = in[7] > 0u ? in[7] : 1u;
      in[9] = static_cast<u32>(-10000);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      if (rng.Chance(70)) {
        PickPresentKey(rng, d, in + 10);
      } else {
        in[10] = rng.Below(5);
        in[11] = in[10] == kLuaString ? in[4] : (in[10] == kLuaNumber ? Bits(GenFloat(rng)) : rng.Below(1000));
      }
    }
    void GenLuaRawSetI(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[7] = in[7] > 0u ? in[7] : 1u;
      in[9] = static_cast<u32>(-10000);
      u32 setnum[6] = {in[0], in[1], in[2], in[3], in[4], 0u};
      GenLuaSetNumKey(rng, setnum);
      in[1] = setnum[1];
      in[10] = setnum[5];
    }
    void GenLuaRawSet(Rng& rng, u32* in)
    {
      GenLuaStackBase(rng, in);
      in[7] = in[7] > 1u ? in[7] : 2u;
      in[9] = static_cast<u32>(-10000);
      LuaTableDesc d;
      BuildLuaTable(in, d);
      for (int tries = 0; tries < 8 && (tries == 0 || in[10] == kLuaNil); ++tries) {
        PickPresentKey(rng, d, in + 10);
      }
      if (in[10] == kLuaNil) {
        in[1] = in[1] > 0u ? in[1] : 1u;
        in[10] = kLuaNumber;
        in[11] = Bits(1.0f);
      }
    }
    void LuaToBooleanRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = retail::LuaToBoolean(s.state.data(), static_cast<int>(in[9]));
    }
    void LuaIsNumberRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      out[0] = retail::LuaIsNumber(s.state.data(), static_cast<int>(in[9]));
    }
    void LuaPushNilRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      retail::LuaPushNil(s.state.data());
      out[0] = s.TopSlot();
      s.Value(in[6] + in[7], out + 1);
    }
    void LuaPushBooleanRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      retail::LuaPushBoolean(s.state.data(), static_cast<int>(in[9]));
      out[0] = s.TopSlot();
      s.Value(in[6] + in[7], out + 1);
    }
    void LuaRawGetRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      s.SetSlot(in[6] + in[7] - 1u, in[10], in[11]);
      retail::LuaRawGet(s.state.data(), static_cast<int>(in[9]));
      out[0] = s.TopSlot();
      s.Value(in[6] + in[7] - 1u, out + 1);
    }
    void LuaRawSetIRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      const std::vector<u32> before = s.TableValues();
      retail::LuaRawSetI(s.state.data(), static_cast<int>(in[9]), static_cast<int>(in[10]));
      out[0] = s.TopSlot();
      out[1] = s.registry.table[0x08];
      LuaTableValueDiff(before, s.TableValues(), static_cast<u32>(s.tableDesc.keyTt.size()), out + 2);
    }
    void LuaRawSetRetail(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      s.SetSlot(in[6] + in[7] - 2u, in[10], in[11]);
      const std::vector<u32> before = s.TableValues();
      retail::LuaRawSet(s.state.data(), static_cast<int>(in[9]));
      out[0] = s.TopSlot();
      out[1] = s.registry.table[0x08];
      LuaTableValueDiff(before, s.TableValues(), static_cast<u32>(s.tableDesc.keyTt.size()), out + 2);
    }
    void LuaNextRetail2(const u32* in, u32* out)
    {
      RetailLuaStack s(in);
      s.SetSlot(in[6] + in[7] - 1u, in[10], in[11]);
      out[0] = retail::LuaNextApi(s.state.data(), static_cast<int>(in[9]));
      out[1] = s.TopSlot();
      s.Value(in[6] + in[7] - 1u, out + 2);
      s.Value(in[6] + in[7], out + 4);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    /// Lua values hold 32-bit pointers on x64, so what they point at comes from the Lua range there.
    template <class T>
    struct LuaFixtureAllocator
    {
      using value_type = T;
      LuaFixtureAllocator() = default;
      template <class U>
      LuaFixtureAllocator(const LuaFixtureAllocator<U>&) noexcept
      {
      }
      [[nodiscard]] T* allocate(const std::size_t count)
      {
#if INTPTR_MAX == INT32_MAX
        return std::allocator<T>{}.allocate(count);
#else
        return static_cast<T*>(lua::ArenaAllocate(count * sizeof(T)));
#endif
      }
      void deallocate(T* const block, const std::size_t count) noexcept
      {
#if INTPTR_MAX == INT32_MAX
        std::allocator<T>{}.deallocate(block, count);
#else
        (void)count;
        lua::ArenaFree(block);
#endif
      }
      template <class U>
      bool operator==(const LuaFixtureAllocator<U>&) const noexcept
      {
        return true;
      }
    };
    template <class T>
    using LuaFixtureVector = std::vector<T, LuaFixtureAllocator<T>>;
    using LuaFixtureStore = LuaFixtureVector<std::uint64_t>;

    struct OursLuaTable
    {
      LuaFixtureStore tableStore;
      LuaFixtureVector<Node> nodes;
      LuaFixtureVector<LuaPlus::TObject> array;
      std::vector<LuaFixtureStore> strings;
      Table* table = nullptr;

      explicit OursLuaTable(const LuaTableDesc& d)
        : tableStore(sizeof(Table) / sizeof(std::uint64_t) + 1u)
        , nodes(d.keyTt.size())
        , array(d.sizearray + 1u)
      {
        for (std::size_t i = 0; i < d.poolHash.size(); ++i) {
          strings.emplace_back(sizeof(TString) / sizeof(std::uint64_t) + 1u);
          String(i)->tt = static_cast<lu_byte>(kLuaString);
          String(i)->hash = d.poolHash[i];
        }
        for (std::size_t i = 0; i < d.keyTt.size(); ++i) {
          Node& n = nodes[i];
          n.i_key.tt = static_cast<int>(d.keyTt[i]);
          if (d.keyTt[i] == kLuaString) {
            n.i_key.value.p = String(d.keyBits[i]);
          } else if (d.keyTt[i] == kLuaLightUserdata) {
            n.i_key.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(d.keyBits[i]));
          } else {
            n.i_key.value.b = static_cast<int>(d.keyBits[i]);
          }
          n.i_val = d.valueNil[i] != 0u ? LuaPlus::TObject() : LuaPlus::TObject(static_cast<float>(i));
          n.SetNext(d.next[i] == kNoNode ? nullptr : &nodes[d.next[i]]);
        }
        for (u32 i = 0; i < d.sizearray; ++i) {
          array[i] = d.arrayNil[i] != 0u ? LuaPlus::TObject() : LuaPlus::TObject(static_cast<float>(i));
        }
        table = reinterpret_cast<Table*>(tableStore.data());
        table->tt = 5; // LUA_TTABLE
        table->flags = -1;
        table->lsizenode = static_cast<lu_byte>(d.lsizenode);
        table->array = array.data();
        table->node = nodes.data();
        table->sizearray = static_cast<int>(d.sizearray);
      }
      [[nodiscard]] TString* String(const std::size_t i)
      {
        return reinterpret_cast<TString*>(strings[i].data());
      }
      [[nodiscard]] u32 Slot(const LuaPlus::TObject* const result) const
      {
        if (result == &luaO_nilobject) {
          return 0xFFFFFFFFu;
        }
        // The array first: its buffer can sit right after the nodes', where
        // `result - offsetof(Node, i_val)` would land inside the last node.
        if (result >= array.data() && result < array.data() + array.size()) {
          return 0x10000u + static_cast<u32>(result - array.data());
        }
        const auto* const asNode = reinterpret_cast<const std::uint8_t*>(result) - offsetof(Node, i_val);
        return static_cast<u32>((asNode - reinterpret_cast<const std::uint8_t*>(nodes.data())) / sizeof(Node));
      }
    };
    void LuaGetStrOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      out[0] = t.Slot(luaH_getstr(t.table, t.String(in[5])));
    }
    void LuaGetNumOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      out[0] = t.Slot(luaH_getnum(t.table, static_cast<int>(in[5])));
    }
    void LuaGetOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      LuaPlus::TObject key;
      key.tt = static_cast<int>(in[5]);
      if (in[5] == kLuaString) {
        key.value.p = t.String(in[6]);
      } else if (in[5] == kLuaLightUserdata) {
        key.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[6]));
      } else {
        key.value.b = static_cast<int>(in[6]);
      }
      out[0] = t.Slot(luaH_get(t.table, &key));
    }
    void LuaMainPositionOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      LuaPlus::TObject key;
      key.tt = static_cast<int>(in[5]);
      if (in[5] == kLuaString) {
        key.value.p = t.String(in[6]);
      } else if (in[5] == kLuaBoolean || in[5] == kLuaNumber) {
        key.value.b = static_cast<int>(in[6]);
      } else {
        key.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[6]));
      }
      out[0] = static_cast<u32>(luaH_mainposition(t.table, &key) - t.nodes.data());
    }
    void LuaEqualValOurs(const u32* in, u32* out)
    {
      LuaPlus::TObject left;
      LuaPlus::TObject right;
      left.tt = right.tt = static_cast<int>(in[0]);
      left.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[1]));
      right.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[2]));
      out[0] = static_cast<u32>(luaV_equalval(nullptr, &left, &right));
    }
    void LuaLessThanOurs(const u32* in, u32* out)
    {
      LuaPlus::TObject left;
      LuaPlus::TObject right;
      left.tt = static_cast<int>(in[0]);
      right.tt = static_cast<int>(in[1]);
      left.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[2]));
      right.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[3]));
      out[0] = static_cast<u32>(luaV_lessthan(nullptr, &left, &right));
    }
    void SetLuaKey(OursLuaTable& t, const u32 tt, const u32 bits, LuaPlus::TObject& key)
    {
      key.tt = static_cast<int>(tt);
      if (tt == kLuaString) {
        key.value.p = t.String(bits);
      } else {
        key.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(bits));
      }
    }
    void LuaIndexOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      LuaPlus::TObject key;
      SetLuaKey(t, in[5], in[6], key);
      out[0] = static_cast<u32>(luaH_index(nullptr, t.table, &key));
    }
    void LuaNextOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      LuaPlus::TObject key[2];
      SetLuaKey(t, in[5], in[6], key[0]);
      out[0] = static_cast<u32>(luaH_next(nullptr, t.table, key));
      const auto word = [](const LuaPlus::TObject& o) {
        return LuaPlus::ValuePointerBits(o.value);
      };
      out[1] = static_cast<u32>(key[0].tt);
      out[2] = word(key[0]);
      if (key[0].tt == static_cast<int>(kLuaString)) {
        for (std::size_t i = 0; i < t.strings.size(); ++i) {
          if (key[0].value.p == t.String(i)) {
            out[2] = static_cast<u32>(i);
          }
        }
      }
      out[3] = static_cast<u32>(key[1].tt);
      out[4] = word(key[1]);
    }
    void LuaSetOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      LuaPlus::TObject key;
      SetLuaKey(t, in[5], in[6], key);
      out[0] = t.Slot(luaH_set(nullptr, t.table, &key));
      out[1] = static_cast<std::uint8_t>(t.table->flags);
    }
    void LuaSetNumOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      out[0] = t.Slot(luaH_setnum(nullptr, t.table, static_cast<int>(in[5])));
      out[1] = static_cast<std::uint8_t>(t.table->flags);
    }

    struct OursLuaStack
    {
      LuaTableDesc tableDesc;
      OursLuaTable registry;
      LuaFixtureStore stateStore, globalStore, frameStore, closureStore;
      std::vector<LuaPlus::TObject> stack;
      lua_State* state = nullptr;
      global_State* global = nullptr;
      CClosure* closure = nullptr;

      [[nodiscard]] static LuaTableDesc Table(const u32* in)
      {
        LuaTableDesc d;
        BuildLuaTable(in, d);
        return d;
      }
      [[nodiscard]] static std::size_t Blocks(const std::size_t bytes)
      {
        return bytes / sizeof(std::uint64_t) + 1u;
      }
      static void Set(LuaPlus::TObject& o, const u32 tt, const u32 bits)
      {
        o.tt = static_cast<int>(tt);
        o.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(bits));
      }
      explicit OursLuaStack(const u32* in)
        : tableDesc(Table(in))
        , registry(tableDesc)
        , stateStore(Blocks(sizeof(lua_State)))
        , globalStore(Blocks(sizeof(global_State)))
        , frameStore(Blocks(sizeof(CallInfo)))
        , closureStore(Blocks(sizeof(CClosure) + 8 * sizeof(LuaPlus::TObject)))
        , stack(kLuaStackSlots)
      {
        LuaStackDesc s;
        BuildLuaStack(in, s);
        for (u32 i = 0; i < kLuaStackSlots; ++i) {
          Set(stack[i], s.slotTt[i], s.slotBits[i]);
        }
        closure = reinterpret_cast<CClosure*>(closureStore.data());
        closure->tt = static_cast<lu_byte>(kLuaFunction);
        closure->nupvalues = static_cast<lu_byte>(s.upvalues);
        closure->isC = 1;
        for (u32 k = 0; k < 8; ++k) {
          Set(closure->upvalue_m1[k + 1u], s.upTt[k], s.upBits[k]);
        }
        stack[s.base - 1u].tt = static_cast<int>(kLuaFunction);
        stack[s.base - 1u].value.p = closure;
        global = reinterpret_cast<global_State*>(globalStore.data());
        global->_registry.tt = static_cast<int>(kLuaTable);
        global->_registry.value.p = registry.table;
        auto* const frame = reinterpret_cast<CallInfo*>(frameStore.data());
        frame->top = reinterpret_cast<LuaPlus::TObject*>(
          reinterpret_cast<std::uintptr_t>(stack.data()) + (kLuaStackSlots + 64u) * sizeof(LuaPlus::TObject)
        );
        state = reinterpret_cast<lua_State*>(stateStore.data());
        state->tt = 8; // LUA_TTHREAD
        state->top = stack.data() + s.base + s.top;
        state->base = stack.data() + s.base;
        state->l_G = global;
        state->ci = frame;
        state->stack_last = stack.data() + (kLuaStackSlots - 1u);
        state->stack = stack.data();
        Set(state->_gt, kLuaTable, kGlobalsWord);
      }
      [[nodiscard]] u32 Classify(const LuaPlus::TObject* const p) const
      {
        if (p == nullptr) {
          return 0u;
        }
        if (p >= stack.data() && p < stack.data() + kLuaStackSlots) {
          return 0x100u + static_cast<u32>(p - stack.data());
        }
        if (p == &global->_registry) {
          return 0x200u;
        }
        if (p == &state->_gt) {
          return 0x201u;
        }
        if (p >= &closure->upvalue_m1[0] && p <= &closure->upvalue_m1[8]) {
          return 0x300u + static_cast<u32>(p - &closure->upvalue_m1[0]);
        }
        return registry.Slot(p);
      }
      void SetSlot(const u32 index, const u32 tt, const u32 bits)
      {
        stack[index].tt = static_cast<int>(tt);
        stack[index].value.p = tt == kLuaString ? static_cast<void*>(registry.String(bits))
                                                : reinterpret_cast<void*>(static_cast<std::uintptr_t>(bits));
      }
      [[nodiscard]] std::vector<u32> TableValues() const
      {
        std::vector<u32> v;
        const auto push = [&v](const LuaPlus::TObject& o) {
          v.push_back(static_cast<u32>(o.tt));
          v.push_back(LuaPlus::ValuePointerBits(o.value));
        };
        for (const Node& n : registry.nodes) {
          push(n.i_val);
        }
        for (u32 i = 0; i < tableDesc.sizearray; ++i) {
          push(registry.array[i]);
        }
        return v;
      }
      void Value(const u32 index, u32* out)
      {
        const LuaPlus::TObject& o = stack[index];
        out[0] = static_cast<u32>(o.tt);
        out[1] = LuaPlus::ValuePointerBits(o.value);
        if (o.tt == static_cast<int>(kLuaString)) {
          for (std::size_t i = 0; i < registry.strings.size(); ++i) {
            if (o.value.p == registry.String(i)) {
              out[1] = static_cast<u32>(i);
            }
          }
        } else if (o.tt == static_cast<int>(kLuaTable) && o.value.p == registry.table) {
          out[1] = 0xAAAA0001u;
        }
      }
    };
    void LuaGetTmOurs(const u32* in, u32* out)
    {
      LuaTableDesc d;
      BuildLuaTable(in, d);
      OursLuaTable t(d);
      t.table->flags = static_cast<std::int8_t>(in[7]);
      const LuaPlus::TObject* const slot = luaT_gettm(t.table, static_cast<int>(in[5]), t.String(in[6]));
      out[0] = slot == nullptr ? 0xEEEE0000u : t.Slot(slot);
      out[1] = static_cast<std::uint8_t>(t.table->flags);
    }
    void LuaToNumberOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = Bits(lua_tonumber(s.state, static_cast<int>(in[9])));
    }
    void LuaRawGetIOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      lua_rawgeti(s.state, static_cast<int>(in[9]), static_cast<int>(in[10]));
      out[0] = s.Classify(s.state->top);
      s.Value(in[6] + in[7], out + 1);
    }
    void LuaPushNumberOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      lua_pushnumber(s.state, F(in, 9));
      out[0] = s.Classify(s.state->top);
      s.Value(in[6] + in[7], out + 1);
    }
    template <bool Index>
    void LuaGetTableOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      Table* const table = s.registry.table;
      table->metatable = table; // its own metatable
      table->flags = static_cast<std::int8_t>(in[11]);
      s.global->tmname[0] = s.registry.String(in[13]);
      LuaPlus::TObject key;
      key.tt = static_cast<int>(in[9]);
      key.value.p = in[9] == kLuaString ? static_cast<void*>(s.registry.String(in[10]))
                                        : reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[10]));
      LuaPlus::TObject t;
      t.tt = static_cast<int>(kLuaTable);
      t.value.p = table;
      const LuaPlus::TObject* const slot = Index ? luaV_index(s.state, &t, &key, static_cast<int>(in[12]))
                                                 : luaV_gettable(s.state, &t, &key, static_cast<int>(in[12]));
      out[0] = s.registry.Slot(slot);
      out[1] = static_cast<std::uint8_t>(table->flags);
    }
    void LuaSetTableOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      Table* const table = s.registry.table;
      table->metatable = table; // its own metatable
      s.global->tmname[1] = s.registry.String(in[13]);
      const auto word = [](const LuaPlus::TObject& o) {
        return LuaPlus::ValuePointerBits(o.value);
      };
      const auto values = [&s, &word]() {
        std::vector<u32> v;
        for (const Node& n : s.registry.nodes) {
          v.push_back(static_cast<u32>(n.i_val.tt));
          v.push_back(word(n.i_val));
        }
        for (u32 i = 0; i < s.tableDesc.sizearray; ++i) {
          v.push_back(static_cast<u32>(s.registry.array[i].tt));
          v.push_back(word(s.registry.array[i]));
        }
        return v;
      };
      const std::vector<u32> before = values();
      LuaPlus::TObject key;
      key.tt = static_cast<int>(in[9]);
      key.value.p = in[9] == kLuaString ? static_cast<void*>(s.registry.String(in[10]))
                                        : reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[10]));
      LuaPlus::TObject val;
      val.tt = static_cast<int>(in[11]);
      val.value.p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(in[12]));
      LuaPlus::TObject t;
      t.tt = static_cast<int>(kLuaTable);
      t.value.p = table;
      luaV_settable(s.state, &t, &key, &val);
      out[0] = static_cast<std::uint8_t>(table->flags);
      LuaTableValueDiff(before, values(), static_cast<u32>(s.registry.nodes.size()), out + 1);
    }
    void LuaToBooleanOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = static_cast<u32>(lua_toboolean(s.state, static_cast<int>(in[9])));
    }
    void LuaIsNumberOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = static_cast<u32>(lua_isnumber(s.state, static_cast<int>(in[9])));
    }
    void LuaPushNilOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      lua_pushnil(s.state);
      out[0] = s.Classify(s.state->top);
      s.Value(in[6] + in[7], out + 1);
    }
    void LuaPushBooleanOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      lua_pushboolean(s.state, static_cast<int>(in[9]));
      out[0] = s.Classify(s.state->top);
      s.Value(in[6] + in[7], out + 1);
    }
    void LuaRawGetOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      s.SetSlot(in[6] + in[7] - 1u, in[10], in[11]);
      lua_rawget(s.state, static_cast<int>(in[9]));
      out[0] = s.Classify(s.state->top);
      s.Value(in[6] + in[7] - 1u, out + 1);
    }
    void LuaRawSetIOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      const std::vector<u32> before = s.TableValues();
      lua_rawseti(s.state, static_cast<int>(in[9]), static_cast<int>(in[10]));
      out[0] = s.Classify(s.state->top);
      out[1] = static_cast<std::uint8_t>(s.registry.table->flags);
      LuaTableValueDiff(before, s.TableValues(), static_cast<u32>(s.tableDesc.keyTt.size()), out + 2);
    }
    void LuaRawSetOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      s.SetSlot(in[6] + in[7] - 2u, in[10], in[11]);
      const std::vector<u32> before = s.TableValues();
      lua_rawset(s.state, static_cast<int>(in[9]));
      out[0] = s.Classify(s.state->top);
      out[1] = static_cast<std::uint8_t>(s.registry.table->flags);
      LuaTableValueDiff(before, s.TableValues(), static_cast<u32>(s.tableDesc.keyTt.size()), out + 2);
    }
    void LuaNextOurs2(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      s.SetSlot(in[6] + in[7] - 1u, in[10], in[11]);
      out[0] = static_cast<u32>(lua_next(s.state, static_cast<int>(in[9])));
      out[1] = s.Classify(s.state->top);
      s.Value(in[6] + in[7] - 1u, out + 2);
      s.Value(in[6] + in[7], out + 4);
    }
    void LuaIndexAnyOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = s.Classify(luaA_index(s.state, static_cast<int>(in[9])));
    }
    void LuaNegIndexOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = s.Classify(negindex(s.state, static_cast<int>(in[9])));
    }
    void LuaTypeOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = static_cast<u32>(lua_type(s.state, static_cast<int>(in[9])));
    }
    void LuaGetTopOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      out[0] = static_cast<u32>(lua_gettop(s.state));
    }
    void LuaSetTopOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      lua_settop(s.state, static_cast<int>(in[9]));
      out[0] = s.Classify(s.state->top);
      for (u32 i = 0; i < 8; ++i) {
        out[1 + i] = static_cast<u32>(s.stack[(in[6] + in[7] + i) % kLuaStackSlots].tt);
      }
    }
    void LuaPushValueOurs(const u32* in, u32* out)
    {
      OursLuaStack s(in);
      const LuaPlus::TObject* const top = s.state->top;
      lua_pushvalue(s.state, static_cast<int>(in[9]));
      out[0] = s.Classify(s.state->top);
      out[1] = static_cast<u32>(top->tt);
      out[2] = LuaPlus::ValuePointerBits(top->value);
      if (out[1] == kLuaTable && top->value.p == s.registry.table) {
        out[2] = 0xAAAA0001u; // the registry table itself
      }
    }
#endif

    // ---- grid walker (GridTraversalLine, COGrid.cpp, engine-only TU) ------------
    //
    // The cell walk under CHeightField::Intersection, the influence map's
    // line queries and the occupancy grid's line checks. The line is a 0x2C
    // plain struct: x0 z0 x1 z1 dx dz (floats), step xEdge zEdge xMask zMask
    // (ints). Coordinates are mostly map-sized with a power-of-two step, and
    // sometimes any float (NaN, infinite, huge) or any int in the edge words.
    constexpr int kLineWords = 11;

    [[nodiscard]] float GenLineCoord(Rng& rng)
    {
      if (rng.Chance(12)) {
        return GenFloat(rng);
      }
      return static_cast<float>(rng.Range(-64.0, 1100.0));
    }
    [[nodiscard]] u32 GenLineStep(Rng& rng)
    {
      if (rng.Chance(5)) {
        return rng.U32();
      }
      return 1u << rng.Below(7);
    }
    void GenLineStruct(Rng& rng, u32* line)
    {
      for (int i = 0; i < 6; ++i) {
        line[i] = Bits(GenLineCoord(rng));
      }
      const u32 step = GenLineStep(rng);
      line[6] = step;
      for (int i = 7; i < 9; ++i) {
        line[i] = rng.Chance(8) ? rng.U32() : (rng.Below(1200u) - 64u) & (0u - step);
      }
      for (int i = 9; i < 11; ++i) {
        line[i] = rng.Chance(50) ? 0u : 0u - step;
      }
    }

    // InitGridTraversalLine 0x0040D860: in = step, xEnd, xStart, zStart, zEnd;
    // out = the 11 words of the line.
    void GenLineInit(Rng& rng, u32* in)
    {
      in[0] = GenLineStep(rng);
      for (int i = 1; i < 5; ++i) {
        in[i] = Bits(GenLineCoord(rng));
      }
    }
    void LineInitRetail(const u32* in, u32* out)
    {
      u32 line[kLineWords];
      for (u32& w : line) {
        w = kCanary;
      }
      retail::GridLineInit(line, static_cast<int>(in[0]), F(in, 1), F(in, 2), F(in, 3), F(in, 4));
      std::memcpy(out, line, sizeof(line));
    }

    // AdvanceGridTraversalEdge 0x00475FD0: in = a line; out = the line after
    // one step. GetGridTraversalCell 0x00476050: out = x, z.
    // IsGridTraversalBeyondEnd 0x00476070: out = 0 or 1.
    void GenLine(Rng& rng, u32* in)
    {
      GenLineStruct(rng, in);
    }
    void LineAdvanceRetail(const u32* in, u32* out)
    {
      u32 line[kLineWords];
      std::memcpy(line, in, sizeof(line));
      retail::GridLineAdvance(line);
      std::memcpy(out, line, sizeof(line));
    }
    void LineCellRetail(const u32* in, u32* out)
    {
      u32 xz[2] = {kCanary, kCanary};
      retail::GridLineCell(in, xz);
      out[0] = xz[0];
      out[1] = xz[1];
    }
    void LineBeyondEndRetail(const u32* in, u32* out)
    {
      out[0] = static_cast<u32>(retail::GridLineBeyondEnd(in));
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void LineInitOurs(const u32* in, u32* out)
    {
      moho::GridTraversalLine line;
      u32 canary[kLineWords];
      for (u32& w : canary) {
        w = kCanary;
      }
      std::memcpy(&line, canary, sizeof(line));
      moho::InitGridTraversalLine(line, static_cast<std::int32_t>(in[0]), F(in, 1), F(in, 2), F(in, 3), F(in, 4));
      std::memcpy(out, &line, sizeof(line));
    }
    void LineAdvanceOurs(const u32* in, u32* out)
    {
      moho::GridTraversalLine line;
      std::memcpy(&line, in, sizeof(line));
      moho::AdvanceGridTraversalEdge(line);
      std::memcpy(out, &line, sizeof(line));
    }
    void LineCellOurs(const u32* in, u32* out)
    {
      moho::GridTraversalLine line;
      std::memcpy(&line, in, sizeof(line));
      std::int32_t x = 0;
      std::int32_t z = 0;
      moho::GetGridTraversalCell(line, x, z);
      out[0] = static_cast<u32>(x);
      out[1] = static_cast<u32>(z);
    }
    void LineBeyondEndOurs(const u32* in, u32* out)
    {
      moho::GridTraversalLine line;
      std::memcpy(&line, in, sizeof(line));
      out[0] = moho::IsGridTraversalBeyondEnd(line) ? 1u : 0u;
    }
    static_assert(sizeof(moho::GridTraversalLine) == kLineWords * 4);
#endif

    // ---- Lua table sizing (LuaObject.cpp, engine-only TU) ------------------------
    //
    // luaO_log2 0x0091A510 sizes the array and hash parts of every Lua table
    // the sim's scripts touch; luaO_int2fb 0x0091A4E0 packs a table size into a
    // byte for OP_NEWTABLE. in = x; out = the result. x is 0, 1, a power of two
    // or one off it, near the limits, small, or any word.
    [[nodiscard]] u32 GenSizeWord(Rng& rng)
    {
      const u32 mode = rng.Below(100);
      if (mode < 30) {
        const u32 shift = rng.Below(32);
        return (1u << shift) + rng.Below(3) - 1u;
      }
      if (mode < 45) {
        return rng.Below(64);
      }
      if (mode < 55) {
        return 0xFFFFFFFFu - rng.Below(4);
      }
      return rng.U32();
    }
    void GenLuaSize(Rng& rng, u32* in)
    {
      in[0] = GenSizeWord(rng);
    }
    void LuaLog2Retail(const u32* in, u32* out)
    {
      out[0] = retail::LuaLog2(in[0]);
    }
    void LuaInt2FbRetail(const u32* in, u32* out)
    {
      out[0] = retail::LuaInt2Fb(in[0]);
    }
#if defined(DIFFFUZZ_ENGINE_LINKED)
    void LuaLog2Ours(const u32* in, u32* out)
    {
      out[0] = static_cast<u32>(luaO_log2(in[0]));
    }
    void LuaInt2FbOurs(const u32* in, u32* out)
    {
      out[0] = luaO_int2fb(in[0]);
    }
#endif

    // ---- occupancy bit grids (gpg::BitArray2D) ----------------------------------
    //
    // COGrid's occupation and the build-site checks (func_LocationIsFree's
    // static path calls GetRectNeg) test footprints against one of these.
    // BitArray2D.cpp compiles standalone, so these rows compare in difffuzz
    // too. A grid of width x height bits keeps 32 rows of one column per word.
    // in = width, height, then fill ops of (x0, z0, w, h, fill).
    constexpr int kFillOps = 3;

    [[nodiscard]] int GenGridEdge(Rng& rng, const u32 size)
    {
      const u32 mode = rng.Below(100);
      if (mode < 85) {
        return static_cast<int>(rng.Below(size + 7u)) - 3;
      }
      if (mode < 92) {
        return static_cast<int>(rng.Below(size + 1u)) - static_cast<int>(size);
      }
      if (mode < 96) {
        return 0x7FFFFFFF - static_cast<int>(rng.Below(4));
      }
      return static_cast<int>(rng.U32());
    }
    [[nodiscard]] int GenGridExtent(Rng& rng, const u32 size)
    {
      const u32 mode = rng.Below(100);
      if (mode < 85) {
        return static_cast<int>(rng.Below(size / 2u + 4u)) - 1;
      }
      if (mode < 95) {
        return static_cast<int>(rng.Below(size + 3u));
      }
      return static_cast<int>(rng.U32());
    }
    /// in[0..1] = width, height (1..80; often 32k +- 1 rows, the word seams).
    void GenGrid(Rng& rng, u32* in)
    {
      const u32 mode = rng.Below(100);
      in[0] = 1u + rng.Below(80);
      if (mode < 30) {
        const u32 words = 1u + rng.Below(2);
        in[1] = 32u * words + rng.Below(3) - 1u;
      } else {
        in[1] = 1u + rng.Below(80);
      }
      for (int op = 0; op < kFillOps; ++op) {
        u32* const o = in + 2 + 5 * op;
        o[0] = static_cast<u32>(GenGridEdge(rng, in[0]));
        o[1] = static_cast<u32>(GenGridEdge(rng, in[1]));
        o[2] = static_cast<u32>(GenGridExtent(rng, in[0]));
        o[3] = static_cast<u32>(GenGridExtent(rng, in[1]));
        o[4] = rng.Chance(75) ? 1u : 0u;
      }
    }
    constexpr int kGridQuery = 2 + 5 * kFillOps;

    struct RetailBitArray
    {
      unsigned char bytes[16]; // ptr, size, width, height
    };
    void BuildRetailGrid(RetailBitArray& grid, const u32* in)
    {
      std::memset(grid.bytes, 0, sizeof(grid.bytes));
      retail::BitArrayConstruct(&grid, in[0], in[1]);
      for (int op = 0; op < kFillOps; ++op) {
        const u32* const o = in + 2 + 5 * op;
        retail::BitArrayFillRect(
          &grid, static_cast<int>(o[0]), static_cast<int>(o[1]), static_cast<int>(o[2]), static_cast<int>(o[3]),
          static_cast<int>(o[4])
        );
      }
    }
    void FreeRetailGrid(RetailBitArray& grid)
    {
      void* words;
      std::memcpy(&words, grid.bytes, 4);
      retail::OperatorDelete(words);
    }
    void BuildOurGrid(gpg::BitArray2D& grid, const u32* in)
    {
      for (int op = 0; op < kFillOps; ++op) {
        const u32* const o = in + 2 + 5 * op;
        grid.FillRect(static_cast<int>(o[0]), static_cast<int>(o[1]), static_cast<int>(o[2]), static_cast<int>(o[3]), o[4] != 0u);
      }
    }
    void HashGrid(const std::int32_t* words, const int size, u32* out)
    {
      Fnv hash;
      for (int i = 0; i < size; ++i) {
        hash.Add32(static_cast<u32>(words[i]));
      }
      out[0] = static_cast<u32>(size);
      out[1] = static_cast<u32>(hash.h);
      out[2] = static_cast<u32>(hash.h >> 32);
    }

    // BitArray2D::FillRect 0x008D8370 (constructor 0x008D82F0): out = word
    // count and a hash of the words after the fills.
    void FillRectRetail(const u32* in, u32* out)
    {
      RetailBitArray grid;
      BuildRetailGrid(grid, in);
      const std::int32_t* words;
      int size;
      std::memcpy(&words, grid.bytes, 4);
      std::memcpy(&size, grid.bytes + 4, 4);
      HashGrid(words, size, out);
      FreeRetailGrid(grid);
    }
    void FillRectOurs(const u32* in, u32* out)
    {
      gpg::BitArray2D grid(in[0], in[1]);
      BuildOurGrid(grid, in);
      HashGrid(grid.ptr, grid.size, out);
    }

    // BitArray2D::GetRectOr 0x008D8460: in += x0, z0, w, h, disallowNegative.
    void GenGetRectOr(Rng& rng, u32* in)
    {
      GenGrid(rng, in);
      in[kGridQuery + 0] = static_cast<u32>(GenGridEdge(rng, in[0]));
      in[kGridQuery + 1] = static_cast<u32>(GenGridEdge(rng, in[1]));
      in[kGridQuery + 2] = static_cast<u32>(GenGridExtent(rng, in[0]));
      in[kGridQuery + 3] = static_cast<u32>(GenGridExtent(rng, in[1]));
      in[kGridQuery + 4] = rng.Chance(50) ? 1u : 0u;
    }
    void GetRectOrRetail(const u32* in, u32* out)
    {
      RetailBitArray grid;
      BuildRetailGrid(grid, in);
      const u32* const q = in + kGridQuery;
      out[0] = static_cast<u32>(retail::BitArrayGetRectOr(
        &grid, static_cast<int>(q[0]), static_cast<int>(q[1]), static_cast<int>(q[2]), static_cast<int>(q[3]),
        static_cast<int>(q[4])
      ));
      FreeRetailGrid(grid);
    }
    void GetRectOrOurs(const u32* in, u32* out)
    {
      gpg::BitArray2D grid(in[0], in[1]);
      BuildOurGrid(grid, in);
      const u32* const q = in + kGridQuery;
      out[0] = grid.GetRectOr(static_cast<int>(q[0]), static_cast<int>(q[1]), static_cast<int>(q[2]), static_cast<int>(q[3]), q[4] != 0u) ? 1u : 0u;
    }

    // BitArray2D::GetRectNeg 0x00720580: in += a rect x0, z0, x1, z1 (x1/z1
    // exclusive), as the build-site check passes a footprint.
    void GenGetRectNeg(Rng& rng, u32* in)
    {
      GenGrid(rng, in);
      const int x0 = GenGridEdge(rng, in[0]);
      const int z0 = GenGridEdge(rng, in[1]);
      const int w = GenGridExtent(rng, in[0]);
      const int h = GenGridExtent(rng, in[1]);
      in[kGridQuery + 0] = static_cast<u32>(x0);
      in[kGridQuery + 1] = static_cast<u32>(z0);
      in[kGridQuery + 2] = static_cast<u32>(x0) + static_cast<u32>(w);
      in[kGridQuery + 3] = static_cast<u32>(z0) + static_cast<u32>(h);
    }
    void GetRectNegRetail(const u32* in, u32* out)
    {
      RetailBitArray grid;
      BuildRetailGrid(grid, in);
      out[0] = static_cast<u32>(retail::BitArrayGetRectNeg(&grid, in + kGridQuery));
      FreeRetailGrid(grid);
    }
    void GetRectNegOurs(const u32* in, u32* out)
    {
      gpg::BitArray2D grid(in[0], in[1]);
      BuildOurGrid(grid, in);
      gpg::Rect2i rect{};
      rect.x0 = static_cast<int>(in[kGridQuery + 0]);
      rect.z0 = static_cast<int>(in[kGridQuery + 1]);
      rect.x1 = static_cast<int>(in[kGridQuery + 2]);
      rect.z1 = static_cast<int>(in[kGridQuery + 3]);
      out[0] = grid.GetRectNeg(rect) ? 1u : 0u;
    }

    // New rows go at the end: a row's random stream comes from its index in
    // AllTargets (math rows first).
    const Target kSimTargets[] = {
      {"CHeightField::UpdateBounds", 0x00476BB0, "moho/sim/STIMap.cpp CHeightField::UpdateBounds", 10, 3, "cellsW cellsH seed shape seed2 shape2 x0 z0 x1 z1", "tiers hash[2]", GenUpdateBounds, UpdateBoundsRetail, ENGINE_ONLY(UpdateBoundsOurs), true},
      {"CHeightField::Intersection", 0x00476F30, "moho/sim/STIMap.cpp CHeightField::Intersection", 12, 5, "cellsW cellsH seed shape pos[3] dir[3] closest farthest", "point[3] distance v1", GenIntersection, IntersectionRetail, ENGINE_ONLY(IntersectionOurs)},
      {"CHeightField::GetNormal", 0x0069A620, "moho/sim/STIMap.cpp CHeightField::GetNormal", 6, 3, "cellsW cellsH seed shape x z", "normal[3]", GenNormal, NormalRetail, ENGINE_ONLY(NormalOurs)},
      {"BitArray2D::FillRect", 0x008D8370, "gpg/core/containers/BitArray2D.cpp BitArray2D::FillRect", kGridQuery, 3, "width height (x0 z0 w h fill)[3]", "size hash[2]", GenGrid, FillRectRetail, FillRectOurs, true},
      {"BitArray2D::GetRectOr", 0x008D8460, "gpg/core/containers/BitArray2D.cpp BitArray2D::GetRectOr", kGridQuery + 5, 1, "width height (x0 z0 w h fill)[3] x0 z0 w h disallowNegative", "ret", GenGetRectOr, GetRectOrRetail, GetRectOrOurs, true},
      {"BitArray2D::GetRectNeg", 0x00720580, "gpg/core/containers/BitArray2D.cpp BitArray2D::GetRectNeg", kGridQuery + 4, 1, "width height (x0 z0 w h fill)[3] x0 z0 x1 z1", "ret", GenGetRectNeg, GetRectNegRetail, GetRectNegOurs, true},
      // Appended: each row's stream is seeded by its index.
      {"CHeightField::ClipSegmentToWorld", 0x004776E0, "moho/sim/STIMap.cpp CHeightField::ClipSegmentToWorld", 12, 3, "cellsW cellsH seed shape pos[3] dir[3] min max", "ret min max", GenClip, ClipRetail, ENGINE_ONLY(ClipOurs)},
      {"CHeightField::GetTierBounds", 0x00475DA0, "moho/sim/STIMap.cpp CHeightField::GetTierBounds", 7, 2, "cellsW cellsH seed shape x z tier", "min max", GenTierBounds, TierBoundsRetail, ENGINE_ONLY(TierBoundsOurs)},
      {"InfluenceGrid::GetThreat", 0x00715750, "moho/sim/CInfluenceMap.cpp InfluenceGrid::GetThreat", 5, 1, "type army armies seed mode", "threat", GenGetThreat, GetThreatRetail, ENGINE_ONLY(GetThreatOurs)},
      {"InfluenceGrid::DecayInfluence", 0x00715130, "moho/sim/CInfluenceMap.cpp InfluenceGrid::DecayInfluence", 2, 14, "seed mode", "threat[14]", GenDecayInfluence, DecayInfluenceRetail, ENGINE_ONLY(DecayInfluenceOurs)},
      {"VEC_LookAt", 0x004ECBD0, "moho/math/MathReflection.cpp VEC_LookAt", 6, 9, "up[3] forward[3]", "axes[9]", GenLookAt, LookAtRetail, ENGINE_ONLY(LookAtOurs)},
      {"VEC_Mul4x3", 0x004EE710, "moho/math/MathReflection.cpp VEC_Mul4x3", 32, 16, "lhs[16] rhs[16]", "out[16]", GenMul4x3, Mul4x3Retail, ENGINE_ONLY(Mul4x3Ours)},
      {"luaO_log2", 0x0091A510, "lua/LuaObject.cpp luaO_log2", 1, 1, "x", "r", GenLuaSize, LuaLog2Retail, ENGINE_ONLY(LuaLog2Ours), true},
      {"luaO_int2fb", 0x0091A4E0, "lua/LuaObject.cpp luaO_int2fb", 1, 1, "x", "r", GenLuaSize, LuaInt2FbRetail, ENGINE_ONLY(LuaInt2FbOurs), true},
      {"InitGridTraversalLine", 0x0040D860, "moho/sim/COGrid.cpp InitGridTraversalLine", 5, kLineWords, "step xEnd xStart zStart zEnd", "line[11]", GenLineInit, LineInitRetail, ENGINE_ONLY(LineInitOurs)},
      {"AdvanceGridTraversalEdge", 0x00475FD0, "moho/sim/COGrid.cpp AdvanceGridTraversalEdge", kLineWords, kLineWords, "line[11]", "line[11]", GenLine, LineAdvanceRetail, ENGINE_ONLY(LineAdvanceOurs)},
      {"GetGridTraversalCell", 0x00476050, "moho/sim/COGrid.cpp GetGridTraversalCell", kLineWords, 2, "line[11]", "x z", GenLine, LineCellRetail, ENGINE_ONLY(LineCellOurs), true},
      {"IsGridTraversalBeyondEnd", 0x00476070, "moho/sim/COGrid.cpp IsGridTraversalBeyondEnd", kLineWords, 1, "line[11]", "beyond", GenLine, LineBeyondEndRetail, ENGINE_ONLY(LineBeyondEndOurs), true},
      {"STIMap::IsBlockingTerrain", 0x00577F20, "moho/sim/STIMap.cpp STIMap::IsBlockingTerrain", 5, 1, "cellsW cellsH seed x z", "blocking", GenBlocking, BlockingRetail, ENGINE_ONLY(BlockingOurs), true},
      {"STIMap::OccupancyCapsOfFootprintAt", 0x00564DF0, "moho/sim/STIMap.cpp STIMap::OccupancyCapsOfFootprintAt", 12, 1, "cellsW cellsH seed shape waterOn waterElev x z caps maxSlope minDepth maxDepth", "caps", GenOccupancyCaps, OccupancyCapsRetail, ENGINE_ONLY(OccupancyCapsOurs), true},
      {"OCCUPY_Filter", 0x00720920, "moho/sim/STIMap.cpp OCCUPY_Filter", 19, 1, "cellsW cellsH seed shape waterOn waterElev x z fpCaps maxSlope minDepth maxDepth fpFlags caps gridSeed terrainPct waterPct gridW gridH", "caps", GenOccupyFilter, OccupyFilterRetail, ENGINE_ONLY(OccupyFilterOurs), true},
      {"CAiPathFinder::IsInBounds", 0x005AA680, "moho/ai/CAiPathFinder.cpp CAiPathFinder::IsInBounds", 9, 1, "useWholeMap inside span x z x0 z0 x1 z1", "inBounds", GenPathInBounds, PathInBoundsRetail, ENGINE_ONLY(PathInBoundsOurs), true},
      {"luaH_getstr", 0x009274D0, "lua/LuaObject.cpp luaH_getstr", 6, 1, "seed sizearray lsizenode fill pool key", "slot", GenLuaGetStr, LuaGetStrRetail, ENGINE_ONLY(LuaGetStrOurs), true},
      {"luaH_getnum", 0x00927450, "lua/LuaObject.cpp luaH_getnum", 6, 1, "seed sizearray lsizenode fill pool key", "slot", GenLuaGetNum, LuaGetNumRetail, ENGINE_ONLY(LuaGetNumOurs), true},
      {"luaH_get", 0x00927510, "lua/LuaObject.cpp luaH_get", 7, 1, "seed sizearray lsizenode fill pool keyTt keyBits", "slot", GenLuaGet, LuaGetRetail, ENGINE_ONLY(LuaGetOurs), true},
      {"luaH_mainposition", 0x00926F70, "lua/LuaObject.cpp luaH_mainposition", 7, 1, "seed sizearray lsizenode fill pool keyTt keyBits", "node", GenLuaMainPosition, LuaMainPositionRetail, ENGINE_ONLY(LuaMainPositionOurs), true},
      {"luaV_equalval", 0x00929810, "lua/LuaObject.cpp luaV_equalval", 3, 1, "tag left right", "equal", GenLuaEqualVal, LuaEqualValRetail, ENGINE_ONLY(LuaEqualValOurs), true},
      {"luaH_index", 0x00927610, "lua/LuaObject.cpp luaH_index", 7, 1, "seed sizearray lsizenode fill pool keyTt keyBits", "index", GenLuaTraverse, LuaIndexRetail, ENGINE_ONLY(LuaIndexOurs), true},
      {"luaH_next", 0x009276A0, "lua/LuaObject.cpp luaH_next", 7, 5, "seed sizearray lsizenode fill pool keyTt keyBits", "ret keyTt keyBits valTt valBits", GenLuaTraverse, LuaNextRetail, ENGINE_ONLY(LuaNextOurs), true},
      {"luaH_set", 0x00927560, "lua/LuaObject.cpp luaH_set", 7, 2, "seed sizearray lsizenode fill pool keyTt keyBits", "slot flags", GenLuaSet, LuaSetRetail, ENGINE_ONLY(LuaSetOurs), true},
      {"luaH_setnum", 0x00927AC0, "lua/LuaObject.cpp luaH_setnum", 6, 2, "seed sizearray lsizenode fill pool key", "slot flags", GenLuaSetNum, LuaSetNumRetail, ENGINE_ONLY(LuaSetNumOurs), true},
      {"luaV_lessthan", 0x009296F0, "lua/LuaObject.cpp luaV_lessthan", 4, 1, "tagLeft tagRight left right", "less", GenLuaLessThan, LuaLessThanRetail, ENGINE_ONLY(LuaLessThanOurs), true},
      {"luaA_index", 0x0090C3D0, "lua/LuaObject.cpp luaA_index", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "slot", GenLuaIndexAny, LuaIndexAnyRetail, ENGINE_ONLY(LuaIndexAnyOurs), true},
      {"negindex", 0x0090C340, "lua/LuaObject.cpp negindex", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "slot", GenLuaIndexNeg, LuaNegIndexRetail, ENGINE_ONLY(LuaNegIndexOurs), true},
      {"lua_type", 0x0090C740, "lua/LuaObject.cpp lua_type", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "type", GenLuaIndexAny, LuaTypeRetail, ENGINE_ONLY(LuaTypeOurs), true},
      {"lua_gettop", 0x0090C590, "lua/LuaObject.cpp lua_gettop", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "top", GenLuaIndexAny, LuaGetTopRetail, ENGINE_ONLY(LuaGetTopOurs), true},
      {"lua_settop", 0x0090C5A0, "lua/LuaObject.cpp lua_settop", 10, 9, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "top tt[8]", GenLuaSetTop, LuaSetTopRetail, ENGINE_ONLY(LuaSetTopOurs), true},
      {"lua_pushvalue", 0x0090C6E0, "lua/LuaObject.cpp lua_pushvalue", 10, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "top tt bits", GenLuaPushValue, LuaPushValueRetail, ENGINE_ONLY(LuaPushValueOurs), true},
      {"lua_tonumber", 0x0090C9F0, "lua/LuaObject.cpp lua_tonumber", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "number", GenLuaToNumber, LuaToNumberRetail, ENGINE_ONLY(LuaToNumberOurs)},
      {"lua_rawgeti", 0x0090D0A0, "lua/LuaObject.cpp lua_rawgeti", 11, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx n", "top tt bits", GenLuaRawGetI, LuaRawGetIRetail, ENGINE_ONLY(LuaRawGetIOurs), true},
      {"lua_pushnumber", 0x0090CD40, "lua/LuaObject.cpp lua_pushnumber", 10, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues n", "top tt bits", GenLuaPushNumber, LuaPushNumberRetail, ENGINE_ONLY(LuaPushNumberOurs), true},
      {"lua_next", 0x0090D6D0, "lua/LuaObject.cpp lua_next", 12, 6, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx keyTt keyBits", "ret top keyTt keyBits valTt valBits", GenLuaNext, LuaNextRetail2, ENGINE_ONLY(LuaNextOurs2), true},
      {"luaT_gettm", 0x00928420, "lua/LuaObject.cpp luaT_gettm", 8, 2, "seed sizearray lsizenode fill pool event key flags", "slot flags", GenLuaGetTm, LuaGetTmRetail, ENGINE_ONLY(LuaGetTmOurs), true},
      {"luaV_gettable", 0x009293E0, "lua/LuaObject.cpp luaV_gettable", 14, 2, "seed sizearray lsizenode fill pool stateSeed base top upvalues keyTt keyBits flags loop tmname0", "slot flags", GenLuaGetTable, LuaGetTableRetail<false>, ENGINE_ONLY(LuaGetTableOurs<false>), true},
      {"luaV_index", 0x00929BF0, "lua/LuaObject.cpp luaV_index", 14, 2, "seed sizearray lsizenode fill pool stateSeed base top upvalues keyTt keyBits flags loop tmname0", "slot flags", GenLuaGetTable, LuaGetTableRetail<true>, ENGINE_ONLY(LuaGetTableOurs<true>), true},
      {"luaV_settable", 0x00929450, "lua/LuaObject.cpp luaV_settable", 14, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues keyTt keyBits valTt valBits tmname1", "flags changedSlot valueHash", GenLuaSetTable, LuaSetTableRetail, ENGINE_ONLY(LuaSetTableOurs), true},
      {"lua_toboolean", 0x0090CA40, "lua/LuaObject.cpp lua_toboolean", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "bool", GenLuaIndexAny, LuaToBooleanRetail, ENGINE_ONLY(LuaToBooleanOurs), true},
      {"lua_isnumber", 0x0090C7A0, "lua/LuaObject.cpp lua_isnumber", 10, 1, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx", "isnumber", GenLuaIndexAny, LuaIsNumberRetail, ENGINE_ONLY(LuaIsNumberOurs), true},
      {"lua_pushnil", 0x0090CD00, "lua/LuaObject.cpp lua_pushnil", 10, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues -", "top tt bits", GenLuaIndexAny, LuaPushNilRetail, ENGINE_ONLY(LuaPushNilOurs), true},
      {"lua_pushboolean", 0x0090CF80, "lua/LuaObject.cpp lua_pushboolean", 10, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues b", "top tt bits", GenLuaPushBoolean, LuaPushBooleanRetail, ENGINE_ONLY(LuaPushBooleanOurs), true},
      {"lua_rawget", 0x0090D050, "lua/LuaObject.cpp lua_rawget", 12, 3, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx keyTt keyBits", "top tt bits", GenLuaRawGet, LuaRawGetRetail, ENGINE_ONLY(LuaRawGetOurs), true},
      {"lua_rawseti", 0x0090D2F0, "lua/LuaObject.cpp lua_rawseti", 11, 4, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx n", "top flags changedSlot valueHash", GenLuaRawSetI, LuaRawSetIRetail, ENGINE_ONLY(LuaRawSetIOurs), true},
      {"lua_rawset", 0x0090D2A0, "lua/LuaObject.cpp lua_rawset", 12, 4, "seed sizearray lsizenode fill pool stateSeed base top upvalues idx keyTt keyBits", "top flags changedSlot valueHash", GenLuaRawSet, LuaRawSetRetail, ENGINE_ONLY(LuaRawSetOurs), true},
      {"CalculateMapWaterRatio", 0x0062D7E0, "moho/ai/CAiBrain.cpp CalculateMapWaterRatio", 6, 1, "cellsW cellsH seed shape waterOn waterElev", "ratio", GenWaterRatio, WaterRatioRetail, ENGINE_ONLY(WaterRatioOurs)},
      {"OCCUPY_MobileCheck", 0x00564AB0, "moho/sim/STIMap.cpp OCCUPY_MobileCheck", 21, 1, "cellsW cellsH seed shape waterOn waterElev x z fpCaps maxSlope minDepth maxDepth fpFlags caps gridSeed terrainPct waterPct gridW gridH sizeX sizeZ", "caps", GenFootprintWorld, MobileCheckRetail, ENGINE_ONLY(MobileCheckOurs), true},
      {"OCCUPY_FootprintFits", 0x007209E0, "moho/sim/STIMap.cpp OCCUPY_FootprintFits", 21, 1, "cellsW cellsH seed shape waterOn waterElev x z fpCaps maxSlope minDepth maxDepth fpFlags caps gridSeed terrainPct waterPct gridW gridH sizeX sizeZ", "caps", GenFootprintWorld, FootprintFitsRetail, ENGINE_ONLY(FootprintFitsOurs), true},
      {"STIMap::IsWithin", 0x0062CA60, "moho/sim/STIMap.cpp STIMap::IsWithin", 11, 1, "cellsW cellsH x0 z0 x1 z1 pos[3] border wholeMap", "inside", GenIsWithin, IsWithinRetail, ENGINE_ONLY(IsWithinOurs), true},
      {"CAiPathFinder::ShouldSearchRect", 0x005AA860, "moho/ai/CAiPathFinder.cpp CAiPathFinder::ShouldSearchRect", 29, 1, "searchType probe anchorX anchorZ goal[8] count history[12] rect[4]", "search", GenShouldSearchRect, ShouldSearchRectRetail, ENGINE_ONLY(ShouldSearchRectOurs), true},
      {"ComputeOctileDistanceCore", 0x005A9D60, "moho/ai/CAiPathFinder.cpp ComputeOctileDistanceCore", 2, 1, "a b", "distance", GenOctile, OctileRetail, ENGINE_ONLY(OctileOurs)},
      {"computesizes", 0x00927090, "lua/LuaObject.cpp computesizes", 2 + kSizeBuckets, 2, "ntotal narray nums[26]", "narray nhash", GenComputeSizes, ComputeSizesRetail, ENGINE_ONLY(ComputeSizesOurs), true},
      {"func_AABoxToRect", 0x004FCBE0, "moho/sim/COGrid.cpp func_AABoxToRect", 6, 2, "min[3] max[3]", "startX|startZ width|height", GenAABoxToRect, AABoxToRectRetail, ENGINE_ONLY(AABoxToRectOurs), true},
      {"COORDS_ToWorldPos", 0x0050B0F0, "moho/entity/Entity.cpp COORDS_ToWorldPos", 11, 3, "cellsW cellsH seed shape waterOn waterElev x z layer sizeX sizeZ", "pos[3]", GenToWorldPos, ToWorldPosRetail, ENGINE_ONLY(ToWorldPosOurs)},
      {"CIntelGrid::IsVisible(rect)", 0x005BE210, "moho/sim/CIntelGrid.cpp CIntelGrid::IsVisible", 9, 1, "cellsW cellsH gridSize seed density rect[4]", "visible", GenIntelRect, IntelRectRetail, ENGINE_ONLY(IntelRectOurs), true},
    };
  } // namespace

  const Target* AllTargets(int& count)
  {
    static const std::vector<Target> all = [] {
      int mathCount = 0;
      const Target* const math = MathTargets(mathCount);
      std::vector<Target> rows(math, math + mathCount);
      rows.insert(rows.end(), std::begin(kSimTargets), std::end(kSimTargets));
      return rows;
    }();
    count = static_cast<int>(all.size());
    return all.data();
  }
} // namespace difffuzz

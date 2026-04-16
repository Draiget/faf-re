#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/Rect2.h"
#include "legacy/containers/Vector.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "lua/LuaObject.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SMinMax.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Vector2.h"

namespace moho
{
  class COGrid;
  class CGeomSolid3;

  struct CHeightFieldMinMaxGrid
  {
    SMinMax<std::uint16_t>* data; // +0x00
    std::int32_t width;           // +0x04
    std::int32_t height;          // +0x08
  };

  struct CHeightFieldI16Grid
  {
    std::int16_t* data;  // +0x00
    std::int32_t width;  // +0x04
    std::int32_t height; // +0x08
  };

  struct CHeightFieldTier
  {
    CHeightFieldMinMaxGrid data1; // +0x00
    CHeightFieldI16Grid data2;    // +0x0C
  };

  struct GeomLine3
  {
    Wm3::Vec3f pos; // +0x00
    Wm3::Vec3f dir; // +0x0C
    float closest;  // +0x18
    float farthest; // +0x1C
  };

  struct VecDist
  {
    Wm3::Vec3f dir; // +0x00
    float dist;     // +0x0C
  };

  struct CGeomHitResult
  {
    float distance; // +0x00
    float v1;       // +0x04
  };

  struct CColHitResult : CGeomHitResult
  {
    std::int32_t hitKind; // +0x08 (1 = terrain, 3 = synthetic plane/water)
  };

  static_assert(sizeof(CHeightFieldMinMaxGrid) == 0x0C, "CHeightFieldMinMaxGrid size must be 0x0C");
  static_assert(sizeof(CHeightFieldI16Grid) == 0x0C, "CHeightFieldI16Grid size must be 0x0C");
  static_assert(sizeof(CHeightFieldTier) == 0x18, "CHeightFieldTier size must be 0x18");
  static_assert(sizeof(GeomLine3) == 0x20, "GeomLine3 size must be 0x20");
  static_assert(sizeof(VecDist) == 0x10, "VecDist size must be 0x10");
  static_assert(sizeof(CGeomHitResult) == 0x08, "CGeomHitResult size must be 0x08");
  static_assert(offsetof(CColHitResult, hitKind) == 0x08, "CColHitResult::hitKind offset must be 0x08");

  class CHeightField
  {
  public:
    /**
     * Address: 0x00476090 (FUN_00476090)
     *
     * int width, int height
     *
     * IDA signature:
     * Moho::CHeightField *__stdcall Moho::CHeightField::CHeightField(Moho::CHeightField *this, int width, int height);
     *
     * What it does:
     * Builds the base height sample grid and allocates tiered min/max + aux
     * subgrids for coarse collision/path queries.
     */
    CHeightField(std::int32_t width, std::int32_t height);

    /**
     * Address: 0x004784F0 (+ chunk 0x00478420 from ctor cleanup island)
     *
     * What it does:
     * Releases all tier subgrid buffers and base height data.
     */
    ~CHeightField();

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
     * Allocates `width * height` 16-bit height samples and zero-initializes them.
     */
    void InitField(std::int32_t width, std::int32_t height);

    /**
     * Address: 0x00478490
     *
     * What it does:
     * Returns a clamped sample from the base 16-bit height grid.
     */
    [[nodiscard]]
    std::uint16_t GetHeightAt(std::int32_t x, std::int32_t z) const;

    /**
     * Address: 0x00478470 (FUN_00478470, Moho::CHeightField::GetArrayAt)
     *
     * int x, int z
     *
     * What it does:
     * Returns pointer to the base height-word sample at `(x,z)` without
     * additional bounds checks.
     */
    [[nodiscard]]
    std::uint16_t* GetArrayAt(std::int32_t x, std::int32_t z);

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
    [[nodiscard]]
    float GetElevation(float x, float z) const;

    /**
     * Address: 0x0069A620 (FUN_0069A620, Moho::CHeightField::GetNormal)
     *
     * float x, float z
     *
     * What it does:
     * Samples four neighboring elevations around `(x,z)`, builds one terrain
     * gradient normal, and normalizes the output vector.
     */
    [[nodiscard]]
    Wm3::Vec3f GetNormal(float x, float z) const;

    /**
     * Address: 0x00476260 (FUN_00476260, Moho::CHeightField::UpdateError)
     *
     * gpg::Rect2<int>
     *
     * IDA signature:
     * unsigned int __userpurge Moho::CHeightField::UpdateError@<eax>(
     *   Moho::CHeightField *this@<esi>, int x0, int z0, int x1, int z1);
     *
     * What it does:
     * Rebuilds terrain error tiers for a changed rectangle with no progress
     * callback handle.
     */
    void UpdateError(gpg::Rect2i rect);

    /**
     * Address: 0x004762E0 (FUN_004762E0, Moho::CHeightField::UpdateError)
     *
     * Moho::CBackgroundTaskControl &, gpg::Rect2<int>
     *
     * IDA signature:
     * struct_iGrid *__userpurge Moho::CHeightField::UpdateError@<eax>(
     *   Moho::CHeightField *this@<esi>,
     *   struct gpg::BinaryReader *loadControl,
     *   int x0, int z0, int x1, int z1);
     *
     * What it does:
     * Rebuilds terrain error tiers for a changed rectangle while pumping the
     * background-load progress control path.
     */
    void UpdateError(CBackgroundTaskControl& loadControl, gpg::Rect2i rect);

    /**
     * Address: 0x00478040 (FUN_00478040, Moho::CHeightField::Rescale)
     *
     * float scale
     *
     * What it does:
     * Scales all 16-bit terrain height samples by `scale` and clamps each result
     * to `[0, 65535]`.
     */
    void Rescale(float scale);

    /**
     * Address: 0x00476BB0 (FUN_00476BB0, Moho::CHeightField::UpdateBounds)
     *
     * gpg::Rect2<int>
     *
     * What it does:
     * Recomputes tiered min/max bounds for all hierarchy levels touched by the
     * changed base-height rectangle.
     */
    void UpdateBounds(gpg::Rect2i rect);

    /**
     * Address: 0x00477E10 (FUN_00477E10, Moho::CHeightField::SetElevationRect)
     *
     * gpg::Rect2<int> const &, float const *
     *
     * What it does:
     * Writes clamped 16-bit heights into the requested rectangle and refreshes
     * impacted tier bounds.
     */
    void SetElevationRect(const gpg::Rect2i& rect, const float* source);

    /**
     * Address: 0x00477F10 (FUN_00477F10, Moho::CHeightField::SetElevationRectRaw)
     *
     * gpg::Rect2<int> const &, unsigned short const *, int
     *
     * What it does:
     * Copies raw 16-bit source heights into the requested rectangle and refreshes
     * impacted tier bounds.
     */
    void SetElevationRectRaw(
      const gpg::Rect2i& rect,
      const std::uint16_t* source,
      std::int32_t sourceRowStride
    );

    /**
     * Address: 0x00478010 (FUN_00478010, Moho::CHeightField::CopyHeightsRectFrom)
     *
     * Moho::CHeightField const *, gpg::Rect2<int> const &
     *
     * What it does:
     * Copies one rectangle of raw heights from another field using the source
     * row stride.
     */
    void CopyHeightsRectFrom(const CHeightField* source, const gpg::Rect2i& rect);

    /**
     * Address: 0x00475DA0 (FUN_00475DA0)
     *
     * int x, int z, int tier
     *
     * IDA signature:
     * void __userpurge Moho::CHeightField::GetTierBounds(
     *   Moho::CHeightField *this@<edx>, Wm3::Vector2f *out@<esi>, int x, int tier, int z@<eax>);
     *
     * What it does:
     * Returns tier-cell min/max heights scaled into world units (`x=min`, `y=max`).
     */
    [[nodiscard]]
    Wm3::Vec2f GetTierBounds(std::int32_t x, std::int32_t z, std::int32_t tier) const;

    /**
     * Address: 0x00475BF0 (FUN_00475BF0)
     *
     * int tier, int x, int z
     *
     * IDA signature:
     * Moho::SMinMax_ushort *__fastcall Moho::CHeightField::GetTierBoundsUWord(int tier, int x, Moho::CHeightField
     * *this, Moho::SMinMax_ushort *dest, int z);
     *
     * What it does:
     * Returns min/max height word pair for one tier cell (or 2x2 base sample block for tier 0).
     */
    [[nodiscard]]
    SMinMax<std::uint16_t> GetTierBoundsUWord(std::int32_t tier, std::int32_t x, std::int32_t z) const;

    /**
     * Address: 0x0080B9D0 (FUN_0080B9D0, Moho::CHeightField::GetTierMaxError)
     *
     * int tier, int x, int z
     *
     * What it does:
     * Returns tier-grid stored max error at `(x,z)` scaled into world units.
     */
    [[nodiscard]]
    float GetTierMaxError(std::int32_t tier, std::int32_t x, std::int32_t z) const;

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
    [[nodiscard]]
    Wm3::AxisAlignedBox3f GetTierBox(std::int32_t x, std::int32_t z, std::int32_t tier) const;

    /**
     * Address: 0x00577660 (FUN_00577660, Moho::CHeightField::GetBounds3D)
     *
     * What it does:
     * Computes the current tier count from `mGrids` and returns
     * `GetTierBox(0, 0, tierCount)`.
     */
    [[nodiscard]]
    Wm3::AxisAlignedBox3f GetBounds3D() const;

    /**
     * Address: 0x00478280 (FUN_00478280, Moho::CHeightField::ConvexIntersection)
     *
     * Moho::CGeomSolid3 const&
     *
     * What it does:
     * Computes world-space AABB covering terrain cells intersecting the input
     * convex solid.
     */
    [[nodiscard]]
    Wm3::AxisAlignedBox3f ConvexIntersection(const CGeomSolid3& solid) const;

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
    [[nodiscard]]
    bool ClipSegmentToWorld(const Wm3::Vec3f& pos, const Wm3::Vec3f& dir, float& min, float& max) const;

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
    [[nodiscard]]
    Wm3::Vec3f Intersection(const GeomLine3& line, CGeomHitResult* res) const;

  private:
    /**
     * Address: 0x00476330 (FUN_00476330, Moho::CHeightField::UpdateError)
     *
     * Moho::CBackgroundTaskControl &, int x0, int z0, int x1, int z1
     *
     * What it does:
     * Computes per-tier geometric error values for the affected region and
     * propagates conservative maxima upward through higher tiers.
     */
    void UpdateError(
      CBackgroundTaskControl& loadControl,
      std::int32_t x0,
      std::int32_t z0,
      std::int32_t x1,
      std::int32_t z1
    );

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
    [[nodiscard]]
    bool
    DoIntersection(const Wm3::Vec3f& pos, const Wm3::Vec3f& dir, float start, float end, CGeomHitResult* res) const;

    /**
     * Address: 0x004778F0 (FUN_004778F0)
     *
     * Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const
     * &, int x, int z, float def, Moho::CGeomHitResult *
     *
     * IDA signature:
     * bool __userpurge Moho::CHeightField::DoIntersectionLL@<al>(Moho::CHeightField *this@<eax>, int x@<edi>,
     * Wm3::Vector3f *pos, Wm3::Vector3f *dir, Wm3::Vector3f *p1, Wm3::Vector3f *p2, int z, float def,
     * Moho::CGeomHitResult *res);
     *
     * What it does:
     * Tests line chunk against the lower-left terrain triangle in cell `(x,z)`.
     */
    [[nodiscard]]
    bool DoIntersectionLL(
      const Wm3::Vec3f& pos,
      const Wm3::Vec3f& dir,
      const Wm3::Vec3f& p1,
      const Wm3::Vec3f& p2,
      std::int32_t x,
      std::int32_t z,
      float def,
      CGeomHitResult* res
    ) const;

    /**
     * Address: 0x00477B80 (FUN_00477B80)
     *
     * Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const &, Wm3::Vector3<float> const
     * &, int x, int z, float def, Moho::CGeomHitResult *
     *
     * IDA signature:
     * bool __userpurge Moho::CHeightField::DoIntersectionUR@<al>(Moho::CHeightField *this@<eax>, Wm3::Vector3f *pos,
     * Wm3::Vector3f *dir, Wm3::Vector3f *p1, Wm3::Vector3f *p2, int x, int z, float def, Moho::CGeomHitResult *res);
     *
     * What it does:
     * Tests line chunk against the upper-right terrain triangle in cell `(x,z)`.
     */
    [[nodiscard]]
    bool DoIntersectionUR(
      const Wm3::Vec3f& pos,
      const Wm3::Vec3f& dir,
      const Wm3::Vec3f& p1,
      const Wm3::Vec3f& p2,
      std::int32_t x,
      std::int32_t z,
      float def,
      CGeomHitResult* res
    ) const;

  public:
    std::uint16_t* data;                    // +0x00
    std::int32_t width;                     // +0x04
    std::int32_t height;                    // +0x08
    msvc8::vector<CHeightFieldTier> mGrids; // +0x0C
  };

  static_assert(sizeof(CHeightField) == 0x1C, "CHeightField size must be 0x1C");

  /**
   * Address context:
   * - 0x005783E0 (FUN_005783E0)
   * - 0x00578460 (FUN_00578460, func_ConstructTerrainTypes)
   * - 0x00577AD0 (FUN_00577AD0)
   *
   * What it does:
   * `fastvector_n`-style header for terrain Lua objects with 0x100 inline slots.
   * Inline storage is raw bytes so element lifetime is managed explicitly by
   * helper routines (construct/destroy loops), matching binary behavior.
   */
  struct TerrainTypesVectorN
  {
    static constexpr std::size_t kInlineCount = 0x100;

    LuaPlus::LuaObject* start;                                                                         // +0x0000
    LuaPlus::LuaObject* finish;                                                                        // +0x0004
    LuaPlus::LuaObject* capacity;                                                                      // +0x0008
    LuaPlus::LuaObject* original;                                                                      // +0x000C
    alignas(LuaPlus::LuaObject) std::uint8_t inlineStorage[sizeof(LuaPlus::LuaObject) * kInlineCount]; // +0x0010

    [[nodiscard]]
    LuaPlus::LuaObject* InlineBegin() noexcept
    {
      return reinterpret_cast<LuaPlus::LuaObject*>(&inlineStorage[0]);
    }

    [[nodiscard]]
    const LuaPlus::LuaObject* InlineBegin() const noexcept
    {
      return reinterpret_cast<const LuaPlus::LuaObject*>(&inlineStorage[0]);
    }

    [[nodiscard]]
    LuaPlus::LuaObject* begin() noexcept
    {
      return start;
    }

    [[nodiscard]]
    const LuaPlus::LuaObject* begin() const noexcept
    {
      return start;
    }

    [[nodiscard]]
    LuaPlus::LuaObject* end() noexcept
    {
      return finish;
    }

    [[nodiscard]]
    const LuaPlus::LuaObject* end() const noexcept
    {
      return finish;
    }

    [[nodiscard]]
    std::size_t Size() const noexcept
    {
      return start ? static_cast<std::size_t>(finish - start) : 0u;
    }

    [[nodiscard]]
    std::size_t Capacity() const noexcept
    {
      return start ? static_cast<std::size_t>(capacity - start) : 0u;
    }

    [[nodiscard]]
    bool IsInitialized() const noexcept
    {
      return start != nullptr;
    }

    [[nodiscard]]
    bool Empty() const noexcept
    {
      return start == finish;
    }

    [[nodiscard]]
    bool UsingInlineStorage() const noexcept
    {
      return start == InlineBegin();
    }

    void BindInlineEmpty() noexcept
    {
      auto* const inlineBegin = InlineBegin();
      start = inlineBegin;
      finish = inlineBegin;
      capacity = inlineBegin + kInlineCount;
      original = inlineBegin;
    }

    void BindHeapStorage(LuaPlus::LuaObject* buffer, const std::size_t size, const std::size_t cap) noexcept
    {
      start = buffer;
      finish = buffer + size;
      capacity = buffer + cap;
      original = InlineBegin();
    }
  };

  struct TerrainTypes
  {
    TerrainTypesVectorN ttvec; // +0x0000
  };

  struct TerrainTypeGrid
  {
    std::uint8_t* data;  // +0x00
    std::int32_t width;  // +0x04
    std::int32_t height; // +0x08
  };

  static_assert(offsetof(TerrainTypesVectorN, start) == 0x0000, "TerrainTypesVectorN::start offset must be 0x0000");
  static_assert(offsetof(TerrainTypesVectorN, finish) == 0x0004, "TerrainTypesVectorN::finish offset must be 0x0004");
  static_assert(
    offsetof(TerrainTypesVectorN, capacity) == 0x0008, "TerrainTypesVectorN::capacity offset must be 0x0008"
  );
  static_assert(
    offsetof(TerrainTypesVectorN, original) == 0x000C, "TerrainTypesVectorN::original offset must be 0x000C"
  );
  static_assert(
    offsetof(TerrainTypesVectorN, inlineStorage) == 0x0010, "TerrainTypesVectorN::inlineStorage offset must be 0x0010"
  );
  static_assert(sizeof(TerrainTypesVectorN) == 0x1410, "TerrainTypesVectorN size must be 0x1410");
  static_assert(sizeof(TerrainTypes) == 0x1410, "TerrainTypes size must be 0x1410");
  static_assert(sizeof(TerrainTypeGrid) == 0x0C, "TerrainTypeGrid size must be 0x0C");

  class STIMap
  {
  public:
    /**
     * Address: 0x005779C0 (FUN_005779C0)
     *
     * unsigned int width, unsigned int height
     *
     * IDA signature:
     * Moho::STIMap *__userpurge Moho::STIMap::STIMap@<eax>(int height@<esi>, Moho::STIMap *this, int width);
     *
     * What it does:
     * Initializes playable rect, terrain type bytes, water defaults, and
     * allocates a new `CHeightField` backing store.
     */
    STIMap(std::uint32_t width, std::uint32_t height);

    /**
     * Address: 0x00577890 (FUN_00577890)
     *
     * Moho::STIMap *
     *
     * IDA signature:
     * Moho::STIMap *__thiscall Moho::STIMap::STIMap(Moho::STIMap *src, Moho::STIMap *this);
     *
     * What it does:
     * Creates a new map container from another map's dimensions/height data.
     */
    explicit STIMap(STIMap* src);

    /**
     * Address: 0x00577AD0 (FUN_00577AD0)
     *
     * What it does:
     * Releases terrain type bytes and Lua terrain type entries.
     */
    ~STIMap();

    /**
     * Address: 0x00577DF0 (FUN_00577DF0)
     *
     * gpg::Rect2<int> const &
     *
     * IDA signature:
     * char __usercall Moho::STIMap::SetPlayableMapRect@<al>(gpg::Rect2i *rect@<eax>, Moho::STIMap *this@<ebx>);
     *
     * What it does:
     * Clamps the input playable rect to height-field bounds and stores it if non-empty.
     */
    bool SetPlayableMapRect(const gpg::Rect2i& rect);

    /**
     * Address: 0x00577EC0 (FUN_00577EC0)
     *
     * unsigned int x, unsigned int z, unsigned char type
     *
     * IDA signature:
     * void __userpurge Moho::STIMap::SetTerrainType(unsigned int z@<ebx>, unsigned int x@<edi>, Moho::STIMap
     * *this@<esi>, char type);
     *
     * What it does:
     * Writes terrain type byte for one map cell when inside valid map bounds.
     */
    void SetTerrainType(std::uint32_t x, std::uint32_t z, std::uint8_t type);

    /**
     * Address: 0x00577F60 (FUN_00577F60)
     *
     * LuaPlus::LuaState *
     *
     * IDA signature:
     * LuaPlus::LuaObject *__thiscall Moho::STIMap::LoadTerrainTypes(LuaPlus::LuaState *state, Moho::STIMap *this);
     *
     * What it does:
     * Loads `/lua/TerrainTypes.lua`, fills 256 terrain-type Lua entries, and
     * updates per-type blocking flags.
     */
    void LoadTerrainTypes(LuaPlus::LuaState* state);

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
    [[nodiscard]]
    bool IsBlockingTerrain(std::uint32_t z, std::uint32_t x) const;

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
    [[nodiscard]]
    EOccupancyCaps OccupancyCapsOfFootprintAt(const SOCellPos& pos, const SFootprint& footprint) const;

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
     * Returns the Lua terrain-type descriptor for the sampled terrain byte.
     */
    [[nodiscard]]
    LuaPlus::LuaObject GetTerrainType(std::uint32_t x, std::uint32_t z) const;

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
     * Returns the Lua terrain-type descriptor by raw type index.
     */
    [[nodiscard]]
    LuaPlus::LuaObject GetTerrainType(std::uint8_t typeIndex) const;

    /**
     * Address: 0x00758E90 (FIND_GetTerrainTypeOffset_exe)
     *
     * float x, float z
     *
     * IDA signature:
     * float __userpurge Moho::STIMap::GetTerrainTypeOffset@<xmm0>(Moho::STIMap *this, float x, float z);
     *
     * What it does:
     * Reads optional `HeightOffset` from the sampled terrain-type Lua table.
     */
    [[nodiscard]]
    float GetTerrainTypeOffset(float x, float z) const;

    /**
     * Address: 0x0069A6F0 (FUN_0069A6F0, ?GetTerrainNormal@STIMap@Moho@@QBE?AV?$Vector3@M@Wm3@@MM@Z)
     *
     * What it does:
     * Forwards terrain-normal sampling to the height-field normal helper.
     */
    [[nodiscard]]
    Wm3::Vec3f GetTerrainNormal(float x, float z) const;

    /**
     * Address: 0x00577B60 (FUN_00577B60)
     *
     * IDA signature:
     * Wm3::AxisAlignedBox3f *__userpurge Moho::STIMap::GetBounds3D@<eax>(Moho::STIMap *this@<ebx>,
     * Wm3::AxisAlignedBox3f *out);
     *
     * What it does:
     * Returns map world bounds from the coarsest height tier and lifts top Y to water level when enabled.
     */
    [[nodiscard]]
    Wm3::AxisAlignedBox3f GetBounds3D() const;

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
     * Intersects segment against terrain/water surface and returns hit point.
     */
    [[nodiscard]]
    Wm3::Vec3f SurfaceIntersection(const GeomLine3& line, CColHitResult* res) const;

    /**
     * Address: 0x005ADC20 (FUN_005ADC20)
     *
     * Wm3::Vector3<float> const &
     *
     * What it does:
     * Returns whether terrain elevation at `position` is above the active
     * water plane (or above `-10000.0f` when water is disabled).
     */
    [[nodiscard]]
    bool AboveWater(const Wm3::Vec3f& position) const;

    /**
     * Address: 0x0086DA60 (FUN_0086DA60)
     * Mangled: ?IsPlayable@STIMap@Moho@@QBE_NABV?$Vector3@M@Wm3@@@Z
     *
     * Wm3::Vector3<float> const &
     *
     * What it does:
     * Truncates world-space `x/z` to ints and checks they lie inside
     * `mPlayableRect` using `[min,max)` bounds.
     */
    [[nodiscard]]
    bool IsPlayable(const Wm3::Vec3f& position) const;

    /**
     * Address: 0x0050ACE0 (FUN_0050ACE0)
     *
     * What it does:
     * Samples terrain elevation at world `(x,z)` and applies map water-floor
     * clamping when water is enabled.
     */
    [[nodiscard]]
    float GetSurface(float x, float z) const;

    /**
     * Address: 0x00541A30 (FUN_00541A30), 0x1012F3B0 (FUN_1012F3B0)
     *
     * Wm3::Vector3<float> const &
     *
     * What it does:
     * Returns max(terrain elevation, water elevation when water is enabled).
     */
    [[nodiscard]]
    float GetSurface(const Wm3::Vec3f& position) const;

    /**
     * Address: 0x0062D620 (FUN_0062D620, Moho::STIMap::LookAheadForMaxTerrain)
     *
     * What it does:
     * Samples terrain elevation ahead of air movement using tiered min/max
     * bounds for long lookahead distances, then applies water-floor rules.
     */
    [[nodiscard]]
    float LookAheadForMaxTerrain(const Wm3::Vec3f& position, bool flyInWater, float lookahead) const;

    /**
     * Address: 0x0062CA60 (FUN_0062CA60, Moho::STIMap::IsWithin)
     *
     * What it does:
     * Returns whether a circle at `position` with `border` radius fits either
     * the whole terrain bounds or the playable-rect bounds.
     */
    [[nodiscard]]
    bool IsWithin(const Wm3::Vec3f& position, float border, bool wholeMap) const;

    /**
     * Address: 0x007F7B00 (FUN_007F7B00, Moho::STIMap::GetHeightField)
     *
     * What it does:
     * Copies this map's shared height-field ownership lane into
     * `outHeightField`.
     */
    void GetHeightField(boost::shared_ptr<CHeightField>& outHeightField) const;

    [[nodiscard]] CHeightField* GetHeightField() const noexcept;
    /**
     * Address: 0x006BC400 (FUN_006BC400, ?GetElevation@CHeightField@Moho@@QBEMHH@Z)
     *
     * What it does:
     * Clamps one cell coordinate pair to the heightfield extents, returns
     * scaled terrain elevation, and applies map water-floor clamping when
     * water is enabled.
     */
    [[nodiscard]] float GetElevation(std::int32_t x, std::int32_t z) const;
    [[nodiscard]] bool IsWaterEnabled() const noexcept;
    [[nodiscard]] float GetWaterElevation() const noexcept;
    /**
     * Address: 0x0089E5C0 (FUN_0089E5C0)
     *
     * What it does:
     * Stores one raw water-enabled byte flag into lane `+0x1534`.
     */
    STIMap* SetWaterEnabledRaw(std::uint8_t enabled) noexcept;
    /**
     * Address: 0x0089E5D0 (FUN_0089E5D0)
     *
     * What it does:
     * Stores one water-elevation float lane at offset `+0x1538`.
     */
    STIMap* SetWaterElevation(float elevation) noexcept;
    /**
     * Address: 0x0089E5E0 (FUN_0089E5E0)
     *
     * What it does:
     * Stores one deep-water elevation float lane at offset `+0x153C`.
     */
    STIMap* SetWaterElevationDeep(float elevation) noexcept;
    /**
     * Address: 0x0089E5F0 (FUN_0089E5F0)
     *
     * What it does:
     * Stores one abyss-water elevation float lane at offset `+0x1540`.
     */
    STIMap* SetWaterElevationAbyss(float elevation) noexcept;

  public:
    boost::shared_ptr<CHeightField> mHeightField; // +0x0000
    gpg::Rect2i mPlayableRect;                    // +0x0008
    TerrainTypes mTerrainTypes;                   // +0x0018
    TerrainTypeGrid mTerrainType;                 // +0x1428
    std::uint8_t mBlocking[0x100];                // +0x1434
    std::uint8_t mWaterEnabled;                   // +0x1534
    std::uint8_t pad_1535[3];                     // +0x1535
    float mWaterElevation;                        // +0x1538
    float mWaterElevationDeep;                    // +0x153C
    float mWaterElevationAbyss;                   // +0x1540
  };

  static_assert(offsetof(STIMap, mTerrainType) == 0x1428, "STIMap::mTerrainType offset must be 0x1428");
  static_assert(offsetof(STIMap, mBlocking) == 0x1434, "STIMap::mBlocking offset must be 0x1434");
  static_assert(offsetof(STIMap, mWaterEnabled) == 0x1534, "STIMap::mWaterEnabled offset must be 0x1534");
  static_assert(sizeof(STIMap) == 0x1544, "STIMap size must be 0x1544");

  /**
   * Address: 0x00564AB0 (FUN_00564AB0, ?OCCUPY_MobileCheck@Moho@@YA?AW4ELayer@1@ABUSFootprint@1@ABUSOCellPos@1@PBVSTIMap@1@@Z)
   *
   * Moho::SFootprint const &, Moho::STIMap const &, Moho::SOCellPos const &
   *
   * What it does:
   * Computes dynamic occupancy caps for multi-cell footprints using terrain,
   * blocking-map, depth, and slope checks.
   */
  [[nodiscard]]
  EOccupancyCaps OCCUPY_MobileCheck(const SFootprint& footprint, const STIMap& map, const SOCellPos& pos);

  /**
   * Address: 0x00720920 (FUN_00720920)
   *
   * Moho::SFootprint const &, Moho::COGrid const &, Moho::SOCellPos const &, Moho::EOccupancyCaps
   *
   * What it does:
   * Applies single-cell occupancy filtering against terrain/water occupation bitmaps.
   */
  [[nodiscard]]
  EOccupancyCaps OCCUPY_Filter(
    const SFootprint& footprint,
    const COGrid& grid,
    const SOCellPos& pos,
    EOccupancyCaps occupancyCaps
  );

  /**
   * Address: 0x007209E0 (FUN_007209E0)
   *
   * Moho::COGrid const &, Moho::SOCellPos const &, Moho::SFootprint const &, Moho::EOccupancyCaps
   *
   * What it does:
   * Returns occupancy-fit caps for a footprint at one origin using mobile
   * terrain checks plus terrain/water occupation bit arrays.
   */
  [[nodiscard]]
  EOccupancyCaps OCCUPY_FootprintFits(
    const COGrid& grid,
    const SOCellPos& pos,
    const SFootprint& footprint,
    EOccupancyCaps occupancyCaps
  );

  /**
   * Address: 0x00720B20 (FUN_00720B20, Moho::OCCUPY_HoverFootprintFits)
   *
   * Moho::SOCellPos const &, Moho::COGrid const &, Moho::SFootprint const &, Moho::EOccupancyCaps
   *
   * What it does:
   * Computes mobile occupancy caps for hover/amphibious motion at one footprint
   * origin and then resolves final fit caps through `OCCUPY_FootprintFits`.
   */
  [[nodiscard]]
  EOccupancyCaps OCCUPY_HoverFootprintFits(
    const SOCellPos& pos,
    const COGrid& grid,
    const SFootprint& footprint,
    EOccupancyCaps occupancyCaps
  );

  struct RUnitBlueprint;
  struct SOccupationResult;
  class ISimResources;
  struct SCoordsVec2;

  /**
   * Address: 0x005651F0 (FUN_005651F0, Moho::OCCUPY_CheckAreaFlatness)
   *
   * What it does:
   * Scans every cell in `rect`, records min/max elevation, writes them to
   * `*outMinHeight`/`*outMaxHeight`, and returns whether the range fits
   * within `blueprint.Physics.MaxGroundVariation`.
   */
  [[nodiscard]]
  bool OCCUPY_CheckAreaFlatness(
    const gpg::Rect2f& rect,
    const RUnitBlueprint& blueprint,
    const STIMap& map,
    float* outMinHeight,
    float* outMaxHeight
  );

  /**
   * Address: 0x00564F80 (FUN_00564F80, Moho::OCCUPY_CheckEdgeFlatness)
   *
   * What it does:
   * `FlattenSkirt`-mode flatness check: walks only the 1-cell-wider
   * perimeter of `rect`, finds min/max elevation, writes them to the out
   * params, and checks whether the deviation from `ceil(pivotArg)` fits
   * within `blueprint.Physics.MaxGroundVariation`. Binary always passes
   * `(pivotArg = 0.0f, xmm1Slot = 0.5f)`; `xmm1Slot` is a register-slot
   * artifact and has no observed input use.
   */
  [[nodiscard]]
  bool OCCUPY_CheckEdgeFlatness(
    const gpg::Rect2f& rect,
    float pivotArg,
    float xmm1Slot,
    const RUnitBlueprint& blueprint,
    const STIMap& map,
    float* outMinHeight,
    float* outMaxHeight
  );

  /**
   * Address: 0x005652E0 (FUN_005652E0, Moho::OCCUPY_Check)
   *
   * What it does:
   * Resolves whether `blueprint` can be placed at `worldPos` and fills
   * `dest` with the chosen world-center position plus the remaining layer
   * bitmask that still passes every check (mobile snapping, flatness,
   * water-depth, build-layer caps, mass/hydrocarbon restriction).
   */
  [[nodiscard]]
  bool OCCUPY_Check(
    STIMap& map,
    const RUnitBlueprint& blueprint,
    const SCoordsVec2& worldPos,
    ISimResources& resources,
    SOccupationResult& dest
  );

  /**
   * Address: 0x00720D90 (FUN_00720D90, Moho::func_LocationIsFree)
   *
   * What it does:
   * Full placement check for `blueprint` at `pos` on `grid`. Wraps
   * `OCCUPY_Check` with additional occupancy-bitmap intersection checks on
   * the footprint rect (for mobile blueprints) plus an existing-unit skirt
   * overlap check (for static blueprints), and writes the resolved
   * placement into `dest`.
   */
  [[nodiscard]]
  bool func_LocationIsFree(
    const RUnitBlueprint& blueprint,
    COGrid& grid,
    const SCoordsVec2& pos,
    SOccupationResult& dest
  );
} // namespace moho
